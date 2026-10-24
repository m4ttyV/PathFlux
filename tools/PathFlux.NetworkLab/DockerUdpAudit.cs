using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using PathFlux.Domain;
using PathFlux.Engine;

namespace PathFlux.NetworkLab;

public static class DockerUdpAudit
{
    // Deployment parameters, not a discovered/guessed container IP or a pinned relay port.
    // Command line with explicit port-range override is below; no profile/production setting is enabled.
    public static async Task<int> RunAsync(string enginePath, string hash, string output, CancellationToken ct,
        int publishedFirst = 20000, int publishedLast = 20030, bool dns = false)
    {
        string target = "1.1.1.1";
        Directory.CreateDirectory(output);
        var report = new LabReport { Elevated = LabRunner.IsElevated(), Scope = $"Experimental IPv4 UDP TUN to {(dns ? "1.1.1.1:53" : "stun.cloudflare.com:3478")} through Dante/Docker/OpenVPN; published loopback ports {publishedFirst}-{publishedLast}; DNS mode={dns}; Discord and sustained media are not accepted" };
        try
        {
            if (!report.Elevated) throw new InvalidOperationException("AdministratorRequired");
            if (!dns) target = (await Dns.GetHostAddressesAsync("stun.cloudflare.com", ct)).First(a => a.AddressFamily == AddressFamily.InterNetwork).ToString();
            await using var binaryLock = new FileStream(enginePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var version = await EngineBinary.VerifyAsync(enginePath, hash, ct); report.EngineVersion = version.ToString();
            report.Before = await NetworkSnapshot.CaptureAsync(ct); await report.SaveAsync(output);
            report.PreflightAllowsTun = report.Before.CanStartLab(target);
            if (!report.PreflightAllowsTun) throw new InvalidOperationException("LabAddressOrInterfaceAlreadyInUse");
            var selected = LabRunner.CloneProbe(Path.Combine(output, "selected"));
            var control = LabRunner.CloneProbe(Path.Combine(output, "control"));
            async Task<ProbeResult> Probe(string path) => await LabChild.RunAsync(path, [dns ? "probe-dns" : "probe-stun", target, dns ? "53" : "3478"], ct);
            if (!(await Probe(control)).Success) throw new InvalidOperationException("DirectUdpBaselineFailed");
            report.ClonedProbeSelfTestPassed = true;
            foreach (string scenario in new[] { "DockerUdpPath", "DockerUdpName", "UnpublishedPort", "ProductionReject", "EngineCrash", "JobClose" })
            {
                var profile = new ProxyProfile { Name = "Existing Dante Docker SOCKS", Host = "127.0.0.1", Port = 1080 };
                await using var bridge = new StrictSocksUdpBridge(new(IPAddress.Loopback, 1080), scenario == "UnpublishedPort"
                    ? new UdpRelayBinding(1, 1) : new UdpRelayBinding(publishedFirst, publishedLast));
                var config = LabPolicy.Create(scenario == "DockerUdpName" ? LabScenario.Name : LabScenario.Path, selected, profile, profile with { Id = Guid.NewGuid() });
                config = config with { Rules = [config.Rules[0] with { Network = NetworkTransport.Both }], Settings = config.Settings with { EnginePath = enginePath } };
                var json = JsonNode.Parse(await LabPolicy.GenerateGuardedAsync(config, ct, version, scenario == "ProductionReject" ? null
                    : new Dictionary<Guid, StrictSocksUdpBridge> { [profile.Id] = bridge }))!;
                json["inbounds"]![0]!["route_address"] = new JsonArray(target + "/32");
                if (!await EngineBinary.CheckAsync(enginePath, json.ToJsonString(), ct)) throw new InvalidOperationException("EngineCheckFailed");
                report.TunStartAttempted = true; await report.SaveAsync(output);
                bool selectedGood, controlGood;
                var counters = new Dictionary<string, int>();
                await using (var engine = await LabEngine.StartAsync(enginePath, json.ToJsonString(), ct))
                {
                    await LabRunner.WaitForInterfaceAsync(engine, ct); report.TunWasStarted = true;
                    if (report.Before.CompareDuring(await NetworkSnapshot.CaptureAsync(ct), target).Length != 0)
                        throw new InvalidOperationException("UnsafeRouteOrAdapterStateDuringLab");
                    var a = await Probe(selected); var b = await Probe(control);
                    bool positive = scenario is not ("UnpublishedPort" or "ProductionReject");
                    int expectedRelayed = positive ? scenario == "DockerUdpName" ? 2 : 1 : 0;
                    selectedGood = a.Success == positive && bridge.ReceivedPackets == expectedRelayed && bridge.SentPackets == expectedRelayed;
                    controlGood = b.Success; // Same DNS destination stays directly reachable while selected traffic fails closed.
                    if (scenario == "UnpublishedPort") selectedGood &= bridge.AssociateAttempts > 0 && bridge.LastEffectiveRelay is null;
                    if (scenario == "ProductionReject") selectedGood &= bridge.AssociateAttempts == 0;
                    counters["SelectedReceived"] = a.Received; counters["ControlReceived"] = b.Received;
                    counters["RelaySent"] = checked((int)bridge.SentPackets); counters["RelayReceived"] = checked((int)bridge.ReceivedPackets);
                    counters["AssociateAttempts"] = bridge.AssociateAttempts;
                    counters["AdvertisedPort"] = bridge.LastAdvertisedRelay?.Port ?? 0;
                    counters["EffectivePort"] = bridge.LastEffectiveRelay?.Port ?? 0;
                    counters["MappedToLoopback"] = bridge.LastEffectiveRelay?.Address.Equals(IPAddress.Loopback) == true ? 1 : 0;
                    if (!selectedGood || !controlGood) report.LaboratoryDiagnostic = $"Selected={a.Code}; Control={b.Code}\n" + engine.Diagnostic
                        .Replace(bridge.LocalCredentials.Username, "REDACTED", StringComparison.Ordinal)
                        .Replace(bridge.LocalCredentials.Password, "REDACTED", StringComparison.Ordinal);
                    if (scenario == "EngineCrash") engine.AbortProcess();
                    if (scenario == "JobClose") engine.CloseOwnerJob();
                }
                bool recovered = await LabRunner.WaitForRecoveryAsync(report.Before, ct);
                report.Cases.Add(new(scenario, selectedGood && controlGood && recovered, selectedGood, controlGood, recovered, counters));
                await report.SaveAsync(output);
                if (!report.Cases[^1].Passed) throw new InvalidOperationException("ScenarioFailed_" + scenario);
            }
            report.Status = dns ? "PassedDockerUdpDnsTunOnly_UserRulesStillReject" : "PassedDockerUdpStunTunOnly_UserRulesStillReject";
        }
        catch (Exception ex) { report.Status = "Failed"; report.ErrorCode = ex is InvalidOperationException ? ex.Message : ex.GetType().Name; }
        finally
        {
            if (report.TunStartAttempted && report.Before is { } before && !await LabRunner.WaitForRecoveryAsync(before, CancellationToken.None)) report.Status = "RecoveryNotConfirmed";
            report.After = await NetworkSnapshot.CaptureAsync(CancellationToken.None); await report.SaveAsync(output);
            Console.WriteLine($"{report.Status}: {Path.Combine(output, "report.json")}");
        }
        return report.Status is "PassedDockerUdpDnsTunOnly_UserRulesStillReject" or "PassedDockerUdpStunTunOnly_UserRulesStillReject" ? 0 : 1;
    }
}
