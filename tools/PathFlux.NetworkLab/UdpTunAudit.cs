using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using PathFlux.Domain;
using PathFlux.Engine;
using PathFlux.Testing;
namespace PathFlux.NetworkLab;

public static class UdpTunAudit
{
    public static async Task<int> RunAsync(string enginePath, string hash, string output, CancellationToken ct)
    {
        Directory.CreateDirectory(output);
        var report = new LabReport { Elevated = LabRunner.IsElevated(), Scope = "Experimental UDP TUN only, single synthetic IPv4 destination; production user Proxy UDP stays rejected" };
        Task SaveAsync() => report.SaveAsync(output);
        try
        {
            if (!report.Elevated) throw new InvalidOperationException("AdministratorRequired");
            await using var binaryLock = new FileStream(enginePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var version = await EngineBinary.VerifyAsync(enginePath, hash, ct); report.EngineVersion = version.ToString();
            report.Before = await NetworkSnapshot.CaptureAsync(ct); await SaveAsync();
            report.PreflightAllowsTun = report.Before.CanStartLab();
            if (!report.PreflightAllowsTun) throw new InvalidOperationException("LabAddressOrInterfaceAlreadyInUse");
            var selected = LabRunner.CloneProbe(Path.Combine(output, "selected")); var control = LabRunner.CloneProbe(Path.Combine(output, "control"));
            foreach (var scenario in new[] { "UdpPath", "UdpName", "ProductionReject", "AssociateRefused", "ControlClosed", "FragmentedReply",
                "FragmentedReply128", "FragmentedReply129", "FragmentedReply255", "ReservedReply", "LostReplies", "Reconnect", "EngineCrash", "JobClose", "Soak60Seconds", "MediaLoad60Seconds" })
            {
                await using var echo = new UdpEchoServer();
                var options = new Socks5UdpRelayOptions { TargetOverride = new(IPAddress.Parse(LabPolicy.TargetAddress), LabPolicy.TargetPort),
                    ReplyCode = scenario == "AssociateRefused" ? (byte)7 : (byte)0,
                    Fault = scenario == "ControlClosed" ? UdpRelayFault.CloseControlBeforeRelay : scenario.StartsWith("FragmentedReply", StringComparison.Ordinal) ? UdpRelayFault.Fragmented
                        : scenario == "ReservedReply" ? UdpRelayFault.NonzeroReserved : scenario == "LostReplies" ? UdpRelayFault.DropResponses
                        : scenario == "Reconnect" ? UdpRelayFault.CloseControlBeforeLastReply : UdpRelayFault.None,
                    FragmentValue = scenario == "FragmentedReply128" ? (byte)128 : scenario == "FragmentedReply129" ? (byte)129 : scenario == "FragmentedReply255" ? (byte)255 : (byte)1,
                    FaultAssociations = scenario == "Reconnect" ? 1 : int.MaxValue, CloseAfterPackets = 1, SessionLifetime = TimeSpan.FromMinutes(5) };
                await using var relay = new Socks5UdpRelay(echo, options);
                await using var bridge = new StrictSocksUdpBridge(new(IPAddress.Loopback, relay.Port));
                var config = LabPolicy.Create(scenario == "UdpName" ? LabScenario.Name : LabScenario.Path, selected, relay.Profile, relay.Profile with { Id = Guid.NewGuid() });
                config = config with { Rules = [config.Rules[0] with { Network = NetworkTransport.Both }], Settings = config.Settings with { EnginePath = enginePath } };
                string json = await LabPolicy.GenerateGuardedAsync(config, ct, version, scenario == "ProductionReject" ? null
                    : new Dictionary<Guid, StrictSocksUdpBridge> { [relay.Profile.Id] = bridge });
                if (!await EngineBinary.CheckAsync(enginePath, json, ct)) throw new InvalidOperationException("EngineCheckFailed");
                report.TunStartAttempted = true; await SaveAsync(); bool selectedGood, controlGood;
                var counters = new Dictionary<string, int>();
                await using (var engine = await LabEngine.StartAsync(enginePath, json, ct))
                {
                    await LabRunner.WaitForInterfaceAsync(engine, ct); report.TunWasStarted = true;
                    if (report.Before.CompareDuring(await NetworkSnapshot.CaptureAsync(ct), LabPolicy.TargetAddress).Length != 0)
                        throw new InvalidOperationException("UnsafeRouteOrAdapterStateDuringLab");
                    int received = 0, controlReceived = 0;
                    bool positive = scenario is "UdpPath" or "UdpName" or "EngineCrash" or "JobClose";
                    if (scenario == "MediaLoad60Seconds")
                    {
                        var stream = await LabChild.RunAsync(selected, ["probe-udp-media", LabPolicy.TargetAddress, LabPolicy.TargetPort.ToString()], ct, TimeSpan.FromSeconds(100));
                        received = stream.Received; counters["Sent"] = stream.Sent;
                        counters["InvalidOrLoadFailure"] = stream.Success ? 0 : 1;
                    }
                    else if (scenario is "Reconnect" or "Soak60Seconds")
                    {
                        int count = scenario == "Reconnect" ? 10 : 3000;
                        var stream = await LabChild.RunAsync(selected, ["probe-udp-stream", LabPolicy.TargetAddress, LabPolicy.TargetPort.ToString(), count.ToString(), (count - 2).ToString()], ct,
                            TimeSpan.FromSeconds(scenario == "Reconnect" ? 12 : 100));
                        received = stream.Received;
                        counters["Sent"] = stream.Sent;
                    }
                    // Each child uses a fresh OS socket and unique random challenge.
                    else for (int i = 0; i < 3; i++)
                        if ((await LabChild.RunAsync(selected, ["probe-udp", LabPolicy.TargetAddress, LabPolicy.TargetPort.ToString(), Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))], ct)).Success) received++;
                    if ((await LabChild.RunAsync(control, ["probe-udp", LabPolicy.TargetAddress, LabPolicy.TargetPort.ToString(), Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))], ct)).Success) controlReceived++;
                    int expected = positive ? 3 : 0;
                    selectedGood = scenario == "Reconnect" ? received >= 8 && bridge.Reconnects >= 1 && relay.AssociateRequests >= 2
                        : scenario == "Soak60Seconds" ? received >= 2998 && echo.ReceivedPackets == 3000
                        : scenario == "MediaLoad60Seconds" ? received >= 59400 && echo.ReceivedPackets >= received && counters["InvalidOrLoadFailure"] == 0
                        : received == expected && (expected == 0 || relay.ForwardedPackets >= 3);
                    controlGood = controlReceived == (scenario == "UdpName" ? 1 : 0);
                    if (scenario == "ProductionReject") selectedGood &= relay.AssociateRequests == 0 && echo.ReceivedPackets == 0;
                    if (scenario is "AssociateRefused" or "ControlClosed") selectedGood &= relay.AssociateRequests > 0 && echo.ReceivedPackets == 0;
                    if (scenario.StartsWith("FragmentedReply", StringComparison.Ordinal)) selectedGood &= echo.ReceivedPackets == 3 && bridge.DroppedFragments == 3;
                    counters["Received"] = received; counters["ControlReceived"] = controlReceived;
                    counters["AssociateRequests"] = relay.AssociateRequests; counters["ForwardedPackets"] = relay.ForwardedPackets; counters["EchoPackets"] = echo.ReceivedPackets;
                    counters["DroppedFragments"] = bridge.DroppedFragments; counters["DroppedInvalid"] = bridge.DroppedInvalid;
                    counters["Reconnects"] = bridge.Reconnects;
                    if (!selectedGood || !controlGood) report.LaboratoryDiagnostic = engine.Diagnostic
                        .Replace(bridge.LocalCredentials.Username, "REDACTED", StringComparison.Ordinal)
                        .Replace(bridge.LocalCredentials.Password, "REDACTED", StringComparison.Ordinal);
                    if (scenario == "EngineCrash") engine.AbortProcess();
                    if (scenario == "JobClose") engine.CloseOwnerJob();
                }
                bool recovered = await LabRunner.WaitForRecoveryAsync(report.Before, ct);
                report.Cases.Add(new(scenario, selectedGood && controlGood && recovered, selectedGood, controlGood, recovered, counters)); await SaveAsync();
                if (!report.Cases[^1].Passed) throw new InvalidOperationException("ScenarioFailed_" + scenario);
            }
            report.Status = "PassedExperimentalUdpTunOnly_UserRulesStillReject";
        }
        catch (Exception ex) { report.Status = "Failed"; report.ErrorCode = ex is InvalidOperationException ? ex.Message : ex.GetType().Name; }
        finally
        {
            if (report.TunStartAttempted && report.Before is { } before && !await LabRunner.WaitForRecoveryAsync(before, CancellationToken.None)) report.Status = "RecoveryNotConfirmed";
            report.After = await NetworkSnapshot.CaptureAsync(CancellationToken.None); await SaveAsync();
            Console.WriteLine($"{report.Status}: {Path.Combine(output, "report.json")}");
        }
        return report.Status == "PassedExperimentalUdpTunOnly_UserRulesStillReject" ? 0 : 1;
    }
}
