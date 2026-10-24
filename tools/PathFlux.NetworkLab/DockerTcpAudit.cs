using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Nodes;
using PathFlux.Domain;
using PathFlux.Engine;
namespace PathFlux.NetworkLab;

public static class DockerTcpAudit
{
    public static async Task<int> RunAsync(string enginePath, string hash, string output, CancellationToken ct, string? productionAgent = null)
    {
        Directory.CreateDirectory(output);
        var report = new LabReport { Elevated = LabRunner.IsElevated(), Scope = productionAgent is null
            ? "IPv4 TCP TUN to one example.com IP; Docker SOCKS5/OpenVPN, reachable Direct control, no full default-route acceptance"
            : "Production agent IPC/UAC and default-route dual-stack TUN, Docker TCP; DNS/IPv6 traffic and kill switch not accepted" };
        bool attempted = false;
        Task SaveAsync() => report.SaveAsync(output);
        try
        {
            if (!report.Elevated && productionAgent is null) throw new InvalidOperationException("AdministratorRequired");
            await using var binaryLock = new FileStream(enginePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var version = await EngineBinary.VerifyAsync(enginePath, hash, ct); report.EngineVersion = version.ToString();
            const string host = "example.com";
            var target = (await Dns.GetHostAddressesAsync(host, ct)).First(a => a.AddressFamily == AddressFamily.InterNetwork);
            report.Before = await NetworkSnapshot.CaptureAsync(ct); await SaveAsync();
            report.PreflightAllowsTun = report.Before.CanStartLab(target.ToString());
            if (!report.PreflightAllowsTun) throw new InvalidOperationException("LabAddressOrInterfaceAlreadyInUse");
            var selected = LabRunner.CloneProbe(Path.Combine(output, "selected"));
            var control = LabRunner.CloneProbe(Path.Combine(output, "control"));
            async Task<ProbeResult> Probe(string path) => await LabChild.RunAsync(path, ["probe-tls", target.ToString(), "443", host], ct);
            if (!(await Probe(control)).Success) throw new InvalidOperationException("DirectTlsBaselineFailed");
            report.ClonedProbeSelfTestPassed = true;
            await using var good = new SocksConnectObserver(target, 443);
            await using var bad = new SocksConnectObserver(target, 443, refuse: true);
            foreach (var scenario in productionAgent is null ? new[] { "DockerPath", "DockerName", "UpstreamRefused", "Block", "Direct" } : new[] { "DockerPath", "DockerName", "UpstreamRefused" })
            {
                var config = LabPolicy.Create(scenario == "DockerName" ? LabScenario.Name : LabScenario.Path, selected, good.Profile, bad.Profile);
                if (scenario == "UpstreamRefused") config = config with { Rules = [config.Rules[0] with { ProfileId = bad.Profile.Id }] };
                if (scenario is "Block" or "Direct") config = config with { Rules = [config.Rules[0] with { Action = scenario == "Block" ? RouteAction.Block : RouteAction.Direct, ProfileId = null }] };
                config = config with { Settings = config.Settings with { EnginePath = enginePath } };
                config = config with { Profiles = config.Profiles.Select(p => p.Id == good.Profile.Id ? p with { Host = "localhost" } : p).ToList() };
                var json = JsonNode.Parse(await LabPolicy.GenerateAsync(config, ct, version))!;
                json["inbounds"]![0]!["route_address"] = new JsonArray(target + "/32");
                if (productionAgent is not null) config = config with { Settings = config.Settings with { EngineSha256 = hash } };
                if (!await EngineBinary.CheckAsync(enginePath, json.ToJsonString(), ct)) throw new InvalidOperationException("EngineCheckFailed");
                int goodBefore = good.Forwards, badBefore = bad.Requests;
                bool selectedGood, controlGood;
                var counters = new Dictionary<string, int>();
                attempted = true; report.TunStartAttempted = true; await SaveAsync();
                LabEngine? engine = null;
                SingBoxEngineAdapter? adapter = null;
                try
                {
                    if (productionAgent is null)
                    {
                        engine = await LabEngine.StartAsync(enginePath, json.ToJsonString(), ct);
                        await LabRunner.WaitForInterfaceAsync(engine, ct);
                    }
                    else
                    {
                        adapter = new SingBoxEngineAdapter(new RecoveryProbeSecrets(), productionAgent);
                        await adapter.StartAsync(config, ct);
                    }
                    report.TunWasStarted = true;
                    var during = await NetworkSnapshot.CaptureAsync(ct);
                    report.During = during;
                    if (productionAgent is null)
                    {
                    if (report.Before.CompareDuring(during, target.ToString()).Length != 0) throw new InvalidOperationException("UnsafeRouteOrAdapterStateDuringLab");
                    if (!during.Routes.Any(r => r.DestinationPrefix == target + "/32")) throw new InvalidOperationException("TargetRouteMissing");
                    if (!report.Before.Routes.Where(r => NetworkSnapshot.IsDefaultLike(r.DestinationPrefix)).OrderBy(r => r.ToString())
                        .SequenceEqual(during.Routes.Where(r => NetworkSnapshot.IsDefaultLike(r.DestinationPrefix)).OrderBy(r => r.ToString())))
                        throw new InvalidOperationException("VpnDefaultRoutesChanged");
                    }
                    bool expectedSelected = scenario is "DockerPath" or "DockerName" or "Direct";
                    var a = await Probe(selected); var b = await Probe(control);
                    int expectedForwards = scenario == "DockerName" ? 2 : scenario == "DockerPath" ? 1 : 0;
                    selectedGood = a.Success == expectedSelected && good.Forwards - goodBefore == expectedForwards
                        && bad.Requests - badBefore == (scenario == "UpstreamRefused" ? 1 : 0);
                    controlGood = b.Success; // Direct remains reachable, including when selected Proxy/Block fails.
                    counters["SelectedSuccess"] = a.Success ? 1 : 0; counters["ControlSuccess"] = b.Success ? 1 : 0;
                    counters["DockerForwards"] = good.Forwards - goodBefore; counters["RefusalRequests"] = bad.Requests - badBefore;
                }
                finally
                {
                    if (adapter is not null) await adapter.DisposeAsync();
                    if (engine is not null) await engine.DisposeAsync();
                }
                bool recovered = await LabRunner.WaitForRecoveryAsync(report.Before, ct);
                report.Cases.Add(new(scenario, selectedGood && controlGood && recovered, selectedGood, controlGood, recovered, counters));
                await SaveAsync();
                if (!report.Cases[^1].Passed) throw new InvalidOperationException("ScenarioFailed_" + scenario);
            }
            report.Status = productionAgent is null ? "PassedDockerTcpTunOnly" : "PassedProductionAgentTcp_DefaultRoutesRecovered";
        }
        catch (Exception ex) { report.Status = "Failed"; report.ErrorCode = ex is InvalidOperationException or PathFlux.Application.EngineOperationException ? ex.Message : ex.GetType().Name; }
        finally
        {
            if (attempted && report.Before is { } before && !await LabRunner.WaitForRecoveryAsync(before, CancellationToken.None)) report.Status = "RecoveryNotConfirmed";
            report.After = await NetworkSnapshot.CaptureAsync(CancellationToken.None); await SaveAsync();
            Console.WriteLine($"{report.Status}: {Path.Combine(output, "report.json")}");
        }
        return report.Status is "PassedDockerTcpTunOnly" or "PassedProductionAgentTcp_DefaultRoutesRecovered" ? 0 : 1;
    }
}
