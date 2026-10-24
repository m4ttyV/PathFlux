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
            foreach (var scenario in new[] { "UdpPath", "UdpName", "ProductionReject", "AssociateRefused", "ControlClosed", "FragmentedReply" })
            {
                await using var echo = new UdpEchoServer();
                var options = new Socks5UdpRelayOptions { TargetOverride = new(IPAddress.Parse(LabPolicy.TargetAddress), LabPolicy.TargetPort),
                    ReplyCode = scenario == "AssociateRefused" ? (byte)7 : (byte)0,
                    Fault = scenario == "ControlClosed" ? UdpRelayFault.CloseControlBeforeRelay : scenario == "FragmentedReply" ? UdpRelayFault.Fragmented : UdpRelayFault.None };
                await using var relay = new Socks5UdpRelay(echo, options);
                var config = LabPolicy.Create(scenario == "UdpName" ? LabScenario.Name : LabScenario.Path, selected, relay.Profile, relay.Profile with { Id = Guid.NewGuid() });
                config = config with { Rules = [config.Rules[0] with { Network = NetworkTransport.Both }], Settings = config.Settings with { EnginePath = enginePath } };
                string json = await LabPolicy.GenerateAsync(config, ct, version, laboratoryUdp: scenario != "ProductionReject");
                if (!await EngineBinary.CheckAsync(enginePath, json, ct)) throw new InvalidOperationException("EngineCheckFailed");
                report.TunStartAttempted = true; await SaveAsync(); bool selectedGood, controlGood;
                var counters = new Dictionary<string, int>();
                await using (var engine = await LabEngine.StartAsync(enginePath, json, ct))
                {
                    await LabRunner.WaitForInterfaceAsync(engine, ct); report.TunWasStarted = true;
                    if (report.Before.CompareDuring(await NetworkSnapshot.CaptureAsync(ct), LabPolicy.TargetAddress).Length != 0)
                        throw new InvalidOperationException("UnsafeRouteOrAdapterStateDuringLab");
                    int received = 0, controlReceived = 0;
                    // Each child uses a fresh OS socket and unique random challenge.
                    for (int i = 0; i < 3; i++)
                        if ((await LabChild.RunAsync(selected, ["probe-udp", LabPolicy.TargetAddress, LabPolicy.TargetPort.ToString(), Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))], ct)).Success) received++;
                    if ((await LabChild.RunAsync(control, ["probe-udp", LabPolicy.TargetAddress, LabPolicy.TargetPort.ToString(), Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))], ct)).Success) controlReceived++;
                    int expected = scenario is "UdpPath" or "UdpName" ? 3 : 0;
                    selectedGood = received == expected && (expected == 0 || relay.ForwardedPackets >= 3);
                    controlGood = controlReceived == (scenario == "UdpName" ? 1 : 0);
                    if (scenario == "ProductionReject") selectedGood &= relay.AssociateRequests == 0 && echo.ReceivedPackets == 0;
                    if (scenario is "AssociateRefused" or "ControlClosed") selectedGood &= relay.AssociateRequests > 0 && echo.ReceivedPackets == 0;
                    if (scenario == "FragmentedReply") selectedGood &= echo.ReceivedPackets == 3;
                    counters["Received"] = received; counters["ControlReceived"] = controlReceived;
                    counters["AssociateRequests"] = relay.AssociateRequests; counters["ForwardedPackets"] = relay.ForwardedPackets; counters["EchoPackets"] = echo.ReceivedPackets;
                    if (!selectedGood || !controlGood) report.LaboratoryDiagnostic = engine.Diagnostic;
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
