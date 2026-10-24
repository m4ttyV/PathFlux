using System.Diagnostics;
using System.Net;
using PathFlux.Agent;
using PathFlux.Domain;
using PathFlux.Engine;
using PathFlux.Testing;

namespace PathFlux.NetworkLab;

/// <summary>Real production EngineSession and full TUN, controlled independent sockets, explicit test mode only.</summary>
public static class SessionUdpAudit
{
    public static async Task<int> RunAsync(string enginePath, string hash, string output, CancellationToken ct)
    {
        Directory.CreateDirectory(output);
        var report = new LabReport { Elevated = LabRunner.IsElevated(), Scope = "Production EngineSession, full default TUN, real local SOCKS/echo fixtures. Container/VPN not stopped; not Discord acceptance." };
        try
        {
            if (!report.Elevated) throw new InvalidOperationException("AdministratorRequired");
            using var singleton = new EventWaitHandle(false, EventResetMode.ManualReset, @"Global\PathFlux.NetworkAgent.Lifetime.v1", out bool created);
            if (!created) throw new InvalidOperationException("AnotherNetworkAgentRunning");
            report.EngineVersion = (await EngineBinary.VerifyAsync(enginePath, hash, ct)).ToString();
            report.Before = await NetworkSnapshot.CaptureAsync(ct);
            if (!report.Before.CanStartLab()) throw new InvalidOperationException("ExistingTunOrLabConflict");
            string selected = LabRunner.CloneProbe(Path.Combine(output, "selected")), control = LabRunner.CloneProbe(Path.Combine(output, "control"));
            foreach (string scenario in new[] { "Both", "TcpOnly", "UdpOnly", "Restart", "TwoProfilesAndApplications", "Refused", "ControlReconnect", "FragmentedReply", "BridgeCrash", "EngineCrash" })
            {
                await using var echo = new UdpEchoServer();
                await using var first = new Socks5UdpRelay(echo, new() { TargetOverride = new(IPAddress.Parse(LabPolicy.TargetAddress), LabPolicy.TargetPort),
                    ReplyCode = scenario == "Refused" ? (byte)7 : (byte)0,
                    Fault = scenario == "FragmentedReply" ? UdpRelayFault.Fragmented : scenario == "ControlReconnect" ? UdpRelayFault.CloseControlBeforeLastReply : UdpRelayFault.None,
                    FaultAssociations = scenario == "ControlReconnect" ? 1 : int.MaxValue, CloseAfterPackets = 1 });
                await using var second = new Socks5UdpRelay(echo, new() { TargetOverride = new(IPAddress.Parse(LabPolicy.TargetAddress), LabPolicy.TargetPort) });
                var config = LabPolicy.Create(LabScenario.Path, selected, first.Profile, second.Profile);
                config = config with { Settings = new() { EnginePath = enginePath, EngineSha256 = hash, ExperimentalSocksUdp = true },
                    Rules = [config.Rules[0] with { Network = scenario == "TcpOnly" ? NetworkTransport.Tcp : scenario == "UdpOnly" ? NetworkTransport.Udp : NetworkTransport.Both }] };
                if (scenario == "TwoProfilesAndApplications") config = config with { Rules = [.. config.Rules,
                    config.Rules[0] with { Id = Guid.NewGuid(), Selector = new(SelectorKind.ExecutablePath, control), ProfileId = second.Profile.Id }] };
                await using var session = new EngineSession();
                report.TunStartAttempted = true; await report.SaveAsync(output);
                var reply = await session.StartAsync(config, [], ct);
                if (!reply.Success) throw new InvalidOperationException("SessionStartFailed_" + reply.Status.Message);
                report.TunWasStarted = true;
                if (scenario == "BridgeCrash") session.FailUdpForLaboratory(first.Profile.Id);
                int received = 0;
                if (scenario == "ControlReconnect")
                {
                    var stream = await LabChild.RunAsync(selected, ["probe-udp-stream", LabPolicy.TargetAddress, LabPolicy.TargetPort.ToString(), "10", "8"], ct);
                    received = stream.Received;
                }
                else
                    for (int i = 0; i < 3; i++)
                        if ((await LabChild.RunAsync(selected, ["probe-udp", LabPolicy.TargetAddress, LabPolicy.TargetPort.ToString(), Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(64))], ct)).Success) received++;
                bool controlReceived = (await LabChild.RunAsync(control, ["probe-udp", LabPolicy.TargetAddress, LabPolicy.TargetPort.ToString(), Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(64))], ct)).Success;
                var status = await session.GetStatusAsync(ct);
                int expected = scenario is "Refused" or "FragmentedReply" or "BridgeCrash" or "TcpOnly" ? 0 : 3;
                bool good = scenario == "ControlReconnect" ? received >= 8 && status.Udp!.Sum(s => s.Reconnects) > 0 : received == expected;
                good &= controlReceived == (scenario == "TwoProfilesAndApplications");
                if (scenario is "Refused" or "BridgeCrash" or "TcpOnly") good &= echo.ReceivedPackets == 0;
                if (scenario == "FragmentedReply") good &= echo.ReceivedPackets == 3 && status.Udp!.Sum(s => s.DroppedFragments) == 3;
                if (scenario == "BridgeCrash") good &= status.Udp!.Single().State == "Failed";
                if (scenario == "EngineCrash")
                {
                    using var process = Process.GetProcessById(status.ProcessId!.Value); process.Kill(true); await process.WaitForExitAsync(ct);
                    for (int i = 0; i < 30; i++)
                    {
                        var failed = await session.GetStatusAsync(ct);
                        if (failed.State == EngineState.Failed && failed.Udp?.All(s => s.State == "Stopped" && s.ActiveAssociations == 0) == true) break;
                        await Task.Delay(200, ct);
                    }
                    good &= (await session.GetStatusAsync(ct)).Udp?.All(s => s.State == "Stopped" && s.ActiveAssociations == 0) == true;
                }
                await session.StopAsync(ct);
                bool recovered = await LabRunner.WaitForRecoveryAsync(report.Before, ct);
                // An independent later snapshot may confirm cleanup after a conservative Stop timeout.
                // Re-run the agent's own comparison; never mark its Failed stop as accepted solely from the lab.
                if (recovered && session.Status.State != EngineState.Stopped) await session.StopAsync(ct);
                recovered &= session.Status.State == EngineState.Stopped;
                var counters = new Dictionary<string, int> { ["Received"] = received, ["EchoPackets"] = echo.ReceivedPackets,
                    ["ProfileOneAssociations"] = first.AssociateRequests, ["ProfileTwoAssociations"] = second.AssociateRequests,
                    ["DroppedFragments"] = checked((int)(status.Udp?.Sum(s => s.DroppedFragments) ?? 0)) };
                report.Cases.Add(new(scenario, good && recovered, good, controlReceived == (scenario == "TwoProfilesAndApplications"), recovered, counters));
                await report.SaveAsync(output);
                if (!report.Cases[^1].Passed) throw new InvalidOperationException("SessionScenarioFailed_" + scenario);
            }
            report.Status = "PassedProductionSessionUdpLifecycle_ControlledSockets";
        }
        catch (Exception ex) { report.Status = "Failed"; report.ErrorCode = ex is InvalidOperationException ? ex.Message : ex.GetType().Name; }
        finally
        {
            if (report.TunStartAttempted && report.Before is { } before && !await LabRunner.WaitForRecoveryAsync(before, CancellationToken.None)) report.Status = "RecoveryNotConfirmed";
            report.After = await NetworkSnapshot.CaptureAsync(CancellationToken.None); await report.SaveAsync(output);
        }
        return report.Status.StartsWith("Passed", StringComparison.Ordinal) ? 0 : 1;
    }
}
