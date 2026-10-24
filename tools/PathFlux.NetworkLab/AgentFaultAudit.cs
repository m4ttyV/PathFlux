using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using PathFlux.Domain;
using PathFlux.Engine;

namespace PathFlux.NetworkLab;

public static class AgentFaultAudit
{
    public static async Task<int> RunAsync(string enginePath, string hash, string output, string agentPath, CancellationToken ct)
    {
        Directory.CreateDirectory(output);
        var report = new LabReport { Elevated = LabRunner.IsElevated(), Scope = "Real production agent/IPC, full TUN, Docker UDP. Intentional termination of owned engine/agent only; VPN/WFP unchanged." };
        try
        {
            if (!report.Elevated) throw new InvalidOperationException("AdministratorRequired");
            var target = (await Dns.GetHostAddressesAsync("stun.cloudflare.com", ct)).First(a => a.AddressFamily == AddressFamily.InterNetwork).ToString();
            report.Before = await NetworkSnapshot.CaptureAsync(ct);
            if (!report.Before.CanStartLab(target)) throw new InvalidOperationException("ExistingTunOrTargetConflict");
            string selected = LabRunner.CloneProbe(Path.Combine(output, "selected"));
            foreach (string scenario in new[] { "EngineCrash", "AgentCrash" })
            {
                var profile = new ProxyProfile { UdpRelayMode = UdpRelayMode.DockerNat, UdpPublishedPortFirst = 20000, UdpPublishedPortLast = 20030 };
                var config = new ProxyConfiguration { Profiles = [profile], Rules = [new() { ProfileId = profile.Id, Selector = new(SelectorKind.ExecutablePath, selected) }],
                    Settings = new() { EnginePath = enginePath, EngineSha256 = hash, ExperimentalSocksUdp = true } };
                var adapter = new SingBoxEngineAdapter(new RecoveryProbeSecrets(), agentPath);
                try
                {
                    report.TunStartAttempted = true; await report.SaveAsync(output);
                    await adapter.StartAsync(config, ct); report.TunWasStarted = true;
                    var good = await LabChild.RunAsync(selected, ["probe-stun", target, "3478"], ct);
                    var beforeKill = await adapter.GetStatusAsync(ct);
                    if (!good.Success || beforeKill.Udp?.Sum(s => s.ReceivedPackets) != 1) throw new InvalidOperationException("RealDockerUdpNotVerifiedBeforeFault");
                    using var ownedEngine = Process.GetProcessById(beforeKill.ProcessId!.Value);
                    using var ownedAgent = Process.GetProcessById(adapter.AgentPidForLaboratory!.Value);
                    if (!string.Equals(ownedEngine.MainModule?.FileName, enginePath, StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(ownedAgent.MainModule?.FileName, agentPath, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("OwnedProcessIdentityMismatch");
                    (scenario == "EngineCrash" ? ownedEngine : ownedAgent).Kill(true);
                    await ownedEngine.WaitForExitAsync(ct);
                    if (scenario == "AgentCrash") await ownedAgent.WaitForExitAsync(ct);
                    EngineStatus final = await adapter.GetStatusAsync(ct);
                    if (scenario == "EngineCrash")
                    {
                        for (int i = 0; i < 20 && final.Udp?.Any(s => s.ActiveAssociations != 0 || s.State != "Stopped") == true; i++)
                        { await Task.Delay(300, ct); final = await adapter.GetStatusAsync(ct); }
                    }
                    bool recovered = await LabRunner.WaitForRecoveryAsync(report.Before, ct);
                    bool journalRetained = File.Exists(RecoveryJournal.DefaultPath);
                    bool passed = recovered && ownedEngine.HasExited && final.State == EngineState.Failed &&
                        (scenario == "EngineCrash" ? final.Udp?.All(s => s.ActiveAssociations == 0 && s.State == "Stopped") == true : ownedAgent.HasExited && journalRetained);
                    if (scenario == "AgentCrash" && recovered) await RecoveryJournal.VerifyAndArchiveAsync(RecoveryJournal.DefaultPath, ct);
                    await adapter.StopAsync(ct);
                    report.Cases.Add(new(scenario, passed, good.Success, true, recovered, new()
                    { ["EngineExited"] = ownedEngine.HasExited ? 1 : 0, ["JournalRetainedBeforeVerification"] = journalRetained ? 1 : 0,
                        ["UdpRepliesBeforeFault"] = 1 }));
                    await report.SaveAsync(output);
                    if (!passed) throw new InvalidOperationException("AgentFaultScenarioFailed_" + scenario);
                }
                finally { await adapter.DisposeAsync(); }
            }
            report.Status = "PassedProductionAgentFaults_RealDockerUdp";
        }
        catch (Exception ex) { report.Status = "Failed"; report.ErrorCode = ex is InvalidOperationException or PathFlux.Application.EngineOperationException ? ex.Message : ex.GetType().Name; }
        finally
        {
            if (report.TunStartAttempted && report.Before is { } before && !await LabRunner.WaitForRecoveryAsync(before, CancellationToken.None)) report.Status = "RecoveryNotConfirmed";
            report.After = await NetworkSnapshot.CaptureAsync(CancellationToken.None); await report.SaveAsync(output);
        }
        return report.Status.StartsWith("Passed", StringComparison.Ordinal) ? 0 : 1;
    }
}
