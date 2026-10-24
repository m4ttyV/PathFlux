using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using PathFlux.Application;
using PathFlux.Domain;
using PathFlux.Engine;
using PathFlux.ViewModels;

namespace PathFlux;

/// <summary>Explicit --udp-acceptance mode. Exercises the ordinary UI commands, storage and UAC agent.
/// Uses a new isolated data directory; never modifies the normal user's profiles.</summary>
internal static class UiUdpAcceptance
{
    private sealed record Input(string EnginePath, string EngineSha256, string ProbeExecutable, string ProxyHost, int ProxyPort,
        UdpRelayMode RelayMode, int? PortFirst, int? PortLast);
    private sealed record Probe(bool Success, string Code);
    public static async Task<int> RunAsync(MainWindowViewModel vm, IProxyEngineAdapter engine, string output)
    {
        string reportFile = Path.Combine(output, "ui-acceptance-report.json");
        if (File.Exists(reportFile)) return 2;
        var cases = new List<object>(); WindowsNetworkState? before = null, after = null;
        string status = "Failed", error = "";
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(8)); var ct = timeout.Token;
        try
        {
            var input = JsonSerializer.Deserialize<Input>(await File.ReadAllTextAsync(Path.Combine(output, "input.json"), ct)) ?? throw new InvalidOperationException("MissingInput");
            if (!Path.IsPathFullyQualified(input.ProbeExecutable) || !File.Exists(input.ProbeExecutable) ||
                Path.GetFileName(input.ProbeExecutable) != "PathFlux.NetworkLab.exe") throw new InvalidOperationException("InvalidProbePath");
            string Clone(string directory)
            {
                Directory.CreateDirectory(directory);
                foreach (string file in Directory.EnumerateFiles(Path.GetDirectoryName(input.ProbeExecutable)!))
                    if (Path.GetExtension(file) is ".dll" or ".json") File.Copy(file, Path.Combine(directory, Path.GetFileName(file)), false);
                string executable = Path.Combine(directory, "PathFlux.LabProbe.exe"); File.Copy(input.ProbeExecutable, executable, false); return executable;
            }
            string selected = Clone(Path.Combine(output, "selected")), control = Clone(Path.Combine(output, "control"));
            string stun = (await Dns.GetHostAddressesAsync("stun.cloudflare.com", ct)).First(a => a.AddressFamily == AddressFamily.InterNetwork).ToString();
            string tls = (await Dns.GetHostAddressesAsync("example.com", ct)).First(a => a.AddressFamily == AddressFamily.InterNetwork).ToString();
            before = await WindowsNetworkState.CaptureAsync(ct);
            if (before.Adapters.Any(a => a.Name == SingBoxConfigGenerator.InterfaceName && !a.Detached)) throw new InvalidOperationException("ExistingTun");
            if (!(await ProbeAsync(control, ["probe-stun", stun, "3478"], ct)).Success) throw new InvalidOperationException("DirectStunBaselineFailed");
            await vm.ToggleUdpRecordingCommand.ExecuteAsync(null);
            vm.EnginePath = input.EnginePath; vm.EngineSha256 = input.EngineSha256;
            vm.ExperimentalSocksUdp = true; await vm.SaveSettingsCommand.ExecuteAsync(null);
            vm.NewProfileCommand.Execute(null); vm.ProfileName = "UDP UI acceptance"; vm.ProfileHost = input.ProxyHost; vm.ProfilePort = input.ProxyPort.ToString();
            vm.ProfileUdpRelayMode = input.RelayMode; vm.ProfileUdpPortFirst = input.PortFirst?.ToString() ?? ""; vm.ProfileUdpPortLast = input.PortLast?.ToString() ?? "";
            await vm.SaveProfileCommand.ExecuteAsync(null);
            if (vm.Profiles.Count != 1) throw new InvalidOperationException("UiProfileSaveFailed");
            vm.NewRuleCommand.Execute(null); vm.RuleValue = selected; vm.RuleSelector = SelectorKind.ExecutablePath;
            vm.RuleProfile = vm.Profiles.Single();
            var scenarios = new List<string> { "TcpAndUdp", "TcpOnly", "UdpOnly", "Restart", "ProcessName" };
            if (input.RelayMode == UdpRelayMode.DockerNat) scenarios.Add("UnpublishedPort");
            scenarios.Add("OptInDisabled");
            foreach (var scenario in scenarios)
            {
                if (scenario == "UnpublishedPort")
                {
                    vm.SelectedProfile = vm.Profiles.Single(); vm.ProfileUdpPortFirst = "1"; vm.ProfileUdpPortLast = "1";
                    await vm.SaveProfileCommand.ExecuteAsync(null);
                }
                if (scenario == "OptInDisabled") { vm.ExperimentalSocksUdp = false; await vm.SaveSettingsCommand.ExecuteAsync(null); }
                vm.RuleNetwork = scenario == "TcpOnly" ? NetworkTransport.Tcp : scenario == "UdpOnly" ? NetworkTransport.Udp : NetworkTransport.Both;
                vm.RuleSelector = scenario == "ProcessName" ? SelectorKind.ProcessName : SelectorKind.ExecutablePath;
                vm.RuleValue = scenario == "ProcessName" ? "PathFlux.LabProbe.exe" : selected;
                await vm.SaveRuleCommand.ExecuteAsync(null);
                if (vm.Rules.Count != 1 || vm.Rules[0].Network != vm.RuleNetwork) throw new InvalidOperationException("UiRuleSaveFailed");
                await vm.StartCommand.ExecuteAsync(null);
                var started = await engine.GetStatusAsync(ct);
                if (started.State is not (EngineState.Running or EngineState.Degraded)) throw new InvalidOperationException("UiEngineStartFailed_" + vm.Notice);
                bool guardExpected = scenario is not ("TcpOnly" or "OptInDisabled");
                if (guardExpected ? started.Udp?.Count != 1 : started.Udp?.Count != 0) throw new InvalidOperationException("UnexpectedGuardCount");
                var during = await WindowsNetworkState.CaptureAsync(ct);
                var udpProbe = await ProbeAsync(selected, ["probe-stun", stun, "3478"], ct);
                var tcpProbe = await ProbeAsync(selected, ["probe-tls", tls, "443", "example.com"], ct);
                var controlProbe = await ProbeAsync(control, ["probe-stun", stun, "3478"], ct);
                bool udp = udpProbe.Success, tcp = tcpProbe.Success, direct = controlProbe.Success;
                var measured = await engine.GetStatusAsync(ct);
                long proxied = measured.Udp?.Sum(s => s.ReceivedPackets) ?? 0;
                int expected = scenario is "TcpOnly" or "UnpublishedPort" or "OptInDisabled" ? 0 : scenario == "ProcessName" ? 2 : 1;
                bool expectedUdp = scenario is not ("UnpublishedPort" or "OptInDisabled");
                bool passed = udp == expectedUdp && tcp && direct && proxied == expected;
                if (scenario == "UnpublishedPort") passed &= measured.Udp!.Single().LastError?.Contains("диапазона Docker NAT", StringComparison.Ordinal) == true;
                // Give the normal two-second UI poll a chance to record this short transaction.
                if (vm.IsRecordingUdp) await Task.Delay(2200, ct);
                await vm.StopCommand.ExecuteAsync(null);
                after = await WindowsNetworkState.CaptureAsync(ct);
                var initialRecoveryIssues = before.RecoveryIssues(after, SingBoxConfigGenerator.InterfaceName);
                var recoverySnapshots = new List<WindowsNetworkState> { after };
                var recoveryDeadline = Stopwatch.StartNew();
                while (before.RecoveryIssues(after, SingBoxConfigGenerator.InterfaceName).Length != 0 && recoveryDeadline.Elapsed < TimeSpan.FromSeconds(12))
                {
                    await Task.Delay(1000, ct);
                    after = await WindowsNetworkState.CaptureAsync(ct);
                    recoverySnapshots.Add(after);
                }
                var recoveryIssues = before.RecoveryIssues(after, SingBoxConfigGenerator.InterfaceName);
                var stopped = await engine.GetStatusAsync(ct);
                bool recovered = recoveryIssues.Length == 0 && stopped.State == EngineState.Stopped;
                cases.Add(new { Name = scenario, Passed = passed && recovered, UdpSuccess = udp, TcpSuccess = tcp, ControlSuccess = direct,
                    ProxiedUdpReplies = proxied, RecoveryConfirmed = recovered, Udp = measured.Udp, During = during,
                    InitialRecoveryIssues = initialRecoveryIssues, RecoveryIssues = recoveryIssues, RecoverySnapshots = recoverySnapshots,
                    StoppedState = stopped.State.ToString(),
                    UdpProbeCode = udpProbe.Code, TcpProbeCode = tcpProbe.Code, ControlProbeCode = controlProbe.Code });
                await SaveAsync();
                if (!passed || !recovered) throw new InvalidOperationException("UiScenarioFailed_" + scenario);
            }
            status = "PassedOrdinaryUiCommands_ExperimentalUdpAndTcp_NotDiscordAcceptance";
        }
        catch (Exception ex) { error = ex is InvalidOperationException ? ex.Message : ex.GetType().Name; }
        finally
        {
            try { await vm.StopCommand.ExecuteAsync(null); after = await WindowsNetworkState.CaptureAsync(CancellationToken.None); }
            catch { error += " CleanupUnknown"; }
            if (vm.IsRecordingUdp) await vm.ToggleUdpRecordingCommand.ExecuteAsync(null);
            if (before is not null && (after is null || before.RecoveryIssues(after, SingBoxConfigGenerator.InterfaceName).Length != 0)) status = "RecoveryNotConfirmed";
            await SaveAsync();
        }
        return status.StartsWith("Passed", StringComparison.Ordinal) ? 0 : 1;
        async Task SaveAsync() => await File.WriteAllTextAsync(reportFile, JsonSerializer.Serialize(new
        { Status = status, ErrorCode = error, Cases = cases, Before = before, After = after, MetricsPath = vm.UdpRecordingPath }, new JsonSerializerOptions { WriteIndented = true }));
    }
    private static async Task<Probe> ProbeAsync(string executable, string[] args, CancellationToken ct)
    {
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string arg in args) info.ArgumentList.Add(arg);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("ProbeStartFailed");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            var stdout = process.StandardOutput.ReadToEndAsync(deadline.Token); var stderr = process.StandardError.BaseStream.CopyToAsync(Stream.Null, deadline.Token);
            await process.WaitForExitAsync(deadline.Token); await stderr;
            return JsonSerializer.Deserialize<Probe>(await stdout) ?? new(false, "InvalidProbeReply");
        }
        finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); } }
    }
}
