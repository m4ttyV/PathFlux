using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using PathFlux.Application;
using PathFlux.Domain;
using PathFlux.Engine;

namespace PathFlux.NetworkLab;

public static class VoiceTcpAudit
{
    private sealed record Target(string Host, int Port);
    public static async Task<int> RunAsync(string enginePath, string hash, string targetsFile, string output, CancellationToken ct)
    {
        if (!Path.IsPathFullyQualified(output) || Directory.Exists(output)) throw new InvalidOperationException("NewAbsoluteOutputRequired");
        Directory.CreateDirectory(output);
        var cases = new List<object>(); string status = "Failed", error = ""; bool allCaseBaselinesMatched = true;
        WindowsNetworkState? before = null, after = null;
        try
        {
            var targets = JsonSerializer.Deserialize<Target[]>(await File.ReadAllTextAsync(targetsFile, ct)) ?? [];
            if (targets.Length is < 1 or > 4 || targets.Any(t => !t.Host.EndsWith(".discord.media", StringComparison.OrdinalIgnoreCase) || Uri.CheckHostName(t.Host) != UriHostNameType.Dns || t.Port is < 1 or > 65535))
                throw new InvalidOperationException("InvalidVoiceTargets");
            var addresses = new List<(Target Target, IPAddress V4, IPAddress V6)>();
            foreach (var target in targets)
            {
                var ips = await Dns.GetHostAddressesAsync(target.Host, ct);
                addresses.Add((target, ips.First(a => a.AddressFamily == AddressFamily.InterNetwork), ips.First(a => a.AddressFamily == AddressFamily.InterNetworkV6)));
            }
            before = await WindowsNetworkState.CaptureAsync(ct);
            string selected = LabRunner.CloneProbe(Path.Combine(output, "selected"));
            foreach (var target in addresses)
            foreach (string scenario in new[] { "OriginalIPv4", "OriginalIPv6", "SniIPv6", "SniIPv4", "SniRefused", "DohRefusedIpv6" })
            {
                var profile = new ProxyProfile { Host = "127.0.0.1", Port = scenario == "SniRefused" ? 1 : 1080,
                    UseTlsServerNameForTcp = scenario.StartsWith("Sni", StringComparison.Ordinal) || scenario == "DohRefusedIpv6",
                    TcpIpv4DohServer = scenario == "DohRefusedIpv6" ? "https://127.0.0.1:1/dns-query" : "https://1.1.1.1/dns-query" };
                var config = new ProxyConfiguration { Profiles = [profile], Rules = [new() { Selector = new(SelectorKind.ExecutablePath, selected), Network = NetworkTransport.Tcp, ProfileId = profile.Id }],
                    Settings = new() { EnginePath = enginePath, EngineSha256 = hash } };
                var caseBefore = await WindowsNetworkState.CaptureAsync(ct);
                ProbeResult probe; string tcpStatus;
                await using (var adapter = new SingBoxEngineAdapter(new NoSecrets(), Path.Combine(AppContext.BaseDirectory, "..", "agent", "PathFlux.Agent.exe")))
                {
                    await adapter.StartAsync(config, ct);
                    var ip = scenario is "OriginalIPv6" or "SniIPv6" or "DohRefusedIpv6" ? target.V6 : target.V4;
                    probe = await LabChild.RunAsync(selected, ["probe-voice-wss", ip.ToString(), target.Target.Port.ToString(), target.Target.Host], ct);
                    tcpStatus = (await adapter.GetStatusAsync(ct)).Message;
                    await adapter.StopAsync(ct);
                    if ((await adapter.GetStatusAsync(ct)).State != EngineState.Stopped) throw new InvalidOperationException("AgentStopNotConfirmed");
                }
                after = await WindowsNetworkState.CaptureAsync(ct);
                var initialRecoveryIssues = caseBefore.RecoveryIssues(after, SingBoxConfigGenerator.InterfaceName);
                var recoverySnapshots = new List<WindowsNetworkState> { after };
                var recoveryTimer = System.Diagnostics.Stopwatch.StartNew();
                while (after.OwnedCleanupIssues(SingBoxConfigGenerator.InterfaceName).Length != 0 && recoveryTimer.Elapsed < TimeSpan.FromSeconds(12))
                { await Task.Delay(1000, ct); after = await WindowsNetworkState.CaptureAsync(ct); recoverySnapshots.Add(after); }
                bool recovered = caseBefore.RecoveryIssues(after, SingBoxConfigGenerator.InterfaceName).Length == 0;
                allCaseBaselinesMatched &= recovered;
                bool ownedCleanup = after.OwnedCleanupIssues(SingBoxConfigGenerator.InterfaceName).Length == 0;
                bool expected = scenario is not ("OriginalIPv6" or "SniRefused" or "DohRefusedIpv6");
                bool passed = probe.Success == expected && ownedCleanup;
                cases.Add(new { Target = target.Target.Host, Name = scenario, Passed = passed, ExpectedSuccess = expected, Probe = probe,
                    TcpStatus = tcpStatus, OwnCleanupConfirmed = ownedCleanup, RecoveryConfirmed = recovered, Baseline = caseBefore,
                    InitialRecoveryIssues = initialRecoveryIssues, RecoverySnapshots = recoverySnapshots });
                await SaveAsync();
                if (!passed) throw new InvalidOperationException("VoiceScenarioFailed_" + scenario);
            }
            status = "PassedVoiceWebSocketTransport_NotDiscordChannelAcceptance";
        }
        catch (Exception ex) { error = ex is InvalidOperationException or EngineOperationException ? ex.Message : ex.GetType().Name; }
        finally
        {
            after = await WindowsNetworkState.CaptureAsync(CancellationToken.None);
            if (after.OwnedCleanupIssues(SingBoxConfigGenerator.InterfaceName).Length != 0) status = "RecoveryNotConfirmed";
            else if (status.StartsWith("Passed", StringComparison.Ordinal) && (!allCaseBaselinesMatched || before is not null && before.RecoveryIssues(after, SingBoxConfigGenerator.InterfaceName).Length != 0))
                status = "PassedVoiceWebSocketTransport_OwnCleanupOnly_GlobalNetworkChanged_NotDiscordAcceptance";
            await SaveAsync();
        }
        return status.StartsWith("Passed", StringComparison.Ordinal) ? 0 : 1;
        Task SaveAsync() => File.WriteAllTextAsync(Path.Combine(output, "report.json"), JsonSerializer.Serialize(new { Status = status, ErrorCode = error, Scope = "Unauthenticated WebSocket transport and owned cleanup; no Discord channel or global DNS acceptance", AllSessionsFullBaselineMatched = allCaseBaselinesMatched, Cases = cases, Before = before, After = after }, new JsonSerializerOptions { WriteIndented = true }));
    }
    private sealed class NoSecrets : ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult<ProxyCredentials?>(null);
        public Task<string> StoreAsync(ProxyCredentials credentials, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }
}
