using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using PathFlux.Engine;
namespace PathFlux.NetworkLab;

public sealed record ProbeResult(bool Success, string Code);
public sealed record LabCaseResult(string Name, bool Passed, bool SelectedReachedExpectedGateway, bool ControlMatchedExpectation, bool RecoveryConfirmed);
public sealed class LabReport
{
    public string Scope { get; init; } = "Isolated IPv4 TCP TUN, single synthetic destination; no default route or application UDP support claim";
    public DateTimeOffset StartedUtc { get; init; } = DateTimeOffset.UtcNow;
    public string? EngineVersion { get; set; }
    public bool Elevated { get; init; }
    public bool Prepared { get; set; }
    public bool PreflightAllowsTun { get; set; }
    public bool ClonedProbeSelfTestPassed { get; set; }
    public List<string> CheckedScenarios { get; } = [];
    public bool TunWasStarted { get; set; }
    public bool TunStartAttempted { get; set; }
    public string Status { get; set; } = "Preparing";
    public string? ErrorCode { get; set; }
    public NetworkSnapshot? Before { get; set; }
    public NetworkSnapshot? After { get; set; }
    public List<LabCaseResult> Cases { get; } = [];
}

public static class LabRunner
{
    public static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
    public static async Task<int> RunAsync(string enginePath, string expectedHash, string output, bool live, CancellationToken ct)
    {
        Directory.CreateDirectory(output);
        var report = new LabReport { Elevated = IsElevated() };
        var reportPath = Path.Combine(output, "report.json");
        async Task SaveAsync()
        {
            var temporary = reportPath + ".tmp";
            await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temporary, reportPath, true);
        }
        try
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            if (live && !report.Elevated) { report.Status = "NotRun"; report.ErrorCode = "AdministratorRequired"; return 3; }
            await using var binaryLock = new FileStream(enginePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var version = await EngineBinary.VerifyAsync(enginePath, expectedHash, ct);
            report.EngineVersion = version.ToString();
            report.Before = await NetworkSnapshot.CaptureAsync(ct);
            await SaveAsync(); // A baseline must exist before any possible TUN change.
            report.PreflightAllowsTun = report.Before.CanStartLab();
            if (live && !report.PreflightAllowsTun) throw new InvalidOperationException("LabAddressOrInterfaceAlreadyInUse");
            var selected = CloneProbe(Path.Combine(output, "selected"));
            var control = CloneProbe(Path.Combine(output, "control"));
            await using var echo = new LabEchoServer();
            await using var first = new LabSocksGateway("Lab gateway one", echo);
            await using var second = new LabSocksGateway("Lab gateway two", echo);
            var self = await RunProbeAsync(selected, echo.Endpoint.Address.ToString(), echo.Endpoint.Port, RandomNumberGenerator.GetBytes(64), ct);
            if (!self.Success) throw new InvalidOperationException("ClonedProbeSelfTestFailed");
            report.ClonedProbeSelfTestPassed = true;
            foreach (var scenario in Enum.GetValues<LabScenario>())
            {
                var config = LabPolicy.Create(scenario, selected, first.Profile, second.Profile);
                config = config with { Settings = config.Settings with { EnginePath = enginePath } };
                string json = await LabPolicy.GenerateAsync(config, ct, version);
                if (!await EngineBinary.CheckAsync(enginePath, json, ct)) throw new InvalidOperationException("EngineCheckFailed");
                report.CheckedScenarios.Add(scenario.ToString());
                if (!live) continue;
                report.TunStartAttempted = true;
                await SaveAsync();
                await using (var engine = await LabEngine.StartAsync(enginePath, json, ct))
                {
                    await WaitForInterfaceAsync(engine, ct);
                    report.TunWasStarted = true;
                    await SaveAsync();
                    // Confirm narrow scope before emitting any traffic from a probe.
                    var during = await NetworkSnapshot.CaptureAsync(ct);
                    if (!report.Before.Defaults.SequenceEqual(during.Defaults)) throw new InvalidOperationException("DefaultRoutesChangedDuringLab");
                    if (!during.Routes.Any(r => r.DestinationPrefix == LabPolicy.TargetAddress + "/32")) throw new InvalidOperationException("LabRouteNotInstalled");
                    var selectedNonce = RandomNumberGenerator.GetBytes(64);
                    var controlNonce = RandomNumberGenerator.GetBytes(64);
                    var a = await RunProbeAsync(selected, LabPolicy.TargetAddress, LabPolicy.TargetPort, selectedNonce, ct);
                    var b = await RunProbeAsync(control, LabPolicy.TargetAddress, LabPolicy.TargetPort, controlNonce, ct);
                    string ah = Convert.ToHexString(SHA256.HashData(selectedNonce));
                    string bh = Convert.ToHexString(SHA256.HashData(controlNonce));
                    bool expectedSelected = scenario is LabScenario.Path or LabScenario.Name or LabScenario.ProfileTwo;
                    bool expectedControl = scenario == LabScenario.Name;
                    var expected = scenario == LabScenario.ProfileTwo ? second : first;
                    var other = scenario == LabScenario.ProfileTwo ? first : second;
                    bool selectedGood = a.Success == expectedSelected
                        && expected.ConfirmedPayloadHashes.Contains(ah) == expectedSelected
                        && !other.ConfirmedPayloadHashes.Contains(ah);
                    bool controlGood = b.Success == expectedControl
                        && first.ConfirmedPayloadHashes.Contains(bh) == expectedControl
                        && !second.ConfirmedPayloadHashes.Contains(bh);
                    report.Cases.Add(new(scenario.ToString(), false, selectedGood, controlGood, false));
                }
                bool recovered = await WaitForRecoveryAsync(report.Before, ct);
                var last = report.Cases[^1];
                report.Cases[^1] = last with { RecoveryConfirmed = recovered,
                    Passed = recovered && last.SelectedReachedExpectedGateway && last.ControlMatchedExpectation };
                await SaveAsync();
                if (!recovered || !report.Cases[^1].Passed) throw new InvalidOperationException("ScenarioFailed_" + scenario);
            }
            report.Prepared = true;
            report.Status = live ? "PassedIsolatedTcpTunOnly" : "Prepared_NoTunStarted";
        }
        catch (Exception ex)
        {
            report.Status = "Failed";
            report.ErrorCode = ex is InvalidOperationException ? ex.Message : ex.GetType().Name;
        }
        finally
        {
            try
            {
                report.After = await NetworkSnapshot.CaptureAsync(CancellationToken.None);
                if (report.TunStartAttempted && report.Before is { } before)
                {
                    if (!await WaitForRecoveryAsync(before, CancellationToken.None)) report.Status = "RecoveryNotConfirmed";
                    report.After = await NetworkSnapshot.CaptureAsync(CancellationToken.None);
                }
            }
            catch { if (report.TunStartAttempted) report.Status = "RecoveryNotConfirmed"; }
            await SaveAsync();
            Console.WriteLine($"{report.Status}: {reportPath}");
        }
        return report.Status is "PassedIsolatedTcpTunOnly" or "Prepared_NoTunStarted" ? 0 : 1;
    }
    public static string CloneProbe(string directory)
    {
        Directory.CreateDirectory(directory);
        foreach (var file in Directory.EnumerateFiles(AppContext.BaseDirectory, "*", SearchOption.TopDirectoryOnly))
            if (Path.GetExtension(file) is ".dll" or ".json") File.Copy(file, Path.Combine(directory, Path.GetFileName(file)), false);
        var path = Path.Combine(directory, LabPolicy.ProbeName);
        File.Copy(Path.Combine(AppContext.BaseDirectory, "PathFlux.NetworkLab.exe"), path, false);
        return path;
    }
    public static async Task<ProbeResult> ProbeAsync(string host, int port, byte[] nonce, CancellationToken ct)
    {
        if (nonce.Length != 64 || !IPAddress.TryParse(host, out var address) || port is < 1 or > 65535) return new(false, "InvalidProbe");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromMilliseconds(1800));
        using var client = new TcpClient(address.AddressFamily);
        try
        {
            await client.ConnectAsync(address, port, timeout.Token);
            var stream = client.GetStream(); await stream.WriteAsync(nonce, timeout.Token);
            var response = new byte[64]; await stream.ReadExactlyAsync(response, timeout.Token);
            return new(response.AsSpan().SequenceEqual(nonce), "EchoChecked");
        }
        catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException) { return new(false, ex.GetType().Name); }
    }
    private static async Task<ProbeResult> RunProbeAsync(string executable, string host, int port, byte[] nonce, CancellationToken ct)
    {
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[] { "probe", host, port.ToString(), Convert.ToBase64String(nonce) }) info.ArgumentList.Add(arg);
        using var child = Process.Start(info) ?? throw new InvalidOperationException("ProbeLaunchFailed");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(7));
        try
        {
            var output = child.StandardOutput.ReadToEndAsync(timeout.Token); var error = child.StandardError.BaseStream.CopyToAsync(Stream.Null, timeout.Token);
            await child.WaitForExitAsync(timeout.Token); await error;
            return JsonSerializer.Deserialize<ProbeResult>(await output) ?? new(false, "InvalidProbeReply");
        }
        finally { if (!child.HasExited) { child.Kill(true); await child.WaitForExitAsync(CancellationToken.None); } }
    }
    private static async Task WaitForInterfaceAsync(LabEngine engine, CancellationToken ct)
    {
        for (int i = 0; i < 50; i++)
        {
            if (engine.HasExited) throw new InvalidOperationException("EngineExitedBeforeTunReady");
            if (NetworkInterface.GetAllNetworkInterfaces().Any(a => a.Name == LabPolicy.InterfaceName)) { await Task.Delay(250, ct); return; }
            await Task.Delay(100, ct);
        }
        throw new InvalidOperationException("TunNotReady");
    }
    private static async Task<bool> WaitForRecoveryAsync(NetworkSnapshot before, CancellationToken ct)
    {
        for (int i = 0; i < 5; i++)
        { if (before.CompareRecovery(await NetworkSnapshot.CaptureAsync(ct)).Length == 0) return true; await Task.Delay(300, ct); }
        return false;
    }
}
