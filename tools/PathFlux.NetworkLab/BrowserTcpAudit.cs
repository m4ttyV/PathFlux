using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Nodes;
using PathFlux.Domain;
using PathFlux.Engine;

namespace PathFlux.NetworkLab;

/// <summary>Actual Chromium TCP attribution; isolated browser profiles and one remote /32 only.</summary>
public static class BrowserTcpAudit
{
    public static async Task<int> RunAsync(string engine, string hash, string output, string browser, CancellationToken ct)
    {
        if (!Path.IsPathFullyQualified(output) || Directory.Exists(output) || !Path.IsPathFullyQualified(browser))
            throw new InvalidOperationException("NewOutputAndAbsoluteBrowserRequired");
        Directory.CreateDirectory(output);
        string status = "Failed", error = "";
        NetworkSnapshot? before = null, after = null;
        var cases = new List<object>();
        try
        {
            if (!LabRunner.IsElevated()) throw new InvalidOperationException("AdministratorRequired");
            if (Process.GetProcessesByName("sing-box").Length != 0) throw new InvalidOperationException("ExistingEngineMustStopFirst");
            using var binaryLock = new FileStream(engine, FileMode.Open, FileAccess.Read, FileShare.Read);
            var version = await EngineBinary.VerifyAsync(engine, hash, ct);
            var target = (await Dns.GetHostAddressesAsync("example.com", ct)).First(a => a.AddressFamily == AddressFamily.InterNetwork);
            before = await NetworkSnapshot.CaptureAsync(ct);
            if (!before.CanStartLab(target.ToString())) throw new InvalidOperationException("LabAddressOrInterfaceAlreadyInUse");
            if (!await ProbeAsync(browser, Path.Combine(output, "baseline-profile"), target, ct))
                throw new InvalidOperationException("IsolatedBrowserBaselineFailed");
            await using var good = new SocksConnectObserver(target, 443);
            await using var bad = new SocksConnectObserver(target, 443, refuse: true);
            foreach (string scenario in new[] { "ProcessPath", "ProcessName", "UpstreamRefused" })
            {
                var config = LabPolicy.Create(LabScenario.Path, browser, good.Profile, bad.Profile);
                var rule = config.Rules[0];
                if (scenario == "ProcessName") rule = rule with { Selector = new(SelectorKind.ProcessName, Path.GetFileName(browser)) };
                if (scenario == "UpstreamRefused") rule = rule with { ProfileId = bad.Profile.Id };
                config = config with { Rules = [rule], Settings = config.Settings with { EnginePath = engine } };
                var json = JsonNode.Parse(await LabPolicy.GenerateAsync(config, ct, version))!;
                json["inbounds"]![0]!["route_address"] = new JsonArray(target + "/32");
                if (!await EngineBinary.CheckAsync(engine, json.ToJsonString(), ct)) throw new InvalidOperationException("EngineCheckFailed");
                int goodBefore = good.Forwards, badBefore = bad.Requests;
                bool pageLoaded;
                await using (var owner = await LabEngine.StartAsync(engine, json.ToJsonString(), ct))
                {
                    await LabRunner.WaitForInterfaceAsync(owner, ct);
                    var during = await NetworkSnapshot.CaptureAsync(ct);
                    if (before.CompareDuring(during, target.ToString()).Length != 0)
                        throw new InvalidOperationException("UnsafeRouteOrAdapterStateDuringLab");
                    pageLoaded = await ProbeAsync(browser, Path.Combine(output, scenario + "-profile"), target, ct);
                }
                bool recovered = await LabRunner.WaitForRecoveryAsync(before, CancellationToken.None);
                int forwards = good.Forwards - goodBefore, refusals = bad.Requests - badBefore;
                bool expected = scenario != "UpstreamRefused";
                bool passed = pageLoaded == expected && recovered && (expected ? forwards > 0 : refusals > 0 && forwards == 0);
                cases.Add(new { Name = scenario, Passed = passed, ExpectedPageLoaded = expected, PageLoaded = pageLoaded,
                    SocksForwards = forwards, SocksRefusals = refusals, RecoveryConfirmed = recovered });
                await SaveAsync();
                if (!passed) throw new InvalidOperationException("BrowserScenarioFailed_" + scenario);
            }
            status = "PassedActualBrowserTcpSelectorsAndNoFallback";
        }
        catch (Exception ex) { error = ex is InvalidOperationException ? ex.Message : ex.GetType().Name; }
        finally
        {
            after = await NetworkSnapshot.CaptureAsync(CancellationToken.None);
            if (before is not null && !await LabRunner.WaitForRecoveryAsync(before, CancellationToken.None)) status = "RecoveryNotConfirmed";
            await SaveAsync();
        }
        return status == "PassedActualBrowserTcpSelectorsAndNoFallback" ? 0 : 1;
        Task SaveAsync() => File.WriteAllTextAsync(Path.Combine(output, "report.json"), JsonSerializer.Serialize(new {
            Status = status, ErrorCode = error,
            Scope = "Actual isolated elevated Chromium automation, IPv4 HTTPS TCP to example.com through Docker SOCKS5; no QUIC, IPv6, ordinary user session or public-IP acceptance",
            Cases = cases, Before = before, After = after }, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static async Task<bool> ProbeAsync(string browser, string profile, IPAddress target, CancellationToken ct)
    {
        var info = new ProcessStartInfo(browser) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true };
        // Chromium automation suppresses automatic de-elevation/relaunch, which would detach the output pipes.
        // This elevated lab is not acceptance of an existing ordinary-user browser session.
        foreach (var arg in new[] { "--headless", "--enable-automation", "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
            "--disable-extensions", "--disable-quic", "--no-proxy-server", "--user-data-dir=" + profile,
            "--host-resolver-rules=MAP example.com " + target, "--dump-dom", "https://example.com/" }) info.ArgumentList.Add(arg);
        using var child = Process.Start(info) ?? throw new InvalidOperationException("BrowserLaunchFailed");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            // Drain output without retaining browser diagnostics or an unbounded DOM.
            var stdout = DrainAsync(child.StandardOutput, deadline.Token);
            var stderr = child.StandardError.BaseStream.CopyToAsync(Stream.Null, deadline.Token);
            await child.WaitForExitAsync(deadline.Token); await stderr;
            return child.ExitCode == 0 && (await stdout).Contains("<title>Example Domain</title>", StringComparison.OrdinalIgnoreCase);
        }
        finally { if (!child.HasExited) { child.Kill(true); await child.WaitForExitAsync(CancellationToken.None); } }
    }

    private static async Task<string> DrainAsync(StreamReader reader, CancellationToken ct)
    {
        var result = new System.Text.StringBuilder(); var buffer = new char[4096]; int count;
        while ((count = await reader.ReadAsync(buffer, ct)) != 0)
            if (result.Length < 65536) result.Append(buffer, 0, Math.Min(count, 65536 - result.Length));
        return result.ToString();
    }
}
