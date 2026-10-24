using System.Text.Json;
using PathFlux.NetworkLab;
using PathFlux.Engine;
using PathFlux.Application;
using PathFlux.Domain;

if (args.Length == 6 && args[0] == "agent-tcp" && args[5] == "--allow-system-tun" && Path.IsPathFullyQualified(args[1]) && Path.IsPathFullyQualified(args[3]) && Path.IsPathFullyQualified(args[4]) && !Directory.Exists(args[3]))
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(4));
    return await DockerTcpAudit.RunAsync(args[1], args[2], args[3], deadline.Token, args[4]);
}

if (args.Length == 3 && args[0] == "recover-journal" && args[2] == "--archive-confirmed" && Path.IsPathFullyQualified(args[1]))
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
    try
    {
        var archive = await RecoveryJournal.VerifyAndArchiveAsync(args[1], deadline.Token);
        Console.WriteLine("NetworkBaselineVerified_JournalArchived: " + archive); return 0;
    }
    catch (Exception ex) { Console.Error.WriteLine(ex is InvalidOperationException ? ex.Message : ex.GetType().Name); return 1; }
}

if (args.Length == 6 && args[0] == "elevate" && args[1] is "run-isolated" or "docker-tcp" or "udp-tun" && args[5] == "--allow-tun")
{
    var info = new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!)
    { UseShellExecute = true, Verb = "runas", WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden };
    foreach (var arg in args.Skip(1)) info.ArgumentList.Add(arg);
    using var child = System.Diagnostics.Process.Start(info) ?? throw new InvalidOperationException("LabLaunchFailed");
    using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(4));
    await child.WaitForExitAsync(deadline.Token); return child.ExitCode;
}

if (args.Length == 4 && args[0] == "probe-udp" && int.TryParse(args[2], out int udpPort))
{
    var result = await UdpProbe.RunAsync(args[1], udpPort, Convert.FromBase64String(args[3]), CancellationToken.None);
    Console.WriteLine(JsonSerializer.Serialize(result)); return result.Success ? 0 : 10;
}
if (args.Length == 5 && args[0] == "udp-tun" && args[4] == "--allow-tun" && Path.IsPathFullyQualified(args[1]) && Path.IsPathFullyQualified(args[3]) && !Directory.Exists(args[3]))
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
    return await UdpTunAudit.RunAsync(args[1], args[2], args[3], deadline.Token);
}

if (args.Length == 4 && args[0] == "probe-tls" && int.TryParse(args[2], out int tlsPort))
{
    var result = await TlsProbe.RunAsync(args[1], tlsPort, args[3], CancellationToken.None);
    Console.WriteLine(JsonSerializer.Serialize(result)); return result.Success ? 0 : 10;
}
if (args.Length == 5 && args[0] == "docker-tcp" && args[4] == "--allow-tun" && Path.IsPathFullyQualified(args[1]) && Path.IsPathFullyQualified(args[3]) && !Directory.Exists(args[3]))
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
    return await DockerTcpAudit.RunAsync(args[1], args[2], args[3], deadline.Token);
}

if (args.Length == 1 && args[0] == "recovery-check")
{
    // Intentionally invalid settings fail validation before any agent, engine or network change.
    await using var adapter = new SingBoxEngineAdapter(new RecoveryProbeSecrets());
    try
    {
        try { await adapter.StartAsync(new(), CancellationToken.None); return 14; }
        catch (EngineOperationException) { }
        await adapter.StopAsync(CancellationToken.None);
        if ((await adapter.GetStatusAsync(CancellationToken.None)).State != EngineState.Stopped) return 15;
        Console.WriteLine("RecoveryCheckPassed_NoEngineOrTunStarted"); return 0;
    }
    catch (EngineOperationException ex) { Console.Error.WriteLine(ex.Message); return 1; }
}

if (args.Length == 2 && args[0] == "agent-check" && Path.IsPathFullyQualified(args[1]))
{
    try
    {
        await AgentConnectionProbe.RunAsync(args[1], CancellationToken.None);
        Console.WriteLine("AgentConnectionPassed_NoEngineOrTunStarted"); return 0;
    }
    catch (Exception ex) { Console.Error.WriteLine(ex is InvalidOperationException ? ex.Message : $"AgentConnectionFailed: {ex.GetType().Name}"); return 1; }
}
if (args.Length == 3 && args[0] == "pipe-probe" && int.TryParse(args[2], out int parentPid))
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    using var pipe = WindowsAgentChannel.CreateClient(args[1]);
    try
    {
        await pipe.ConnectAsync(deadline.Token);
        WindowsAgentChannel.VerifyServer(pipe, parentPid);
        await PathFlux.Engine.AgentProtocol.WriteAsync(pipe, new AgentRequest("status"), deadline.Token);
        return (await AgentProtocol.ReadAsync<AgentReply>(pipe, deadline.Token)).Success ? 0 : 12;
    }
    catch { return 13; }
}

if (args.Length == 4 && args[0] == "probe" && int.TryParse(args[2], out var port))
{
    try
    {
        var result = await LabRunner.ProbeAsync(args[1], port, Convert.FromBase64String(args[3]), CancellationToken.None);
        Console.WriteLine(JsonSerializer.Serialize(result)); return result.Success ? 0 : 10;
    }
    catch { return 11; }
}
bool live = args.Length == 5 && args[0] == "run-isolated" && args[4] == "--allow-tun";
bool prepare = args.Length == 4 && args[0] == "prepare";
if ((!live && !prepare) || !Path.IsPathFullyQualified(args[1]) || !Path.IsPathFullyQualified(args[3]))
{
    Console.WriteLine("PathFlux.NetworkLab prepare <absolute sing-box.exe> <SHA-256> <new absolute report directory>");
    Console.WriteLine("PathFlux.NetworkLab run-isolated <absolute sing-box.exe> <SHA-256> <new absolute report directory> --allow-tun");
    Console.WriteLine("Isolated TUN uses only 198.18.0.1/32; administrator required; Wintun driver may be installed. No default route or UDP acceptance.");
    return 2;
}
if (Directory.Exists(args[3])) { Console.Error.WriteLine("Use a new report directory for each run."); return 2; }
using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(3));
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
return await LabRunner.RunAsync(args[1], args[2], args[3], live, stop.Token);

internal sealed class RecoveryProbeSecrets : ISecretStore
{
    public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult<ProxyCredentials?>(null);
    public Task<string> StoreAsync(ProxyCredentials credentials, CancellationToken ct) => throw new NotSupportedException();
    public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
}
