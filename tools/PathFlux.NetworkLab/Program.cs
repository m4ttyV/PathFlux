using System.Text.Json;
using PathFlux.NetworkLab;

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
