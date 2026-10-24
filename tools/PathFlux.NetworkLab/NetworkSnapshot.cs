using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.Json;
namespace PathFlux.NetworkLab;

public sealed record LabRoute(string DestinationPrefix, string NextHop, int InterfaceIndex, int RouteMetric);
public sealed record LabAdapter(string Id, string Name, string[] Dns, string[] Addresses);
public sealed record NetworkSnapshot(LabRoute[] Routes, LabAdapter[] Adapters)
{
    public static async Task<NetworkSnapshot> CaptureAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        // Fixed, read-only command: no user inputs or shell interpolation, no profile execution.
        const string script = "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; ConvertTo-Json -InputObject @(Get-NetRoute -ErrorAction Stop | Select-Object DestinationPrefix,NextHop,InterfaceIndex,RouteMetric) -Compress";
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"))
        { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, StandardOutputEncoding = Encoding.UTF8 };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) }) info.ArgumentList.Add(arg);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(15));
        using var process = Process.Start(info) ?? throw new InvalidOperationException("Не удалось прочитать таблицу маршрутов.");
        try
        {
            var stdout = process.StandardOutput.ReadToEndAsync(deadline.Token);
            var stderr = process.StandardError.BaseStream.CopyToAsync(Stream.Null, deadline.Token);
            await process.WaitForExitAsync(deadline.Token); await stderr;
            if (process.ExitCode != 0) throw new InvalidOperationException("Get-NetRoute завершился с ошибкой. Сеть не изменена.");
            var routes = JsonSerializer.Deserialize<LabRoute[]>(await stdout, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? throw new InvalidDataException("Не удалось разобрать таблицу маршрутов.");
            var adapters = NetworkInterface.GetAllNetworkInterfaces().Select(i =>
            {
                var p = i.GetIPProperties();
                return new LabAdapter(i.Id, i.Name, p.DnsAddresses.Select(a => a.ToString()).Order().ToArray(),
                    p.UnicastAddresses.Select(a => $"{a.Address}/{a.PrefixLength}").Order().ToArray());
            }).ToArray();
            return new(routes, adapters);
        }
        finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); } }
    }
    public string[] Defaults => Routes.Where(r => r.DestinationPrefix is "0.0.0.0/0" or "::/0")
        .Select(r => $"{r.DestinationPrefix}|{r.NextHop}|{r.InterfaceIndex}|{r.RouteMetric}").Order().ToArray();
    public bool CanStartLab() => !Adapters.Any(a => a.Name is LabPolicy.InterfaceName or "PathFlux-TUN")
        && !Routes.Any(r => Covers(r.DestinationPrefix, LabPolicy.TargetAddress) || Covers(r.DestinationPrefix, "172.30.254.1"));
    private static bool Covers(string prefix, string target)
    {
        if (!System.Net.IPNetwork.TryParse(prefix, out var network) || network.PrefixLength == 0) return false;
        return network.Contains(IPAddress.Parse(target));
    }
    public string[] CompareRecovery(NetworkSnapshot after)
    {
        var issues = new List<string>();
        if (!Defaults.SequenceEqual(after.Defaults)) issues.Add("DefaultRoutesChanged");
        foreach (var original in Adapters)
        {
            var current = after.Adapters.FirstOrDefault(a => a.Id == original.Id);
            if (current is null || !original.Dns.SequenceEqual(current.Dns)) issues.Add("OriginalAdapterDnsChanged");
            if (current is null || !original.Addresses.SequenceEqual(current.Addresses)) issues.Add("OriginalAdapterAddressesChanged");
        }
        if (after.Adapters.Any(a => a.Name == LabPolicy.InterfaceName)) issues.Add("LabInterfaceRemains");
        if (!after.Routes.Where(r => Covers(r.DestinationPrefix, LabPolicy.TargetAddress)).OrderBy(r => r.ToString())
            .SequenceEqual(Routes.Where(r => Covers(r.DestinationPrefix, LabPolicy.TargetAddress)).OrderBy(r => r.ToString())))
            issues.Add("LabRouteRemainsOrNetworkChanged");
        return issues.Distinct().ToArray();
    }
}
