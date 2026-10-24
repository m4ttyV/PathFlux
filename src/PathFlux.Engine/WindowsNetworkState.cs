using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.Json;
namespace PathFlux.Engine;

public sealed record WindowsNetworkRoute(string DestinationPrefix, string NextHop, int InterfaceIndex, int RouteMetric);
public sealed record WindowsNetworkAdapter(string Id, string Name, string[] Dns, string[] Addresses, bool Detached, int InterfaceIndex);
public sealed record WindowsNetworkState(WindowsNetworkRoute[] Routes, WindowsNetworkAdapter[] Adapters)
{
    public static async Task<WindowsNetworkState> CaptureAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        const string script = "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; ConvertTo-Json -InputObject @(Get-NetRoute -ErrorAction Stop | Select-Object DestinationPrefix,NextHop,InterfaceIndex,RouteMetric) -Compress";
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"))
        { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, StandardOutputEncoding = Encoding.UTF8 };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) }) info.ArgumentList.Add(arg);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(15));
        using var process = Process.Start(info) ?? throw new InvalidOperationException("NetworkSnapshotLaunchFailed");
        try
        {
            var stdout = process.StandardOutput.ReadToEndAsync(deadline.Token);
            var stderr = process.StandardError.BaseStream.CopyToAsync(Stream.Null, deadline.Token);
            await process.WaitForExitAsync(deadline.Token); await stderr;
            if (process.ExitCode != 0) throw new InvalidOperationException("NetworkSnapshotQueryFailed");
            var routes = JsonSerializer.Deserialize<WindowsNetworkRoute[]>(await stdout, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? throw new InvalidDataException();
            var adapters = NetworkInterface.GetAllNetworkInterfaces().Select(i =>
            {
                var p = i.GetIPProperties();
                return new WindowsNetworkAdapter(i.Id, i.Name, p.DnsAddresses.Select(a => a.ToString()).ToArray(),
                    p.UnicastAddresses.Select(a => $"{a.Address}/{a.PrefixLength}").Order(StringComparer.Ordinal).ToArray(),
                    !TunInterfaceProbe.Observe(i).RequiresCleanup, i.Supports(NetworkInterfaceComponent.IPv4) ? p.GetIPv4Properties().Index : 0);
            }).ToArray();
            return new(routes, adapters);
        }
        finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); } }
    }
    public string[] RecoveryIssues(WindowsNetworkState after, string ownInterface)
    {
        var issues = new List<string>();
        if (!Routes.OrderBy(r => r.ToString(), StringComparer.Ordinal).SequenceEqual(after.Routes.OrderBy(r => r.ToString(), StringComparer.Ordinal))) issues.Add("RoutesChanged");
        foreach (var original in Adapters)
        {
            var current = after.Adapters.FirstOrDefault(a => a.Id == original.Id);
            if (original.Detached && current is null) continue;
            if (current is null || !original.Dns.SequenceEqual(current.Dns)) issues.Add("OriginalAdapterDnsChanged");
            if (current is null || !original.Addresses.SequenceEqual(current.Addresses)) issues.Add("OriginalAdapterAddressesChanged");
        }
        if (after.Adapters.Any(a => a.Name.Equals(ownInterface, StringComparison.OrdinalIgnoreCase) && !a.Detached)) issues.Add("OwnInterfaceRemains");
        return issues.Distinct().ToArray();
    }
    // A VPN/DHCP transition can change the global baseline independently of PathFlux.
    // This narrower check proves only removal of our reserved TUN resources, never global recovery.
    public string[] OwnedCleanupIssues(string ownInterface)
    {
        var issues = new List<string>();
        if (Adapters.Any(a => a.Name.Equals(ownInterface, StringComparison.OrdinalIgnoreCase) && !a.Detached)) issues.Add("OwnInterfaceRemains");
        static bool Reserved(string value)
        {
            string host = value.Split('/')[0].Split('%')[0];
            if (!System.Net.IPAddress.TryParse(host, out var ip)) return false;
            var bytes = ip.GetAddressBytes();
            return bytes.Length == 4 ? bytes[0] == 172 && bytes[1] == 30 && bytes[2] == 254 && bytes[3] <= 3
                : ip.ToString().StartsWith("fdfe:7061:7468:", StringComparison.OrdinalIgnoreCase);
        }
        var ownIndexes = Adapters.Where(a => a.Name.Equals(ownInterface, StringComparison.OrdinalIgnoreCase) && a.InterfaceIndex > 0)
            .Select(a => a.InterfaceIndex).ToHashSet();
        if (Routes.Any(r => ownIndexes.Contains(r.InterfaceIndex) || Reserved(r.NextHop) || Reserved(r.DestinationPrefix))) issues.Add("OwnRoutesRemain");
        if (Adapters.Any(a => a.Addresses.Any(Reserved))) issues.Add("OwnAddressesRemain");
        if (Adapters.Any(a => a.Dns.Any(Reserved))) issues.Add("OwnDnsRemains");
        return issues.ToArray();
    }
}
