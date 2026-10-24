using System.Net;
using PathFlux.Engine;
namespace PathFlux.NetworkLab;

public sealed record LabRoute(string DestinationPrefix, string NextHop, int InterfaceIndex, int RouteMetric);
public sealed record LabAdapter(string Id, string Name, string[] Dns, string[] Addresses, bool Detached = false, int InterfaceIndex = 0);
public sealed record NetworkSnapshot(LabRoute[] Routes, LabAdapter[] Adapters)
{
    public static async Task<NetworkSnapshot> CaptureAsync(CancellationToken ct)
    {
        var state = await WindowsNetworkState.CaptureAsync(ct);
        return new(state.Routes.Select(r => new LabRoute(r.DestinationPrefix, r.NextHop, r.InterfaceIndex, r.RouteMetric)).ToArray(),
            state.Adapters.Select(a => new LabAdapter(a.Id, a.Name, a.Dns, a.Addresses, a.Detached, a.InterfaceIndex)).ToArray());
    }
    public string[] Defaults => Routes.Where(r => r.DestinationPrefix is "0.0.0.0/0" or "::/0")
        .Select(r => $"{r.DestinationPrefix}|{r.NextHop}|{r.InterfaceIndex}|{r.RouteMetric}").Order().ToArray();
    public bool CanStartLab(string target = LabPolicy.TargetAddress) => !Adapters.Any(a => !a.Detached && (a.Name is LabPolicy.InterfaceName or "PathFlux-TUN"))
        && !Routes.Any(r => !IsDefaultLike(r.DestinationPrefix) && (Covers(r.DestinationPrefix, target)
            || new[] { "172.30.254.0", "172.30.254.1", "172.30.254.2", "172.30.254.3" }.Any(a => Covers(r.DestinationPrefix, a))));
    // Split-default VPN routes are kept and compared in full; only the lab's single /32 is overridden.
    public static bool IsDefaultLike(string prefix) => prefix is "0.0.0.0/0" or "::/0" or "0.0.0.0/1" or "128.0.0.0/1";
    public string[] CompareDuring(NetworkSnapshot during, string target)
    {
        var issues = new List<string>();
        var own = during.Adapters.FirstOrDefault(a => a.Name == LabPolicy.InterfaceName && !a.Detached);
        if (own is null || !during.Routes.Any(r => r.DestinationPrefix == target + "/32" && r.InterfaceIndex == own.InterfaceIndex)) issues.Add("OwnTargetRouteMissing");
        if (Routes.Except(during.Routes).Any()) issues.Add("ExistingRoutesChangedDuringLab");
        foreach (var original in Adapters.Where(a => !a.Detached && a.Name != LabPolicy.InterfaceName))
        {
            var current = during.Adapters.FirstOrDefault(a => a.Id == original.Id);
            if (current is null || !original.Dns.SequenceEqual(current.Dns) || !original.Addresses.SequenceEqual(current.Addresses)) issues.Add("OriginalAdapterChangedDuringLab");
        }
        return issues.Distinct().ToArray();
    }
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
            if (original.Detached && current is null) continue;
            if (current is null || !original.Dns.SequenceEqual(current.Dns)) issues.Add("OriginalAdapterDnsChanged");
            if (current is null || !original.Addresses.SequenceEqual(current.Addresses)) issues.Add("OriginalAdapterAddressesChanged");
        }
        if (after.Adapters.Any(a => a.Name == LabPolicy.InterfaceName && !a.Detached)) issues.Add("LabInterfaceRemains");
        if (!Routes.OrderBy(r => r.ToString()).SequenceEqual(after.Routes.OrderBy(r => r.ToString()))) issues.Add("RoutesChanged");
        if (!after.Routes.Where(r => Covers(r.DestinationPrefix, LabPolicy.TargetAddress)).OrderBy(r => r.ToString())
            .SequenceEqual(Routes.Where(r => Covers(r.DestinationPrefix, LabPolicy.TargetAddress)).OrderBy(r => r.ToString())))
            issues.Add("LabRouteRemainsOrNetworkChanged");
        return issues.Distinct().ToArray();
    }
}
