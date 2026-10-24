using System.Net.NetworkInformation;
namespace PathFlux.Engine;

public sealed record TunInterfaceObservation(OperationalStatus Status, bool Ipv4, bool Ipv6, int AddressCount, int DnsCount)
{
    // Windows can retain a phantom adapter in GetAllNetworkInterfaces after Wintun is removed.
    // Only this completely detached state is safe to ignore. Down alone proves nothing.
    public bool RequiresCleanup => !((Status is OperationalStatus.Down or OperationalStatus.NotPresent)
        && !Ipv4 && !Ipv6 && AddressCount == 0 && DnsCount == 0);
    public bool IsReady => Status == OperationalStatus.Up && (Ipv4 || Ipv6) && AddressCount > 0;
}

public static class TunInterfaceProbe
{
    public static TunInterfaceObservation Observe(NetworkInterface adapter)
    {
        var properties = adapter.GetIPProperties();
        return new(adapter.OperationalStatus, adapter.Supports(NetworkInterfaceComponent.IPv4),
            adapter.Supports(NetworkInterfaceComponent.IPv6), properties.UnicastAddresses.Count, properties.DnsAddresses.Count);
    }
    public static bool RequiresCleanup(string name) => NetworkInterface.GetAllNetworkInterfaces()
        .Where(i => i.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Any(i => Observe(i).RequiresCleanup);
    public static bool IsReady(string name) => NetworkInterface.GetAllNetworkInterfaces()
        .Where(i => i.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Any(i => Observe(i).IsReady);
}
