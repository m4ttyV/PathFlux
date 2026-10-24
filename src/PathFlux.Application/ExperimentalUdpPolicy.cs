using System.Net;
using PathFlux.Domain;

namespace PathFlux.Application;

public static class ExperimentalUdpPolicy
{
    public static string? Incompatibility(ProxyProfile profile)
    {
        if (profile.Protocol != ProxyProtocol.Socks5) return "UDP поддерживается только через SOCKS5; для HTTP/HTTPS CONNECT выберите TCP.";
        if (profile.UdpRelayMode == UdpRelayMode.DockerNat && !IsDockerHost(profile.Host))
            return "Docker NAT требует явного IPv4 loopback-адреса прокси (127.0.0.1 или localhost). Для удалённого прокси используйте Standard SOCKS5.";
        return null;
    }
    public static bool IsDockerHost(string host) => host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
        host.Equals("localhost.", StringComparison.OrdinalIgnoreCase) || host == "127.0.0.1";
    public static bool UsesUdp(RoutingRule rule) => rule.Enabled && rule.Action == RouteAction.Proxy && rule.Network is NetworkTransport.Udp or NetworkTransport.Both;
    public static bool IsUnicast(IPAddress ip) => UdpVerificationPolicy.IsProbeTarget(ip.ToString(), out _);
}
