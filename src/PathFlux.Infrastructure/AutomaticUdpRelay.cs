using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using PathFlux.Domain;

namespace PathFlux.Infrastructure;

/// <summary>Read-only Docker discovery. Never guesses a loopback port or scans host services.</summary>
public static class AutomaticUdpRelay
{
    public static async Task<IPEndPoint> ResolveAsync(ProxyProfile profile, IPEndPoint peer, IPEndPoint advertised, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (advertised.Port is < 1 or > 65535) throw new IOException("InvalidUdpRelayPort");
        var address = advertised.Address.IsIPv4MappedToIPv6 ? advertised.Address.MapToIPv4() : advertised.Address;
        if (peer.Address.Equals(IPAddress.Loopback) && IsPrivate(address))
        {
            if (!OperatingSystem.IsWindows()) throw DiscoveryRequired();
            foreach (var pipeName in new[] { "docker_engine", "dockerDesktopLinuxEngine" })
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(TimeSpan.FromSeconds(2));
                try
                {
                    using var handler = new SocketsHttpHandler { UseProxy = false, ConnectCallback = async (_, token) =>
                    {
                        var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                        try { await pipe.ConnectAsync(token); return pipe; }
                        catch { pipe.Dispose(); throw; }
                    }};
                    using var client = new HttpClient(handler) { BaseAddress = new Uri("http://docker/") };
                    await using var stream = await client.GetStreamAsync("containers/json?all=false", deadline.Token);
                    using var limited = new MemoryStream();
                    var buffer = new byte[8192];
                    int count;
                    while ((count = await stream.ReadAsync(buffer, deadline.Token)) != 0)
                    {
                        if (limited.Length + count > 2 * 1024 * 1024) throw new IOException("DockerResponseTooLarge");
                        limited.Write(buffer, 0, count);
                    }
                    var port = FindPublishedPort(limited.ToArray(), profile.Port, address, advertised.Port);
                    if (port is { } published) return new(IPAddress.Loopback, published);
                }
                catch (Exception ex) when (ex is IOException or HttpRequestException or JsonException or UnauthorizedAccessException or OperationCanceledException)
                { ct.ThrowIfCancellationRequested(); }
            }
            throw DiscoveryRequired();
        }
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) address = peer.Address;
        if (!PathFlux.Application.ExperimentalUdpPolicy.IsUnicast(address)) throw new IOException("InvalidUdpRelayAddress");
        return new(address, advertised.Port);
    }

    public static int? FindPublishedPort(ReadOnlyMemory<byte> json, int tcpHostPort, IPAddress relayAddress, int relayPort)
    {
        try { return ParsePublishedPort(json, tcpHostPort, relayAddress, relayPort); }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        { return null; }
    }

    private static int? ParsePublishedPort(ReadOnlyMemory<byte> json, int tcpHostPort, IPAddress relayAddress, int relayPort)
    {
        using var doc = JsonDocument.Parse(json);
        var candidates = new List<int>();
        foreach (var container in doc.RootElement.EnumerateArray())
        {
            if (!container.TryGetProperty("NetworkSettings", out var settings) || !settings.TryGetProperty("Networks", out var networks) ||
                !networks.EnumerateObject().Any(n => n.Value.TryGetProperty("IPAddress", out var ip) && ip.GetString() == relayAddress.ToString()) ||
                !container.TryGetProperty("Ports", out var ports)) continue;
            bool Published(JsonElement p) => p.TryGetProperty("IP", out var host) && host.GetString() is "127.0.0.1" or "0.0.0.0";
            if (!ports.EnumerateArray().Any(p => p.GetProperty("Type").GetString() == "tcp" && Published(p) &&
                p.TryGetProperty("PublicPort", out var port) && port.GetInt32() == tcpHostPort)) continue;
            foreach (var p in ports.EnumerateArray())
                if (p.GetProperty("Type").GetString() == "udp" && Published(p) && p.GetProperty("PrivatePort").GetInt32() == relayPort &&
                    p.TryGetProperty("PublicPort", out var port) && port.GetInt32() is >= 1 and <= 65535) candidates.Add(port.GetInt32());
        }
        return candidates.Count == 1 ? candidates[0] : null;
    }
    private static bool IsPrivate(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = ip.GetAddressBytes();
        return b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31 || b[0] == 192 && b[1] == 168;
    }
    private static IOException DiscoveryRequired() => new("UdpDockerDiscoveryRequired");
}
