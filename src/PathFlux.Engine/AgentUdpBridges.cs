using System.Net;
using PathFlux.Application;
using PathFlux.Domain;

namespace PathFlux.Engine;

/// <summary>One agent-owned transport per used profile, never per rule. No global/static instances.</summary>
internal sealed class AgentUdpBridges : IAsyncDisposable
{
    internal Dictionary<Guid, StrictSocksUdpBridge> Bridges { get; } = [];
    internal Dictionary<Guid, TlsNameSocksBridge> TcpBridges { get; } = [];
    public IReadOnlyList<UdpBridgeStatistics> Snapshot() => Bridges.Select(b => b.Value.Snapshot(b.Key)).ToArray();
    public static async Task<AgentUdpBridges> CreateAsync(ProxyConfiguration config, ISecretStore secrets, CancellationToken ct)
    {
        var owner = new AgentUdpBridges();
        try
        {
            var usedTcp = config.Rules.Where(r => r.Enabled && r.Action == RouteAction.Proxy && r.Network is NetworkTransport.Tcp or NetworkTransport.Both)
                .Select(r => r.ProfileId).ToHashSet();
            var usedUdp = config.Settings.ExperimentalSocksUdp ? config.Rules.Where(ExperimentalUdpPolicy.UsesUdp).Select(r => r.ProfileId).ToHashSet() : [];
            if (usedUdp.Count == 0 && !config.Profiles.Any(p => p.UseTlsServerNameForTcp && usedTcp.Contains(p.Id))) return owner;
            var validation = ConfigurationValidator.Validate(config);
            if (!validation.IsValid) throw new InvalidOperationException("Параметры UDP несовместимы.");
            foreach (var profile in config.Profiles.Where(p => usedUdp.Contains(p.Id) || p.UseTlsServerNameForTcp && usedTcp.Contains(p.Id)))
            {
                ct.ThrowIfCancellationRequested();
                if (usedUdp.Contains(profile.Id) && ExperimentalUdpPolicy.Incompatibility(profile) is { } reason) throw new InvalidOperationException(reason);
                string host = ExperimentalUdpPolicy.IsDockerHost(profile.Host) ? "127.0.0.1" : profile.Host;
                var address = IPAddress.TryParse(host, out var literal) ? literal :
                    (await Dns.GetHostAddressesAsync(host, ct)).FirstOrDefault(ExperimentalUdpPolicy.IsUnicast);
                if (address is null || !ExperimentalUdpPolicy.IsUnicast(address)) throw new InvalidOperationException("Не удалось определить допустимый IP SOCKS5 для UDP.");
                var credentials = profile.CredentialsRef is { } reference ? await secrets.GetAsync(reference, ct)
                    ?? throw new InvalidOperationException("Не найдены учётные данные SOCKS5.") : null;
                var binding = profile.UdpRelayMode == UdpRelayMode.DockerNat ? new UdpRelayBinding(profile.UdpPublishedPortFirst, profile.UdpPublishedPortLast)
                    : profile.UdpRelayMode == UdpRelayMode.Auto ? new UdpRelayBinding(AutomaticProfile: profile) : new();
                if (usedUdp.Contains(profile.Id)) owner.Bridges.Add(profile.Id, new(new(address, profile.Port), binding, credentials));
                if (usedTcp.Contains(profile.Id) && profile.UseTlsServerNameForTcp) owner.TcpBridges.Add(profile.Id, new(new(address, profile.Port), credentials, profile.TcpIpv4DohServer));
            }
            return owner;
        }
        catch { await owner.DisposeAsync(); throw; }
    }
    public async ValueTask DisposeAsync()
    {
        foreach (var bridge in Bridges.Values) await bridge.DisposeAsync();
        Bridges.Clear();
        foreach (var bridge in TcpBridges.Values) await bridge.DisposeAsync();
        TcpBridges.Clear();
    }
}
