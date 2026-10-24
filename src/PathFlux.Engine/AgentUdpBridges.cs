using System.Net;
using PathFlux.Application;
using PathFlux.Domain;

namespace PathFlux.Engine;

/// <summary>One agent-owned transport per used profile, never per rule. No global/static instances.</summary>
internal sealed class AgentUdpBridges : IAsyncDisposable
{
    internal Dictionary<Guid, StrictSocksUdpBridge> Bridges { get; } = [];
    public IReadOnlyList<UdpBridgeStatistics> Snapshot() => Bridges.Select(b => b.Value.Snapshot(b.Key)).ToArray();
    public static async Task<AgentUdpBridges> CreateAsync(ProxyConfiguration config, ISecretStore secrets, CancellationToken ct)
    {
        var owner = new AgentUdpBridges();
        try
        {
            if (!config.Settings.ExperimentalSocksUdp) return owner;
            var validation = ConfigurationValidator.Validate(config);
            if (!validation.IsValid) throw new InvalidOperationException("Конфигурация экспериментального UDP несовместима.");
            var used = config.Rules.Where(ExperimentalUdpPolicy.UsesUdp).Select(r => r.ProfileId).ToHashSet();
            foreach (var profile in config.Profiles.Where(p => used.Contains(p.Id)))
            {
                ct.ThrowIfCancellationRequested();
                if (ExperimentalUdpPolicy.Incompatibility(profile) is { } reason) throw new InvalidOperationException(reason);
                string host = ExperimentalUdpPolicy.IsDockerHost(profile.Host) ? "127.0.0.1" : profile.Host;
                var address = IPAddress.TryParse(host, out var literal) ? literal :
                    (await Dns.GetHostAddressesAsync(host, ct)).FirstOrDefault(ExperimentalUdpPolicy.IsUnicast);
                if (address is null || !ExperimentalUdpPolicy.IsUnicast(address)) throw new InvalidOperationException("Не удалось определить допустимый IP SOCKS5 для UDP.");
                var credentials = profile.CredentialsRef is { } reference ? await secrets.GetAsync(reference, ct)
                    ?? throw new InvalidOperationException("Не найдены учётные данные SOCKS5.") : null;
                var binding = profile.UdpRelayMode == UdpRelayMode.DockerNat ? new UdpRelayBinding(profile.UdpPublishedPortFirst, profile.UdpPublishedPortLast) : new();
                owner.Bridges.Add(profile.Id, new(new(address, profile.Port), binding, credentials));
            }
            return owner;
        }
        catch { await owner.DisposeAsync(); throw; }
    }
    public async ValueTask DisposeAsync()
    {
        foreach (var bridge in Bridges.Values) await bridge.DisposeAsync();
        Bridges.Clear();
    }
}
