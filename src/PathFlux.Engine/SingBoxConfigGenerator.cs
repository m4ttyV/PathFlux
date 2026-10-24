using System.Text.Json;
using System.Text.Json.Nodes;
using System.Net;
using PathFlux.Application;
using PathFlux.Domain;
namespace PathFlux.Engine;

public sealed class SingBoxConfigGenerator(ISecretStore secrets)
{
    private sealed record UdpOutbound(IPEndPoint EndPoint, ProxyCredentials LocalCredentials);
    public const string InterfaceName = "PathFlux-TUN";
    public Task<string> GenerateAsync(ProxyConfiguration configuration, CancellationToken ct, bool redactSecrets = false, Version? engineVersion = null)
        => GenerateCoreAsync(configuration, ct, redactSecrets, engineVersion, guards: null);
    // Agent owns the live guards; a feature flag alone cannot create a working UDP outbound.
    internal Task<string> GenerateAgentAsync(ProxyConfiguration configuration, IReadOnlyDictionary<Guid, StrictSocksUdpBridge> guards,
        CancellationToken ct, Version? engineVersion = null)
        => GenerateCoreAsync(configuration, ct, false, engineVersion, configuration.Settings.ExperimentalSocksUdp ?
            guards.ToDictionary(p => p.Key, p => new UdpOutbound(p.Value.EndPoint, p.Value.LocalCredentials)) : null);
    // sing-box check does not connect. Validation must not create transport listeners in the unelevated UI.
    internal Task<string> GenerateValidationAsync(ProxyConfiguration configuration, CancellationToken ct, Version? engineVersion = null)
    {
        var used = configuration.Rules.Where(ExperimentalUdpPolicy.UsesUdp).Select(r => r.ProfileId).ToHashSet();
        var descriptors = configuration.Settings.ExperimentalSocksUdp ? configuration.Profiles.Where(p => used.Contains(p.Id) && p.Protocol == ProxyProtocol.Socks5)
            .ToDictionary(p => p.Id, p => new UdpOutbound(new(IPAddress.Loopback, 9), new("validation-only", "validation-only"))) : null;
        return GenerateCoreAsync(configuration, ct, false, engineVersion, descriptors);
    }
    internal Task<string> GenerateExperimentalUdpAsync(ProxyConfiguration configuration, CancellationToken ct, Version? engineVersion = null,
        IReadOnlyDictionary<Guid, StrictSocksUdpBridge>? guards = null)
        => GenerateCoreAsync(configuration, ct, false, engineVersion, guards?.ToDictionary(p => p.Key, p => new UdpOutbound(p.Value.EndPoint, p.Value.LocalCredentials)));
    private async Task<string> GenerateCoreAsync(ProxyConfiguration configuration, CancellationToken ct, bool redactSecrets, Version? engineVersion,
        IReadOnlyDictionary<Guid, UdpOutbound>? guards)
    {
        var validation = ConfigurationValidator.Validate(configuration);
        if (!validation.IsValid) throw new InvalidOperationException(string.Join("; ", validation.Issues.Where(i => !i.IsWarning).Select(i => i.Message)));
        var policy = await new RuleCompiler().CompileAsync(configuration.Rules, configuration.Profiles, ct);
        if (!policy.IsValid) throw new InvalidOperationException("Правила не прошли проверку.");
        JsonArray outbounds = [new JsonObject { ["type"] = "direct", ["tag"] = "direct" }];
        foreach (var p in policy.Profiles)
        {
            var outbound = new JsonObject
            {
                ["type"] = p.Protocol == ProxyProtocol.Socks5 ? "socks" : "http",
                // Resolve the conventional local Docker endpoint without consulting TUN DNS or choosing ::1.
                // IPv6-only local proxies remain available through an explicit ::1 address.
                ["tag"] = Tag(p.Id), ["server"] = p.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || p.Host.Equals("localhost.", StringComparison.OrdinalIgnoreCase) ? "127.0.0.1" : p.Host, ["server_port"] = p.Port,
                ["connect_timeout"] = "10s"
            };
            if (p.Protocol == ProxyProtocol.Socks5) { outbound["version"] = "5"; outbound["network"] = "tcp"; }
            if (p.Protocol == ProxyProtocol.HttpsConnect)
                outbound["tls"] = new JsonObject { ["enabled"] = true, ["server_name"] = string.IsNullOrWhiteSpace(p.TlsServerName) ? p.Host : p.TlsServerName, ["insecure"] = false };
            if (p.CredentialsRef is not null)
            {
                if (redactSecrets) { outbound["username"] = "REDACTED"; outbound["password"] = "REDACTED"; }
                else
                {
                    var credential = await secrets.GetAsync(p.CredentialsRef, ct) ?? throw new InvalidOperationException("Не найдены учётные данные прокси.");
                    outbound["username"] = credential.Username; outbound["password"] = credential.Password;
                }
            }
            outbounds.Add(outbound);
            if (p.Protocol == ProxyProtocol.Socks5 && guards?.TryGetValue(p.Id, out var bridge) == true)
                outbounds.Add(new JsonObject { ["type"] = "socks", ["tag"] = UdpTag(p.Id), ["server"] = bridge.EndPoint.Address.ToString(),
                    ["server_port"] = bridge.EndPoint.Port, ["version"] = "5", ["network"] = "udp", ["connect_timeout"] = "10s",
                    ["username"] = bridge.LocalCredentials.Username, ["password"] = bridge.LocalCredentials.Password });
        }
        JsonArray rules = [];
        // Exact executable paths avoid exempting unrelated applications with a matching filename.
        var basePath = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var uiDirectory = Path.GetFileName(basePath).Equals("agent", StringComparison.OrdinalIgnoreCase) ? Path.GetDirectoryName(basePath)! : basePath;
        var internalPaths = new[] { Path.Combine(uiDirectory, "PathFlux.exe"), Path.Combine(uiDirectory, "agent", "PathFlux.Agent.exe"), configuration.Settings.EnginePath }
            .Where(p => !string.IsNullOrWhiteSpace(p)).Distinct(StringComparer.OrdinalIgnoreCase).Select(p => JsonValue.Create(p)).ToArray();
        rules.Add(new JsonObject { ["process_path"] = new JsonArray(internalPaths), ["action"] = "route", ["outbound"] = "direct" });
        // sing-tun 0.7.3 assigns next-address DNS to its Windows TUN. Serve these virtual
        // destinations before LAN/user rules; local transport excludes MyInterface on Windows.
        rules.Add(new JsonObject { ["inbound"] = "tun-in", ["ip_cidr"] = new JsonArray("172.30.254.2/32", "fdfe:7061:7468::2/128"), ["port"] = 53, ["action"] = "hijack-dns" });
        rules.Add(new JsonObject { ["ip_cidr"] = new JsonArray("127.0.0.0/8", "::1/128"), ["action"] = "route", ["outbound"] = "direct" });
        if (configuration.Settings.BypassLan)
            rules.Add(new JsonObject { ["ip_is_private"] = true, ["action"] = "route", ["outbound"] = "direct" });
        // Preserve ordered first-match semantics by expanding each rule in place (UDP rejection then TCP).
        foreach (var r in policy.Rules)
        {
            var transports = r.Network == NetworkTransport.Both ? new[] { "udp", "tcp" } : [r.Network == NetworkTransport.Tcp ? "tcp" : "udp"];
            foreach (var network in transports)
            {
                var rule = new JsonObject { [r.Selector.Kind == SelectorKind.ProcessName ? "process_name" : "process_path"] = new JsonArray(r.Selector.Value), ["network"] = network };
                // A verified relay probe does not prove transparent TUN routing. Proxy UDP remains blocked.
                bool labSocksUdp = guards is not null && r.ProfileId is { } profileId && guards.ContainsKey(profileId) && policy.Profiles.Any(p => p.Id == profileId && p.Protocol == ProxyProtocol.Socks5);
                if (r.Action == RouteAction.Block || (r.Action == RouteAction.Proxy && network == "udp" && !labSocksUdp))
                    rule["action"] = "reject";
                else { rule["action"] = "route"; rule["outbound"] = r.Action == RouteAction.Direct ? "direct" : network == "udp" ? UdpTag(r.ProfileId!.Value) : Tag(r.ProfileId!.Value); }
                rules.Add(rule);
            }
        }
        var root = new JsonObject
        {
            ["log"] = new JsonObject { ["level"] = "warn", ["timestamp"] = true, ["disabled"] = false },
            ["dns"] = new JsonObject { ["servers"] = new JsonArray(new JsonObject { ["type"] = "local", ["tag"] = "local-dns" }) },
            ["inbounds"] = new JsonArray(new JsonObject
            {
                ["type"] = "tun", ["tag"] = "tun-in", ["interface_name"] = InterfaceName,
                ["address"] = new JsonArray("172.30.254.1/30", "fdfe:7061:7468::1/126"),
                // Windows auto_route defaults to /0, which loses to OpenVPN's two /1 routes.
                // Keep the existing VPN routes; TUN's lower-metric /1 routes capture application traffic.
                ["route_address"] = new JsonArray("0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"),
                ["mtu"] = 1500, ["auto_route"] = true, ["strict_route"] = false, ["stack"] = "mixed"
            }),
            ["outbounds"] = outbounds,
            ["route"] = new JsonObject { ["rules"] = rules, ["final"] = "direct", ["auto_detect_interface"] = true, ["default_domain_resolver"] = "local-dns" }
        };
        if (engineVersion >= new Version(1, 15, 0)) root["inbounds"]![0]!.AsObject().Remove("stack");
        return root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }
    public static string Tag(Guid id) => $"proxy-{id:D}";
    internal static string UdpTag(Guid id) => $"udp-guard-{id:D}";
}
