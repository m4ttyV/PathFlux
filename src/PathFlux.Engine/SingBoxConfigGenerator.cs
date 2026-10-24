using System.Text.Json;
using System.Text.Json.Nodes;
using PathFlux.Application;
using PathFlux.Domain;
namespace PathFlux.Engine;

public sealed class SingBoxConfigGenerator(ISecretStore secrets)
{
    public const string InterfaceName = "PathFlux-TUN";
    public async Task<string> GenerateAsync(ProxyConfiguration configuration, CancellationToken ct, bool redactSecrets = false, Version? engineVersion = null)
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
                ["tag"] = Tag(p.Id), ["server"] = p.Host, ["server_port"] = p.Port,
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
                if (r.Action == RouteAction.Block || (r.Action == RouteAction.Proxy && network == "udp"))
                    rule["action"] = "reject";
                else { rule["action"] = "route"; rule["outbound"] = r.Action == RouteAction.Direct ? "direct" : Tag(r.ProfileId!.Value); }
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
                ["mtu"] = 1500, ["auto_route"] = true, ["strict_route"] = false, ["stack"] = "mixed"
            }),
            ["outbounds"] = outbounds,
            ["route"] = new JsonObject { ["rules"] = rules, ["final"] = "direct", ["auto_detect_interface"] = true, ["default_domain_resolver"] = "local-dns" }
        };
        if (engineVersion >= new Version(1, 15, 0)) root["inbounds"]![0]!.AsObject().Remove("stack");
        return root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }
    public static string Tag(Guid id) => $"proxy-{id:D}";
}
