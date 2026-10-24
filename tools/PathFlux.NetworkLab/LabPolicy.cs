using System.Text.Json.Nodes;
using PathFlux.Application;
using PathFlux.Domain;
using PathFlux.Engine;
namespace PathFlux.NetworkLab;

public enum LabScenario { Path, Name, Disabled, Block, Priority, ProfileTwo, UpstreamRefused, EngineCrash, JobClose }
public static class LabPolicy
{
    public const string InterfaceName = "PathFlux-Lab-TUN";
    public const string TargetAddress = "198.18.0.1";
    public const int TargetPort = 4444;
    public const string ProbeName = "PathFlux.LabProbe.exe";
    public const string InterfaceAddress = "172.30.254.1/32";
    public static ProxyConfiguration Create(LabScenario scenario, string selectedPath, ProxyProfile first, ProxyProfile second)
    {
        var rule = new RoutingRule { Name = "Lab selected path", Network = NetworkTransport.Tcp,
            Selector = new(SelectorKind.ExecutablePath, selectedPath), ProfileId = first.Id };
        var rules = new List<RoutingRule> { rule };
        switch (scenario)
        {
            case LabScenario.Name: rules = [rule with { Selector = new(SelectorKind.ProcessName, ProbeName) }]; break;
            case LabScenario.Disabled: rules = [rule with { Enabled = false }]; break;
            case LabScenario.Block: rules = [rule with { Action = RouteAction.Block, ProfileId = null }]; break;
            case LabScenario.Priority:
                rules = [rule, rule with { Id = Guid.NewGuid(), Priority = 1, Action = RouteAction.Block, ProfileId = null }]; break;
            case LabScenario.ProfileTwo: rules = [rule with { ProfileId = second.Id }]; break;
            case LabScenario.UpstreamRefused: rules = [rule with { ProfileId = second.Id }]; break;
        }
        return new() { Profiles = [first, second], Rules = rules };
    }
    public static async Task<string> GenerateAsync(ProxyConfiguration config, CancellationToken ct, Version? engineVersion = null)
        => await GenerateGuardedAsync(config, ct, engineVersion, null);
    internal static async Task<string> GenerateGuardedAsync(ProxyConfiguration config, CancellationToken ct, Version? engineVersion,
        IReadOnlyDictionary<Guid, StrictSocksUdpBridge>? guards)
    {
        // Use actual domain rule compiler. Only TUN scope is narrowed for this isolated lab.
        var generator = new SingBoxConfigGenerator(new NoSecrets());
        var root = JsonNode.Parse(guards is not null ? await generator.GenerateExperimentalUdpAsync(config, ct, engineVersion, guards)
            : await generator.GenerateAsync(config, ct, engineVersion: engineVersion))!;
        if (guards is not null) root["log"]!["level"] = "debug";
        root["inbounds"] = new JsonArray(new JsonObject
        {
            ["type"] = "tun", ["tag"] = "tun-in", ["interface_name"] = InterfaceName,
            ["address"] = new JsonArray(InterfaceAddress), ["route_address"] = new JsonArray(TargetAddress + "/32"),
            ["auto_route"] = true, ["strict_route"] = false, ["stack"] = "gvisor", ["mtu"] = 1500
        });
        if (engineVersion >= new Version(1, 15, 0)) root["inbounds"]![0]!.AsObject().Remove("stack");
        if (engineVersion >= new Version(1, 14, 0))
        {
            root["inbounds"]![0]!["dns_mode"] = "disabled";
            root["inbounds"]![0]!["address"] = new JsonArray("172.30.254.1/30");
            if (engineVersion < new Version(1, 15, 0)) root["inbounds"]![0]!["stack"] = "mixed";
        }
        // No IPv6/default route; /32 has no next DNS address, newer /30 explicitly disables DNS.
        return root.ToJsonString();
    }
    private sealed class NoSecrets : ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult<ProxyCredentials?>(null);
        public Task<string> StoreAsync(ProxyCredentials credentials, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }
}
