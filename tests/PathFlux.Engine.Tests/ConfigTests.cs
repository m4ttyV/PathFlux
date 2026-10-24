using System.Buffers.Binary;
using System.Text.Json.Nodes;
using PathFlux.Application;
using PathFlux.Domain;
using PathFlux.Engine;
using Xunit;
namespace PathFlux.Engine.Tests;

public class ConfigTests
{
    private readonly ProxyProfile profile = new() { Name = "Local SOCKS" };
    private ProxyConfiguration Config(params RoutingRule[] rules) => new() { Profiles = [profile], Rules = rules.ToList() };
    private RoutingRule ProxyRule(NetworkTransport network = NetworkTransport.Both) => new() { ProfileId = profile.Id, Network = network };
    [Fact] public async Task GeneratedPolicyHasDirectDefaultLoopProtectionAndInPlaceUdpReject()
    {
        var json = JsonNode.Parse(await new SingBoxConfigGenerator(new Secrets()).GenerateAsync(Config(ProxyRule()), default))!;
        Assert.Equal("direct", (string?)json["route"]!["final"]);
        var rules = json["route"]!["rules"]!.AsArray();
        Assert.Contains(rules[0]!["process_path"]!.AsArray(), n => ((string?)n)?.EndsWith("PathFlux.Agent.exe", StringComparison.Ordinal) == true);
        Assert.Null(rules[0]!["process_name"]);
        Assert.Equal("reject", (string?)rules[3]!["action"]);
        Assert.Equal("udp", (string?)rules[3]!["network"]);
        Assert.Equal(SingBoxConfigGenerator.Tag(profile.Id), (string?)rules[4]!["outbound"]);
        Assert.True((bool)json["route"]!["auto_detect_interface"]!);
        Assert.Null(json["inbounds"]![0]!["auto_redirect"]);
    }
    [Fact] public async Task ExactPidIsNeverSubstitutedWithProcessName()
    {
        var config = Config(ProxyRule() with { Selector = new(SelectorKind.ProcessInstance, "42", new(42, DateTimeOffset.UtcNow)) });
        await Assert.ThrowsAsync<InvalidOperationException>(() => new SingBoxConfigGenerator(new Secrets()).GenerateAsync(config, default));
    }
    [Fact] public async Task HttpsVerificationAndRedactedPreview()
    {
        var config = Config() with { Profiles = [profile with { Protocol = ProxyProtocol.HttpsConnect, CredentialsRef = "ref" }] };
        string preview = await new SingBoxConfigGenerator(new Secrets()).GenerateAsync(config, default, true);
        Assert.DoesNotContain("sensitive-password", preview);
        var json = JsonNode.Parse(preview)!;
        Assert.False((bool)json["outbounds"]![1]!["tls"]!["insecure"]!);
        Assert.Contains("REDACTED", preview);
    }
    [Fact] public async Task HigherPriorityDirectRuleStaysBeforeLowerPriorityProxyUdpReject()
    {
        var config = Config(ProxyRule() with { Priority = 200 }, new RoutingRule { Priority = 1, Action = RouteAction.Direct });
        var json = JsonNode.Parse(await new SingBoxConfigGenerator(new Secrets()).GenerateAsync(config, default))!;
        var rules = json["route"]!["rules"]!.AsArray();
        Assert.Equal("direct", (string?)rules[3]!["outbound"]);
        Assert.Equal("direct", (string?)rules[4]!["outbound"]);
        Assert.Equal("reject", (string?)rules[5]!["action"]);
    }
    [Fact] public async Task VirtualTunDnsIsServedBeforeLanAndUserRulesWithoutHijackingOtherResolvers()
    {
        var config = Config(ProxyRule()) with { Settings = new() { BypassLan = true } };
        var json = JsonNode.Parse(await new SingBoxConfigGenerator(new Secrets()).GenerateAsync(config, default))!;
        var rules = json["route"]!["rules"]!.AsArray();
        var hijack = Assert.Single(rules, r => (string?)r!["action"] == "hijack-dns");
        Assert.Equal(53, (int)hijack!["port"]!);
        Assert.Equal("tun-in", (string?)hijack["inbound"]);
        Assert.Equal(new[] { "172.30.254.2/32", "fdfe:7061:7468::2/128" }, hijack["ip_cidr"]!.AsArray().Select(n => (string?)n));
        Assert.True(rules.IndexOf(hijack) < rules.IndexOf(rules.Single(r => r?["ip_is_private"] is not null)));
        Assert.Equal("local", (string?)json["dns"]!["servers"]![0]!["type"]);
    }
    [Fact] public async Task ProtocolRoundTripAndBounds()
    {
        using var stream = new MemoryStream();
        await AgentProtocol.WriteAsync(stream, new AgentRequest("status"), default);
        stream.Position = 0;
        Assert.Equal("status", (await AgentProtocol.ReadAsync<AgentRequest>(stream, default)).Operation);
        byte[] invalid = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(invalid, AgentProtocol.MaxMessageBytes + 1);
        using var malicious = new MemoryStream(invalid);
        await Assert.ThrowsAsync<InvalidDataException>(() => AgentProtocol.ReadAsync<AgentRequest>(malicious, default));
    }
    [Fact] public async Task ProtocolRejectsTruncatedMessagesAndOversizedWrites()
    {
        using var stream = new MemoryStream([4, 0, 0, 0, 123]);
        await Assert.ThrowsAsync<EndOfStreamException>(() => AgentProtocol.ReadAsync<AgentRequest>(stream, default));
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<InvalidDataException>(() => AgentProtocol.WriteAsync(output, new string('x', AgentProtocol.MaxMessageBytes), default));
        Assert.Equal(0, output.Length);
    }
    [Fact] public async Task AdapterRejectsInvalidConfigurationWithoutLaunchingAgent()
    {
        await using var adapter = new SingBoxEngineAdapter(new Secrets(), Path.Combine(Path.GetTempPath(), "unused-agent.exe"),
            Path.Combine(Path.GetTempPath(), "PathFlux-test-" + Guid.NewGuid().ToString("N"), "recovery.json"));
        var result = await adapter.ValidateAsync(Config(ProxyRule() with { IncludeChildren = true }), default);
        Assert.False(result.IsValid);
        Assert.Equal(EngineState.Stopped, (await adapter.GetStatusAsync(default)).State);
        await adapter.StopAsync(default); await adapter.StopAsync(default);
        Assert.Equal(EngineState.Stopped, (await adapter.GetStatusAsync(default)).State);
    }
    [Fact] public async Task MissingCredentialsFailBeforeEngineInvocation()
    {
        var config = Config() with { Profiles = [profile with { CredentialsRef = "absent" }] };
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => new SingBoxConfigGenerator(new MissingSecrets()).GenerateAsync(config, default));
        Assert.DoesNotContain("absent", error.Message);
    }
    [Fact] public async Task BypassLanMustBeExplicitAndHttpsOnlyGetsTls()
    {
        var generator = new SingBoxConfigGenerator(new Secrets());
        string ordinary = await generator.GenerateAsync(Config(ProxyRule()), default);
        Assert.DoesNotContain("ip_is_private", ordinary);
        string withLan = await generator.GenerateAsync(Config(ProxyRule()) with { Settings = new() { BypassLan = true } }, default);
        Assert.Contains("ip_is_private", withLan);
        Assert.Null(JsonNode.Parse(ordinary)!["outbounds"]![1]!["tls"]);
    }
    [Fact] public async Task VerifiedRelayEvidenceCannotEnableUnverifiedTransparentUdpRouting()
    {
        var verified = profile with
        {
            UdpVerification = new(UdpVerificationPolicy.Fingerprint(profile), DateTimeOffset.UtcNow,
                UdpRelayStatus.Verified, "127.0.0.1", 4444, 3, 3, 1.0)
        };
        Assert.True(UdpVerificationPolicy.IsCurrent(verified, DateTimeOffset.UtcNow));
        var config = Config(ProxyRule()) with { Profiles = [verified] };
        var json = JsonNode.Parse(await new SingBoxConfigGenerator(new Secrets()).GenerateAsync(config, default))!;
        Assert.Equal("tcp", (string?)json["outbounds"]![1]!["network"]);
        Assert.Contains(json["route"]!["rules"]!.AsArray(), r =>
            (string?)r?["network"] == "udp" && (string?)r["action"] == "reject");
    }
    [EngineFact] public async Task OfficialEngineAcceptsGeneratedConfigurationWhenInstalled()
    {
        string? path = Environment.GetEnvironmentVariable("PATHFLUX_TEST_ENGINE");
        Assert.False(string.IsNullOrEmpty(path));
        var version = await EngineBinary.VerifyAsync(path!, EngineTestBinary.ExpectedHash, default);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        foreach (var protocol in Enum.GetValues<ProxyProtocol>())
        {
            var config = Config(ProxyRule(), new RoutingRule { Action = RouteAction.Block, Selector = new(SelectorKind.ExecutablePath, @"C:\Apps\Test.exe"), Priority = 1 })
                with { Profiles = [profile with { Protocol = protocol, CredentialsRef = "test" }], Settings = new() { EnginePath = path! } };
            string json = await new SingBoxConfigGenerator(new Secrets()).GenerateAsync(config, timeout.Token, engineVersion: version);
            Assert.True(await EngineBinary.CheckAsync(path!, json, timeout.Token), $"Official check rejected {protocol}");
        }
    }
    private sealed class MissingSecrets : ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult<ProxyCredentials?>(null);
        public Task<string> StoreAsync(ProxyCredentials credentials, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }
    private sealed class Secrets : ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult<ProxyCredentials?>(new("user", "sensitive-password"));
        public Task<string> StoreAsync(ProxyCredentials credentials, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }
}
public sealed class EngineFactAttribute : FactAttribute
{
    public EngineFactAttribute()
    { if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("PATHFLUX_TEST_ENGINE"))) Skip = "Set PATHFLUX_TEST_ENGINE to an official Windows binary >= 1.12.2 and PATHFLUX_TEST_ENGINE_SHA256 for engine validation/loopback tests (no TUN)."; }
}
