using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using PathFlux.Application;
using PathFlux.Domain;
using PathFlux.Infrastructure;
using PathFlux.Testing;
using Xunit;

namespace PathFlux.Engine.Tests;

public class AgentUdpLifecycleTests
{
    [Fact]
    public async Task ValidationDescribesUdpWithoutStartingAnyTransport()
    {
        var config = Configuration(new(), NetworkTransport.Both);
        var root = JsonNode.Parse(await new SingBoxConfigGenerator(new Secrets(null)).GenerateValidationAsync(config, default))!;
        Assert.Equal("tcp", (string?)root["outbounds"]![1]!["network"]);
        Assert.Equal("udp", (string?)root["outbounds"]![2]!["network"]);
        Assert.Equal(9, (int)root["outbounds"]![2]!["server_port"]!);
        Assert.Equal("validation-only", (string?)root["outbounds"]![2]!["password"]);
    }
    [Theory]
    [InlineData(NetworkTransport.Tcp, 0)] [InlineData(NetworkTransport.Udp, 1)] [InlineData(NetworkTransport.Both, 1)]
    public async Task AgentOwnsOneGuardPerUsedProfileAndDisposesItsSockets(NetworkTransport transport, int expected)
    {
        await using var echo = new UdpEchoServer(); await using var relay = new Socks5UdpRelay(echo);
        var config = Configuration(relay.Profile, transport);
        var owner = await AgentUdpBridges.CreateAsync(config, new Secrets(null), default);
        try
        {
            Assert.Equal(expected, owner.Bridges.Count);
            var root = JsonNode.Parse(await new SingBoxConfigGenerator(new Secrets(null)).GenerateAgentAsync(config, owner.Bridges, default))!;
            Assert.Equal("tcp", (string?)root["outbounds"]![1]!["network"]);
            if (expected == 0) { Assert.DoesNotContain("udp-guard", root.ToJsonString()); return; }
            var bridge = Assert.Single(owner.Bridges).Value; var endpoint = bridge.EndPoint;
            var result = await EchoAsync(bridge, echo);
            Assert.True(result.Success, result.Message);
            Assert.Equal(3, Assert.Single(owner.Snapshot()).SentPackets);
            await owner.DisposeAsync();
            Assert.Empty(owner.Bridges); Assert.Equal(0, bridge.Snapshot(relay.Profile.Id).ActiveAssociations);
            using var tcp = new TcpClient(); await Assert.ThrowsAsync<SocketException>(() => tcp.ConnectAsync(endpoint.Address, endpoint.Port));
        }
        finally { await owner.DisposeAsync(); }
    }

    [Fact]
    public async Task DifferentProfilesRemainIndependentAndBridgeFaultDoesNotSendDirectly()
    {
        await using var echo = new UdpEchoServer(); await using var a = new Socks5UdpRelay(echo); await using var b = new Socks5UdpRelay(echo);
        var config = Configuration(a.Profile, NetworkTransport.Both);
        config = config with { Profiles = [a.Profile, b.Profile], Rules = [config.Rules[0], config.Rules[0] with { Id = Guid.NewGuid(), ProfileId = b.Profile.Id }] };
        await using var owner = await AgentUdpBridges.CreateAsync(config, new Secrets(null), default);
        Assert.Equal(2, owner.Bridges.Count); var first = owner.Bridges[a.Profile.Id]; var second = owner.Bridges[b.Profile.Id];
        Assert.True((await EchoAsync(first, echo)).Success); first.FailClosed();
        Assert.True(first.HasFailed); Assert.True((await EchoAsync(second, echo)).Success);
        Assert.Equal(3, first.SentPackets); Assert.Equal(3, second.SentPackets); Assert.Equal(6, echo.ReceivedPackets);
        Assert.Equal("Failed", owner.Snapshot().Single(s => s.ProfileId == a.Profile.Id).State);
    }

    [Fact]
    public async Task FeatureFlagIsExplicitAndNeverChangesTcpOutbound()
    {
        var profile = new ProxyProfile();
        var config = Configuration(profile, NetworkTransport.Both) with { Settings = new() };
        await using var off = await AgentUdpBridges.CreateAsync(config, new Secrets(null), default);
        Assert.Empty(off.Bridges);
        var generator = new SingBoxConfigGenerator(new Secrets(null));
        var before = JsonNode.Parse(await generator.GenerateAgentAsync(config, off.Bridges, default))!;
        config = config with { Settings = new() { ExperimentalSocksUdp = true } };
        await using var on = await AgentUdpBridges.CreateAsync(config, new Secrets(null), default);
        var after = JsonNode.Parse(await generator.GenerateAgentAsync(config, on.Bridges, default))!;
        Assert.Equal(before["outbounds"]![1]!.ToJsonString(), after["outbounds"]![1]!.ToJsonString());
        Assert.Equal("reject", (string?)before["route"]!["rules"]![3]!["action"]);
        Assert.Equal("route", (string?)after["route"]!["rules"]![3]!["action"]);
    }

    [Fact]
    public async Task CancellationBeforeStartupDoesNotLeaveAListener()
    {
        using var stop = new CancellationTokenSource(); stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => AgentUdpBridges.CreateAsync(Configuration(new(), NetworkTransport.Udp), new Secrets(null), stop.Token));
    }
    private static ProxyConfiguration Configuration(ProxyProfile p, NetworkTransport transport) => new()
    { Profiles = [p], Rules = [new() { ProfileId = p.Id, Network = transport }, new() { ProfileId = p.Id, Network = transport }], Settings = new() { ExperimentalSocksUdp = true } };
    private static Task<UdpRelayProbeResult> EchoAsync(StrictSocksUdpBridge bridge, UdpEchoServer echo) =>
        new ProxyDiagnostics(new Secrets(bridge.LocalCredentials), TimeSpan.FromSeconds(2)).TestUdpRelayAsync(
            new() { Host = "127.0.0.1", Port = bridge.EndPoint.Port, CredentialsRef = "test" }, new(echo.EndPoint.Address.ToString(), echo.EndPoint.Port), default);
    private sealed class Secrets(ProxyCredentials? credentials) : ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult(credentials);
        public Task<string> StoreAsync(ProxyCredentials value, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }
}
