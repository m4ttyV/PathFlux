using System.Text.Json.Nodes;
using PathFlux.Domain;
using PathFlux.NetworkLab;
using Xunit;
namespace PathFlux.Engine.Tests;

public sealed class NetworkAuditTests
{
    [Theory]
    [InlineData("localhost", "127.0.0.1")]
    [InlineData("LOCALHOST", "127.0.0.1")]
    [InlineData("localhost.", "127.0.0.1")]
    [InlineData("::1", "::1")]
    [InlineData("proxy.example", "proxy.example")]
    public async Task LocalDockerUpstreamDoesNotDependOnTunDnsAndKeepsTlsHostname(string host, string expected)
    {
        var profile = new ProxyProfile { Host = host, Protocol = ProxyProtocol.HttpsConnect };
        var root = JsonNode.Parse(await new SingBoxConfigGenerator(new Secrets()).GenerateAsync(new() { Profiles = [profile], Rules = [new() { ProfileId = profile.Id }] }, default))!;
        Assert.Equal(expected, (string?)root["outbounds"]![1]!["server"]);
        Assert.Equal(host, (string?)root["outbounds"]![1]!["tls"]!["server_name"]);
        Assert.False((bool)root["outbounds"]![1]!["tls"]!["insecure"]!);
    }
    [Fact]
    public async Task ProductionRoutesCannotLoseToOpenVpnSplitDefaultsByPrefixLength()
    {
        var root = JsonNode.Parse(await new SingBoxConfigGenerator(new Secrets()).GenerateAsync(new(), default))!;
        Assert.Equal(new[] { "0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1" },
            root["inbounds"]![0]!["route_address"]!.AsArray().Select(n => (string?)n));
        Assert.True((bool)root["route"]!["auto_detect_interface"]!);
    }
    [Theory]
    [InlineData(12, "gvisor", "172.30.254.1/32", false)]
    [InlineData(13, "gvisor", "172.30.254.1/32", false)]
    [InlineData(14, "mixed", "172.30.254.1/30", true)]
    [InlineData(15, null, "172.30.254.1/30", true)]
    public async Task LabAvoidsSystemStack32AndNewDnsPanic(int minor, string? stack, string address, bool disableDns)
    {
        var json = JsonNode.Parse(await LabPolicy.GenerateAsync(new(), default, new Version(1, minor, 2)))!;
        var inbound = json["inbounds"]![0]!;
        Assert.Equal(stack, (string?)inbound["stack"]);
        Assert.Equal(address, (string?)inbound["address"]![0]);
        Assert.Equal(disableDns ? "disabled" : null, (string?)inbound["dns_mode"]);
        Assert.Equal(LabPolicy.TargetAddress + "/32", (string?)inbound["route_address"]![0]);
    }

    [Fact]
    public void SplitVpnDefaultsAndDetachedPhantomsArePreservedWithoutBlockingNarrowLab()
    {
        var before = new NetworkSnapshot([new("0.0.0.0/1", "10.8.0.1", 31, 1), new("128.0.0.0/1", "10.8.0.1", 31, 1)],
            [new("old", "PathFlux-TUN", [], [], true)]);
        Assert.True(before.CanStartLab());
        Assert.Empty(before.CompareRecovery(before));
        Assert.Contains("RoutesChanged", before.CompareRecovery(before with { Routes = [before.Routes[0]] }));
        Assert.False((before with { Adapters = [new("active", "PathFlux-TUN", [], [], false)] }).CanStartLab());
    }

    [Fact]
    public void ReadinessRequiresRouteOnOwnInterfaceAndExistingRoutesUnchanged()
    {
        var before = new NetworkSnapshot([new("0.0.0.0/0", "192.0.2.1", 1, 1)], [new("lan", "LAN", ["192.0.2.53"], ["192.0.2.2/24"])]);
        var during = new NetworkSnapshot([.. before.Routes, new("198.18.0.1/32", "0.0.0.0", 8, 0)],
            [.. before.Adapters, new("tun", LabPolicy.InterfaceName, [], ["172.30.254.1/30"], false, 8)]);
        Assert.Empty(before.CompareDuring(during, LabPolicy.TargetAddress));
        Assert.Contains("OwnTargetRouteMissing", before.CompareDuring(during with { Routes = [.. before.Routes, new("198.18.0.1/32", "0.0.0.0", 9, 0)] }, LabPolicy.TargetAddress));
        Assert.Contains("ExistingRoutesChangedDuringLab", before.CompareDuring(during with { Routes = [during.Routes[1]] }, LabPolicy.TargetAddress));
    }

    [Theory]
    [InlineData(ProxyProtocol.Socks5, "route")]
    [InlineData(ProxyProtocol.HttpConnect, "reject")]
    [InlineData(ProxyProtocol.HttpsConnect, "reject")]
    public async Task ExperimentalUdpDoesNotMutateProductionPolicyOrBypassHigherPriorityBlock(ProxyProtocol protocol, string experimentalAction)
    {
        var profile = new ProxyProfile { Protocol = protocol };
        var config = new ProxyConfiguration { Profiles = [profile], Rules = [new() { ProfileId = profile.Id }, new() { Priority = 1, Action = RouteAction.Block }] };
        var generator = new SingBoxConfigGenerator(new Secrets());
        string before = await generator.GenerateAsync(config, default);
        var experimental = JsonNode.Parse(await generator.GenerateExperimentalUdpAsync(config, default))!;
        string after = await generator.GenerateAsync(config, default);
        Assert.Equal(before, after);
        var rules = experimental["route"]!["rules"]!.AsArray();
        Assert.Equal("reject", (string?)rules[3]!["action"]);
        Assert.Equal(experimentalAction, (string?)rules[5]!["action"]);
        Assert.Equal("reject", (string?)JsonNode.Parse(after)!["route"]!["rules"]![5]!["action"]);
        if (protocol == ProxyProtocol.Socks5)
        { Assert.Null(experimental["outbounds"]![1]!["network"]); Assert.Equal("tcp", (string?)JsonNode.Parse(after)!["outbounds"]![1]!["network"]); }
    }

    [Fact]
    public async Task RawUdpProbeVerifiesIndependentEcho()
    {
        await using var echo = new PathFlux.Testing.UdpEchoServer();
        var probe = await UdpProbe.RunAsync(echo.EndPoint.Address.ToString(), echo.EndPoint.Port, System.Security.Cryptography.RandomNumberGenerator.GetBytes(64), default);
        Assert.True(probe.Success); Assert.Equal(1, echo.ReceivedPackets);
    }

    private sealed class Secrets : PathFlux.Application.ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult<ProxyCredentials?>(null);
        public Task<string> StoreAsync(ProxyCredentials credentials, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }
}
