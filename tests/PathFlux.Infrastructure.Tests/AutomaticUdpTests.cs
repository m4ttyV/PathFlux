using System.Net;
using System.Text;
using System.Text.Json;
using PathFlux.Domain;
using PathFlux.Infrastructure;

namespace PathFlux.Infrastructure.Tests;

public sealed class AutomaticUdpTests
{
    [Theory]
    [InlineData("null")] [InlineData("{bad")]
    [InlineData("[{\"NetworkSettings\":null}]")] [InlineData("[]")]
    public void MissingOrMalformedDockerMetadataDoesNotAuthorizeAPort(string json)
    {
        Assert.Null(AutomaticUdpRelay.FindPublishedPort(Encoding.UTF8.GetBytes(json), 1080, IPAddress.Parse("172.22.0.2"), 20018));
    }
    [Theory]
    [InlineData(20018, 20018)] [InlineData(20018, 31018)] [InlineData(50321, 19001)]
    public void DockerDiscoveryMatchesTcpEndpointContainerAndUdpMapping(int innerPort, int hostPort)
    {
        var json = Container("172.29.7.9", 1080, innerPort, hostPort);
        Assert.Equal(hostPort, AutomaticUdpRelay.FindPublishedPort(json, 1080, IPAddress.Parse("172.29.7.9"), innerPort));
        Assert.Null(AutomaticUdpRelay.FindPublishedPort(json, 1081, IPAddress.Parse("172.29.7.9"), innerPort));
        Assert.Null(AutomaticUdpRelay.FindPublishedPort(json, 1080, IPAddress.Parse("172.29.7.8"), innerPort));
        Assert.Null(AutomaticUdpRelay.FindPublishedPort(json, 1080, IPAddress.Parse("172.29.7.9"), innerPort + 1));
    }

    [Fact]
    public void AmbiguousMappingIsRejectedRatherThanChoosingFirstContainer()
    {
        var one = Encoding.UTF8.GetString(Container("172.22.0.2", 1080, 20018, 20018));
        var json = Encoding.UTF8.GetBytes("[" + one[1..^1] + "," + one[1..^1] + "]");
        Assert.Null(AutomaticUdpRelay.FindPublishedPort(json, 1080, IPAddress.Parse("172.22.0.2"), 20018));
    }

    [Theory]
    [InlineData("192.168.1.3")] [InlineData("::")]
    public void MappingNotPublishedOnIpv4LoopbackIsRejected(string binding)
    {
        Assert.Null(AutomaticUdpRelay.FindPublishedPort(Container("172.22.0.2", 1080, 20018, 20018, binding), 1080, IPAddress.Parse("172.22.0.2"), 20018));
    }

    [Fact]
    public async Task RemoteServerUsesItsAdvertisedRelayWithoutDockerDependency()
    {
        var relay = new IPEndPoint(IPAddress.Parse("192.168.1.4"), 40001);
        var actual = await AutomaticUdpRelay.ResolveAsync(new(), new(IPAddress.Parse("192.168.1.3"), 1080), relay, default);
        Assert.Equal(relay, actual);
    }

    [Fact]
    public async Task MulticastAndZeroPortNeverResolve()
    {
        await Assert.ThrowsAsync<IOException>(() => AutomaticUdpRelay.ResolveAsync(new(), new(IPAddress.Loopback, 1080), new(IPAddress.Parse("224.0.0.1"), 1234), default));
        await Assert.ThrowsAsync<IOException>(() => AutomaticUdpRelay.ResolveAsync(new(), new(IPAddress.Loopback, 1080), new(IPAddress.Loopback, 0), default));
    }

    private static byte[] Container(string address, int tcp, int inner, int host, string binding = "127.0.0.1") => JsonSerializer.SerializeToUtf8Bytes(new[]
    {
        new { NetworkSettings = new { Networks = new Dictionary<string, object> { ["arbitrary-network"] = new { IPAddress = address } } }, Ports = new[]
        {
            new { IP = binding, PrivatePort = 1080, PublicPort = tcp, Type = "tcp" },
            new { IP = binding, PrivatePort = inner, PublicPort = host, Type = "udp" }
        }}
    });
}
