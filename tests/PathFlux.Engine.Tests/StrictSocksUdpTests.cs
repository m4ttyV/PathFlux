using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using PathFlux.Domain;
using PathFlux.Infrastructure;
using PathFlux.Testing;
using Xunit;

namespace PathFlux.Engine.Tests;

public class StrictSocksUdpTests
{
    [Fact]
    public async Task AutomaticModeCarriesRealDatagramsWithoutManualPorts()
    {
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo);
        await using var bridge = new StrictSocksUdpBridge(new(IPAddress.Loopback, relay.Port), new(AutomaticProfile: relay.Profile with { UdpRelayMode = UdpRelayMode.Auto }));
        await using var client = await Client.OpenAsync(bridge);
        var packet = StrictSocksUdpBridge.Encode(echo.EndPoint, RandomNumberGenerator.GetBytes(64));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await client.Udp.SendAsync(packet, deadline.Token);
        Assert.Equal(packet, (await client.Udp.ReceiveAsync(deadline.Token)).Buffer);
        Assert.Equal(1, echo.ReceivedPackets);
    }
    [Fact]
    public void EveryNonzeroFragmentValueIsRejectedForBothIpFamilies()
    {
        foreach (var address in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
        for (int frag = 1; frag <= 255; frag++)
        {
            var packet = StrictSocksUdpBridge.Encode(new(address, 53), new byte[12]); packet[2] = (byte)frag;
            Assert.False(StrictSocksUdpBridge.TryDecode(packet, out _, out _));
        }
    }

    [Theory]
    [InlineData("172.22.0.2")] [InlineData("172.31.99.13")]
    public async Task DockerMappingWorksAcrossRealSocketsWithDifferentContainerAddressesAndDynamicPorts(string container)
    {
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo, new() { AdvertisedAddress = IPAddress.Parse(container) });
        await using var bridge = new StrictSocksUdpBridge(new(IPAddress.Loopback, relay.Port), new(1024, 65535));
        await using var client = await Client.OpenAsync(bridge);
        var packet = StrictSocksUdpBridge.Encode(echo.EndPoint, RandomNumberGenerator.GetBytes(64));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await client.Udp.SendAsync(packet, deadline.Token); Assert.Equal(packet, (await client.Udp.ReceiveAsync(deadline.Token)).Buffer);
        Assert.Equal(IPAddress.Parse(container), bridge.LastAdvertisedRelay!.Address);
        Assert.Equal(IPAddress.Loopback, bridge.LastEffectiveRelay!.Address);
        Assert.Equal(bridge.LastAdvertisedRelay.Port, bridge.LastEffectiveRelay.Port);
        Assert.Equal(1, echo.ReceivedPackets);
    }

    [Fact]
    public async Task UnauthenticatedLocalClientsCannotCreateUpstreamAssociations()
    {
        await using var echo = new UdpEchoServer(); await using var relay = new Socks5UdpRelay(echo);
        await using var bridge = new StrictSocksUdpBridge(new(IPAddress.Loopback, relay.Port));
        using var tcp = new TcpClient(); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await tcp.ConnectAsync(bridge.EndPoint, deadline.Token); var stream = tcp.GetStream();
        await stream.WriteAsync(new byte[] { 5, 1, 0 }, deadline.Token); var reply = new byte[2]; await stream.ReadExactlyAsync(reply, deadline.Token);
        Assert.Equal(new byte[] { 5, 255 }, reply); Assert.Equal(0, relay.AssociateRequests); Assert.Equal(0, echo.ReceivedPackets);
    }
    [Theory]
    [InlineData(0, true)] [InlineData(1, false)] [InlineData(2, false)] [InlineData(127, false)]
    [InlineData(128, false)] [InlineData(129, false)] [InlineData(255, false)]
    public void FragmentPolicyNeverTreatsAFragmentAsAStandaloneDatagram(byte frag, bool accepted)
    {
        var packet = StrictSocksUdpBridge.Encode(new(IPAddress.Loopback, 53), new byte[12]); packet[2] = frag;
        Assert.Equal(accepted, StrictSocksUdpBridge.TryDecode(packet, out _, out _));
    }
    [Theory]
    [InlineData("172.22.0.2", 20018)] [InlineData("172.31.99.13", 20000)] [InlineData("0.0.0.0", 20030)]
    public void ExplicitDockerMappingUsesTcpPeerAndDynamicAdvertisedPort(string address, int port)
    {
        var endpoint = new UdpRelayBinding(20000, 20030).Resolve(new(IPAddress.Loopback, 1080), new(IPAddress.Parse(address), port));
        Assert.Equal(new(IPAddress.Loopback, port), endpoint);
    }
    [Theory]
    [InlineData(0)] [InlineData(19999)] [InlineData(20031)] [InlineData(65535)]
    public void DockerMappingRejectsUnpublishedPorts(int port) => Assert.Throws<IOException>(() =>
        new UdpRelayBinding(20000, 20030).Resolve(new(IPAddress.Loopback, 1080), new(IPAddress.Parse("172.22.0.2"), port)));

    [Fact]
    public void DockerMappingNeverRedirectsARemoteProxyOrSilentlyChangesNormalBinding()
    {
        Assert.Throws<IOException>(() => new UdpRelayBinding(20000, 20030).Resolve(new(IPAddress.Parse("192.0.2.1"), 1080), new(IPAddress.Loopback, 20001)));
        var advertised = new IPEndPoint(IPAddress.Parse("172.22.0.2"), 20018);
        Assert.Equal(advertised, new UdpRelayBinding().Resolve(new(IPAddress.Loopback, 1080), advertised));
    }

    [Theory]
    [InlineData(UdpRelayFault.None, true, false)] [InlineData(UdpRelayFault.Fragmented, false, false)]
    [InlineData(UdpRelayFault.NonzeroReserved, false, false)] [InlineData(UdpRelayFault.Truncated, false, false)]
    [InlineData(UdpRelayFault.WrongTargetPort, false, false)] [InlineData(UdpRelayFault.WrongTargetAddress, false, false)]
    [InlineData(UdpRelayFault.WrongOuterSource, false, false)] [InlineData(UdpRelayFault.DropResponses, false, false)]
    [InlineData(UdpRelayFault.None, true, true)] [InlineData(UdpRelayFault.Fragmented, false, true)]
    [InlineData(UdpRelayFault.DropResponses, false, true)] [InlineData(UdpRelayFault.WrongOuterSource, false, true)]
    public async Task BridgeValidatesRealRelayRepliesWithoutDirectFallback(UdpRelayFault fault, bool expected, bool automatic)
    {
        await using var echo = new UdpEchoServer(); await using var relay = new Socks5UdpRelay(echo, new() { Fault = fault });
        await using var bridge = new StrictSocksUdpBridge(new(IPAddress.Loopback, relay.Port), automatic ? new(AutomaticProfile: relay.Profile with { UdpRelayMode = UdpRelayMode.Auto }) : null);
        var result = await new ProxyDiagnostics(new LocalSecrets(bridge.LocalCredentials), TimeSpan.FromSeconds(1)).TestUdpRelayAsync(
            new() { Host = "127.0.0.1", Port = bridge.EndPoint.Port, CredentialsRef = "local" },
            new(echo.EndPoint.Address.ToString(), echo.EndPoint.Port), default);
        Assert.Equal(expected, result.Success); Assert.Equal(3, echo.ReceivedPackets);
        Assert.All(relay.ClientEndpoints, e => Assert.Equal(new(IPAddress.Any, 0), e));
        if (fault == UdpRelayFault.Fragmented) Assert.Equal(3, bridge.DroppedFragments);
        Assert.Empty(relay.UnexpectedErrors);
    }

    [Fact]
    public async Task SameDownstreamUdpSocketRecoversAfterUpstreamControlDisconnectWithoutReplayingPackets()
    {
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo, new() { Fault = UdpRelayFault.CloseControlBeforeLastReply, CloseAfterPackets = 1, FaultAssociations = 1 });
        await using var bridge = new StrictSocksUdpBridge(new(IPAddress.Loopback, relay.Port));
        await using var client = await Client.OpenAsync(bridge);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var first = StrictSocksUdpBridge.Encode(echo.EndPoint, RandomNumberGenerator.GetBytes(64));
        await client.Udp.SendAsync(first, deadline.Token);
        while (bridge.Reconnects == 0) await Task.Delay(20, deadline.Token);
        var second = StrictSocksUdpBridge.Encode(echo.EndPoint, RandomNumberGenerator.GetBytes(64));
        await client.Udp.SendAsync(second, deadline.Token);
        // A late reply to the old epoch must not be delivered as a reply in the new epoch.
        Assert.Equal(second, (await client.Udp.ReceiveAsync(deadline.Token)).Buffer);
        Assert.Equal(2, echo.ReceivedPackets); Assert.True(relay.AssociateRequests >= 2);
        Assert.Empty(relay.UnexpectedErrors);
    }

    [Fact]
    public async Task LostPacketsTimeOutWithoutReplayAndSubsequentDatagramsStillWork()
    {
        await using var echo = new UdpEchoServer(); await using var relay = new Socks5UdpRelay(echo, new() { DropEveryNthReply = 2 });
        await using var bridge = new StrictSocksUdpBridge(new(IPAddress.Loopback, relay.Port));
        await using var client = await Client.OpenAsync(bridge);
        for (int i = 1; i <= 5; i++)
        {
            var packet = StrictSocksUdpBridge.Encode(echo.EndPoint, RandomNumberGenerator.GetBytes(64));
            await client.Udp.SendAsync(packet);
            using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(400));
            if (i % 2 == 0) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.Udp.ReceiveAsync(deadline.Token).AsTask());
            else Assert.Equal(packet, (await client.Udp.ReceiveAsync(deadline.Token)).Buffer);
        }
        Assert.Equal(5, echo.ReceivedPackets); Assert.Equal(3, bridge.ReceivedPackets); Assert.Equal(1, relay.AssociateRequests);
    }

    [Fact]
    public async Task OutboundFragmentsAndMalformedRequestsNeverReachTheUpstream()
    {
        await using var echo = new UdpEchoServer(); await using var relay = new Socks5UdpRelay(echo);
        await using var bridge = new StrictSocksUdpBridge(new(IPAddress.Loopback, relay.Port));
        await using var client = await Client.OpenAsync(bridge);
        foreach (byte frag in new byte[] { 1, 128, 129, 255 })
        { var packet = StrictSocksUdpBridge.Encode(echo.EndPoint, new byte[64]); packet[2] = frag; await client.Udp.SendAsync(packet); }
        var good = StrictSocksUdpBridge.Encode(echo.EndPoint, RandomNumberGenerator.GetBytes(64)); await client.Udp.SendAsync(good);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        Assert.Equal(good, (await client.Udp.ReceiveAsync(deadline.Token)).Buffer);
        Assert.Equal(1, echo.ReceivedPackets); Assert.Equal(4, bridge.DroppedFragments);
    }

    private sealed class Client(TcpClient tcp, UdpClient udp) : IAsyncDisposable
    {
        public UdpClient Udp => udp;
        public static async Task<Client> OpenAsync(StrictSocksUdpBridge bridge)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3)); var ct = deadline.Token;
            var tcp = new TcpClient(); UdpClient? udp = null;
            try
            {
                await tcp.ConnectAsync(bridge.EndPoint, ct); var stream = tcp.GetStream();
                await stream.WriteAsync(new byte[] { 5, 1, 2 }, ct); var choice = new byte[2]; await stream.ReadExactlyAsync(choice, ct);
                Assert.Equal(new byte[] { 5, 2 }, choice);
                var user = Encoding.UTF8.GetBytes(bridge.LocalCredentials.Username); var pass = Encoding.UTF8.GetBytes(bridge.LocalCredentials.Password);
                await stream.WriteAsync(new byte[] { 1, (byte)user.Length }.Concat(user).Concat(new byte[] { (byte)pass.Length }).Concat(pass).ToArray(), ct);
                await stream.ReadExactlyAsync(choice, ct); Assert.Equal(new byte[] { 1, 0 }, choice);
                await stream.WriteAsync(new byte[] { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 }, ct);
                var response = new byte[10]; await stream.ReadExactlyAsync(response, ct); Assert.Equal(0, response[1]);
                udp = new UdpClient(); udp.Connect(new IPAddress(response.AsSpan(4, 4)), (response[8] << 8) | response[9]); return new(tcp, udp);
            }
            catch { tcp.Dispose(); udp?.Dispose(); throw; }
        }
        public ValueTask DisposeAsync() { Udp.Dispose(); tcp.Dispose(); return ValueTask.CompletedTask; }
    }
    private sealed class LocalSecrets(ProxyCredentials credentials) : PathFlux.Application.ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult<ProxyCredentials?>(credentials);
        public Task<string> StoreAsync(ProxyCredentials value, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }
}
