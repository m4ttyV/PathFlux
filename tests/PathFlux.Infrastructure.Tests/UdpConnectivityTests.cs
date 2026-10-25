using System.Net;
using PathFlux.Domain;
using PathFlux.Infrastructure;
using PathFlux.Testing;

namespace PathFlux.Infrastructure.Tests;

public sealed class UdpConnectivityTests
{
    [Theory]
    [InlineData(UdpRelayFault.None, true)] [InlineData(UdpRelayFault.Fragmented, false)]
    [InlineData(UdpRelayFault.DropResponses, false)] [InlineData(UdpRelayFault.WrongTargetPort, false)]
    [InlineData(UdpRelayFault.CloseControlBeforeRelay, false)]
    public async Task OneClickUdpChecksActualDnsPayloadWithoutDirectRetry(UdpRelayFault fault, bool success)
    {
        await using var dns = new UdpEchoServer(transform: packet => { packet[2] = 0x81; packet[3] = 0x83; return packet; });
        await using var relay = new Socks5UdpRelay(dns, new() { TargetOverride = new(IPAddress.Parse("1.1.1.1"), 53), Fault = fault });
        var profile = relay.Profile with { UdpRelayMode = UdpRelayMode.Auto };
        var result = await new ProxyDiagnostics(new NoSecrets(), TimeSpan.FromMilliseconds(600)).TestUdpConnectivityAsync(profile, default);
        Assert.Equal(success, result.Success);
        Assert.InRange(dns.ReceivedPackets, 0, 1);
    }
    [Fact]
    public async Task AssociationSuccessAndEchoedQuestionCannotMasqueradeAsADnsReply()
    {
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo, new() { TargetOverride = new(IPAddress.Parse("1.1.1.1"), 53) });
        var result = await new ProxyDiagnostics(new NoSecrets(), TimeSpan.FromMilliseconds(500)).TestUdpConnectivityAsync(relay.Profile, default);
        Assert.False(result.Success); Assert.Equal(1, echo.ReceivedPackets);
    }
    [Fact]
    public async Task UnsupportedAssociationIsClearlyReported()
    {
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo, new() { ReplyCode = 7 });
        var result = await new ProxyDiagnostics(new NoSecrets(), TimeSpan.FromSeconds(1)).TestUdpConnectivityAsync(relay.Profile, default);
        Assert.False(result.Success); Assert.Equal(SupportStatus.Unsupported, result.Udp);
        Assert.Equal(0, echo.ReceivedPackets);
    }
    private sealed class NoSecrets : PathFlux.Application.ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult<ProxyCredentials?>(null);
        public Task<string> StoreAsync(ProxyCredentials credentials, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }
}
