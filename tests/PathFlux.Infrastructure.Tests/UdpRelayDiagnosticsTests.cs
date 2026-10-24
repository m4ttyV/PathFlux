using System.Net;
using System.Net.Sockets;
using PathFlux.Application;
using PathFlux.Domain;
using PathFlux.Infrastructure;
using PathFlux.Testing;

namespace PathFlux.Infrastructure.Tests;

public sealed class UdpRelayDiagnosticsTests
{
    [Theory]
    [InlineData(3)]
    [InlineData(8)]
    public async Task VerifiesRealIndependentEchoRoundtripsAndAdvertisesBoundUdpEndpoint(int count)
    {
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo);
        var started = DateTimeOffset.UtcNow;
        var result = await Diagnostics().TestUdpRelayAsync(relay.Profile, Options(echo, count), CancellationToken.None);
        Assert.True(result.Success, result.Message);
        Assert.Equal(UdpRelayStatus.Verified, result.Evidence.Status);
        Assert.Equal("udp-relay", result.Stage);
        Assert.Equal(count, result.Evidence.SentPackets);
        Assert.Equal(count, result.Evidence.ReceivedPackets);
        Assert.Equal(count, echo.ReceivedPackets);
        Assert.Equal(count, relay.ForwardedPackets);
        Assert.Equal(UdpVerificationPolicy.Fingerprint(relay.Profile), result.Evidence.ProfileFingerprint);
        Assert.InRange(result.Evidence.CheckedAtUtc, started, DateTimeOffset.UtcNow);
        Assert.True(result.Evidence.AverageRoundTripMs is >= 0 and < 5000);
        Assert.Equal(count, echo.Payloads.Select(Convert.ToHexString).Distinct().Count());
        Assert.All(echo.Payloads, p => Assert.Equal(64, p.Length));
        var advertised = Assert.Single(relay.ClientEndpoints);
        Assert.Equal(IPAddress.Loopback, advertised.Address);
        Assert.NotEqual(echo.EndPoint.Port, advertised.Port);
        Assert.InRange(advertised.Port, 1, 65535);
        Assert.Empty(relay.UnexpectedErrors);
    }

    [Theory]
    [InlineData(UdpRelayAddressMode.Wildcard)]
    [InlineData(UdpRelayAddressMode.Domain)]
    [InlineData(UdpRelayAddressMode.Literal)]
    public async Task ResolvesNegotiatedRelayAndSupportsFragmentedTcpReads(UdpRelayAddressMode mode)
    {
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo, new() { AddressMode = mode, FragmentTcpReplies = true });
        var result = await Diagnostics().TestUdpRelayAsync(relay.Profile, Options(echo), CancellationToken.None);
        Assert.True(result.Success, result.Message);
        Assert.Equal(3, relay.ForwardedPackets);
        Assert.Empty(relay.UnexpectedErrors);
    }

    [Theory]
    [InlineData(AddressFamily.InterNetworkV6, AddressFamily.InterNetworkV6)]
    [InlineData(AddressFamily.InterNetwork, AddressFamily.InterNetworkV6)]
    public async Task SupportsIpv6EchoTargetAndBothRelayAddressFamilies(AddressFamily relayFamily, AddressFamily targetFamily)
    {
        await using var echo = new UdpEchoServer(targetFamily);
        await using var relay = new Socks5UdpRelay(echo, relayFamily: relayFamily);
        var result = await Diagnostics().TestUdpRelayAsync(relay.Profile, Options(echo), CancellationToken.None);
        Assert.True(result.Success, result.Message);
        Assert.Equal("::1", result.Evidence.TargetHost);
        Assert.Equal(3, echo.ReceivedPackets);
        Assert.Empty(relay.UnexpectedErrors);
    }

    [Theory]
    [InlineData(UdpRelayFault.WrongPayload)]
    [InlineData(UdpRelayFault.WrongPayloadLength)]
    [InlineData(UdpRelayFault.WrongTargetAddress)]
    [InlineData(UdpRelayFault.WrongTargetPort)]
    [InlineData(UdpRelayFault.NonzeroReserved)]
    [InlineData(UdpRelayFault.Fragmented)]
    [InlineData(UdpRelayFault.Truncated)]
    [InlineData(UdpRelayFault.DomainTarget)]
    [InlineData(UdpRelayFault.WrongAddressType)]
    [InlineData(UdpRelayFault.WrongOuterSource)]
    public async Task RejectsMalformedUnrelatedOrIncorrectEchoReplies(UdpRelayFault fault)
    {
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo, new() { Fault = fault });
        var result = await Diagnostics(milliseconds: 350).TestUdpRelayAsync(relay.Profile, Options(echo), CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal(UdpRelayStatus.Failed, result.Evidence.Status);
        Assert.Equal(3, result.Evidence.SentPackets);
        Assert.Equal(0, result.Evidence.ReceivedPackets);
        Assert.Equal(3, echo.ReceivedPackets);
        Assert.Empty(relay.UnexpectedErrors);
    }

    [Fact]
    public async Task IgnoresStaleNonceDuplicateAndMalformedPacketsBeforeValidEcho()
    {
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo, new() { Fault = UdpRelayFault.StaleThenValid });
        var result = await Diagnostics().TestUdpRelayAsync(relay.Profile, Options(echo), CancellationToken.None);
        Assert.True(result.Success, result.Message);
        Assert.Equal(3, result.Evidence.ReceivedPackets);
        Assert.Equal(3, echo.ReceivedPackets);
    }

    [Theory]
    [InlineData(UdpRelayFault.CloseControlBeforeRelay)]
    [InlineData(UdpRelayFault.CloseControlBeforeLastReply)]
    public async Task TcpControlClosureInvalidatesAssociation(UdpRelayFault fault)
    {
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo, new() { Fault = fault });
        var result = await Diagnostics().TestUdpRelayAsync(relay.Profile, Options(echo), CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal(UdpRelayStatus.Failed, result.Evidence.Status);
        Assert.True(result.Evidence.ReceivedPackets < 3);
    }

    [Theory]
    [InlineData((byte)7, UdpRelayStatus.Unsupported)]
    [InlineData((byte)5, UdpRelayStatus.Failed)]
    public async Task DistinguishesUnsupportedAssociateFromOtherFailures(byte replyCode, UdpRelayStatus expected)
    {
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo, new() { ReplyCode = replyCode });
        var result = await Diagnostics().TestUdpRelayAsync(relay.Profile, Options(echo), CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal(expected, result.Evidence.Status);
        Assert.Equal("udp-associate", result.Stage);
        Assert.Equal(0, result.Evidence.SentPackets);
        Assert.Equal(0, echo.ReceivedPackets);
    }

    [Fact]
    public async Task RejectsZeroRelayPort()
    {
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo, new() { ZeroRelayPort = true });
        var result = await Diagnostics().TestUdpRelayAsync(relay.Profile, Options(echo), CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal("udp-associate", result.Stage);
        Assert.Equal(0, result.Evidence.SentPackets);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task UsesProtectedAuthenticationAndSanitizesRejection(bool validPassword)
    {
        var credentials = new ProxyCredentials("private-lab-user", "private-lab-password");
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo, new() { Credentials = credentials });
        var supplied = validPassword ? credentials : credentials with { Password = "private-wrong-password" };
        var result = await Diagnostics(supplied).TestUdpRelayAsync(relay.Profile, Options(echo), CancellationToken.None);
        Assert.Equal(validPassword, result.Success);
        Assert.Equal(validPassword ? UdpRelayStatus.Verified : UdpRelayStatus.Failed, result.Evidence.Status);
        Assert.DoesNotContain("private-lab", result.Message);
        Assert.DoesNotContain("private-wrong", result.Message);
        if (!validPassword) Assert.Equal("authentication", result.Stage);
    }

    [Theory]
    [InlineData("localhost")]
    [InlineData("example.invalid")]
    [InlineData("0.0.0.0")]
    [InlineData("0.12.34.56")]
    [InlineData("255.255.255.255")]
    [InlineData("224.0.0.1")]
    [InlineData("ff02::1")]
    [InlineData("fe80::1%3")]
    [InlineData("::")]
    public async Task RejectsUnsupportedTargetsBeforeAnyNetworkOperation(string target)
    {
        var result = await Diagnostics().TestUdpRelayAsync(new(), new(target, 7), CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal("validation", result.Stage);
        Assert.Equal(UdpRelayStatus.Failed, result.Evidence.Status);
        Assert.Equal(0, result.Evidence.SentPackets);
    }

    [Theory]
    [InlineData(7, 2)]
    [InlineData(7, 9)]
    [InlineData(0, 3)]
    [InlineData(65536, 3)]
    public async Task RejectsInvalidPortOrPacketCount(int port, int count)
    {
        var result = await Diagnostics().TestUdpRelayAsync(new(), new("127.0.0.1", port, count), CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal("validation", result.Stage);
        Assert.Equal(0, result.Evidence.SentPackets);
    }

    [Theory]
    [InlineData(ProxyProtocol.HttpConnect)]
    [InlineData(ProxyProtocol.HttpsConnect)]
    public async Task HttpProfilesExplicitlyDoNotSupportUdpRelay(ProxyProtocol protocol)
    {
        var result = await Diagnostics().TestUdpRelayAsync(new() { Protocol = protocol }, new("127.0.0.1", 7), CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal(UdpRelayStatus.Unsupported, result.Evidence.Status);
    }

    [Fact]
    public async Task MissingEchoExpiresWithActualCountersAndNoDirectFallback()
    {
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo, new() { Fault = UdpRelayFault.DropResponses });
        var result = await Diagnostics(milliseconds: 350).TestUdpRelayAsync(relay.Profile, Options(echo), CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal("udp-relay", result.Stage);
        Assert.Equal(UdpRelayStatus.Failed, result.Evidence.Status);
        Assert.Equal(3, result.Evidence.SentPackets);
        Assert.Equal(0, result.Evidence.ReceivedPackets);
        Assert.Null(result.Evidence.AverageRoundTripMs);
        Assert.Equal(3, echo.ReceivedPackets);
        Assert.Equal(3, relay.ForwardedPackets);
    }

    [Fact]
    public async Task CallerCancellationPropagatesWhileWaitingForEcho()
    {
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo, new() { Fault = UdpRelayFault.DropResponses });
        using var cancellation = new CancellationTokenSource();
        var running = Diagnostics().TestUdpRelayAsync(relay.Profile, Options(echo), cancellation.Token);
        for (var retry = 0; retry < 100 && relay.ForwardedPackets < 3; retry++) await Task.Delay(10);
        Assert.Equal(3, relay.ForwardedPackets);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running);
    }

    [Fact]
    public async Task ReadinessConnectionsDoNotBreakSubsequentRealAssociation()
    {
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo);
        using (var readiness = new TcpClient()) await readiness.ConnectAsync(relay.Profile.Host, relay.Port);
        var result = await Diagnostics().TestUdpRelayAsync(relay.Profile, Options(echo), CancellationToken.None);
        Assert.True(result.Success, result.Message);
        Assert.Empty(relay.UnexpectedErrors);
    }

    private static UdpProbeOptions Options(UdpEchoServer echo, int count = 3) => new(echo.EndPoint.Address.ToString(), echo.EndPoint.Port, count);
    private static ProxyDiagnostics Diagnostics(ProxyCredentials? credentials = null, int milliseconds = 3000) =>
        new(new MemorySecrets(credentials), TimeSpan.FromMilliseconds(milliseconds));
    private sealed class MemorySecrets(ProxyCredentials? credentials) : ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult(credentials);
        public Task<string> StoreAsync(ProxyCredentials value, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }
}
