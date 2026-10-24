using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PathFlux.Application;
using PathFlux.Domain;
using PathFlux.Infrastructure;

namespace PathFlux.Infrastructure.Tests;

public sealed class ProxyDiagnosticsTests
{
    private static readonly byte[] AcceptedSocks = [5, 0, 0, 1, 127, 0, 0, 1, 31, 144];

    [Fact]
    public async Task SocksConnectSendsTargetToProxyAndHandlesSingleByteReads()
    {
        await using var proxy = new LoopbackProxy(async (stream, ct) =>
        {
            Assert.Equal(new byte[] { 5, 1, 0 }, await ReadAsync(stream, 3, ct));
            await FragmentAsync(stream, [5, 0], ct);
            var command = await ReadSocksCommandAsync(stream, ct);
            Assert.Equal((byte)1, command.Command);
            Assert.Equal("target.example.invalid", command.Host);
            Assert.Equal(443, command.Port);
            await FragmentAsync(stream, AcceptedSocks, ct);
        });
        var result = await Diagnostics().TestTcpAsync(proxy.Profile(), "target.example.invalid", 443, CancellationToken.None);
        Assert.True(result.Success, result.Message);
        Assert.Equal("connect", result.Stage);
        Assert.Equal(SupportStatus.NotVerified, result.Udp);
    }

    [Fact]
    public async Task SocksAuthenticationUsesStoredCredentials()
    {
        var credentials = new ProxyCredentials("tester", "private-password");
        await using var proxy = new LoopbackProxy(async (stream, ct) =>
        {
            Assert.Equal(new byte[] { 5, 1, 2 }, await ReadAsync(stream, 3, ct));
            await FragmentAsync(stream, [5, 2], ct);
            var auth = await ReadAsync(stream, 2, ct);
            Assert.Equal((byte)1, auth[0]);
            Assert.Equal(credentials.Username, Encoding.UTF8.GetString(await ReadAsync(stream, auth[1], ct)));
            var passwordLength = (await ReadAsync(stream, 1, ct))[0];
            Assert.Equal(credentials.Password, Encoding.UTF8.GetString(await ReadAsync(stream, passwordLength, ct)));
            await FragmentAsync(stream, [1, 0], ct);
            var command = await ReadSocksCommandAsync(stream, ct);
            Assert.Equal("192.0.2.1", command.Host);
            await FragmentAsync(stream, AcceptedSocks, ct);
        });
        var result = await Diagnostics(credentials).TestTcpAsync(proxy.Profile() with { CredentialsRef = "reference" }, "192.0.2.1", 80, CancellationToken.None);
        Assert.True(result.Success, result.Message);
        Assert.DoesNotContain(credentials.Password, result.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SocksAuthenticationFailureDoesNotExposePassword(bool udp)
    {
        await using var proxy = new LoopbackProxy(async (stream, ct) =>
        {
            await ReadAsync(stream, 3, ct);
            await stream.WriteAsync(new byte[] { 5, 2 }, ct);
            var auth = await ReadAsync(stream, 2, ct);
            await ReadAsync(stream, auth[1], ct);
            await ReadAsync(stream, (await ReadAsync(stream, 1, ct))[0], ct);
            await stream.WriteAsync(new byte[] { 1, 1 }, ct);
        });
        var diagnostics = Diagnostics(new("user", "private-password"));
        var profile = proxy.Profile() with { CredentialsRef = "reference" };
        var result = udp
            ? await diagnostics.TestUdpAssociateAsync(profile, CancellationToken.None)
            : await diagnostics.TestTcpAsync(profile, "example.invalid", 443, CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal("authentication", result.Stage);
        Assert.DoesNotContain("private-password", result.Message);
        Assert.Equal(udp ? SupportStatus.Failed : SupportStatus.NotVerified, result.Udp);
    }

    [Theory]
    [InlineData(4, 0)]
    [InlineData(5, 255)]
    [InlineData(5, 2)]
    public async Task SocksRejectsMalformedOrUnrequestedMethod(byte version, byte method)
    {
        await using var proxy = new LoopbackProxy(async (stream, ct) =>
        {
            await ReadAsync(stream, 3, ct);
            await stream.WriteAsync(new byte[] { version, method }, ct);
        });
        Assert.False((await Diagnostics().TestTcpAsync(proxy.Profile(), "example.invalid", 443, CancellationToken.None)).Success);
    }

    [Fact]
    public async Task SocksDoesNotSilentlyDowngradeCredentialAuthentication()
    {
        await using var proxy = new LoopbackProxy(async (stream, ct) =>
        {
            Assert.Equal(new byte[] { 5, 1, 2 }, await ReadAsync(stream, 3, ct));
            await stream.WriteAsync(new byte[] { 5, 0 }, ct);
        });
        var result = await Diagnostics(new("user", "password")).TestTcpAsync(proxy.Profile() with { CredentialsRef = "ref" }, "example.invalid", 443, CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal("authentication", result.Stage);
    }

    [Theory]
    [InlineData(5, 5, 0, 1)]
    [InlineData(4, 0, 0, 1)]
    [InlineData(5, 0, 1, 1)]
    [InlineData(5, 0, 0, 9)]
    public async Task SocksRejectsFailureAndMalformedConnectResponses(byte version, byte status, byte reserved, byte addressType)
    {
        await using var proxy = new LoopbackProxy(async (stream, ct) =>
        {
            await SocksNegotiateAsync(stream, ct);
            await ReadSocksCommandAsync(stream, ct);
            await stream.WriteAsync(new byte[] { version, status, reserved, addressType }, ct);
        });
        Assert.False((await Diagnostics().TestTcpAsync(proxy.Profile(), "example.invalid", 443, CancellationToken.None)).Success);
    }

    [Fact]
    public async Task SocksTruncatedReplyIsFailure()
    {
        await using var proxy = new LoopbackProxy(async (stream, ct) =>
        {
            await SocksNegotiateAsync(stream, ct);
            await ReadSocksCommandAsync(stream, ct);
            await stream.WriteAsync(new byte[] { 5, 0, 0, 4, 0 }, ct);
        });
        Assert.False((await Diagnostics().TestTcpAsync(proxy.Profile(), "2001:db8::1", 443, CancellationToken.None)).Success);
    }

    [Fact]
    public async Task UdpAssociateAcceptanceDoesNotClaimUdpRelaySupport()
    {
        await using var proxy = new LoopbackProxy(async (stream, ct) =>
        {
            await SocksNegotiateAsync(stream, ct);
            var command = await ReadSocksCommandAsync(stream, ct);
            Assert.Equal((byte)3, command.Command);
            Assert.Equal("0.0.0.0", command.Host);
            Assert.Equal(0, command.Port);
            await stream.WriteAsync(AcceptedSocks, ct);
        });
        var result = await Diagnostics().TestUdpAssociateAsync(proxy.Profile(), CancellationToken.None);
        Assert.True(result.Success);
        Assert.Equal(SupportStatus.NotVerified, result.Udp);
    }

    [Theory]
    [InlineData((byte)7, SupportStatus.Unsupported)]
    [InlineData((byte)5, SupportStatus.Failed)]
    public async Task UdpAssociateCommandRejectionReportsSupportStatus(byte replyCode, SupportStatus expectedStatus)
    {
        await using var proxy = new LoopbackProxy(async (stream, ct) =>
        {
            await SocksNegotiateAsync(stream, ct);
            await ReadSocksCommandAsync(stream, ct);
            await stream.WriteAsync(new byte[] { 5, replyCode, 0, 1 }, ct);
        });
        var result = await Diagnostics().TestUdpAssociateAsync(proxy.Profile(), CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal("udp-associate", result.Stage);
        Assert.Equal(expectedStatus, result.Udp);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ClosedProxyReportsFailureWithoutClaimingUdpUnsupported(bool udp)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        var profile = new ProxyProfile { Host = "127.0.0.1", Port = port };
        var result = udp
            ? await Diagnostics().TestUdpAssociateAsync(profile, CancellationToken.None)
            : await Diagnostics().TestTcpAsync(profile, "example.invalid", 443, CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal("tcp", result.Stage);
        Assert.Equal(udp ? SupportStatus.Failed : SupportStatus.NotVerified, result.Udp);
    }

    [Theory]
    [InlineData(ProxyProtocol.HttpConnect)]
    [InlineData(ProxyProtocol.HttpsConnect)]
    public async Task HttpUdpIsExplicitlyUnsupported(ProxyProtocol protocol)
    {
        var result = await Diagnostics().TestUdpAssociateAsync(new() { Protocol = protocol }, CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal(SupportStatus.Unsupported, result.Udp);
    }

    [Fact]
    public async Task HttpConnectSendsAuthorityAndBasicAuthenticationAndHandlesInterimResponse()
    {
        var credentials = new ProxyCredentials("http-user", "private-http-password");
        await using var proxy = new LoopbackProxy(async (stream, ct) =>
        {
            var header = await ReadHttpHeaderAsync(stream, ct);
            Assert.StartsWith("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n", header);
            Assert.Contains("Proxy-Authorization: Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("http-user:private-http-password")), header);
            await FragmentAsync(stream, Encoding.ASCII.GetBytes("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 Connection established\r\n\r\n"), ct);
        });
        var result = await Diagnostics(credentials).TestTcpAsync(proxy.Profile(ProxyProtocol.HttpConnect) with { CredentialsRef = "ref" }, "2001:db8::1", 443, CancellationToken.None);
        Assert.True(result.Success, result.Message);
        Assert.DoesNotContain(credentials.Password, result.Message);
    }

    [Theory]
    [InlineData("HTTP/1.1 407 private-password\r\n\r\n", "authentication")]
    [InlineData("HTTP/1.1 502 private-password\r\n\r\n", "connect")]
    [InlineData("HTTP/1.1 XYZ private-password\r\n\r\n", "http")]
    [InlineData("NOTHTTP 200 private-password\r\n\r\n", "http")]
    public async Task HttpFailuresAreSanitized(string response, string expectedStage)
    {
        await using var proxy = new LoopbackProxy(async (stream, ct) =>
        {
            await ReadHttpHeaderAsync(stream, ct);
            await stream.WriteAsync(Encoding.ASCII.GetBytes(response), ct);
        });
        var result = await Diagnostics().TestTcpAsync(proxy.Profile(ProxyProtocol.HttpConnect), "example.invalid", 443, CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal(expectedStage, result.Stage);
        Assert.DoesNotContain("private-password", result.Message);
    }

    [Fact]
    public async Task HttpsProxyChecksCertificateTrust()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        request.CertificateExtensions.Add(san.Build());
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        await using var proxy = new LoopbackProxy(async (stream, ct) =>
        {
            await using var tls = new SslStream(stream, leaveInnerStreamOpen: true);
            try
            {
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate }, ct);
                // Some TLS stacks report the client's rejection at the first application read.
                Assert.Equal(0, await tls.ReadAsync(new byte[1], ct));
            }
            catch (AuthenticationException) { }
            catch (IOException) { }
        });
        var result = await Diagnostics().TestTcpAsync(proxy.Profile(ProxyProtocol.HttpsConnect) with { TlsServerName = "localhost" }, "example.invalid", 443, CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal("tls", result.Stage);
    }

    [Fact]
    public async Task TimeoutAndCallerCancellationAreDistinct()
    {
        await using (var proxy = new LoopbackProxy(async (stream, ct) =>
        {
            await ReadAsync(stream, 3, ct);
            Assert.Equal(0, await stream.ReadAsync(new byte[1], ct));
        }))
        {
            var result = await new ProxyDiagnostics(new MemorySecrets(), TimeSpan.FromMilliseconds(100))
                .TestTcpAsync(proxy.Profile(), "example.invalid", 443, CancellationToken.None);
            Assert.False(result.Success);
            Assert.Contains("время", result.Message);
        }
        await using (var proxy = new LoopbackProxy(async (stream, ct) =>
        {
            await ReadAsync(stream, 3, ct);
            Assert.Equal(0, await stream.ReadAsync(new byte[1], ct));
        }))
        {
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Diagnostics().TestTcpAsync(proxy.Profile(), "example.invalid", 443, cancellation.Token));
        }
    }

    [Fact]
    public async Task TargetHeaderInjectionIsRejectedBeforeConnection()
    {
        var result = await Diagnostics().TestTcpAsync(new() { Protocol = ProxyProtocol.HttpConnect }, "host\r\nInjected: true", 443, CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal("validation", result.Stage);
    }

    [Fact]
    public async Task MissingCredentialsFailBeforeConnection()
    {
        var result = await Diagnostics().TestTcpAsync(new() { CredentialsRef = "missing" }, "example.invalid", 443, CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal("credentials", result.Stage);
    }

    private static ProxyDiagnostics Diagnostics(ProxyCredentials? credentials = null) => new(new MemorySecrets(credentials), TimeSpan.FromSeconds(5));

    private static async Task SocksNegotiateAsync(Stream stream, CancellationToken ct)
    {
        Assert.Equal(new byte[] { 5, 1, 0 }, await ReadAsync(stream, 3, ct));
        await stream.WriteAsync(new byte[] { 5, 0 }, ct);
    }

    private static async Task<(byte Command, string Host, int Port)> ReadSocksCommandAsync(Stream stream, CancellationToken ct)
    {
        var header = await ReadAsync(stream, 4, ct);
        Assert.Equal((byte)5, header[0]);
        Assert.Equal((byte)0, header[2]);
        var host = header[3] switch
        {
            1 => new IPAddress(await ReadAsync(stream, 4, ct)).ToString(),
            4 => new IPAddress(await ReadAsync(stream, 16, ct)).ToString(),
            3 => Encoding.ASCII.GetString(await ReadAsync(stream, (await ReadAsync(stream, 1, ct))[0], ct)),
            _ => throw new InvalidDataException("Unexpected test address type.")
        };
        var port = await ReadAsync(stream, 2, ct);
        return (header[1], host, (port[0] << 8) | port[1]);
    }

    private static async Task<byte[]> ReadAsync(Stream stream, int count, CancellationToken ct)
    {
        var bytes = new byte[count];
        await stream.ReadExactlyAsync(bytes, ct);
        return bytes;
    }

    private static async Task<string> ReadHttpHeaderAsync(Stream stream, CancellationToken ct)
    {
        var result = new List<byte>();
        while (result.Count < 16384)
        {
            result.Add((await ReadAsync(stream, 1, ct))[0]);
            if (result.Count >= 4 && result[^4] == 13 && result[^3] == 10 && result[^2] == 13 && result[^1] == 10)
                return Encoding.ASCII.GetString(result.ToArray());
        }
        throw new InvalidDataException("Test header too long.");
    }

    private static async Task FragmentAsync(Stream stream, byte[] bytes, CancellationToken ct)
    {
        foreach (var value in bytes) { await stream.WriteAsync(new[] { value }, ct); await Task.Yield(); }
    }

    private sealed class MemorySecrets(ProxyCredentials? credentials = null) : ISecretStore
    {
        public Task<string> StoreAsync(ProxyCredentials value, CancellationToken ct) => Task.FromResult("ref");
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult(credentials);
        public Task DeleteAsync(string reference, CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class LoopbackProxy : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _lifetime = new(TimeSpan.FromSeconds(10));
        private readonly Task _handler;
        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
        public LoopbackProxy(Func<NetworkStream, CancellationToken, Task> handler)
        {
            _listener.Start();
            _handler = Task.Run(async () =>
            {
                using var client = await _listener.AcceptTcpClientAsync(_lifetime.Token);
                await handler(client.GetStream(), _lifetime.Token);
            });
        }
        public ProxyProfile Profile(ProxyProtocol protocol = ProxyProtocol.Socks5) => new() { Host = "127.0.0.1", Port = Port, Protocol = protocol };
        public async ValueTask DisposeAsync()
        {
            try { await _handler.WaitAsync(TimeSpan.FromSeconds(10)); }
            finally { _lifetime.Cancel(); _listener.Stop(); _lifetime.Dispose(); }
        }
    }
}
