using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PathFlux.Engine;
using PathFlux.Application;
using PathFlux.Domain;
using System.Text.Json.Nodes;
using Xunit;

namespace PathFlux.Engine.Tests;

public class TlsNameBridgeTests
{
    [Fact]
    public async Task FlagRequiresAgentBridgeWhileValidationUsesOnlyInertEndpoints()
    {
        var profile = new ProxyProfile { UseTlsServerNameForTcp = true };
        var config = new ProxyConfiguration { Profiles = [profile], Rules = [new() { ProfileId = profile.Id, Network = NetworkTransport.Both }] };
        var generator = new SingBoxConfigGenerator(new NoSecrets());
        var preview = JsonNode.Parse(await generator.GenerateAsync(config, default))!;
        Assert.All(preview["route"]!["rules"]!.AsArray().Where(r => r?["process_name"] is not null), r => Assert.Equal("reject", (string?)r!["action"]));
        var validation = JsonNode.Parse(await generator.GenerateValidationAsync(config, default))!;
        Assert.Equal(9, (int)validation["outbounds"]![1]!["server_port"]!);
        Assert.Equal("validation-only", (string?)validation["outbounds"]![1]!["username"]);
        await using var owner = await AgentUdpBridges.CreateAsync(config, new NoSecrets(), default);
        var bridge = Assert.Single(owner.TcpBridges).Value; Assert.Empty(owner.Bridges);
        var actual = JsonNode.Parse(await generator.GenerateAgentAsync(config, owner.Bridges, default, tcpGuards: owner.TcpBridges))!;
        Assert.Equal(bridge.EndPoint.Port, (int)actual["outbounds"]![1]!["server_port"]!);
        Assert.Equal(bridge.LocalCredentials.Username, (string?)actual["outbounds"]![1]!["username"]);
        var endpoint = bridge.EndPoint; await owner.DisposeAsync();
        using var socket = new TcpClient(); await Assert.ThrowsAsync<SocketException>(() => socket.ConnectAsync(endpoint.Address, endpoint.Port));
    }

    [EngineFact]
    public async Task OfficialEngineAcceptsTcpCompatibilityWithoutSniffOrGlobalDnsChanges()
    {
        string path = Environment.GetEnvironmentVariable("PATHFLUX_TEST_ENGINE")!;
        var version = await EngineBinary.VerifyAsync(path, EngineTestBinary.ExpectedHash, default);
        var profile = new ProxyProfile { UseTlsServerNameForTcp = true };
        var config = new ProxyConfiguration { Profiles = [profile], Rules = [new() { ProfileId = profile.Id, Network = NetworkTransport.Tcp }] };
        string json = await new SingBoxConfigGenerator(new NoSecrets()).GenerateValidationAsync(config, default, version);
        Assert.DoesNotContain("\"sniff\"", json); Assert.True(await EngineBinary.CheckAsync(path, json, default));
    }

    [Theory]
    [InlineData(ProxyProtocol.HttpConnect)] [InlineData(ProxyProtocol.HttpsConnect)]
    public void UnsupportedProxyCannotSilentlyAcceptTcpCompatibility(ProxyProtocol protocol)
    {
        var result = ConfigurationValidator.ValidatePolicy([], [new() { Protocol = protocol, UseTlsServerNameForTcp = true }]);
        Assert.Contains(result.Issues, i => i.Code == "profile.tcpSni");
    }

    [Fact]
    public async Task WrongLocalCredentialsNeverReachUpstreamAndDisposeClosesClients()
    {
        using var ct = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        using var upstream = new TcpListener(IPAddress.Loopback, 0); upstream.Start();
        await using var bridge = new TlsNameSocksBridge((IPEndPoint)upstream.LocalEndpoint, null);
        using var client = new TcpClient(); await client.ConnectAsync(bridge.EndPoint, ct.Token); var stream = client.GetStream();
        await stream.WriteAsync(new byte[] { 5, 1, 2 }, ct.Token); var reply = new byte[2]; await stream.ReadExactlyAsync(reply, ct.Token);
        await stream.WriteAsync(new byte[] { 1, 1, 65, 1, 66 }, ct.Token); await stream.ReadExactlyAsync(reply, ct.Token);
        Assert.Equal(new byte[] { 1, 1 }, reply); Assert.False(upstream.Pending());
        await bridge.DisposeAsync(); Assert.Equal(0, await stream.ReadAsync(new byte[1], ct.Token));
    }

    private sealed class NoSecrets : ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult<ProxyCredentials?>(null);
        public Task<string> StoreAsync(ProxyCredentials credentials, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }

    [Fact]
    public async Task Ipv6RequestBecomesDomainUpstreamAndTlsStillAuthenticatesTheRealServer()
    {
        using var ct = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        using var cert = X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pfx), null);
        using var upstream = new TcpListener(IPAddress.Loopback, 0); upstream.Start();
        async Task<byte[]> Read(Stream s, int n) { var b = new byte[n]; await s.ReadExactlyAsync(b, ct.Token); return b; }
        var observed = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = Task.Run(async () =>
        {
            using var remote = await upstream.AcceptTcpClientAsync(ct.Token); var s = remote.GetStream();
            Assert.Equal(new byte[] { 5, 1, 0 }, await Read(s, 3)); await s.WriteAsync(new byte[] { 5, 0 }, ct.Token);
            Assert.Equal(new byte[] { 5, 1, 0, 1 }, await Read(s, 4));
            Assert.True(IPAddress.IsLoopback(new IPAddress(await Read(s, 4)))); await Read(s, 2);
            await s.WriteAsync(new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 }, ct.Token);
            using var tls = new SslStream(s, true); await tls.AuthenticateAsServerAsync((_, hello, _, _) =>
            { observed.SetResult(hello.ServerName); return ValueTask.FromResult(new SslServerAuthenticationOptions { ServerCertificate = cert }); }, null, ct.Token);
            var payload = await Read(tls, 16); await tls.WriteAsync(payload, ct.Token);
        });
        await using var bridge = new TlsNameSocksBridge((IPEndPoint)upstream.LocalEndpoint, null,
            resolveForTesting: (host, _) => { Assert.Equal("localhost", host); return Task.FromResult(IPAddress.Loopback); });
        using var client = new TcpClient(); await client.ConnectAsync(bridge.EndPoint, ct.Token); var stream = client.GetStream();
        await stream.WriteAsync(new byte[] { 5, 1, 2 }, ct.Token); Assert.Equal(new byte[] { 5, 2 }, await Read(stream, 2));
        var u = Encoding.UTF8.GetBytes(bridge.LocalCredentials.Username); var p = Encoding.UTF8.GetBytes(bridge.LocalCredentials.Password);
        await stream.WriteAsync(new byte[] { 1, (byte)u.Length }.Concat(u).Concat(new byte[] { (byte)p.Length }).Concat(p).ToArray(), ct.Token);
        Assert.Equal(new byte[] { 1, 0 }, await Read(stream, 2));
        await stream.WriteAsync(new byte[] { 5, 1, 0, 4 }.Concat(IPAddress.Parse("2001:db8::1").GetAddressBytes()).Concat(new byte[] { 1, 187 }).ToArray(), ct.Token);
        Assert.Equal(0, (await Read(stream, 10))[1]);
        using var applicationTls = new SslStream(stream, true, (_, c, _, _) => c?.GetCertHashString() == cert.GetCertHashString());
        try { await applicationTls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "localhost" }, ct.Token); }
        catch (Exception ex) { throw new Xunit.Sdk.XunitException(bridge.Diagnostic + " Test upstream: " + server.Exception?.GetBaseException().Message + " Client: " + ex.GetType().Name); }
        var data = RandomNumberGenerator.GetBytes(16); await applicationTls.WriteAsync(data, ct.Token);
        Assert.Equal(data, await Read(applicationTls, 16)); Assert.Equal("localhost", await observed.Task.WaitAsync(ct.Token));
        await server;
    }

    [Fact]
    public async Task PeekingRealClientHelloCapturesServerNameWithoutSendingTlsBytesToClient()
    {
        using var ct = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var client = new TcpClient(); await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint, ct.Token);
        using var server = await listener.AcceptTcpClientAsync(ct.Token);
        using var tls = new SslStream(client.GetStream(), true);
        var handshake = tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = "voice.example.test" }, ct.Token);
        var hello = await TlsNameSocksBridge.PeekClientHelloAsync(server.GetStream(), ct.Token);
        Assert.Equal("voice.example.test", hello.ServerName); Assert.NotEmpty(hello.Bytes); Assert.Equal(22, hello.Bytes[0]);
        Assert.Equal(0, client.Available); Assert.False(handshake.IsCompleted);
        server.Close(); await Assert.ThrowsAnyAsync<Exception>(() => handshake);
    }

    [Fact]
    public async Task PlaintextIsCapturedWithoutInventingAServerNameOrWritingToTheSource()
    {
        var bytes = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n");
        using var source = new MemoryStream(bytes, writable: false);
        var hello = await TlsNameSocksBridge.PeekClientHelloAsync(source, default);
        Assert.Null(hello.ServerName); Assert.Equal(bytes.Take(hello.Bytes.Length), hello.Bytes);
        Assert.InRange(hello.Bytes.Length, 1, 65536);
    }
}
