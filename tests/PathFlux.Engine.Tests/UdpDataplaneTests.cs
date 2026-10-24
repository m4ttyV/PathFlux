using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using PathFlux.Application;
using PathFlux.Domain;
using PathFlux.Infrastructure;
using PathFlux.Testing;
using Xunit;

namespace PathFlux.Engine.Tests;

/// <summary>Real engine traffic through loopback sockets. This deliberately never creates a TUN or elevates.</summary>
public sealed class UdpDataplaneTests
{
    [EngineFact]
    public async Task ProductionSocksOutboundStillRefusesUdpWithDirectlyReachableEcho()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo, new() { Fault = UdpRelayFault.Fragmented });
        await using var engine = await StartLabEngineAsync(relay.Profile, new Secrets(null), deadline.Token, experimental: false);
        var result = await new ProxyDiagnostics(new Secrets(null), TimeSpan.FromSeconds(2)).TestUdpRelayAsync(engine.Profile,
            new(echo.EndPoint.Address.ToString(), echo.EndPoint.Port), deadline.Token);
        Assert.False(result.Success); Assert.Equal(0, echo.ReceivedPackets); Assert.Equal(0, relay.ForwardedPackets);
    }
    [EngineFact]
    public async Task OfficialEngineForwardsUdpThroughAuthenticatedSocksUpstreamToIndependentEcho()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var credentials = new ProxyCredentials("udp-lab-user", "udp-lab-test-password");
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo, new() { Credentials = credentials });
        await using var engine = await StartLabEngineAsync(relay.Profile, new Secrets(credentials), deadline.Token);
        var diagnostics = new ProxyDiagnostics(new Secrets(null), TimeSpan.FromSeconds(5));
        var result = await diagnostics.TestUdpRelayAsync(engine.Profile,
            new(echo.EndPoint.Address.ToString(), echo.EndPoint.Port), deadline.Token);

        Assert.True(result.Success, $"{result.Stage}: {result.Message}");
        Assert.Equal(UdpRelayStatus.Verified, result.Evidence.Status);
        Assert.Equal(3, result.Evidence.ReceivedPackets);
        Assert.True(relay.AssociateRequests >= 1);
        Assert.Equal(3, relay.ForwardedPackets);
        Assert.Equal(3, echo.ReceivedPackets);
        Assert.Equal(3, echo.Payloads.Select(Convert.ToHexString).Distinct().Count());
        Assert.Empty(relay.UnexpectedErrors);
    }

    [EngineFact]
    public async Task OfficialEngineDoesNotFallBackToDirectWhenUpstreamRejectsUdp()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var echo = new UdpEchoServer();
        await using var relay = new Socks5UdpRelay(echo, new() { ReplyCode = 7 });
        await using var engine = await StartLabEngineAsync(relay.Profile, new Secrets(null), deadline.Token);
        // The echo target is directly reachable locally: any hidden Direct fallback would reach it.
        var result = await new ProxyDiagnostics(new Secrets(null), TimeSpan.FromSeconds(2)).TestUdpRelayAsync(engine.Profile,
            new(echo.EndPoint.Address.ToString(), echo.EndPoint.Port), deadline.Token);

        Assert.False(result.Success);
        Assert.Equal(UdpRelayStatus.Failed, result.Evidence.Status);
        Assert.Equal(0, result.Evidence.ReceivedPackets);
        Assert.True(relay.AssociateRequests >= 1);
        Assert.Equal(0, relay.ForwardedPackets);
        Assert.Equal(0, echo.ReceivedPackets);
        Assert.Empty(relay.UnexpectedErrors);
    }

    private static async Task<LabEngine> StartLabEngineAsync(ProxyProfile upstream, ISecretStore secrets, CancellationToken ct, bool experimental = true)
    {
        var path = Environment.GetEnvironmentVariable("PATHFLUX_TEST_ENGINE")!;
        var binaryLock = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Process? process = null;
        StrictSocksUdpBridge? bridge = null;
        try
        {
            var version = await EngineBinary.VerifyAsync(path, EngineTestBinary.ExpectedHash, ct);
            using var reservation = new DualPortReservation();
            int port = reservation.Port;
            var config = new ProxyConfiguration { Profiles = [upstream] };
            var generator = new SingBoxConfigGenerator(secrets);
            var production = JsonNode.Parse(await generator.GenerateAsync(config, ct, engineVersion: version))!;
            Assert.Equal("tcp", (string?)production["outbounds"]![1]!["network"]);
            if (experimental) bridge = new StrictSocksUdpBridge(new(IPAddress.Parse(upstream.Host), upstream.Port), credentials:
                upstream.CredentialsRef is null ? null : await secrets.GetAsync(upstream.CredentialsRef, ct));
            var json = experimental ? JsonNode.Parse(await generator.GenerateExperimentalUdpAsync(config, ct, version,
                new Dictionary<Guid, StrictSocksUdpBridge> { [upstream.Id] = bridge! }))! : production;
            // TEST-ONLY configuration: replace TUN and process rules with a local SOCKS inlet.
            // Let the engine exercise its UDP outbound; production still rejects Proxy UDP.
            json["inbounds"] = new JsonArray(new JsonObject
            { ["type"] = "socks", ["tag"] = "lab-in", ["listen"] = "127.0.0.1", ["listen_port"] = port });
            json["route"] = new JsonObject { ["final"] = experimental ? SingBoxConfigGenerator.UdpTag(upstream.Id) : SingBoxConfigGenerator.Tag(upstream.Id) };
            string text = json.ToJsonString();
            Assert.True(await EngineBinary.CheckAsync(path, text, ct));
            reservation.Dispose();
            process = new Process { StartInfo = EngineBinary.CreateStartInfo(path, "run") };
            process.Start();
            var output = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
            var error = process.StandardError.BaseStream.CopyToAsync(Stream.Null);
            await process.StandardInput.WriteAsync(text.AsMemory(), ct); process.StandardInput.Close();
            for (int attempt = 0; attempt < 100; attempt++)
            {
                if (process.HasExited) throw new InvalidOperationException("Loopback engine exited before readiness.");
                try
                {
                    using var probe = new TcpClient();
                    await probe.ConnectAsync(IPAddress.Loopback, port, ct);
                    return new LabEngine(process, binaryLock, output, error,
                        new ProxyProfile { Name = "Engine loopback inlet", Host = "127.0.0.1", Port = port }, bridge);
                }
                catch (SocketException) { await Task.Delay(50, ct); }
            }
            throw new TimeoutException("Loopback engine did not become ready.");
        }
        catch
        {
            if (process is not null)
            {
                try { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); } }
                catch (InvalidOperationException) { }
                process.Dispose();
            }
            binaryLock.Dispose();
            if (bridge is not null) await bridge.DisposeAsync();
            throw;
        }
    }
    private sealed class DualPortReservation : IDisposable
    {
        private TcpListener? tcp;
        private UdpClient? udp;
        public int Port { get; private set; }
        public DualPortReservation()
        {
            for (int attempt = 0; attempt < 32; attempt++)
            {
                // TCP's sequential ephemeral allocator can stay inside a UDP-excluded Hyper-V range.
                // Sample independently and reserve the SAME concrete port in both protocol tables.
                Port = System.Security.Cryptography.RandomNumberGenerator.GetInt32(16384, 49152);
                tcp = new TcpListener(IPAddress.Loopback, Port);
                try
                {
                    tcp.Start(); udp = new UdpClient(AddressFamily.InterNetwork);
                    udp.Client.Bind(new IPEndPoint(IPAddress.Loopback, Port)); return;
                }
                catch (SocketException ex) when (ex.SocketErrorCode is SocketError.AccessDenied or SocketError.AddressAlreadyInUse)
                { Dispose(); } // Hyper-V/Docker can reserve a UDP range separately from TCP.
                catch { Dispose(); throw; }
            }
            throw new InvalidOperationException("NoSharedLoopbackTcpUdpPortAvailable");
        }
        public void Dispose() { tcp?.Stop(); tcp = null; udp?.Dispose(); udp = null; }
    }
    private sealed class LabEngine(Process process, FileStream binaryLock, Task output, Task error, ProxyProfile profile, StrictSocksUdpBridge? bridge) : IAsyncDisposable
    {
        public ProxyProfile Profile => profile;
        public async ValueTask DisposeAsync()
        {
            try
            {
                if (!process.HasExited) process.Kill(true);
                await process.WaitForExitAsync(CancellationToken.None);
                await Task.WhenAll(output, error);
            }
            finally { process.Dispose(); binaryLock.Dispose(); if (bridge is not null) await bridge.DisposeAsync(); }
        }
    }
    private sealed class Secrets(ProxyCredentials? credentials) : ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult(credentials);
        public Task<string> StoreAsync(ProxyCredentials value, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }
}
