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

    private static async Task<LabEngine> StartLabEngineAsync(ProxyProfile upstream, ISecretStore secrets, CancellationToken ct)
    {
        var path = Environment.GetEnvironmentVariable("PATHFLUX_TEST_ENGINE")!;
        var binaryLock = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Process? process = null;
        try
        {
            var version = await EngineBinary.VerifyAsync(path, EngineTestBinary.ExpectedHash, ct);
            using var reservation = new TcpListener(IPAddress.Loopback, 0);
            reservation.Start();
            int port = ((IPEndPoint)reservation.LocalEndpoint).Port;
            using var udpReservation = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
            var config = new ProxyConfiguration { Profiles = [upstream] };
            var json = JsonNode.Parse(await new SingBoxConfigGenerator(secrets).GenerateAsync(config, ct, engineVersion: version))!;
            Assert.Equal("tcp", (string?)json["outbounds"]![1]!["network"]);
            // TEST-ONLY configuration: replace TUN and process rules with a local SOCKS inlet.
            // Let the engine exercise its UDP outbound; production still rejects Proxy UDP.
            json["outbounds"]![1]!.AsObject().Remove("network");
            json["inbounds"] = new JsonArray(new JsonObject
            { ["type"] = "socks", ["tag"] = "lab-in", ["listen"] = "127.0.0.1", ["listen_port"] = port });
            json["route"] = new JsonObject { ["final"] = SingBoxConfigGenerator.Tag(upstream.Id) };
            string text = json.ToJsonString();
            Assert.True(await EngineBinary.CheckAsync(path, text, ct));
            reservation.Stop(); udpReservation.Dispose();
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
                        new ProxyProfile { Name = "Engine loopback inlet", Host = "127.0.0.1", Port = port });
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
            throw;
        }
    }
    private sealed class LabEngine(Process process, FileStream binaryLock, Task output, Task error, ProxyProfile profile) : IAsyncDisposable
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
            finally { process.Dispose(); binaryLock.Dispose(); }
        }
    }
    private sealed class Secrets(ProxyCredentials? credentials) : ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult(credentials);
        public Task<string> StoreAsync(ProxyCredentials value, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }
}
