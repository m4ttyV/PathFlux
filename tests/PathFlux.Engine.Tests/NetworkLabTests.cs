using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using PathFlux.Domain;
using PathFlux.NetworkLab;
using Xunit;

namespace PathFlux.Engine.Tests;

public class NetworkLabTests
{
    [Fact]
    public async Task LabConfigOnlyRoutesSyntheticAddressAndCannotCreateDefaultOrIpv6Route()
    {
        var first = new ProxyProfile(); var second = new ProxyProfile();
        foreach (var scenario in Enum.GetValues<LabScenario>())
        {
            var config = LabPolicy.Create(scenario, @"C:\Lab\selected\PathFlux.LabProbe.exe", first, second);
            var root = JsonNode.Parse(await LabPolicy.GenerateAsync(config, default))!;
            var tun = Assert.Single(root["inbounds"]!.AsArray())!;
            Assert.Equal(new[] { "172.30.254.1/32" }, tun["address"]!.AsArray().Select(n => (string?)n));
            Assert.Equal(new[] { "198.18.0.1/32" }, tun["route_address"]!.AsArray().Select(n => (string?)n));
            Assert.False((bool)tun["strict_route"]!);
            Assert.Null(tun["dns_address"]); Assert.Null(tun["auto_redirect"]);
            Assert.Equal("direct", (string?)root["route"]!["final"]);
            Assert.Equal(LabPolicy.InterfaceName, (string?)tun["interface_name"]);
        }
    }
    [Theory]
    [InlineData("198.18.0.1/32")]
    [InlineData("198.18.0.0/15")]
    [InlineData("172.30.0.0/16")]
    [InlineData("128.0.0.0/1")]
    public void ExistingOverlappingLabOrVpnRoutesRefuseStart(string prefix)
    {
        var snapshot = new NetworkSnapshot([new(prefix, "0.0.0.0", 1, 0)], []);
        Assert.False(snapshot.CanStartLab());
    }
    [Fact]
    public void RecoveryChecksDefaultsOriginalDnsAndResidualTunWithoutGlobalReset()
    {
        var before = new NetworkSnapshot([new("0.0.0.0/0", "192.0.2.1", 1, 5), new("::/0", "fe80::1", 1, 5)],
            [new("original", "Ethernet", ["192.0.2.53"], ["192.0.2.2/24"])]);
        Assert.True(before.CanStartLab()); Assert.Empty(before.CompareRecovery(before));
        var after = before with
        {
            Routes = [new("0.0.0.0/0", "172.30.254.1", 9, 0), new("198.18.0.1/32", "172.30.254.1", 9, 0)],
            Adapters = [new("original", "Ethernet", ["172.30.254.1"], ["192.0.2.2/24"]), new("lab", LabPolicy.InterfaceName, [], [])]
        };
        var issues = before.CompareRecovery(after);
        Assert.Contains("DefaultRoutesChanged", issues);
        Assert.Contains("OriginalAdapterDnsChanged", issues);
        Assert.Contains("LabInterfaceRemains", issues);
        Assert.Contains("LabRouteRemainsOrNetworkChanged", issues);
    }
    [Fact]
    public async Task LabGatewayActuallyForwardsOnlyAllowedSyntheticTargetToSeparateEcho()
    {
        await using var echo = new LabEchoServer(); await using var gateway = new LabSocksGateway("Test gateway", echo);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var tcp = new TcpClient(); await tcp.ConnectAsync(IPAddress.Loopback, gateway.Profile.Port, deadline.Token);
        var stream = tcp.GetStream(); await stream.WriteAsync(new byte[] { 5, 1, 0 }, deadline.Token);
        var selection = new byte[2]; await stream.ReadExactlyAsync(selection, deadline.Token); Assert.Equal(new byte[] { 5, 0 }, selection);
        await stream.WriteAsync(new byte[] { 5, 1, 0, 1, 198, 18, 0, 1, 17, 92 }, deadline.Token); // 4444
        var response = new byte[10]; await stream.ReadExactlyAsync(response, deadline.Token); Assert.Equal(0, response[1]);
        var payload = RandomNumberGenerator.GetBytes(64); await stream.WriteAsync(payload, deadline.Token);
        var echoed = new byte[64]; await stream.ReadExactlyAsync(echoed, deadline.Token);
        Assert.Equal(payload, echoed); Assert.Equal(1, echo.Echoes);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(payload)), Assert.Single(gateway.ConfirmedPayloadHashes));
    }
    [EngineFact]
    public async Task PinnedEngineAcceptsEveryNarrowTunLabConfigWithoutRunningTun()
    {
        var path = Environment.GetEnvironmentVariable("PATHFLUX_TEST_ENGINE")!;
        var version = await EngineBinary.VerifyAsync(path, EngineTestBinary.ExpectedHash, default);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        foreach (var scenario in Enum.GetValues<LabScenario>())
        {
            var config = LabPolicy.Create(scenario, @"C:\Lab\selected\PathFlux.LabProbe.exe", new(), new());
            Assert.True(await EngineBinary.CheckAsync(path, await LabPolicy.GenerateAsync(config, deadline.Token, version), deadline.Token));
        }
    }
    [EngineFact]
    public async Task ClosingSharedProductionJobTerminatesEngineBeforeAnyConfigIsProvided()
    {
        var path = Environment.GetEnvironmentVariable("PATHFLUX_TEST_ENGINE")!;
        await EngineBinary.VerifyAsync(path, EngineTestBinary.ExpectedHash, default);
        using var process = new Process { StartInfo = EngineBinary.CreateStartInfo(path, "run") };
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var job = new WindowsProcessJob(); process.Start();
        try
        {
            job.Assign(process); job.Dispose();
            await process.WaitForExitAsync(deadline.Token); Assert.True(process.HasExited);
        }
        finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); } }
    }
}
