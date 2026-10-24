using System.Net;
using System.Net.Sockets;
using System.Text;
using PathFlux.Engine;
using PathFlux.Application;
using PathFlux.Domain;
using Xunit;

namespace PathFlux.Engine.Tests;

public class ProxyDohTests
{
    [Theory]
    [InlineData("http://1.1.1.1/dns-query")]
    [InlineData("https://resolver.example/dns-query")]
    [InlineData("https://user:secret@1.1.1.1/dns-query")]
    [InlineData("https://1.1.1.1/dns-query?name=other")]
    [InlineData("https://[::1]/dns-query")]
    [InlineData("https://0.0.0.0/dns-query")]
    [InlineData("https://1.1.1.1/dns-query#other")]
    public void UnsafeOrBootstrapDependentResolverIsRejected(string endpoint)
    {
        var result = ConfigurationValidator.ValidatePolicy([], [new ProxyProfile { UseTlsServerNameForTcp = true, TcpIpv4DohServer = endpoint }]);
        Assert.Contains(result.Issues, i => i.Code == "profile.tcpDoh");
        Assert.DoesNotContain("secret", string.Join(" ", result.Issues.Select(i => i.Message)));
    }

    [Fact]
    public void ValidCnameChainAcceptsOnlyItsFinalIpv4AndShortestTtl()
    {
        var result = ProxyDohIpv4Resolver.Parse("voice.test", Encoding.UTF8.GetBytes("""
            {"Status":0,"Question":[{"name":"voice.test.","type":1}],"Answer":[
            {"name":"unrelated.test.","type":1,"TTL":500,"data":"203.0.113.9"},
            {"name":"edge.test.","type":1,"TTL":80,"data":"203.0.113.8"},
            {"name":"voice.test.","type":5,"TTL":20,"data":"edge.test."}]}
            """));
        Assert.Equal(IPAddress.Parse("203.0.113.8"), result.Address); Assert.Equal(20, result.Ttl);
    }
    [Theory]
    [InlineData("{\"Status\":3}")]
    [InlineData("{\"Status\":0,\"TC\":true}")]
    [InlineData("{\"Status\":0,\"Question\":[{\"name\":\"other.test\",\"type\":1}]}")]
    [InlineData("{\"Status\":0,\"Question\":[{\"name\":\"voice.test\",\"type\":28}]}")]
    [InlineData("{\"Status\":0,\"Question\":[{\"name\":\"voice.test\",\"type\":1}],\"Answer\":[{\"name\":\"other.test\",\"type\":1,\"data\":\"203.0.113.9\"}]}")]
    [InlineData("{\"Status\":0,\"Question\":[{\"name\":\"voice.test\",\"type\":1}],\"Answer\":[{\"name\":\"voice.test\",\"type\":5,\"data\":\"voice.test\"}]}")]
    [InlineData("{\"Status\":0,\"Question\":[{\"name\":\"voice.test\",\"type\":1}],\"Answer\":[{\"name\":\"voice.test\",\"type\":1,\"data\":\"::1\"}]}")]
    public void InvalidDnsEvidenceIsRejected(string json) => Assert.ThrowsAny<Exception>(() => ProxyDohIpv4Resolver.Parse("voice.test", Encoding.UTF8.GetBytes(json)));

    [Fact]
    public async Task RefusedProxyNeverConnectsDirectlyToEvenALoopbackDohEndpoint()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var doh = new TcpListener(IPAddress.Loopback, 0); doh.Start();
        using var socks = new TcpListener(IPAddress.Loopback, 0); socks.Start();
        var server = Task.Run(async () =>
        {
            using var client = await socks.AcceptTcpClientAsync(deadline.Token); var s = client.GetStream();
            var greeting = new byte[3]; await s.ReadExactlyAsync(greeting, deadline.Token); await s.WriteAsync(new byte[] { 5, 0 }, deadline.Token);
            var request = new byte[10]; await s.ReadExactlyAsync(request, deadline.Token);
            Assert.Equal(new byte[] { 5, 1, 0, 1 }, request[..4]);
            Assert.Equal(((IPEndPoint)doh.LocalEndpoint).Port, (request[8] << 8) | request[9]);
            await s.WriteAsync(new byte[] { 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }, deadline.Token);
        });
        using var resolver = new ProxyDohIpv4Resolver((IPEndPoint)socks.LocalEndpoint, null, $"https://127.0.0.1:{((IPEndPoint)doh.LocalEndpoint).Port}/dns-query");
        await Assert.ThrowsAsync<HttpRequestException>(() => resolver.ResolveAsync("voice.test", deadline.Token));
        await server; Assert.False(doh.Pending());
    }
}
