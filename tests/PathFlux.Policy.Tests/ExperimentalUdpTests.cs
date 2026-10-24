using PathFlux.Application;
using PathFlux.Domain;
using Xunit;

namespace PathFlux.Policy.Tests;

public class ExperimentalUdpTests
{
    [Theory]
    [InlineData(1, 65535, true)] [InlineData(20000, 20030, true)] [InlineData(0, 30, false)]
    [InlineData(31, 30, false)] [InlineData(20000, 65536, false)] [InlineData(null, null, false)]
    public void DockerRangeIsExplicitAndValidated(int? first, int? last, bool valid)
    {
        var p = new ProxyProfile { UdpRelayMode = UdpRelayMode.DockerNat, UdpPublishedPortFirst = first, UdpPublishedPortLast = last };
        Assert.Equal(valid, ConfigurationValidator.Validate(new() { Profiles = [p] }).IsValid);
    }
    [Theory]
    [InlineData(ProxyProtocol.Socks5, true)] [InlineData(ProxyProtocol.HttpConnect, false)] [InlineData(ProxyProtocol.HttpsConnect, false)]
    public void EnabledUdpRefusesIncompatibleProfilesWithSpecificReason(ProxyProtocol protocol, bool valid)
    {
        var p = new ProxyProfile { Protocol = protocol };
        var result = ConfigurationValidator.Validate(new() { Profiles = [p], Rules = [new() { ProfileId = p.Id }], Settings = new() { ExperimentalSocksUdp = true } });
        Assert.Equal(valid, result.IsValid);
        if (!valid) Assert.Contains(result.Issues, i => i.Code == "udp.incompatible" && i.Message.Contains("TCP"));
    }
    [Fact]
    public void DockerNatCannotBeGuessedForRemoteProxy()
    {
        var p = new ProxyProfile { Host = "192.0.2.1", UdpRelayMode = UdpRelayMode.DockerNat, UdpPublishedPortFirst = 20000, UdpPublishedPortLast = 20030 };
        Assert.Contains(ConfigurationValidator.Validate(new() { Profiles = [p] }).Issues, i => i.Code == "udp.docker.host");
    }
}
