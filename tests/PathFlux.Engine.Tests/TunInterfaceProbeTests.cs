using System.Net.NetworkInformation;
using Xunit;
namespace PathFlux.Engine.Tests;

public sealed class TunInterfaceProbeTests
{
    [Theory]
    [InlineData(OperationalStatus.Down)]
    [InlineData(OperationalStatus.NotPresent)]
    public void DetachedPhantomDoesNotBlockStopOrNextStart(OperationalStatus status)
    {
        var phantom = new TunInterfaceObservation(status, false, false, 0, 0);
        Assert.False(phantom.RequiresCleanup);
        Assert.False(phantom.IsReady);
    }

    [Theory]
    [InlineData(OperationalStatus.Down, true, false, 0, 0)]
    [InlineData(OperationalStatus.Down, false, true, 0, 0)]
    [InlineData(OperationalStatus.Down, false, false, 1, 0)]
    [InlineData(OperationalStatus.Down, false, false, 0, 1)]
    [InlineData(OperationalStatus.Up, false, false, 0, 0)]
    [InlineData(OperationalStatus.Unknown, false, false, 0, 0)]
    [InlineData(OperationalStatus.Dormant, false, false, 0, 0)]
    public void DownOrEmptyAloneCannotConfirmCleanup(OperationalStatus status, bool ipv4, bool ipv6, int addresses, int dns)
        => Assert.True(new TunInterfaceObservation(status, ipv4, ipv6, addresses, dns).RequiresCleanup);

    [Theory]
    [InlineData(OperationalStatus.Up, true, false, 1, true)]
    [InlineData(OperationalStatus.Up, false, true, 1, true)]
    [InlineData(OperationalStatus.Down, true, true, 1, false)]
    [InlineData(OperationalStatus.Up, true, false, 0, false)]
    [InlineData(OperationalStatus.Up, false, false, 1, false)]
    public void ReadinessRequiresUpProtocolAndAddress(OperationalStatus status, bool ipv4, bool ipv6, int addresses, bool ready)
        => Assert.Equal(ready, new TunInterfaceObservation(status, ipv4, ipv6, addresses, 0).IsReady);
}
