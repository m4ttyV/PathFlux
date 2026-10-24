using PathFlux.Agent;
using PathFlux.Domain;
using Xunit;
namespace PathFlux.Engine.Tests;

public sealed class ProductionRecoveryTests
{
    [Fact]
    public void DnsPriorityOrderIsPartOfRecoveryEvidence()
    {
        var before = new WindowsNetworkState([], [new("lan", "LAN", ["192.0.2.53", "192.0.2.54"], [], false, 1)]);
        var after = before with { Adapters = [before.Adapters[0] with { Dns = ["192.0.2.54", "192.0.2.53"] }] };
        Assert.Contains("OriginalAdapterDnsChanged", before.RecoveryIssues(after, "PathFlux-TUN"));
    }
    [Fact]
    public async Task PendingOrCorruptRecoveryEvidenceCannotBeSilentlyIgnored()
    {
        var path = Path.Combine(Path.GetTempPath(), "PathFlux-recovery-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            Assert.False(RecoveryJournal.HasPendingBaseline(path));
            await File.WriteAllTextAsync(path, "{\"SchemaVersion\":1}");
            Assert.False(RecoveryJournal.HasPendingBaseline(path)); // Original journal did not contain a baseline.
            await File.WriteAllTextAsync(path, "{\"SchemaVersion\":1,\"Baseline\":{}}");
            Assert.True(RecoveryJournal.HasPendingBaseline(path));
            await File.WriteAllTextAsync(path, "{corrupt");
            Assert.True(RecoveryJournal.HasPendingBaseline(path));
            await File.WriteAllTextAsync(path, "{\"SchemaVersion\":99}");
            Assert.True(RecoveryJournal.HasPendingBaseline(path));
        }
        finally { File.Delete(path); }
    }
    [Fact]
    public void SharedRecoveryComparisonRequiresAllRoutesDnsAddressesAndDetachedOwnInterface()
    {
        var before = new WindowsNetworkState([new("0.0.0.0/1", "10.8.0.1", 31, 1), new("128.0.0.0/1", "10.8.0.1", 31, 1)],
            [new("lan", "LAN", ["192.0.2.53"], ["192.0.2.2/24"], false, 1)]);
        Assert.Empty(before.RecoveryIssues(before, "PathFlux-TUN"));
        var phantom = new WindowsNetworkAdapter("tun", "PathFlux-TUN", [], [], true, 0);
        Assert.Empty(before.RecoveryIssues(before with { Adapters = [.. before.Adapters, phantom] }, "PathFlux-TUN"));
        var after = new WindowsNetworkState([before.Routes[0]],
            [before.Adapters[0] with { Dns = ["172.30.254.2"], Addresses = [] }, phantom with { Detached = false }]);
        var issues = before.RecoveryIssues(after, "PathFlux-TUN");
        Assert.Contains("RoutesChanged", issues); Assert.Contains("OriginalAdapterDnsChanged", issues);
        Assert.Contains("OriginalAdapterAddressesChanged", issues); Assert.Contains("OwnInterfaceRemains", issues);
    }

    [Fact]
    public async Task StartupFailureBeforeNetworkChangePreservesCauseAndCanBeStopped()
    {
        using var session = new EngineSession();
        var reply = await session.StartAsync(new(), [], default);
        Assert.False(reply.Success);
        Assert.Equal(EngineState.Failed, reply.Status.State);
        Assert.Contains("sing-box.exe", reply.Status.Message);
        Assert.DoesNotContain("Очистка", reply.Status.Message);
        Assert.Equal(reply.Status.Message, session.Status.Message);
        await session.StopAsync(default);
        Assert.Equal(EngineState.Stopped, session.Status.State);
    }
}
