using PathFlux.Engine;
using PathFlux.Application;
using PathFlux.Domain;
using Xunit;

namespace PathFlux.Engine.Tests;

public class NetworkTransitionRecoveryTests
{
    [Fact]
    public void EngineRecoveryIdentityIncludesStartTimeSoReusedPidDoesNotBlockAnotherSession()
    {
        using var current = System.Diagnostics.Process.GetCurrentProcess();
        long ticks = current.StartTime.ToUniversalTime().Ticks;
        Assert.True(RecoveryJournal.IsRecordedEngineRunning(current.Id, ticks));
        Assert.False(RecoveryJournal.IsRecordedEngineRunning(current.Id, ticks - 1));
        Assert.False(RecoveryJournal.IsRecordedEngineRunning(int.MaxValue, ticks));
    }
    [Fact]
    public async Task DisposingAnUnusedAdapterDoesNotFinalizeAPreviousSessionsJournal()
    {
        string directory = Path.Combine(Path.GetTempPath(), "PathFlux-passive-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "recovery.json");
        const string evidence = "{\"SchemaVersion\":1,\"Baseline\":{\"Routes\":[],\"Adapters\":[]}}";
        try
        {
            await File.WriteAllTextAsync(path, evidence);
            await using (var adapter = new SingBoxEngineAdapter(new NoSecrets(), Path.Combine(directory, "agent.exe"), path))
                Assert.Equal(EngineState.Stopped, (await adapter.GetStatusAsync(default)).State);
            Assert.Equal(evidence, await File.ReadAllTextAsync(path));
            Assert.Single(Directory.GetFiles(directory));
        }
        finally { Directory.Delete(directory, true); }
    }

    private sealed class NoSecrets : ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult<ProxyCredentials?>(null);
        public Task<string> StoreAsync(ProxyCredentials credentials, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }

    [Fact]
    public void VpnConnectAndDisconnectDoNotLeaveOwnedResourcesButStillFailGlobalComparison()
    {
        var disconnected = new WindowsNetworkState([], [new("vpn", "OpenVPN", [], ["169.254.1.2/16"], false, 31)]);
        var connected = new WindowsNetworkState([new("0.0.0.0/1", "10.8.0.5", 31, 256), new("128.0.0.0/1", "10.8.0.5", 31, 256)],
            [new("vpn", "OpenVPN", ["1.1.1.1"], ["10.8.0.6/30"], false, 31)]);
        Assert.NotEmpty(disconnected.RecoveryIssues(connected, SingBoxConfigGenerator.InterfaceName));
        Assert.NotEmpty(connected.RecoveryIssues(disconnected, SingBoxConfigGenerator.InterfaceName));
        Assert.Empty(connected.OwnedCleanupIssues(SingBoxConfigGenerator.InterfaceName));
        Assert.Empty(disconnected.OwnedCleanupIssues(SingBoxConfigGenerator.InterfaceName));
    }

    [Theory]
    [InlineData("0.0.0.0/1", "172.30.254.2")]
    [InlineData("128.0.0.0/1", "172.30.254.2")]
    [InlineData("172.30.254.0/30", "0.0.0.0")]
    [InlineData("8000::/1", "fdfe:7061:7468::2")]
    [InlineData("fdfe:7061:7468::/64", "::")]
    public void OrphanedTunRoutesBlockFinalizationEvenWithoutAnAdapter(string prefix, string nextHop)
    {
        var current = new WindowsNetworkState([new(prefix, nextHop, 99, 0)], []);
        Assert.Contains("OwnRoutesRemain", current.OwnedCleanupIssues(SingBoxConfigGenerator.InterfaceName));
    }

    [Theory]
    [InlineData("172.30.254.1")]
    [InlineData("fdfe:7061:7468::2")]
    public void OwnDnsAndAddressesOnOtherAdaptersAlsoBlockFinalization(string address)
    {
        var current = new WindowsNetworkState([], [new("lan", "Ethernet", [address], [address + "/32"], false, 12)]);
        var issues = current.OwnedCleanupIssues(SingBoxConfigGenerator.InterfaceName);
        Assert.Contains("OwnDnsRemains", issues);
        Assert.Contains("OwnAddressesRemain", issues);
    }

    [Fact]
    public void LiveTunAndRoutesOnItsIndexBlockFinalization()
    {
        var current = new WindowsNetworkState([new("0.0.0.0/1", "0.0.0.0", 99, 0)],
            [new("tun", SingBoxConfigGenerator.InterfaceName, [], [], false, 99)]);
        var issues = current.OwnedCleanupIssues(SingBoxConfigGenerator.InterfaceName);
        Assert.Contains("OwnInterfaceRemains", issues);
        Assert.Contains("OwnRoutesRemain", issues);
    }
}
