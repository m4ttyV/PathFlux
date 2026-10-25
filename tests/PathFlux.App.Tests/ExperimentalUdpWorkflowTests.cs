using PathFlux.Domain;
using Xunit;

namespace PathFlux.App.Tests;

public sealed partial class WorkflowTests
{
    [Fact]
    public async Task UdpOptInAndDockerProfilePersistThroughNormalEditorCommands()
    {
        var store = new MemoryStore(new());
        await using var vm = Create(store, new()); await vm.InitializeAsync();
        Assert.False(vm.ExperimentalSocksUdp);
        vm.ExperimentalSocksUdp = true; await vm.SaveSettingsCommand.ExecuteAsync(null);
        Assert.True(store.Configuration.Settings.ExperimentalSocksUdp);
        vm.ProfileUdpRelayMode = UdpRelayMode.DockerNat; vm.ProfileUdpPortFirst = "20000"; vm.ProfileUdpPortLast = "20030";
        vm.ProfileUseTlsServerNameForTcp = true;
        await vm.SaveProfileCommand.ExecuteAsync(null);
        var profile = Assert.Single(store.Configuration.Profiles);
        Assert.Equal(UdpRelayMode.DockerNat, profile.UdpRelayMode); Assert.Equal(20000, profile.UdpPublishedPortFirst);
        Assert.True(profile.UseTlsServerNameForTcp); Assert.True(vm.ProfileUseTlsServerNameForTcp);
        vm.RuleName = "Голос приложения"; vm.RuleValue = "voice-client.exe";
        vm.RuleProfile = vm.Profiles.Single(); vm.RuleNetwork = NetworkTransport.Udp;
        await vm.SaveRuleCommand.ExecuteAsync(null);
        Assert.Equal(NetworkTransport.Udp, Assert.Single(store.Configuration.Rules).Network);
    }
    [Fact]
    public async Task InvalidDockerRangeDoesNotPersistAndHttpUdpHasSpecificReason()
    {
        var store = new MemoryStore(new());
        await using var vm = Create(store, new()); await vm.InitializeAsync();
        vm.ProfileUdpRelayMode = UdpRelayMode.DockerNat; vm.ProfileUdpPortFirst = "30000"; vm.ProfileUdpPortLast = "20000";
        await vm.SaveProfileCommand.ExecuteAsync(null); Assert.Empty(store.Configuration.Profiles);
        vm.ProfileProtocol = ProxyProtocol.HttpConnect; await vm.SaveProfileCommand.ExecuteAsync(null);
        Assert.Single(store.Configuration.Profiles);
        vm.ExperimentalSocksUdp = true; await vm.SaveSettingsCommand.ExecuteAsync(null);
        vm.RuleName = "Голос приложения"; vm.RuleValue = "voice-client.exe";
        vm.RuleProfile = vm.Profiles.Single(); vm.RuleNetwork = NetworkTransport.Udp;
        await vm.SaveRuleCommand.ExecuteAsync(null);
        Assert.Empty(store.Configuration.Rules); Assert.Contains("HTTP/HTTPS", vm.Notice);
    }
}
