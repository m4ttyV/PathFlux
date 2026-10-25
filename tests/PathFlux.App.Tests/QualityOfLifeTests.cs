using PathFlux.Application;
using PathFlux.Domain;

namespace PathFlux.App.Tests;

public sealed partial class WorkflowTests
{
    [Fact]
    public async Task NewEditorsUseIpv4AndAutomaticUdpWithoutInventingAnApplication()
    {
        await using var vm = Create(new MemoryStore(new()), new());
        await vm.InitializeAsync();
        vm.NewProfileCommand.Execute(null);
        Assert.True(vm.ProfileUseTlsServerNameForTcp);
        Assert.Equal(UdpRelayMode.Auto, vm.ProfileUdpRelayMode);
        vm.NewRuleCommand.Execute(null);
        Assert.Empty(vm.RuleValue); Assert.Empty(vm.RuleName);
        await vm.SaveRuleCommand.ExecuteAsync(null);
        Assert.Empty(vm.Rules);
    }

    [Fact]
    public async Task ExistingProfilesKeepExplicitTransportChoices()
    {
        var profile = new ProxyProfile { UseTlsServerNameForTcp = false, UdpRelayMode = UdpRelayMode.Standard };
        await using var vm = Create(new MemoryStore(new() { Profiles = [profile] }), new());
        await vm.InitializeAsync(); vm.SelectedProfile = vm.Profiles.Single();
        Assert.False(vm.ProfileUseTlsServerNameForTcp);
        Assert.Equal(UdpRelayMode.Standard, vm.ProfileUdpRelayMode);
    }

    [Fact]
    public async Task InstallingEnginePersistsBothFieldsWithoutEnablingNetworkFeatures()
    {
        var installer = new FakeInstaller(); var store = new MemoryStore(new());
        await using var vm = Create(store, new(), installer: installer);
        await vm.InitializeAsync(); await vm.InstallEngineCommand.ExecuteAsync(null);
        Assert.Equal(installer.Result.Path, vm.EnginePath);
        Assert.Equal(installer.Result.Sha256, vm.EngineSha256);
        Assert.Equal(vm.EnginePath, store.Configuration.Settings.EnginePath);
        Assert.Equal(vm.EngineSha256, store.Configuration.Settings.EngineSha256);
        Assert.False(store.Configuration.Settings.ExperimentalProcessTrees);
        Assert.False(store.Configuration.Settings.ExperimentalSocksUdp);
    }

    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task FailedInstallOrSaveDoesNotReplaceConfiguredEngine(bool failInstall)
    {
        var store = new MemoryStore(new() { Settings = new() { EnginePath = @"C:\old\sing-box.exe", EngineSha256 = new('a', 64) } }) { FailSave = !failInstall };
        var installer = new FakeInstaller { Fail = failInstall };
        await using var vm = Create(store, new(), installer: installer);
        await vm.InitializeAsync(); await vm.InstallEngineCommand.ExecuteAsync(null);
        Assert.Equal(@"C:\old\sing-box.exe", vm.EnginePath);
        Assert.Equal(vm.EnginePath, store.Configuration.Settings.EnginePath);
        Assert.Equal(new string('a', 64), vm.EngineSha256);
    }

    [Fact]
    public async Task InstallWhileRunningDoesNotTouchInstaller()
    {
        var installer = new FakeInstaller();
        await using var vm = Create(new MemoryStore(new()), new(), new FakeEngine { State = EngineState.Running }, installer: installer);
        await vm.InitializeAsync(); await vm.InstallEngineCommand.ExecuteAsync(null);
        Assert.Equal(0, installer.Calls);
    }
    private sealed class FakeInstaller : IEngineInstaller
    {
        public int Calls { get; private set; }
        public bool Fail { get; init; }
        public EngineInstallation Result { get; } = new(@"C:\installed\sing-box.exe", new('b', 64));
        public Task<EngineInstallation> InstallAsync(CancellationToken ct)
        {
            Calls++;
            if (Fail) throw new InvalidOperationException("Пакет повреждён.");
            return Task.FromResult(Result);
        }
    }
}
