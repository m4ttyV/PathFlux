using PathFlux.Application;
using PathFlux.Domain;
using PathFlux.Infrastructure;
using PathFlux.ViewModels;

namespace PathFlux.App.Tests;

public sealed partial class WorkflowTests
{
    [Fact]
    public async Task SafeEngineFailureIsVisibleInsteadOfOnlyExceptionType()
    {
        const string message = "Windows запретила доступ к каналу UI–агент.";
        var engine = new FakeEngine { StartFailure = new EngineOperationException(message) };
        await using var vm = Create(new MemoryStore(new()), new(), engine);
        await vm.InitializeAsync(); await vm.StartCommand.ExecuteAsync(null);
        Assert.Equal(message, vm.Notice);
        Assert.Contains(vm.LogEntries, line => line.Contains(message));
    }

    [Fact]
    public async Task UnexpectedEngineExceptionStillHidesRawSecrets()
    {
        var engine = new FakeEngine { StartFailure = new InvalidOperationException("raw-private-password") };
        await using var vm = Create(new MemoryStore(new()), new(), engine);
        await vm.InitializeAsync(); await vm.StartCommand.ExecuteAsync(null);
        Assert.DoesNotContain("raw-private-password", vm.Notice);
        Assert.DoesNotContain(vm.LogEntries, line => line.Contains("raw-private-password"));
    }
    [Fact]
    public async Task InvalidProfileIsRejectedWithoutPersistenceOrSecretLeak()
    {
        var store = new MemoryStore(new()); var secrets = new MemorySecrets();
        await using var vm = Create(store, secrets);
        await vm.InitializeAsync();
        vm.ProfileHost = "https://username:private-password@example.com";
        vm.ReplaceCredentials = true; vm.ProfileUsername = "username"; vm.ProfilePassword = "private-password";
        await vm.SaveProfileCommand.ExecuteAsync(null);
        Assert.Empty(vm.Profiles);
        Assert.Equal(0, store.SaveCalls);
        Assert.Empty(secrets.Values);
        Assert.Single(secrets.Deleted);
        Assert.DoesNotContain("private-password", vm.Notice);
        Assert.DoesNotContain(vm.LogEntries, line => line.Contains("private-password"));
    }

    [Fact]
    public async Task SaveFailureRetainsOldConfigurationAndRollsBackNewSecret()
    {
        var oldReference = Guid.NewGuid().ToString("N");
        var oldProfile = new ProxyProfile { Name = "Original", CredentialsRef = oldReference };
        var store = new MemoryStore(new() { Profiles = [oldProfile] }) { FailSave = true };
        var secrets = new MemorySecrets(); secrets.Values.Add(oldReference, new("old", "old-password"));
        await using var vm = Create(store, secrets); await vm.InitializeAsync();
        vm.SelectedProfile = vm.Profiles.Single(); vm.ProfileName = "Replacement";
        vm.ReplaceCredentials = true; vm.ProfileUsername = "new"; vm.ProfilePassword = "new-password";
        await vm.SaveProfileCommand.ExecuteAsync(null);
        Assert.Equal(oldProfile, vm.Profiles.Single());
        Assert.Equal(oldProfile, store.Configuration.Profiles.Single());
        Assert.Equal(oldReference, Assert.Single(secrets.Values).Key);
        Assert.Single(secrets.Deleted);
        Assert.DoesNotContain("new-password", vm.Notice);
        Assert.DoesNotContain(vm.LogEntries, line => line.Contains("new-password"));
    }

    [Fact]
    public async Task ReplacingCredentialsPreservesSecretNeededByRecoveryBackup()
    {
        var directory = Path.Combine(Path.GetTempPath(), "PathFlux.App.Tests", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "config.json");
        try
        {
            var oldReference = Guid.NewGuid().ToString("N");
            var store = new JsonConfigurationStore(path); var secrets = new MemorySecrets();
            secrets.Values.Add(oldReference, new("old-user", "old-password"));
            await store.SaveAsync(new() { Profiles = [new() { Name = "Original", CredentialsRef = oldReference }] }, CancellationToken.None);
            await using var vm = Create(store, secrets); await vm.InitializeAsync();
            vm.SelectedProfile = vm.Profiles.Single(); vm.ReplaceCredentials = true;
            vm.ProfileUsername = "new-user"; vm.ProfilePassword = "new-password";
            await vm.SaveProfileCommand.ExecuteAsync(null);
            var newReference = vm.Profiles.Single().CredentialsRef;
            Assert.NotEqual(oldReference, newReference);
            Assert.True(secrets.Values.ContainsKey(oldReference)); Assert.True(secrets.Values.ContainsKey(newReference!));
            Assert.Empty(secrets.Deleted);
            Assert.Empty(vm.ProfilePassword); Assert.Empty(vm.ProfileUsername);
            await File.WriteAllTextAsync(path, "{damaged");
            var recovered = await store.LoadAsync(CancellationToken.None);
            Assert.Equal(oldReference, recovered.Profiles.Single().CredentialsRef);
            Assert.Equal("old-password", (await secrets.GetAsync(oldReference, CancellationToken.None))!.Password);
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
    }

    [Fact]
    public async Task FailedEngineBlocksMutationsUntilExplicitStop()
    {
        var store = new MemoryStore(new()); var engine = new FakeEngine { State = EngineState.Failed };
        await using var vm = Create(store, new(), engine); await vm.InitializeAsync();
        Assert.False(vm.CanEdit); Assert.True(vm.CanStop);
        vm.ProfileName = "Pending"; await vm.SaveProfileCommand.ExecuteAsync(null);
        Assert.Equal(0, store.SaveCalls);
        await vm.StopCommand.ExecuteAsync(null);
        Assert.True(vm.CanEdit); Assert.False(vm.CanStop);
        await vm.SaveProfileCommand.ExecuteAsync(null);
        Assert.Equal("Pending", Assert.Single(store.Configuration.Profiles).Name);
    }

    [Fact]
    public async Task MultiProcessRulesDeduplicateNamesAndPathsWithoutPretendingPidSupport()
    {
        ProcessInfo[] processes =
        [
            new(101, "Discord.exe", @"C:\Apps\Discord.exe", DateTimeOffset.UtcNow),
            new(102, "discord.exe", @"C:\Apps\Discord.exe", DateTimeOffset.UtcNow),
            new(103, "Discord.exe", @"D:\Other\Discord.exe", DateTimeOffset.UtcNow)
        ];
        var profile = new ProxyProfile { Name = "Local test" };
        var store = new MemoryStore(new() { Profiles = [profile] });
        await using var vm = Create(store, new(), processes: processes); await vm.InitializeAsync();
        foreach (var p in vm.Processes) vm.SelectedProcesses.Add(p);
        await vm.CreateNameRulesCommand.ExecuteAsync(null);
        var nameRule = Assert.Single(store.Configuration.Rules);
        Assert.Equal(SelectorKind.ProcessName, nameRule.Selector.Kind);
        Assert.Null(nameRule.Selector.Instance);
        await vm.CreatePathRulesCommand.ExecuteAsync(null);
        Assert.Equal(3, store.Configuration.Rules.Count);
        Assert.Equal(2, store.Configuration.Rules.Count(r => r.Selector.Kind == SelectorKind.ExecutablePath));
        Assert.All(store.Configuration.Rules, r =>
        {
            Assert.Equal(NetworkTransport.Tcp, r.Network); Assert.Equal(profile.Id, r.ProfileId);
            Assert.Equal(FailurePolicy.Block, r.OnProxyFailure); Assert.False(r.IncludeChildren);
        });
    }

    [Fact]
    public async Task InaccessibleProcessPathDoesNotCreateMisleadingPathRule()
    {
        var store = new MemoryStore(new() { Profiles = [new()] });
        await using var vm = Create(store, new(), processes: [new(42, "protected.exe", null, null)]);
        await vm.InitializeAsync(); vm.SelectedProcesses.Add(vm.Processes.Single());
        await vm.CreatePathRulesCommand.ExecuteAsync(null);
        Assert.Empty(store.Configuration.Rules); Assert.Equal(0, store.SaveCalls);
        Assert.Contains("недоступен", vm.Notice);
    }

    private static MainWindowViewModel Create(IConfigurationStore store, MemorySecrets secrets, FakeEngine? engine = null,
        IReadOnlyList<ProcessInfo>? processes = null, IProxyDiagnostics? diagnostics = null) => new(store, secrets,
            new FakeProcesses(processes ?? []), diagnostics ?? new FakeDiagnostics(), engine ?? new());

    private sealed class MemoryStore(ProxyConfiguration configuration) : IConfigurationStore
    {
        public ProxyConfiguration Configuration { get; private set; } = configuration;
        public bool FailSave { get; init; }
        public int SaveCalls { get; private set; }
        public Task<ProxyConfiguration> LoadAsync(CancellationToken ct) => Task.FromResult(Configuration);
        public Task SaveAsync(ProxyConfiguration next, CancellationToken ct)
        {
            SaveCalls++;
            if (FailSave) throw new IOException("Failure details new-password must not reach UI or logs.");
            Configuration = next; return Task.CompletedTask;
        }
    }
    private sealed class MemorySecrets : ISecretStore
    {
        public Dictionary<string, ProxyCredentials> Values { get; } = [];
        public List<string> Deleted { get; } = [];
        public Task<string> StoreAsync(ProxyCredentials credentials, CancellationToken ct)
        { var reference = Guid.NewGuid().ToString("N"); Values.Add(reference, credentials); return Task.FromResult(reference); }
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult(Values.GetValueOrDefault(reference));
        public Task DeleteAsync(string reference, CancellationToken ct) { Values.Remove(reference); Deleted.Add(reference); return Task.CompletedTask; }
    }
    private sealed class FakeProcesses(IReadOnlyList<ProcessInfo> processes) : IProcessDiscoveryService
    { public Task<IReadOnlyList<ProcessInfo>> GetProcessesAsync(CancellationToken ct) => Task.FromResult(processes); }
    private sealed class FakeDiagnostics : IProxyDiagnostics
    {
        public Task<DiagnosticResult> TestTcpAsync(ProxyProfile profile, string targetHost, int targetPort, CancellationToken ct) => throw new NotSupportedException();
        public Task<DiagnosticResult> TestUdpAssociateAsync(ProxyProfile profile, CancellationToken ct) => throw new NotSupportedException();
    }
    private sealed class FakeEngine : IProxyEngineAdapter
    {
        public Exception? StartFailure { get; init; }
        public Exception? StopFailure { get; set; }
        public TaskCompletionSource? StartGate { get; init; }
        public bool KeepRunningAfterStop { get; set; }
        public int StopCalls { get; private set; }
        public EngineState State { get; set; } = EngineState.Stopped;
        public Task<EngineCapabilities> GetCapabilitiesAsync(CancellationToken ct) => Task.FromResult(new EngineCapabilities(
            SupportStatus.NotVerified, SupportStatus.NotVerified, SupportStatus.Unsupported, SupportStatus.Unsupported,
            SupportStatus.NotVerified, SupportStatus.Unsupported, SupportStatus.Unsupported));
        public Task<ConfigValidationResult> ValidateAsync(ProxyConfiguration config, CancellationToken ct) => Task.FromResult(ConfigurationValidator.Validate(config));
        public async Task StartAsync(ProxyConfiguration config, CancellationToken ct)
        {
            if (StartFailure is not null) throw StartFailure;
            if (StartGate is not null) await StartGate.Task.WaitAsync(ct);
            State = EngineState.Running;
        }
        public Task StopAsync(CancellationToken ct)
        {
            StopCalls++;
            if (StopFailure is not null) throw StopFailure;
            if (!KeepRunningAfterStop) State = EngineState.Stopped;
            return Task.CompletedTask;
        }
        public Task<EngineStatus> GetStatusAsync(CancellationToken ct) => Task.FromResult(new EngineStatus(State, "Test engine; no network changes."));
    }
}
