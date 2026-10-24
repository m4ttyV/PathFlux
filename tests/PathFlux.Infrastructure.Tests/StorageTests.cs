using System.Security.Cryptography;
using System.Text;
using PathFlux.Domain;
using PathFlux.Infrastructure;

namespace PathFlux.Infrastructure.Tests;

public sealed class StorageTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "PathFlux.Tests", Guid.NewGuid().ToString("N"));
    private string FilePath => Path.Combine(_directory, "configuration.json");
    private readonly CancellationToken _ct = CancellationToken.None;

    [Fact]
    public async Task ConfigurationRoundtripUsesOnlyOpaqueCredentialReferences()
    {
        var store = new JsonConfigurationStore(FilePath);
        var profile = new ProxyProfile { Name = "Test", CredentialsRef = Guid.NewGuid().ToString("N") };
        var rule = new RoutingRule { ProfileId = profile.Id };
        var config = new ProxyConfiguration { Profiles = [profile], Rules = [rule] };
        await store.SaveAsync(config, _ct);
        var loaded = await new JsonConfigurationStore(FilePath).LoadAsync(_ct);
        Assert.Equal(profile, Assert.Single(loaded.Profiles));
        Assert.Equal(rule, Assert.Single(loaded.Rules));
        var json = await File.ReadAllTextAsync(FilePath, _ct);
        Assert.Contains("credentialsRef", json);
        Assert.DoesNotContain("password", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("username", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SavingTwiceRetainsPreviousValidConfiguration()
    {
        var store = new JsonConfigurationStore(FilePath);
        await store.SaveAsync(Config("first"), _ct);
        await store.SaveAsync(Config("second"), _ct);
        Assert.Equal("second", Assert.Single((await store.LoadAsync(_ct)).Profiles).Name);
        Assert.Equal("first", Assert.Single((await new JsonConfigurationStore(FilePath + ".bak").LoadAsync(_ct)).Profiles).Name);
        Assert.Empty(Directory.GetFiles(_directory, "*.tmp"));
    }

    [Theory]
    [InlineData("{broken")]
    [InlineData("{\"schemaVersion\":\"broken\"}")]
    [InlineData("{\"schemaVersion\":1,\"profiles\":null}")]
    public async Task CorruptionRecoveryPreservesBackupAndDamagedOriginal(string damaged)
    {
        var store = new JsonConfigurationStore(FilePath);
        await store.SaveAsync(Config("recovery"), _ct);
        await store.SaveAsync(Config("latest"), _ct);
        await File.WriteAllTextAsync(FilePath, damaged, _ct);
        Assert.Equal("recovery", Assert.Single((await store.LoadAsync(_ct)).Profiles).Name);
        Assert.Equal(damaged, await File.ReadAllTextAsync(FilePath, _ct));
        await store.SaveAsync(Config("after-recovery"), _ct);
        Assert.Equal("recovery", Assert.Single((await new JsonConfigurationStore(FilePath + ".bak").LoadAsync(_ct)).Profiles).Name);
        Assert.Equal(damaged, await File.ReadAllTextAsync(Assert.Single(Directory.GetFiles(_directory, "*.corrupt-*")), _ct));
    }

    [Fact]
    public async Task FutureSchemaNeverFallsBackOrGetsOverwritten()
    {
        var store = new JsonConfigurationStore(FilePath);
        await store.SaveAsync(Config("backup"), _ct);
        await store.SaveAsync(Config("old"), _ct);
        const string future = "{\"schemaVersion\":999,\"newData\":\"preserve\"}";
        await File.WriteAllTextAsync(FilePath, future, _ct);
        await Assert.ThrowsAsync<NotSupportedException>(() => store.LoadAsync(_ct));
        await Assert.ThrowsAsync<NotSupportedException>(() => store.SaveAsync(Config("replacement"), _ct));
        Assert.Equal(future, await File.ReadAllTextAsync(FilePath, _ct));
    }

    [Fact]
    public async Task FutureBackupIsPreservedEvenWhenPrimaryIsCorrupt()
    {
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(FilePath, "broken", _ct);
        const string future = "{\"schemaVersion\":2}";
        await File.WriteAllTextAsync(FilePath + ".bak", future, _ct);
        var store = new JsonConfigurationStore(FilePath);
        await Assert.ThrowsAsync<NotSupportedException>(() => store.LoadAsync(_ct));
        await Assert.ThrowsAsync<NotSupportedException>(() => store.SaveAsync(Config("replacement"), _ct));
        Assert.Equal(future, await File.ReadAllTextAsync(FilePath + ".bak", _ct));
        Assert.Equal("broken", await File.ReadAllTextAsync(FilePath, _ct));
    }

    [Fact]
    public async Task InvalidConfigurationWithoutBackupFailsAndDoesNotEraseData()
    {
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(FilePath, "invalid sensitive-value", _ct);
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => new JsonConfigurationStore(FilePath).LoadAsync(_ct));
        Assert.DoesNotContain("sensitive-value", error.Message);
        Assert.Equal("invalid sensitive-value", await File.ReadAllTextAsync(FilePath, _ct));
    }

    [Fact]
    public async Task CancellationDoesNotReplaceExistingConfiguration()
    {
        var store = new JsonConfigurationStore(FilePath);
        await store.SaveAsync(Config("valid"), _ct);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.SaveAsync(Config("new"), new CancellationToken(true)));
        Assert.Equal("valid", Assert.Single((await store.LoadAsync(_ct)).Profiles).Name);
    }

    [Fact]
    public async Task MissingPrimaryCanRecoverFromBackup()
    {
        var store = new JsonConfigurationStore(FilePath);
        await store.SaveAsync(Config("saved"), _ct);
        File.Move(FilePath, FilePath + ".bak");
        Assert.Equal("saved", Assert.Single((await store.LoadAsync(_ct)).Profiles).Name);
    }

    [Fact]
    public async Task CredentialsReferencedByRecoveryCopyAreRetainedUntilBackupRotates()
    {
        var store = new JsonConfigurationStore(FilePath);
        var oldReference = Guid.NewGuid().ToString("N");
        var newReference = Guid.NewGuid().ToString("N");
        await store.SaveAsync(new() { Profiles = [new() { CredentialsRef = oldReference }] }, _ct);
        await store.SaveAsync(new() { Profiles = [new() { CredentialsRef = newReference }] }, _ct);
        Assert.True(await store.IsReferencedAsync(oldReference, _ct));
        Assert.True(await store.IsReferencedAsync(newReference, _ct));
        await store.SaveAsync(new() { Profiles = [new() { CredentialsRef = newReference }] }, _ct);
        Assert.False(await store.IsReferencedAsync(oldReference, _ct));
        Assert.True(await store.IsReferencedAsync(newReference, _ct));
    }

    [Fact]
    public async Task UnreadableRecoveryDataConservativelyRetainsCredentials()
    {
        var store = new JsonConfigurationStore(FilePath);
        Assert.False(await store.IsReferencedAsync("unused", _ct));
        await store.SaveAsync(Config("valid"), _ct);
        Assert.False(await store.IsReferencedAsync("unused", _ct));
        await File.WriteAllTextAsync(FilePath, "damaged", _ct);
        Assert.True(await store.IsReferencedAsync("unused", _ct));
        await store.SaveAsync(Config("replacement"), _ct);
        Assert.True(await store.IsReferencedAsync("unused", _ct));
    }

    [Fact]
    public async Task FutureRecoveryDataConservativelyRetainsCredentials()
    {
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(FilePath + ".bak", "{\"schemaVersion\":99}", _ct);
        Assert.True(await new JsonConfigurationStore(FilePath).IsReferencedAsync("unused", _ct));
    }

    [WindowsFact]
    public async Task DpapiRoundtripEncryptsCredentialsAtRestAndDeletionIsIdempotent()
    {
        var store = new DpapiSecretStore(_directory);
        var credentials = new ProxyCredentials("private-user-98", "private-password-73");
        var reference = await store.StoreAsync(credentials, _ct);
        Assert.True(Guid.TryParseExact(reference, "N", out _));
        Assert.Equal(credentials, await new DpapiSecretStore(_directory).GetAsync(reference, _ct));
        var bytes = await File.ReadAllBytesAsync(Assert.Single(Directory.GetFiles(_directory)), _ct);
        Assert.DoesNotContain(credentials.Password, Encoding.UTF8.GetString(bytes));
        Assert.DoesNotContain(credentials.Username, Encoding.Unicode.GetString(bytes));
        await store.DeleteAsync(reference, _ct);
        await store.DeleteAsync(reference, _ct);
        Assert.Null(await store.GetAsync(reference, _ct));
    }

    [WindowsTheory]
    [InlineData("../outside")]
    [InlineData("00000000000000000000000000000000")]
    [InlineData("a/b")]
    public async Task SecretReferencesCannotEscapeDirectory(string reference)
    {
        var store = new DpapiSecretStore(_directory);
        await Assert.ThrowsAsync<ArgumentException>(() => store.GetAsync(reference, _ct));
        await Assert.ThrowsAsync<ArgumentException>(() => store.DeleteAsync(reference, _ct));
    }

    [WindowsFact]
    public async Task CorruptDpapiDataFailsWithoutLeakingContents()
    {
        Directory.CreateDirectory(_directory);
        var reference = Guid.NewGuid().ToString("N");
        await File.WriteAllTextAsync(Path.Combine(_directory, reference + ".bin"), "private-corrupt-value", _ct);
        var error = await Assert.ThrowsAsync<CryptographicException>(() => new DpapiSecretStore(_directory).GetAsync(reference, _ct));
        Assert.DoesNotContain("private-corrupt-value", error.Message);
    }

    [Fact]
    public async Task ProcessEnumerationHandlesProtectedProcessesAndCancellation()
    {
        var processes = await new ProcessDiscoveryService().GetProcessesAsync(_ct);
        Assert.Contains(processes, p => p.Pid == Environment.ProcessId);
        Assert.All(processes, p => Assert.NotNull(p.Name));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new ProcessDiscoveryService().GetProcessesAsync(new CancellationToken(true)));
    }

    private static ProxyConfiguration Config(string name) => new() { Profiles = [new ProxyProfile { Name = name }] };
    public void Dispose() { if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true); }
}

internal sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute() { if (!OperatingSystem.IsWindows()) Skip = "Windows DPAPI integration test."; }
}
internal sealed class WindowsTheoryAttribute : TheoryAttribute
{
    public WindowsTheoryAttribute() { if (!OperatingSystem.IsWindows()) Skip = "Windows DPAPI integration test."; }
}
