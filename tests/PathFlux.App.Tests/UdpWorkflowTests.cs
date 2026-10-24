using PathFlux.Application;
using PathFlux.Domain;

namespace PathFlux.App.Tests;

public sealed partial class WorkflowTests
{
    [Fact]
    public async Task MalformedMaximumTimestampCannotOverflowProfileStatusOrCrashInitialization()
    {
        var profile = VerifiedProfile();
        profile = profile with { UdpVerification = profile.UdpVerification! with { CheckedAtUtc = DateTimeOffset.MaxValue } };
        var store = new MemoryStore(new() { Profiles = [profile] });
        await using var vm = Create(store, new()); await vm.InitializeAsync();
        Assert.True(vm.IsInitialized);
        vm.SelectedProfile = vm.Profiles.Single();
        Assert.Contains("неактуальна", vm.ProfileUdpStatus);
        Assert.Contains("неактуальна", vm.DiagnosticUdpStatus);
        Assert.DoesNotContain("до ", vm.DiagnosticUdpStatus);
        Assert.Equal(0, store.SaveCalls);
    }
    [Fact]
    public async Task SuccessfulEchoSavesEvidenceAndStatsWithoutEnablingUdpRouting()
    {
        var profile = new ProxyProfile { Name = "Controlled SOCKS" };
        var rule = new RoutingRule { ProfileId = profile.Id, Network = NetworkTransport.Both };
        var store = new MemoryStore(new() { Profiles = [profile], Rules = [rule] });
        var diagnostics = new EchoDiagnostics((p, options) => Task.FromResult(Probe(p, options)));
        await using var vm = Create(store, new(), diagnostics: diagnostics); await vm.InitializeAsync();
        Assert.Empty(vm.UdpEchoHost); Assert.Empty(vm.UdpEchoPort);
        vm.UdpEchoHost = "127.0.0.1"; vm.UdpEchoPort = "39001";
        await vm.TestUdpEchoCommand.ExecuteAsync(null);
        var saved = store.Configuration.Profiles.Single();
        Assert.True(UdpVerificationPolicy.IsCurrent(saved, DateTimeOffset.UtcNow));
        Assert.Equal(saved, vm.DiagnosticProfile);
        Assert.Equal(rule, store.Configuration.Rules.Single());
        Assert.Equal(3, diagnostics.LastOptions!.PacketCount);
        Assert.Contains("Отправлено: 3; получено точных ответов: 3", vm.DiagnosticText);
        Assert.Contains("Средний RTT", vm.DiagnosticText);
        Assert.Contains("TUN, DNS и Discord voice не проверены", vm.DiagnosticText);
        Assert.Contains("не включает экспериментальный UDP автоматически", vm.DiagnosticText);
        Assert.False(store.Configuration.Settings.ExperimentalSocksUdp);
        Assert.Contains("15 минут", vm.DiagnosticUdpStatus);
        Assert.Equal(1, store.SaveCalls);
    }

    [Fact]
    public async Task FailedEchoReplacesPreviousSuccessWithHistoricalFailure()
    {
        var original = VerifiedProfile();
        var store = new MemoryStore(new() { Profiles = [original] });
        var diagnostics = new EchoDiagnostics((p, options) => Task.FromResult(Probe(p, options, success: false)));
        await using var vm = Create(store, new(), diagnostics: diagnostics); await vm.InitializeAsync();
        vm.UdpEchoHost = "127.0.0.1"; vm.UdpEchoPort = "39001";
        await vm.TestUdpEchoCommand.ExecuteAsync(null);
        var saved = store.Configuration.Profiles.Single();
        Assert.Equal(UdpRelayStatus.Failed, saved.UdpVerification!.Status);
        Assert.False(UdpVerificationPolicy.IsCurrent(saved, DateTimeOffset.UtcNow));
        Assert.Equal(0, saved.UdpVerification.ReceivedPackets);
        Assert.Contains("UDP echo не подтверждён", vm.DiagnosticUdpStatus);
        Assert.Contains("нет подтверждённых ответов", vm.DiagnosticText);
        Assert.Equal(1, store.SaveCalls);
    }

    [Theory]
    [InlineData("host")]
    [InlineData("port")]
    [InlineData("protocol")]
    [InlineData("credentials")]
    public async Task EditingProfileIdentityClearsPersistedEchoProof(string changedField)
    {
        var profile = VerifiedProfile(); var secrets = new MemorySecrets();
        var store = new MemoryStore(new() { Profiles = [profile] });
        await using var vm = Create(store, secrets); await vm.InitializeAsync();
        vm.SelectedProfile = vm.Profiles.Single();
        switch (changedField)
        {
            case "host": vm.ProfileHost = "127.0.0.2"; break;
            case "port": vm.ProfilePort = "1081"; break;
            case "protocol": vm.ProfileProtocol = ProxyProtocol.HttpConnect; break;
            case "credentials": vm.ReplaceCredentials = true; vm.ProfileUsername = "new-user"; vm.ProfilePassword = "new-password"; break;
        }
        Assert.Contains("изменены", vm.ProfileUdpStatus);
        await vm.SaveProfileCommand.ExecuteAsync(null);
        Assert.Null(store.Configuration.Profiles.Single().UdpVerification);
        Assert.Null(vm.SelectedProfile!.UdpVerification);
        Assert.Contains("не проверялась", vm.ProfileUdpStatus);
    }

    [Fact]
    public async Task CosmeticProfileChangesKeepProofButDuplicationClearsIt()
    {
        var profile = VerifiedProfile(); var store = new MemoryStore(new() { Profiles = [profile] });
        await using var vm = Create(store, new()); await vm.InitializeAsync();
        vm.SelectedProfile = vm.Profiles.Single(); vm.ProfileName = "Renamed"; vm.ProfileEnabled = false;
        await vm.SaveProfileCommand.ExecuteAsync(null);
        Assert.Equal(profile.UdpVerification, store.Configuration.Profiles.Single().UdpVerification);
        vm.DuplicateProfileCommand.Execute(null); await vm.SaveProfileCommand.ExecuteAsync(null);
        Assert.Equal(2, store.Configuration.Profiles.Count);
        Assert.Null(store.Configuration.Profiles.Single(p => p.Id != profile.Id).UdpVerification);
        Assert.Equal(profile.UdpVerification, store.Configuration.Profiles.Single(p => p.Id == profile.Id).UdpVerification);
    }

    [Theory]
    [InlineData("")]
    [InlineData("echo.example.com")]
    [InlineData("0.0.0.0")]
    [InlineData("255.255.255.255")]
    public async Task EchoRequiresExplicitUsableLiteralIpBeforeSending(string target)
    {
        var store = new MemoryStore(new() { Profiles = [new()] });
        var diagnostics = new EchoDiagnostics((p, options) => Task.FromResult(Probe(p, options)));
        await using var vm = Create(store, new(), diagnostics: diagnostics); await vm.InitializeAsync();
        vm.UdpEchoHost = target; vm.UdpEchoPort = "39001";
        await vm.TestUdpEchoCommand.ExecuteAsync(null);
        Assert.Equal(0, diagnostics.Calls); Assert.Equal(0, store.SaveCalls);
        Assert.Null(store.Configuration.Profiles.Single().UdpVerification);
    }

    [Fact]
    public async Task EchoCannotMutateProfilesWhileEngineIsRunning()
    {
        var store = new MemoryStore(new() { Profiles = [new()] });
        var diagnostics = new EchoDiagnostics((p, options) => Task.FromResult(Probe(p, options)));
        var engine = new FakeEngine { State = EngineState.Running };
        await using var vm = Create(store, new(), engine, diagnostics: diagnostics); await vm.InitializeAsync();
        vm.UdpEchoHost = "127.0.0.1"; vm.UdpEchoPort = "39001";
        await vm.TestUdpEchoCommand.ExecuteAsync(null);
        Assert.Equal(0, diagnostics.Calls); Assert.Equal(0, store.SaveCalls);
        Assert.Contains("остановите", vm.Notice);
    }

    [Fact]
    public async Task EvidenceForDifferentProfileCannotBeSaved()
    {
        var store = new MemoryStore(new() { Profiles = [new()] });
        var diagnostics = new EchoDiagnostics((p, options) => Task.FromResult(Probe(p, options) with
        { Evidence = Probe(p with { Port = 1081 }, options).Evidence }));
        await using var vm = Create(store, new(), diagnostics: diagnostics); await vm.InitializeAsync();
        vm.UdpEchoHost = "127.0.0.1"; vm.UdpEchoPort = "39001";
        await vm.TestUdpEchoCommand.ExecuteAsync(null);
        Assert.Equal(0, store.SaveCalls); Assert.Null(store.Configuration.Profiles.Single().UdpVerification);
        Assert.Contains("не сохранён", vm.Notice);
    }

    [Fact]
    public async Task EchoPersistenceFailureKeepsPreviousProofAndHidesExceptionSecrets()
    {
        var profile = VerifiedProfile(); var store = new MemoryStore(new() { Profiles = [profile] }) { FailSave = true };
        var diagnostics = new EchoDiagnostics((p, options) => Task.FromResult(Probe(p, options, success: false)));
        await using var vm = Create(store, new(), diagnostics: diagnostics); await vm.InitializeAsync();
        vm.UdpEchoHost = "127.0.0.1"; vm.UdpEchoPort = "39001";
        await vm.TestUdpEchoCommand.ExecuteAsync(null);
        Assert.Equal(profile, vm.DiagnosticProfile); Assert.Equal(profile, store.Configuration.Profiles.Single());
        Assert.Contains("Не удалось сохранить", vm.DiagnosticText);
        Assert.DoesNotContain("new-password", vm.Notice);
        Assert.DoesNotContain(vm.LogEntries, line => line.Contains("new-password"));
    }

    [Fact]
    public async Task EchoProtocolExceptionsNeverReachUiOrLog()
    {
        const string sensitive = "user:private-secret-password";
        var store = new MemoryStore(new() { Profiles = [new()] });
        var diagnostics = new EchoDiagnostics((_, _) => throw new IOException(sensitive));
        await using var vm = Create(store, new(), diagnostics: diagnostics); await vm.InitializeAsync();
        vm.UdpEchoHost = "127.0.0.1"; vm.UdpEchoPort = "39001";
        await vm.TestUdpEchoCommand.ExecuteAsync(null);
        Assert.Equal(0, store.SaveCalls);
        Assert.DoesNotContain(sensitive, vm.Notice); Assert.DoesNotContain(sensitive, vm.DiagnosticText);
        Assert.DoesNotContain(vm.LogEntries, line => line.Contains(sensitive));
    }

    private static ProxyProfile VerifiedProfile()
    {
        var profile = new ProxyProfile { Name = "Previously verified" };
        return profile with { UdpVerification = Probe(profile, new("127.0.0.1", 39001)).Evidence };
    }
    private static UdpRelayProbeResult Probe(ProxyProfile profile, UdpProbeOptions options, bool success = true) => new(success,
        success ? "UdpEcho" : "UdpEchoTimeout", success ? "Получены точные ответы." : "Ответы не получены.",
        new(UdpVerificationPolicy.Fingerprint(profile), DateTimeOffset.UtcNow, success ? UdpRelayStatus.Verified : UdpRelayStatus.Failed,
            options.TargetHost, options.TargetPort, options.PacketCount, success ? options.PacketCount : 0, success ? 2.5 : null));
    private sealed class EchoDiagnostics(Func<ProxyProfile, UdpProbeOptions, Task<UdpRelayProbeResult>> probe) : IProxyDiagnostics, IUdpRelayDiagnostics
    {
        public int Calls { get; private set; }
        public UdpProbeOptions? LastOptions { get; private set; }
        public Task<UdpRelayProbeResult> TestUdpRelayAsync(ProxyProfile profile, UdpProbeOptions options, CancellationToken ct)
        { Calls++; LastOptions = options; return probe(profile, options); }
        public Task<DiagnosticResult> TestTcpAsync(ProxyProfile profile, string targetHost, int targetPort, CancellationToken ct) => throw new NotSupportedException();
        public Task<DiagnosticResult> TestUdpAssociateAsync(ProxyProfile profile, CancellationToken ct) => throw new NotSupportedException();
    }
}
