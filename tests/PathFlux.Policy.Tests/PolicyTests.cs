using PathFlux.Application;
using PathFlux.Domain;
using Xunit;

namespace PathFlux.Policy.Tests;

public sealed class PolicyTests
{
    private static readonly Guid FirstId = Guid.Parse("00000000-0000-0000-0000-000000000001");
    private static readonly Guid SecondId = Guid.Parse("00000000-0000-0000-0000-000000000002");
    private static readonly ProxyProfile Profile = new() { Id = Guid.Parse("20000000-0000-0000-0000-000000000001"), Name = "Local SOCKS5" };
    private static RoutingRule ProxyRule() => new() { ProfileId = Profile.Id, Network = NetworkTransport.Tcp };
    private static CompiledPolicy Compile(params RoutingRule[] rules) => new RuleCompiler().Compile(rules, [Profile]);
    private static void HasError(CompiledPolicy policy, string code)
    {
        Assert.False(policy.IsValid);
        Assert.Empty(policy.Rules);
        Assert.Contains(policy.Issues, issue => issue.Code == code && !issue.IsWarning);
    }

    [Fact]
    public void PriorityAndUuidProduceStableFirstMatchOrderAcrossInputPermutations()
    {
        var first = ProxyRule() with { Id = FirstId, Priority = 100 };
        var second = ProxyRule() with { Id = SecondId, Priority = 100 };
        var higherPriority = ProxyRule() with { Priority = -10 };
        var result = Compile(second, higherPriority, first);
        var permuted = Compile(first, second, higherPriority);
        Assert.True(result.IsValid);
        Assert.Equal(new[] { higherPriority.Id, FirstId, SecondId }, result.Rules.Select(rule => rule.Id));
        Assert.Equal(result.Rules.Select(rule => rule.Id), permuted.Rules.Select(rule => rule.Id));
    }

    [Fact]
    public void DisabledUnsupportedDraftDoesNotBlockActiveRulesOrReappearInCompiledTable()
    {
        var draft = ProxyRule() with
        {
            Enabled = false, ProfileId = Guid.NewGuid(), IncludeChildren = true,
            Selector = new(SelectorKind.ProcessInstance, "PID", new(42, DateTimeOffset.UtcNow)),
            Lifetime = RuleLifetime.UntilProcessExit, OnProxyFailure = FailurePolicy.Direct
        };
        var active = ProxyRule();
        var result = Compile(draft, active);
        Assert.True(result.IsValid);
        Assert.Equal(active, Assert.Single(result.Rules));
    }

    [Fact]
    public void DisabledRuleStillRequiresUniquePersistentIdentity()
    {
        var first = ProxyRule() with { Id = FirstId, Enabled = false };
        HasError(Compile(first, first with { Name = "duplicate" }), "rule.id");
    }

    [Fact]
    public void DuplicateProfileIdsCannotChooseAnArbitraryOutbound()
    {
        var result = new RuleCompiler().Compile([ProxyRule()], [Profile, Profile with { Host = "other.example" }]);
        HasError(result, "profile.id");
        Assert.Empty(result.Profiles);
    }

    [Fact]
    public void MissingProxyProfileCannotBecomeDirect()
        => HasError(Compile(ProxyRule() with { ProfileId = Guid.NewGuid() }), "rule.profile.missing");

    [Fact]
    public void DisabledProfileCannotBeReferencedByEnabledRule()
        => HasError(new RuleCompiler().Compile([ProxyRule()], [Profile with { Enabled = false }]), "rule.profile.disabled");

    [Fact]
    public void UnusedDisabledProfileIsExcludedFromEnginePolicy()
    {
        var result = new RuleCompiler().Compile([], [Profile with { Enabled = false }]);
        Assert.True(result.IsValid);
        Assert.Empty(result.Profiles);
    }

    [Theory]
    [InlineData(RouteAction.Direct)]
    [InlineData(RouteAction.Block)]
    public void DirectAndBlockDoNotRequireAProxyProfile(RouteAction action)
    {
        var rule = ProxyRule() with { Action = action, ProfileId = null };
        Assert.True(new RuleCompiler().Compile([rule], []).IsValid);
        HasError(Compile(rule with { ProfileId = Profile.Id }), "rule.profile.unexpected");
    }

    [Theory]
    [InlineData(NetworkTransport.Tcp)]
    [InlineData(NetworkTransport.Udp)]
    [InlineData(NetworkTransport.Both)]
    public void UnsupportedDirectFallbackIsNeverSilentlyAccepted(NetworkTransport transport)
        => HasError(Compile(ProxyRule() with { Network = transport, OnProxyFailure = FailurePolicy.Direct }), "fallback.unsupported");

    [Theory]
    [InlineData(NetworkTransport.Udp)]
    [InlineData(NetworkTransport.Both)]
    public void ProxyUdpAlwaysExplainsThatItWillBeBlocked(NetworkTransport transport)
    {
        var result = Compile(ProxyRule() with { Network = transport });
        Assert.True(result.IsValid);
        Assert.Contains(result.Issues, issue => issue.Code == "udp.unverified" && issue.IsWarning);
        Assert.Equal(FailurePolicy.Block, Assert.Single(result.Rules).OnProxyFailure);
    }

    [Fact]
    public void ProcessInstanceIsRejectedWithoutConvertingItToProcessName()
    {
        var rule = ProxyRule() with { Selector = new(SelectorKind.ProcessInstance, "Discord.exe", new(10, DateTimeOffset.UtcNow)) };
        HasError(Compile(rule), "pid.unsupported");
    }

    [Fact]
    public void ChildrenAndUntilExitAreRejected()
    {
        HasError(Compile(ProxyRule() with { IncludeChildren = true }), "children.unsupported");
        HasError(Compile(ProxyRule() with { Lifetime = RuleLifetime.UntilProcessExit }), "lifetime.unsupported");
    }

    [Fact]
    public void PersistentSelectorCannotSmuggleAProcessInstance()
        => HasError(Compile(ProxyRule() with { Selector = new(SelectorKind.ProcessName, "app.exe", new(1, DateTimeOffset.UtcNow)) }), "selector.instance");

    [Theory]
    [InlineData("Discord.exe")]
    [InlineData("APP.EXE")]
    [InlineData("my app.exe")]
    public void ExeNamesAreAccepted(string name)
        => Assert.True(Compile(ProxyRule() with { Selector = new(SelectorKind.ProcessName, name) }).IsValid);

    [Theory]
    [InlineData("Discord")]
    [InlineData("*.exe")]
    [InlineData("C:\\App\\Discord.exe")]
    [InlineData("../app.exe")]
    [InlineData("app.exe ")]
    public void ProcessNameCannotBeAPathOrWildcard(string name)
        => HasError(Compile(ProxyRule() with { Selector = new(SelectorKind.ProcessName, name) }), "selector.name");

    [Theory]
    [InlineData("C:\\Apps\\Discord.exe")]
    [InlineData("D:/Apps/Discord.exe")]
    [InlineData("\\\\server\\share\\App\\Discord.exe")]
    public void AbsoluteWindowsExePathsDoNotRequireFilesToExistDuringCompilation(string path)
        => Assert.True(Compile(ProxyRule() with { Selector = new(SelectorKind.ExecutablePath, path) }).IsValid);

    [Theory]
    [InlineData("Discord.exe")]
    [InlineData("C:Discord.exe")]
    [InlineData("C:\\Apps\\..\\Discord.exe")]
    [InlineData("%APPDATA%\\Discord.exe")]
    [InlineData("C:\\Apps\\*.exe")]
    [InlineData("C:\\Apps\\Discord.dll")]
    public void RelativeAndAmbiguousExePathsAreRejected(string path)
        => HasError(Compile(ProxyRule() with { Selector = new(SelectorKind.ExecutablePath, path) }), "selector.path");

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("proxy.example")]
    public void HostCanBeDnsOrAnUnbracketedIpAddress(string host)
        => Assert.True(new RuleCompiler().Compile([], [Profile with { Host = host }]).IsValid);

    [Theory]
    [InlineData("http://proxy.example")]
    [InlineData("user:pass@proxy.example")]
    [InlineData("proxy.example:1080")]
    [InlineData(" proxy.example")]
    [InlineData("proxy.example/path")]
    [InlineData("[::1]")]
    [InlineData("")]
    public void HostCannotContainAnEndpointUriOrCredentials(string host)
        => HasError(new RuleCompiler().Compile([], [Profile with { Host = host }]), "profile.host");

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    public void InvalidPortsAreRejected(int port)
        => HasError(new RuleCompiler().Compile([], [Profile with { Port = port }]), "profile.port");

    [Fact]
    public void TlsNameIsRestrictedToHttpsConnectAndValidHostSyntax()
    {
        HasError(new RuleCompiler().Compile([], [Profile with { TlsServerName = "proxy.example" }]), "profile.tls.protocol");
        HasError(new RuleCompiler().Compile([], [Profile with { Protocol = ProxyProtocol.HttpsConnect, TlsServerName = "https://proxy.example" }]), "profile.tls.name");
        Assert.True(new RuleCompiler().Compile([], [Profile with { Protocol = ProxyProtocol.HttpsConnect, TlsServerName = "proxy.example" }]).IsValid);
    }

    [Fact]
    public void ActiveOverlapIsDiagnosticAndEarlierBlockRetainsPrecedence()
    {
        var block = ProxyRule() with { Action = RouteAction.Block, ProfileId = null, Priority = 0 };
        var proxy = ProxyRule() with { Priority = 1 };
        var result = Compile(proxy, block);
        Assert.True(result.IsValid);
        Assert.Equal(block.Id, result.Rules[0].Id);
        Assert.Contains(result.Issues, issue => issue.Code == "rule.overlap" && issue.RuleId == proxy.Id && issue.IsWarning);
    }

    [Fact]
    public void MalformedSettingsAndUnknownSchemaCannotBeApplied()
    {
        var result = ConfigurationValidator.Validate(new() { SchemaVersion = 99, DefaultAction = RouteAction.Proxy, Settings = new() { DnsMode = "Unimplemented", ProcessRefreshSeconds = 0 } });
        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue => issue.Code == "schema.unsupported");
        Assert.Contains(result.Issues, issue => issue.Code == "default.unsupported");
        Assert.Contains(result.Issues, issue => issue.Code == "dns.unsupported");
        Assert.Contains(result.Issues, issue => issue.Code == "settings.refresh");
    }

    [Fact]
    public void MalformedDeserializedListsProduceValidationErrors()
    {
        Assert.False(ConfigurationValidator.Validate(new() { Profiles = null!, Rules = null! }).IsValid);
        Assert.False(ConfigurationValidator.Validate(new() { Profiles = [null!], Rules = [null!] }).IsValid);
        Assert.False(ConfigurationValidator.Validate(new() { Settings = null! }).IsValid);
    }

    [Fact]
    public void UnknownEnumValuesAndMissingSelectorsAreRejected()
    {
        HasError(Compile(ProxyRule() with { Network = (NetworkTransport)999 }), "rule.network");
        HasError(Compile(ProxyRule() with { Action = (RouteAction)999, ProfileId = null }), "rule.action");
        HasError(Compile(ProxyRule() with { Selector = null! }), "selector.required");
        HasError(new RuleCompiler().Compile([], [Profile with { Protocol = (ProxyProtocol)999 }]), "profile.protocol");
    }

    [Fact]
    public async Task CancellationPreventsCompilation()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new RuleCompiler().CompileAsync([], [], cancellation.Token));
    }
}
