using System.Text.Json.Nodes;
using PathFlux.Application;
using PathFlux.Domain;
using PathFlux.Engine;
using Xunit;

namespace PathFlux.Engine.Tests;

public sealed class ProcessTreeConfigTests
{
    private static ProxyConfiguration Config()
    {
        var profile=new ProxyProfile();
        return new(){Profiles=[profile],Rules=[new(){ProfileId=profile.Id,IncludeChildren=true,Network=NetworkTransport.Both,
            Selector=new(SelectorKind.ProcessInstance,"42",new(42,new DateTimeOffset(2026,10,25,0,0,0,TimeSpan.Zero),4242))}],
            Settings=new(){ExperimentalProcessTrees=true}};
    }
    [Fact] public async Task FeatureFlagCannotImpersonateVerifiedBackend()
    {
        var config=Config(); Assert.True(ConfigurationValidator.Validate(config).IsValid);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>new SingBoxConfigGenerator(new NoSecrets()).GenerateAsync(config,default));
        Assert.False(ConfigurationValidator.Validate(config with {Settings=new()}).IsValid);
    }
    [Fact] public async Task PinnedTreeHasBirthIdentityAndFailClosedRuleForBothTransports()
    {
        var config=Config();
        var json=JsonNode.Parse(await new SingBoxConfigGenerator(new NoSecrets()).GenerateValidationAsync(config,default,processTreeBackend:true))!;
        var rules=json["route"]!["rules"]!.AsArray().Where(r=>r?["pathflux_process_tree"] is not null).ToArray();
        Assert.Equal(4,rules.Length);
        Assert.All(rules,r=>{Assert.Equal(42,(int)r!["pathflux_process_tree"]!["pid"]!); Assert.Equal(config.Rules[0].Selector.Instance!.StartTimeUtc.UtcDateTime.ToFileTimeUtc().ToString(System.Globalization.CultureInfo.InvariantCulture),(string?)r["pathflux_process_tree"]!["started"]); Assert.Null(r["process_name"]); Assert.Null(r["process_path"]);});
        Assert.All(rules.Where(r=>(bool?)r!["pathflux_process_tree"]!["unresolved"]==true),r=>Assert.Equal("reject",(string?)r!["action"]));
        Assert.True((bool)json["route"]!["find_process"]!);
    }
    [Fact] public async Task SelfOnlyPidCannotSilentlyIncludeChildren()
    {
        var config=Config(); config=config with {Rules=[config.Rules[0] with {IncludeChildren=false}]};
        var json=JsonNode.Parse(await new SingBoxConfigGenerator(new NoSecrets()).GenerateValidationAsync(config,default,processTreeBackend:true))!;
        Assert.All(json["route"]!["rules"]!.AsArray().Where(r=>r?["pathflux_process_tree"] is not null),r=>Assert.True((bool)r!["pathflux_process_tree"]!["self_only"]!));
    }
    [Fact] public void MismatchedOrMissingIdentityIsRejected()
    {
        var config=Config();
        foreach(var selector in new[]{new ProcessSelector(SelectorKind.ProcessInstance,"43",config.Rules[0].Selector.Instance),new ProcessSelector(SelectorKind.ProcessInstance,"42"),new ProcessSelector(SelectorKind.ProcessInstance,"4",new(4,DateTimeOffset.UtcNow))})
            Assert.Contains(ConfigurationValidator.Validate(config with{Rules=[config.Rules[0] with{Selector=selector}]}).Issues,i=>i.Code=="pid.identity"&&!i.IsWarning);
    }
    [Fact] public void UdpTreeActivationIsBlockedWithoutChangingOrdinaryUdpRules()
    {
        var config=Config();
        Assert.Contains(ConfigurationValidator.ValidateEngineActivation(config).Issues,i=>i.Code=="tree.udp.notVerified"&&!i.IsWarning);
        Assert.True(ConfigurationValidator.ValidateEngineActivation(config with{Rules=[config.Rules[0] with{Network=NetworkTransport.Tcp}]}).IsValid);
        Assert.True(ConfigurationValidator.ValidateEngineActivation(config with{Settings=new(),Rules=[config.Rules[0] with{IncludeChildren=false,Selector=new(SelectorKind.ProcessName,"Discord.exe")}]}).IsValid);
    }
    [EngineFact] public async Task OfficialEngineIsRejectedBeforeAnyTunStart()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(()=>EngineBinary.VerifyProcessTreeBackendAsync(Environment.GetEnvironmentVariable("PATHFLUX_TEST_ENGINE")!,default));
    }
    private sealed class NoSecrets:ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference,CancellationToken ct)=>Task.FromResult<ProxyCredentials?>(null);
        public Task<string> StoreAsync(ProxyCredentials credentials,CancellationToken ct)=>throw new NotSupportedException();
        public Task DeleteAsync(string reference,CancellationToken ct)=>throw new NotSupportedException();
    }
}
