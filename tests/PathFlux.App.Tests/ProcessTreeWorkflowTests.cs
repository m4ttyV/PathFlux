using PathFlux.Domain;

namespace PathFlux.App.Tests;

public sealed partial class WorkflowTests
{
    [Fact] public async Task PidTreeEditorPreservesRootIdentityAndExplicitOptIn()
    {
        var profile=new ProxyProfile(); var started=DateTimeOffset.UtcNow;
        var store=new MemoryStore(new(){Profiles=[profile]});
        await using var vm=Create(store,new(),processes:[new(42,"root.exe",@"C:\Apps\root.exe",started,SequenceNumber:4242)]);
        await vm.InitializeAsync(); vm.SelectedProcesses.Add(vm.Processes.Single());
        await vm.CreatePidTreeRulesCommand.ExecuteAsync(null); Assert.Empty(store.Configuration.Rules);
        vm.ExperimentalProcessTrees=true; await vm.SaveSettingsCommand.ExecuteAsync(null);
        await vm.CreatePidTreeRulesCommand.ExecuteAsync(null);
        var rule=Assert.Single(store.Configuration.Rules); Assert.True(rule.IncludeChildren);
        Assert.Equal(new ProcessInstanceId(42,started,4242),rule.Selector.Instance); Assert.True(vm.RuleIncludeChildren);
        vm.RuleName="Изменённое дерево"; await vm.SaveRuleCommand.ExecuteAsync(null);
        var saved=Assert.Single(store.Configuration.Rules); Assert.Equal(rule.Selector,saved.Selector); Assert.True(saved.IncludeChildren);
        vm.NewRuleCommand.Execute(null); Assert.False(vm.RuleIncludeChildren);
    }
}
