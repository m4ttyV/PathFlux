using PathFlux.Domain;

namespace PathFlux.App.Tests;

public sealed partial class WorkflowTests
{
    [Fact]
    public async Task TrayExitWaitsForPendingStartBeforeStopping()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var engine = new FakeEngine { StartGate = gate };
        await using var vm = Create(new MemoryStore(new()), new(), engine);
        await vm.InitializeAsync();
        var start = vm.StartCommand.ExecuteAsync(null);
        var exit = vm.TryStopForExitAsync();
        Assert.False(exit.IsCompleted);
        Assert.Equal(0, engine.StopCalls);
        gate.SetResult();
        await start;
        Assert.True(await exit);
        Assert.Equal(1, engine.StopCalls);
        Assert.False(vm.EngineActive);
    }

    [Fact]
    public async Task TrayExitRequiresConfirmedCleanupAndAllowsRetry()
    {
        var engine = new FakeEngine { State = EngineState.Failed, KeepRunningAfterStop = true };
        await using var vm = Create(new MemoryStore(new()), new(), engine);
        await vm.InitializeAsync();
        Assert.False(await vm.TryStopForExitAsync());
        Assert.True(vm.CanStop);
        Assert.Contains("Выход отложен", vm.Notice);
        engine.KeepRunningAfterStop = false;
        Assert.True(await vm.TryStopForExitAsync());
        Assert.Equal(2, engine.StopCalls);
        Assert.False(vm.EngineActive);
    }

    [Fact]
    public async Task TrayExitKeepsRecoveryAvailableAfterStopExceptionWithoutLeakingDetails()
    {
        var engine = new FakeEngine { State = EngineState.Running, StopFailure = new InvalidOperationException("private-upstream-secret") };
        await using var vm = Create(new MemoryStore(new()), new(), engine);
        await vm.InitializeAsync();
        Assert.False(await vm.TryStopForExitAsync());
        Assert.True(vm.CanStop);
        Assert.DoesNotContain("private-upstream-secret", vm.Notice);
        Assert.DoesNotContain(vm.LogEntries, line => line.Contains("private-upstream-secret"));
        engine.StopFailure = null;
        Assert.True(await vm.TryStopForExitAsync());
    }
}
