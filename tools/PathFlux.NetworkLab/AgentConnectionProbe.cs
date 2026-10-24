using System.Diagnostics;
using PathFlux.Domain;
using PathFlux.Engine;
namespace PathFlux.NetworkLab;

public static class AgentConnectionProbe
{
    // Does not send start, configuration or credentials. Exercises the actual elevated agent only.
    public static async Task RunAsync(string agentPath, CancellationToken ct)
    {
        var name = "PathFlux-" + Guid.NewGuid().ToString("N");
        using var pipe = WindowsAgentChannel.CreateServer(name);
        using var agent = Process.Start(WindowsAgentChannel.CreateStartInfo(agentPath, name))
            ?? throw new InvalidOperationException("Агент не запущен.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(60));
        var connected = pipe.WaitForConnectionAsync(deadline.Token);
        var exited = agent.WaitForExitAsync(deadline.Token);
        if (await Task.WhenAny(connected, exited) == exited)
            throw new InvalidOperationException(WindowsAgentChannel.DescribeExit(agent.ExitCode));
        await connected;
        WindowsAgentChannel.VerifyClient(pipe, agent.Id);
        await AgentProtocol.WriteAsync(pipe, new AgentRequest("status"), deadline.Token);
        var status = await AgentProtocol.ReadAsync<AgentReply>(pipe, deadline.Token);
        if (!status.Success || status.Status.State != EngineState.Stopped) throw new InvalidOperationException("Неожиданное состояние агента.");
        await AgentProtocol.WriteAsync(pipe, new AgentRequest("stop"), deadline.Token);
        var stopped = await AgentProtocol.ReadAsync<AgentReply>(pipe, deadline.Token);
        if (!stopped.Success) throw new InvalidOperationException("Агент не подтвердил остановку.");
        await agent.WaitForExitAsync(deadline.Token);
        if (agent.ExitCode != 0) throw new InvalidOperationException(WindowsAgentChannel.DescribeExit(agent.ExitCode));
    }
}
