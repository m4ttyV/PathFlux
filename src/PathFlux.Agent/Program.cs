using System.Diagnostics;
using System.Security.Principal;
using PathFlux.Agent;
using PathFlux.Application;
using PathFlux.Domain;
using PathFlux.Engine;

if (!OperatingSystem.IsWindows() || args.Length != 6 || args[0] != "--pipe" || args[2] != "--parent" || args[4] != "--started" ||
    !args[1].StartsWith("PathFlux-", StringComparison.Ordinal) || !Guid.TryParseExact(args[1][9..], "N", out _) ||
    !int.TryParse(args[3], out int parentPid) || !long.TryParse(args[5], out long started)) return 2;
using var identity = WindowsIdentity.GetCurrent();
if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) return 3;
// Named event creation is atomic and its lifetime is not tied to an async continuation's thread.
using var singletonEvent = new EventWaitHandle(false, EventResetMode.ManualReset, @"Global\PathFlux.NetworkAgent.Lifetime.v1", out bool created);
if (!created) return 4;
using var session = new EngineSession();
try
{
    using var parent = Process.GetProcessById(parentPid);
    if (parent.StartTime.ToUniversalTime().Ticks != started) return 5;
    using var pipe = WindowsAgentChannel.CreateClient(args[1]);
    using (var connectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(45))) await pipe.ConnectAsync(connectTimeout.Token);
    WindowsAgentChannel.VerifyServer(pipe, parentPid);
    bool startedOnce = false;
    while (!parent.HasExited && pipe.IsConnected)
    {
        using var idle = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var request = await AgentProtocol.ReadAsync<AgentRequest>(pipe, idle.Token);
        AgentReply reply;
        switch (request.Operation)
        {
            case "start" when !startedOnce && request.Configuration is not null:
                startedOnce = true;
                using (var startup = new CancellationTokenSource(TimeSpan.FromSeconds(60)))
                    reply = await session.StartAsync(request.Configuration, request.Credentials ?? [], startup.Token);
                break;
            case "status": reply = new(true, session.Status); break;
            case "stop":
                await session.StopAsync(idle.Token);
                await AgentProtocol.WriteAsync(pipe, new AgentReply(session.Status.State == EngineState.Stopped, session.Status), idle.Token);
                return 0;
            default: reply = new(false, new(EngineState.Failed, "Операция агента отклонена.")); break;
        }
        using var replyTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await AgentProtocol.WriteAsync(pipe, reply, replyTimeout.Token);
    }
}
catch (UnauthorizedAccessException) { return 6; }
catch (IOException) { return 7; }
catch (OperationCanceledException) { return 8; }
catch { return 1; } // Never persist raw exception messages or IPC payloads.
return 0;
