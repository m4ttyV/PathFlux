using System.Diagnostics;
using System.IO.Pipes;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
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
    using var pipe = new NamedPipeClientStream(".", args[1], PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
    using (var connectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(45))) await pipe.ConnectAsync(connectTimeout.Token);
    if (!Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out uint serverPid) || serverPid != parentPid) return 5;
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
                reply = await session.StartAsync(request.Configuration, request.Credentials ?? [], idle.Token);
                break;
            case "status": reply = new(true, session.Status); break;
            case "stop":
                session.Stop();
                await AgentProtocol.WriteAsync(pipe, new AgentReply(session.Status.State == EngineState.Stopped, session.Status), idle.Token);
                return 0;
            default: reply = new(false, new(EngineState.Failed, "Операция агента отклонена.")); break;
        }
        await AgentProtocol.WriteAsync(pipe, reply, idle.Token);
    }
}
catch { return 1; } // Never persist raw exception messages or IPC payloads.
return 0;

internal static class Native
{
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);
}
