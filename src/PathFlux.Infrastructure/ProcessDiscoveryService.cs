using System.ComponentModel;
using System.Diagnostics;
using PathFlux.Application;
using PathFlux.Domain;

namespace PathFlux.Infrastructure;

public sealed class ProcessDiscoveryService : IProcessDiscoveryService
{
    public Task<IReadOnlyList<ProcessInfo>> GetProcessesAsync(CancellationToken ct) => Task.Run<IReadOnlyList<ProcessInfo>>(() =>
    {
        ct.ThrowIfCancellationRequested();
        var processes = Process.GetProcesses();
        try
        {
            var result = new List<ProcessInfo>(processes.Length);
            foreach (var process in processes)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var pid = process.Id;
                    var name = Read(() => process.ProcessName) ?? "Недоступен";
                    var executable = Read(() => process.MainModule?.FileName);
                    var started = Read<DateTimeOffset?>(() => new DateTimeOffset(process.StartTime.ToUniversalTime()));
                    if (OperatingSystem.IsWindows() && !name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) name += ".exe";
                    result.Add(new ProcessInfo(pid, name, executable, started));
                }
                catch (InvalidOperationException) { /* Process exited during enumeration. */ }
                catch (Win32Exception) { /* Protected or already exited process. */ }
            }
            return result.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ThenBy(p => p.Pid).ToArray();
        }
        finally { foreach (var process in processes) process.Dispose(); }
    }, ct);

    private static T? Read<T>(Func<T> read)
    {
        try { return read(); }
        catch (Win32Exception) { return default; }
        catch (InvalidOperationException) { return default; }
        catch (NotSupportedException) { return default; }
    }
}
