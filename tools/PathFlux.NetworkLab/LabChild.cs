using System.Diagnostics;
using System.Text.Json;
namespace PathFlux.NetworkLab;

public static class LabChild
{
    public static async Task<ProbeResult> RunAsync(string executable, string[] args, CancellationToken ct, TimeSpan? timeout = null)
    {
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args) info.ArgumentList.Add(arg);
        using var child = Process.Start(info) ?? throw new InvalidOperationException("ProbeLaunchFailed");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(timeout ?? TimeSpan.FromSeconds(12));
        try
        {
            var stdout = child.StandardOutput.ReadToEndAsync(deadline.Token);
            var stderr = child.StandardError.BaseStream.CopyToAsync(Stream.Null, deadline.Token);
            await child.WaitForExitAsync(deadline.Token); await stderr;
            return JsonSerializer.Deserialize<ProbeResult>(await stdout) ?? new(false, "InvalidProbeReply");
        }
        finally { if (!child.HasExited) { child.Kill(true); await child.WaitForExitAsync(CancellationToken.None); } }
    }
}
