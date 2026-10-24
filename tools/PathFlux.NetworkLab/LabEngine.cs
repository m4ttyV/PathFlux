using System.Diagnostics;
using PathFlux.Engine;
namespace PathFlux.NetworkLab;

internal sealed class LabEngine : IAsyncDisposable
{
    private readonly WindowsProcessJob job = new();
    private readonly Process child;
    private bool started;
    private Task output = Task.CompletedTask, error = Task.CompletedTask;
    private LabEngine(string path) => child = new() { StartInfo = EngineBinary.CreateStartInfo(path, "run") };
    public bool HasExited => child.HasExited;
    public static async Task<LabEngine> StartAsync(string path, string json, CancellationToken ct)
    {
        var owner = new LabEngine(path);
        try
        {
            owner.child.Start(); owner.started = true; owner.job.Assign(owner.child);
            owner.output = owner.child.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
            owner.error = owner.child.StandardError.BaseStream.CopyToAsync(Stream.Null);
            await owner.child.StandardInput.WriteAsync(json.AsMemory(), ct); owner.child.StandardInput.Close();
            return owner;
        }
        catch { await owner.DisposeAsync(); throw; }
    }
    public async ValueTask DisposeAsync()
    {
        job.Dispose(); // Kernel kills the bound engine even if this controller crashes.
        try
        {
            if (started) { if (!child.HasExited) child.Kill(true); await child.WaitForExitAsync(CancellationToken.None); }
            await Task.WhenAll(output, error);
        }
        catch (InvalidOperationException) { }
        finally { child.Dispose(); }
    }
}
