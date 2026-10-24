using System.Diagnostics;
using PathFlux.Engine;
using System.Text;
namespace PathFlux.NetworkLab;

internal sealed class LabEngine : IAsyncDisposable
{
    private readonly WindowsProcessJob job = new();
    private readonly Process child;
    private bool started;
    private Task output = Task.CompletedTask, error = Task.CompletedTask;
    private LabEngine(string path) => child = new() { StartInfo = EngineBinary.CreateStartInfo(path, "run") };
    public bool HasExited => child.HasExited;
    public void AbortProcess() => child.Kill(true);
    public void CloseOwnerJob() => job.Dispose();
    private readonly StringBuilder diagnostics = new();
    // LabPolicy uses only generated, credential-free profiles; bounded diagnostic is lab-only.
    public string Diagnostic { get { lock (diagnostics) return diagnostics.ToString(); } }
    private async Task CaptureAsync(StreamReader reader)
    {
        var buffer = new char[512]; int count;
        while ((count = await reader.ReadAsync(buffer)) > 0)
            lock (diagnostics) if (diagnostics.Length < 8000) diagnostics.Append(buffer, 0, Math.Min(count, 8000 - diagnostics.Length));
    }
    public static async Task<LabEngine> StartAsync(string path, string json, CancellationToken ct)
    {
        var owner = new LabEngine(path);
        try
        {
            owner.child.Start(); owner.started = true; owner.job.Assign(owner.child);
            owner.output = owner.CaptureAsync(owner.child.StandardOutput);
            owner.error = owner.CaptureAsync(owner.child.StandardError);
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
