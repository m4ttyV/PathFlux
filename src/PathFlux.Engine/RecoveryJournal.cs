using System.Security.AccessControl;
using System.Text.Json;
namespace PathFlux.Engine;

public static class RecoveryJournal
{
    public static string DefaultPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PathFlux", "network-recovery.json");
    public static bool HasPendingBaseline(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var json = JsonDocument.Parse(stream);
            return json.RootElement.TryGetProperty("Baseline", out _) || !json.RootElement.TryGetProperty("SchemaVersion", out var schema) || schema.GetInt32() != 1;
        }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
        catch { return true; } // Corrupt, locked or inaccessible evidence cannot confirm recovery.
    }

    public static async Task<string> VerifyAndArchiveAsync(string path, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        // Hold the journal exclusively: a concurrent start sees pending/inaccessible evidence and aborts before TUN.
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            if (!document.RootElement.TryGetProperty("Baseline", out var baselineJson)) throw new InvalidOperationException("NoRecoveryBaseline");
            var baseline = baselineJson.Deserialize<WindowsNetworkState>() ?? throw new InvalidOperationException("InvalidRecoveryBaseline");
            EnsureNoAgent();
            if (baseline.RecoveryIssues(await WindowsNetworkState.CaptureAsync(ct), SingBoxConfigGenerator.InterfaceName).Length != 0)
                throw new InvalidOperationException("NetworkRecoveryDoesNotMatchBaseline");
            EnsureNoAgent();
        }
        var archive = path + ".verified-" + Guid.NewGuid().ToString("N");
        File.Move(path, archive, false);
        return archive;
    }
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void EnsureNoAgent()
    {
        try
        {
            using var lifetime = EventWaitHandleAcl.OpenExisting(@"Global\PathFlux.NetworkAgent.Lifetime.v1", EventWaitHandleRights.Synchronize);
            throw new InvalidOperationException("AgentStillRunning");
        }
        catch (WaitHandleCannotBeOpenedException) { }
    }
}
