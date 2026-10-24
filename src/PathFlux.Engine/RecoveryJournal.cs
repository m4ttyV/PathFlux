using System.Security.AccessControl;
using System.Text.Json;
namespace PathFlux.Engine;

public static class RecoveryJournal
{
    public sealed record CleanupArchive(string Path, bool GlobalBaselineMatched);
    public static async Task<CleanupArchive> VerifyOwnedCleanupAndArchiveAsync(string path, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        bool matched;
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            if (!document.RootElement.TryGetProperty("SchemaVersion", out var schema) || schema.GetInt32() != 1 ||
                !document.RootElement.TryGetProperty("Baseline", out var baselineJson)) throw new InvalidOperationException("NoRecoveryBaseline");
            var baseline = baselineJson.Deserialize<WindowsNetworkState>() ?? throw new InvalidOperationException("InvalidRecoveryBaseline");
            if (baseline.Routes is null || baseline.Adapters is null) throw new InvalidOperationException("InvalidRecoveryBaseline");
            EnsureNoAgent();
            // Do not finalize evidence while an engine may still own sockets or recreate its interface.
            EnsureRecordedEngineExited(document.RootElement);
            var current = await WindowsNetworkState.CaptureAsync(ct);
            if (current.OwnedCleanupIssues(SingBoxConfigGenerator.InterfaceName).Length != 0)
                throw new InvalidOperationException("PathFluxResourcesRemain");
            matched = baseline.RecoveryIssues(current, SingBoxConfigGenerator.InterfaceName).Length == 0;
            EnsureNoAgent();
        }
        // Preserve the original bytes, including topology and baseline, when unrelated network changes exist.
        string archive = path + (matched ? ".verified-" : ".unconfirmed-network-change-") + Guid.NewGuid().ToString("N");
        File.Move(path, archive, false);
        return new(archive, matched);
    }
    internal static bool IsRecordedEngineRunning(int pid, long startedUtcTicks)
    {
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(pid);
            return !process.HasExited && process.StartTime.ToUniversalTime().Ticks == startedUtcTicks;
        }
        catch (ArgumentException) { return false; }
        catch (InvalidOperationException) { return false; }
    }
    private static void EnsureRecordedEngineExited(JsonElement root)
    {
        if (root.TryGetProperty("EnginePid", out var pid))
        {
            if (!pid.TryGetInt32(out int id) || id < 1 || !root.TryGetProperty("EngineStartedUtcTicks", out var started) || !started.TryGetInt64(out long ticks) || ticks < 1)
                throw new InvalidOperationException("InvalidRecordedEngineIdentity");
            if (IsRecordedEngineRunning(id, ticks)) throw new InvalidOperationException("EngineStillRunning");
        }
        else
        {
            // Legacy evidence has no process identity: keep the conservative rule for those files only.
            foreach (var process in System.Diagnostics.Process.GetProcessesByName("sing-box"))
                using (process) { if (!process.HasExited) throw new InvalidOperationException("LegacyEngineIdentityUnknown"); }
        }
    }
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
