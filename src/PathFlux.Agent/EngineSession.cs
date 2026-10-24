using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using PathFlux.Application;
using PathFlux.Domain;
using PathFlux.Engine;
namespace PathFlux.Agent;

internal sealed class EngineSession : IDisposable
{
    private Process? engine;
    private bool engineStarted;
    private SafeFileHandle? job;
    private FileStream? binaryLock;
    private Task? drainOutput, drainError;
    private string? journal;
    private EngineState state = EngineState.Stopped;
    public EngineStatus Status => engineStarted && engine is not null && engine.HasExited
        ? new(EngineState.Failed, "Движок аварийно завершился. Проверьте сеть; системный kill switch отсутствует.")
        : new(state, state == EngineState.Failed ? "Очистка TUN не подтверждена. Проверьте network-recovery.json и recovery-инструкцию." : state == EngineState.Degraded
            ? "TUN запущен. Selective TCP требует Windows-проверки; UDP заблокирован, DNS системный."
            : "Движок остановлен.", engine?.Id);

    public async Task<AgentReply> StartAsync(ProxyConfiguration config, Dictionary<string, ProxyCredentials> credentials, CancellationToken ct)
    {
        if (engine is not null) return new(false, new(EngineState.Failed, "Повторный запуск отклонён."));
        try
        {
            var validation = ConfigurationValidator.Validate(config);
            if (!validation.IsValid) return new(false, new(EngineState.Failed, "Агент отклонил конфигурацию."));
            // Elevated process verifies independently and holds executable open (denies writes and deletion).
            EngineBinary.EnsurePath(config.Settings.EnginePath);
            binaryLock = new FileStream(config.Settings.EnginePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            await EngineBinary.VerifyAsync(config.Settings.EnginePath, config.Settings.EngineSha256, ct);
            if (NetworkInterface.GetAllNetworkInterfaces().Any(i => i.Name == SingBoxConfigGenerator.InterfaceName))
                throw new InvalidOperationException("Интерфейс PathFlux-TUN уже существует. Выполните recovery перед запуском.");
            string json = await new SingBoxConfigGenerator(new MemorySecrets(credentials)).GenerateAsync(config, ct);
            if (!await EngineBinary.CheckAsync(config.Settings.EnginePath, json, ct))
                throw new InvalidOperationException("sing-box check отклонил конфигурацию.");
            string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PathFlux");
            Directory.CreateDirectory(directory);
            journal = Path.Combine(directory, "network-recovery.json");
            // The engine owns routes, addresses and DNS of a new transient TUN; existing adapters are not edited.
            await File.WriteAllTextAsync(journal, JsonSerializer.Serialize(new NetworkStateRecoveryMetadata(1, Environment.ProcessId, DateTimeOffset.UtcNow, SingBoxConfigGenerator.InterfaceName, "Starting; transient TUN addresses/routes/DNS; original adapters unchanged; firewall unchanged")), ct);
            job = CreateJobObject(IntPtr.Zero, null);
            if (job.IsInvalid) throw new InvalidOperationException("Не удалось создать Windows Job Object.");
            var limits = new JobExtendedLimitInformation { BasicLimitInformation = new() { LimitFlags = 0x2000 /* KILL_ON_JOB_CLOSE */ } };
            if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<JobExtendedLimitInformation>()))
                throw new InvalidOperationException("Не удалось настроить надзор за движком.");
            engine = new Process { StartInfo = EngineBinary.CreateStartInfo(config.Settings.EnginePath, "run") };
            engine.Start();
            engineStarted = true;
            // The child cannot load config or change routes before stdin is completed below.
            if (!AssignProcessToJobObject(job, engine.Handle)) throw new InvalidOperationException("Не удалось изолировать процесс движка.");
            drainOutput = engine.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
            drainError = engine.StandardError.BaseStream.CopyToAsync(Stream.Null);
            await engine.StandardInput.WriteAsync(json.AsMemory(), ct); engine.StandardInput.Close();
            await Task.Delay(1800, ct);
            if (engine.HasExited || !NetworkInterface.GetAllNetworkInterfaces().Any(i => i.Name == SingBoxConfigGenerator.InterfaceName))
                throw new InvalidOperationException("TUN не запустился. Проверьте права, конфликт адресов и инструкцию sing-box.");
            state = EngineState.Degraded; // A running process does not prove process-based routing.
            return new(true, Status);
        }
        catch (Exception ex)
        {
            Stop(); state = EngineState.Failed;
            // All strings created here are fixed. Underlying exception text may include secrets and is suppressed.
            return new(false, new(EngineState.Failed, ex is InvalidOperationException ? ex.Message : $"Ошибка агента ({ex.GetType().Name})."));
        }
    }
    public void Stop()
    {
        state = EngineState.Stopping;
        try
        {
            if (engineStarted && engine is not null && !engine.HasExited) { engine.Kill(true); engine.WaitForExit(5000); }
        }
        finally
        {
            job?.Dispose(); job = null;
            engine?.Dispose(); engine = null;
            engineStarted = false;
            binaryLock?.Dispose(); binaryLock = null;
            state = EngineState.Stopped;
            // Preserve journal if cleanup cannot be confirmed; never delete arbitrary routes or interfaces.
            if (journal is not null)
            {
                bool remains = NetworkInterface.GetAllNetworkInterfaces().Any(i => i.Name == SingBoxConfigGenerator.InterfaceName);
                if (!remains) { try { File.Delete(journal); } catch (IOException) { } }
                else state = EngineState.Failed;
            }
        }
    }
    public void Dispose() => Stop();
    private sealed class MemorySecrets(Dictionary<string, ProxyCredentials> values) : ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult(values.GetValueOrDefault(reference));
        public Task<string> StoreAsync(ProxyCredentials credentials, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }
    [StructLayout(LayoutKind.Sequential)] private struct JobBasicLimitInformation
    { public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)] private struct JobExtendedLimitInformation
    { public JobBasicLimitInformation BasicLimitInformation; public IoCounters IoInfo; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateJobObject(IntPtr attrs, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetInformationJobObject(SafeFileHandle job, int infoClass, ref JobExtendedLimitInformation info, uint length);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
}
