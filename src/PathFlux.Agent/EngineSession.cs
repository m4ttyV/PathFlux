using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text.Json;
using PathFlux.Application;
using PathFlux.Domain;
using PathFlux.Engine;
namespace PathFlux.Agent;

internal sealed class EngineSession : IDisposable
{
    private Process? engine;
    private bool engineStarted;
    private WindowsProcessJob? job;
    private FileStream? binaryLock;
    private Task? drainOutput, drainError;
    private string? journal;
    private WindowsNetworkState? networkBefore;
    private bool networkTouched;
    private bool ownsJournal;
    private string failureMessage = "Ошибка сетевого агента.";
    private EngineState state = EngineState.Stopped;
    public EngineStatus Status => engineStarted && engine is not null && engine.HasExited
        ? new(EngineState.Failed, "Движок аварийно завершился. Проверьте сеть; системный kill switch отсутствует.")
        : new(state, state == EngineState.Failed ? failureMessage : state == EngineState.Degraded
            ? "TUN запущен. Выборочный TCP доступен с ограничениями; UDP заблокирован, DNS системный."
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
            var version = await EngineBinary.VerifyAsync(config.Settings.EnginePath, config.Settings.EngineSha256, ct);
            if (TunInterfaceProbe.RequiresCleanup(SingBoxConfigGenerator.InterfaceName))
                throw new InvalidOperationException("Интерфейс PathFlux-TUN уже существует. Выполните recovery перед запуском.");
            string json = await new SingBoxConfigGenerator(new MemorySecrets(credentials)).GenerateAsync(config, ct, engineVersion: version);
            if (!await EngineBinary.CheckAsync(config.Settings.EnginePath, json, ct))
                throw new InvalidOperationException("sing-box check отклонил конфигурацию.");
            string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PathFlux");
            Directory.CreateDirectory(directory);
            journal = Path.Combine(directory, "network-recovery.json");
            if (RecoveryJournal.HasPendingBaseline(journal))
                throw new InvalidOperationException("Остался неподтверждённый снимок сети. Выполните проверку recovery-журнала перед новым запуском.");
            networkBefore = await WindowsNetworkState.CaptureAsync(ct);
            // The engine owns routes, addresses and DNS of a new transient TUN; existing adapters are not edited.
            var metadata = new NetworkStateRecoveryMetadata(1, Environment.ProcessId, DateTimeOffset.UtcNow, SingBoxConfigGenerator.InterfaceName, "Starting; baseline recorded; firewall unchanged");
            await File.WriteAllTextAsync(journal + ".tmp", JsonSerializer.Serialize(new { metadata.SchemaVersion, metadata.AgentPid, metadata.StartedUtc, metadata.InterfaceName, metadata.State, Baseline = networkBefore }), ct);
            if (File.Exists(journal)) File.Copy(journal, journal + ".previous", true);
            File.Move(journal + ".tmp", journal, true); ownsJournal = true;
            job = new WindowsProcessJob();
            engine = new Process { StartInfo = EngineBinary.CreateStartInfo(config.Settings.EnginePath, "run") };
            engine.Start();
            engineStarted = true;
            // The child cannot load config or change routes before stdin is completed below.
            job.Assign(engine);
            drainOutput = engine.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
            drainError = engine.StandardError.BaseStream.CopyToAsync(Stream.Null);
            networkTouched = true;
            await engine.StandardInput.WriteAsync(json.AsMemory(), ct); engine.StandardInput.Close();
            var readiness = Stopwatch.StartNew();
            while (!engine.HasExited && !TunInterfaceProbe.IsReady(SingBoxConfigGenerator.InterfaceName) && readiness.Elapsed < TimeSpan.FromSeconds(12))
                await Task.Delay(200, ct);
            if (engine.HasExited)
                throw new InvalidOperationException($"sing-box завершился при запуске TUN (код {engine.ExitCode}). Проверьте конфликты сети и доступ к драйверу Wintun.");
            if (!TunInterfaceProbe.IsReady(SingBoxConfigGenerator.InterfaceName))
                throw new InvalidOperationException("TUN не стал готов за 12 секунд. Проверьте права, конфликт адресов и доступ к Wintun.");
            state = EngineState.Degraded; // A running process does not prove process-based routing.
            return new(true, Status);
        }
        catch (Exception ex)
        {
            await StopAsync(CancellationToken.None);
            string cleanupFailure = state == EngineState.Failed ? " Очистка сети не подтверждена; сохранён network-recovery.json." : "";
            state = EngineState.Failed;
            // All strings created here are fixed. Underlying exception text may include secrets and is suppressed.
            failureMessage = (ex is InvalidOperationException ? ex.Message : $"Ошибка агента ({ex.GetType().Name}).") + cleanupFailure;
            return new(false, Status);
        }
    }
    public async Task StopAsync(CancellationToken ct)
    {
        state = EngineState.Stopping;
        try
        {
            if (engineStarted && engine is not null && !engine.HasExited)
            {
                engine.Kill(true);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(5));
                await engine.WaitForExitAsync(deadline.Token);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or OperationCanceledException) { }
        finally
        {
            job?.Dispose(); job = null;
            engine?.Dispose(); engine = null;
            engineStarted = false;
            binaryLock?.Dispose(); binaryLock = null;
            state = EngineState.Stopped;
            // Never reset routes: compare the baseline and retain the journal on any uncertainty.
            if (networkTouched && networkBefore is not null)
            {
                state = EngineState.Failed;
                failureMessage = "Восстановление маршрутов, DNS или адресов не подтверждено. Сохранён network-recovery.json.";
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(12));
                try
                {
                    for (int i = 0; i < 3; i++)
                    {
                        var after = await WindowsNetworkState.CaptureAsync(deadline.Token);
                        var issues = networkBefore.RecoveryIssues(after, SingBoxConfigGenerator.InterfaceName);
                        if (issues.Length == 0) { state = EngineState.Stopped; networkTouched = false; break; }
                        failureMessage = "Очистка сети не подтверждена: " + string.Join(", ", issues) + ". Сохранён network-recovery.json.";
                        await Task.Delay(250, deadline.Token);
                    }
                }
                catch { /* Unknown state remains Failed; raw OS diagnostics are never exposed. */ }
            }
            if (state == EngineState.Stopped && ownsJournal && journal is not null)
                try { File.Delete(journal); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
    public void Dispose() => StopAsync(CancellationToken.None).GetAwaiter().GetResult();
    private sealed class MemorySecrets(Dictionary<string, ProxyCredentials> values) : ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult(values.GetValueOrDefault(reference));
        public Task<string> StoreAsync(ProxyCredentials credentials, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }
}
