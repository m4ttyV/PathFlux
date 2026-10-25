using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Text.Json;
using PathFlux.Application;
using PathFlux.Domain;
using PathFlux.Engine;
namespace PathFlux.Agent;

internal sealed class EngineSession : IDisposable, IAsyncDisposable
{
    private readonly SemaphoreSlim operations = new(1, 1);
    private AgentUdpBridges? udpBridges;
    private CancellationTokenSource? monitorStop;
    private Task? monitor;
    private IReadOnlyList<UdpBridgeStatistics> lastUdp = [];
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
    private string stoppedMessage = "Движок остановлен.";
    private EngineState state = EngineState.Stopped;
    private bool processTreesActive;
    // Only the explicit elevated NetworkLab mode can inject this fault; no production IPC operation exposes it.
    internal void FailUdpForLaboratory(Guid profileId) => udpBridges?.Bridges[profileId].FailClosed();
    public async Task<EngineStatus> GetStatusAsync(CancellationToken ct)
    {
        await operations.WaitAsync(ct);
        try { return Status; } finally { operations.Release(); }
    }
    public EngineStatus Status => engineStarted && engine is not null && engine.HasExited
        ? new(EngineState.Failed, "Движок аварийно завершился. Проверьте сеть; системный kill switch отсутствует.", Udp: udpBridges?.Snapshot() ?? lastUdp)
        : new(state, (state == EngineState.Failed ? failureMessage : state == EngineState.Degraded
            ? processTreesActive ? "TUN запущен. Дерево PID: TCP Experimental; TCP-правило не охватывает UDP, DNS системный."
                : udpBridges?.Bridges.Count > 0 ? "TUN запущен. UDP Experimental: проверяйте статистику; Discord не принят, DNS системный, kill switch отсутствует."
                : "TUN запущен. Выборочный TCP доступен с ограничениями; UDP заблокирован, DNS системный."
            : stoppedMessage) + (udpBridges?.TcpBridges.Count > 0 ? " " + string.Join(" ", udpBridges.TcpBridges.Values.Select(b => b.Diagnostic)) : ""), engine?.Id, udpBridges?.Snapshot() ?? lastUdp);

    public async Task<AgentReply> StartAsync(ProxyConfiguration config, Dictionary<string, ProxyCredentials> credentials, CancellationToken ct)
    {
        await operations.WaitAsync(ct);
        try { return await StartCoreAsync(config, credentials, ct); }
        finally { operations.Release(); }
    }
    private async Task<AgentReply> StartCoreAsync(ProxyConfiguration config, Dictionary<string, ProxyCredentials> credentials, CancellationToken ct)
    {
        if (engine is not null) return new(false, new(EngineState.Failed, "Повторный запуск отклонён."));
        try
        {
            var validation = ConfigurationValidator.ValidateEngineActivation(config);
            if (!validation.IsValid) return new(false, new(EngineState.Failed, "Агент отклонил конфигурацию."));
            processTreesActive = config.Settings.ExperimentalProcessTrees && config.Rules.Any(r => r.Enabled && (r.IncludeChildren || r.Selector.Kind == SelectorKind.ProcessInstance));
            // Elevated process verifies independently and holds executable open (denies writes and deletion).
            EngineBinary.EnsurePath(config.Settings.EnginePath);
            binaryLock = new FileStream(config.Settings.EnginePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var version = await EngineBinary.VerifyAsync(config.Settings.EnginePath, config.Settings.EngineSha256, ct);
            if (config.Settings.ExperimentalProcessTrees) await EngineBinary.VerifyProcessTreeBackendAsync(config.Settings.EnginePath, ct);
            if (TunInterfaceProbe.RequiresCleanup(SingBoxConfigGenerator.InterfaceName))
                throw new InvalidOperationException("Интерфейс PathFlux-TUN уже существует. Выполните recovery перед запуском.");
            var memorySecrets = new MemorySecrets(credentials);
            udpBridges = await AgentUdpBridges.CreateAsync(config, memorySecrets, ct);
            lastUdp = [];
            string json = await new SingBoxConfigGenerator(memorySecrets).GenerateAgentAsync(config, udpBridges.Bridges, ct, version, udpBridges.TcpBridges, config.Settings.ExperimentalProcessTrees);
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
            await File.WriteAllTextAsync(journal + ".tmp", JsonSerializer.Serialize(new { metadata.SchemaVersion, metadata.AgentPid, metadata.StartedUtc,
                metadata.InterfaceName, metadata.State, EnginePid = engine.Id, EngineStartedUtcTicks = engine.StartTime.ToUniversalTime().Ticks, Baseline = networkBefore }), ct);
            File.Move(journal + ".tmp", journal, true);
            drainOutput = engine.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
            drainError = engine.StandardError.BaseStream.CopyToAsync(Stream.Null);
            networkTouched = true;
            await engine.StandardInput.WriteAsync(json.AsMemory(), ct); engine.StandardInput.Close();
            var readiness = Stopwatch.StartNew();
            bool routesReady = false;
            while (!engine.HasExited && readiness.Elapsed < TimeSpan.FromSeconds(15))
            {
                if (TunInterfaceProbe.IsReady(SingBoxConfigGenerator.InterfaceName))
                {
                    var current = await WindowsNetworkState.CaptureAsync(ct);
                    var own = current.Adapters.FirstOrDefault(a => a.Name == SingBoxConfigGenerator.InterfaceName && !a.Detached);
                    string[] prefixes = ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"];
                    routesReady = own is not null && prefixes.All(prefix => current.Routes.Any(r => r.InterfaceIndex == own.InterfaceIndex && r.DestinationPrefix == prefix));
                    if (routesReady) break;
                }
                await Task.Delay(200, ct);
            }
            if (engine.HasExited)
                throw new InvalidOperationException($"sing-box завершился при запуске TUN (код {engine.ExitCode}). Проверьте конфликты сети и доступ к драйверу Wintun.");
            if (!routesReady)
                throw new InvalidOperationException("TUN и его маршруты не стали готовы за 15 секунд. Проверьте права, конфликт адресов и доступ к Wintun.");
            state = EngineState.Degraded; // A running process does not prove process-based routing.
            monitorStop?.Dispose(); monitorStop = new();
            monitor = MonitorExitAsync(engine, monitorStop.Token);
            return new(true, Status);
        }
        catch (Exception ex)
        {
            await StopCoreAsync(CancellationToken.None);
            string cleanupFailure = state == EngineState.Failed ? " Очистка сети не подтверждена; сохранён network-recovery.json." : "";
            state = EngineState.Failed;
            // All strings created here are fixed. Underlying exception text may include secrets and is suppressed.
            failureMessage = (ex is InvalidOperationException ? ex.Message : $"Ошибка агента ({ex.GetType().Name}).") + cleanupFailure;
            return new(false, Status);
        }
    }
    public async Task StopAsync(CancellationToken ct)
    {
        await operations.WaitAsync(ct);
        try { await StopCoreAsync(ct); }
        finally { operations.Release(); }
        if (monitor is { } pending) await pending;
    }
    private async Task MonitorExitAsync(Process observed, CancellationToken ct)
    {
        try
        {
            await observed.WaitForExitAsync(ct);
            await operations.WaitAsync(ct);
            try
            {
                if (engine != observed || !engineStarted) return;
                await StopCoreAsync(CancellationToken.None);
                string recovery = state == EngineState.Stopped ? networkTouched ? stoppedMessage : "Восстановление сети подтверждено." : failureMessage;
                state = EngineState.Failed; failureMessage = "Движок аварийно завершился; UDP-посредники остановлены. " + recovery + " Системного kill switch нет.";
            }
            finally { operations.Release(); }
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or InvalidOperationException) { }
    }
    private async Task StopCoreAsync(CancellationToken ct)
    {
        monitorStop?.Cancel();
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
            processTreesActive = false;
            // Stop routing first. Sockets are owned by this agent, never by a detached helper.
            if (udpBridges is not null)
            {
                lastUdp = udpBridges.Snapshot();
                await udpBridges.DisposeAsync();
                lastUdp = lastUdp.Select(s => s with { State = "Stopped", ActiveAssociations = 0 }).ToArray();
                udpBridges = null;
            }
            binaryLock?.Dispose(); binaryLock = null;
            state = EngineState.Stopped;
            stoppedMessage = "Движок остановлен.";
            // Never reset routes: compare the baseline and retain the journal on any uncertainty.
            if (networkTouched && networkBefore is not null)
            {
                state = EngineState.Failed;
                failureMessage = "Восстановление маршрутов, DNS или адресов не подтверждено. Сохранён network-recovery.json.";
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(12));
                try
                {
                    while (!deadline.IsCancellationRequested)
                    {
                        var after = await WindowsNetworkState.CaptureAsync(deadline.Token);
                        var issues = networkBefore.RecoveryIssues(after, SingBoxConfigGenerator.InterfaceName);
                        if (issues.Length == 0) { state = EngineState.Stopped; networkTouched = false; break; }
                        if (after.OwnedCleanupIssues(SingBoxConfigGenerator.InterfaceName).Length == 0)
                        {
                            state = EngineState.Stopped;
                            stoppedMessage = "Движок остановлен, ресурсы PathFlux удалены. Сеть изменилась; исходный снимок сохранён, полное восстановление не подтверждено.";
                            break;
                        }
                        failureMessage = "Очистка сети не подтверждена: " + string.Join(", ", issues) + ". Сохранён network-recovery.json.";
                        await Task.Delay(250, deadline.Token);
                    }
                }
                catch { /* Unknown state remains Failed; raw OS diagnostics are never exposed. */ }
            }
            if (state == EngineState.Stopped && !networkTouched && ownsJournal && journal is not null)
                try { File.Delete(journal); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
    public async ValueTask DisposeAsync() { await StopAsync(CancellationToken.None); monitorStop?.Dispose(); }
    private sealed class MemorySecrets(Dictionary<string, ProxyCredentials> values) : ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult(values.GetValueOrDefault(reference));
        public Task<string> StoreAsync(ProxyCredentials credentials, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }
}
