using System.Diagnostics;
using System.IO.Pipes;
using System.Net.NetworkInformation;
using System.Security.AccessControl;
using PathFlux.Application;
using PathFlux.Domain;
namespace PathFlux.Engine;

public sealed class SingBoxEngineAdapter(ISecretStore secrets) : IProxyEngineAdapter, IAsyncDisposable
{
    private readonly string agentExecutablePath = Path.Combine(AppContext.BaseDirectory, "agent", "PathFlux.Agent.exe");
    internal SingBoxEngineAdapter(ISecretStore secrets, string agentPath) : this(secrets)
        => agentExecutablePath = Path.GetFullPath(agentPath);
    private readonly SemaphoreSlim gate = new(1, 1);
    private NamedPipeServerStream? pipe;
    private Process? agent;
    private string? lastStartFailure;
    private EngineStatus status = new(EngineState.Stopped, "Движок остановлен.");
    public Task<EngineCapabilities> GetCapabilitiesAsync(CancellationToken ct) => Task.FromResult(new EngineCapabilities(
        SupportStatus.Partial, SupportStatus.Partial, SupportStatus.Unsupported, SupportStatus.Unsupported,
        SupportStatus.Partial, SupportStatus.Unsupported, SupportStatus.Unsupported));

    public async Task<ConfigValidationResult> ValidateAsync(ProxyConfiguration config, CancellationToken ct)
    {
        var result = ConfigurationValidator.Validate(config);
        if (!result.IsValid) return result;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(20));
        try
        {
            EngineBinary.EnsurePath(config.Settings.EnginePath);
            // Keep the executable locked against replacement until validation completes.
            await using var binaryLock = new FileStream(config.Settings.EnginePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var version = await EngineBinary.VerifyAsync(config.Settings.EnginePath, config.Settings.EngineSha256, timeout.Token);
            string json = await new SingBoxConfigGenerator(secrets).GenerateAsync(config, timeout.Token, engineVersion: version);
            bool valid = await EngineBinary.CheckAsync(config.Settings.EnginePath, json, timeout.Token);
            return new(result.Issues.Concat(valid ? [] : new[] { new ValidationIssue("EngineCheck", "sing-box check отклонил конфигурацию. Секретные сообщения движка скрыты.") }).ToList());
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return new([new("Timeout", "Проверка движка превысила 20 секунд.")]); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        { return new([new("EngineValidation", SafeMessage(ex))]); }
    }
    public async Task StartAsync(ProxyConfiguration config, CancellationToken ct)
    {
        await gate.WaitAsync(ct);
        try
        {
            if (pipe?.IsConnected == true)
            {
                if (status.State == EngineState.Failed) throw new InvalidOperationException("Сначала остановите предыдущую сессию движка.");
                return;
            }
            status = new(EngineState.Starting, "Проверка конфигурации…");
            lastStartFailure = null;
            if (RecoveryJournal.HasPendingBaseline(RecoveryJournal.DefaultPath))
                throw new InvalidOperationException("Остался неподтверждённый снимок сети. Проверьте network-recovery.json командой recover-journal из NetworkLab перед новым запуском.");
            var validation = await ValidateAsync(config, ct);
            if (!validation.IsValid) throw new InvalidOperationException(string.Join("; ", validation.Issues.Where(i => !i.IsWarning).Select(i => i.Message)));
            string agentPath = agentExecutablePath;
            if (!File.Exists(agentPath)) throw new InvalidOperationException("Не найден сетевой агент. Выполните сборку всего решения.");
            string pipeName = "PathFlux-" + Guid.NewGuid().ToString("N");
            pipe = WindowsAgentChannel.CreateServer(pipeName);
            var startInfo = WindowsAgentChannel.CreateStartInfo(agentPath, pipeName);
            agent = await Task.Run(() => Process.Start(startInfo), ct) ?? throw new InvalidOperationException("Не удалось запустить сетевой агент.");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(90));
            var connected = pipe.WaitForConnectionAsync(timeout.Token);
            var exited = agent.WaitForExitAsync(timeout.Token);
            if (await Task.WhenAny(connected, exited) == exited)
                throw new InvalidOperationException(WindowsAgentChannel.DescribeExit(agent.ExitCode));
            await connected;
            WindowsAgentChannel.VerifyClient(pipe, agent.Id);
            var credentials = new Dictionary<string, ProxyCredentials>();
            foreach (var profile in config.Profiles.Where(p => p.Enabled && p.CredentialsRef is not null))
                credentials[profile.CredentialsRef!] = await secrets.GetAsync(profile.CredentialsRef!, ct) ?? throw new InvalidOperationException("Не найдены учётные данные прокси.");
            await AgentProtocol.WriteAsync(pipe, new AgentRequest("start", config, credentials), timeout.Token);
            var reply = await AgentProtocol.ReadAsync<AgentReply>(pipe, timeout.Token); status = reply.Status;
            if (!reply.Success) throw new InvalidOperationException(reply.Status.Message);
        }
        catch (Exception ex)
        {
            lastStartFailure = SafeMessage(ex);
            Cleanup(); status = new(EngineState.Failed, lastStartFailure);
            throw new EngineOperationException(status.Message);
        }
        finally { gate.Release(); }
    }
    public async Task StopAsync(CancellationToken ct)
    {
        await gate.WaitAsync(ct);
        try
        {
            if (pipe?.IsConnected == true)
            {
                status = new(EngineState.Stopping, "Остановка движка…");
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(30));
                await AgentProtocol.WriteAsync(pipe, new AgentRequest("stop"), timeout.Token);
                var reply = await AgentProtocol.ReadAsync<AgentReply>(pipe, timeout.Token); status = reply.Status;
                if (!reply.Success) throw new InvalidOperationException("Агент сообщил об ошибке остановки. Проверьте восстановление сети.");
                if (agent is not null) await agent.WaitForExitAsync(timeout.Token);
            }
            else
            {
                if (status.State == EngineState.Failed && !await WaitForStoppedAsync(ct))
                    throw new InvalidOperationException("Остановка агента или очистка TUN не подтверждена. Выполните recovery-проверку сети.");
                status = new(EngineState.Stopped, "Движок остановлен. При сбое проверьте состояние сети по recovery-инструкции.");
            }
        }
        catch (Exception ex)
        {
            // Closing IPC tells our agent to stop. Give the process and transient IP interface time to disappear.
            pipe?.Dispose(); pipe = null;
            if (await WaitForStoppedAsync(CancellationToken.None))
            {
                status = new(EngineState.Stopped, "Движок остановлен. Завершение агента и очистка IP-интерфейса подтверждены.");
                return;
            }
            string reason = ex is OperationCanceledException ? "Истекло время ожидания." : SafeMessage(ex);
            string initial = lastStartFailure is null ? "" : $" Ошибка запуска: {lastStartFailure}";
            status = new(EngineState.Failed, $"Остановка не подтверждена. {reason}{initial} Проверьте восстановление сети.");
            throw new EngineOperationException(status.Message);
        }
        finally { Cleanup(); gate.Release(); }
    }
    public async Task<EngineStatus> GetStatusAsync(CancellationToken ct)
    {
        await gate.WaitAsync(ct);
        try
        {
            if (pipe is null) return status;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(5));
            await AgentProtocol.WriteAsync(pipe, new AgentRequest("status"), timeout.Token);
            status = (await AgentProtocol.ReadAsync<AgentReply>(pipe, timeout.Token)).Status;
            return status;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        { Cleanup(); return status = new(EngineState.Failed, "Связь с агентом потеряна. Агент завершает движок; проверьте восстановление сети."); }
        finally { gate.Release(); }
    }
    private void Cleanup() { pipe?.Dispose(); pipe = null; agent?.Dispose(); agent = null; }
    private static bool CanConfirmStopped()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            if (TunInterfaceProbe.RequiresCleanup(SingBoxConfigGenerator.InterfaceName)) return false;
            if (RecoveryJournal.HasPendingBaseline(RecoveryJournal.DefaultPath)) return false;
            // Query existence without requesting write access across the integrity-level boundary.
            try { using var runningAgent = EventWaitHandleAcl.OpenExisting(@"Global\PathFlux.NetworkAgent.Lifetime.v1", EventWaitHandleRights.Synchronize); return false; }
            catch (WaitHandleCannotBeOpenedException) { return true; }
        }
        catch { return false; }
    }
    private static async Task<bool> WaitForStoppedAsync(CancellationToken ct)
    {
        var timer = Stopwatch.StartNew();
        while (true)
        {
            if (CanConfirmStopped()) return true;
            if (timer.Elapsed >= TimeSpan.FromSeconds(5)) return false;
            await Task.Delay(200, ct);
        }
    }
    public async ValueTask DisposeAsync() { try { await StopAsync(CancellationToken.None); } finally { gate.Dispose(); } }
    private static string SafeMessage(Exception ex) => ex switch
    {
        InvalidOperationException => ex.Message,
        PlatformNotSupportedException => "Сетевой агент доступен только в Windows.",
        System.ComponentModel.Win32Exception => "Запуск отклонён Windows или отменён запрос UAC.",
        OperationCanceledException => "Операция отменена или истекло время ожидания.",
        UnauthorizedAccessException => "Нет доступа к движку или локальному каналу агента.",
        _ => $"Ошибка сетевого компонента ({ex.GetType().Name})."
    };
}
