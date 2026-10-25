using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Data.Core.Plugins;
using Avalonia.Markup.Xaml;
using Avalonia.Media.Imaging;
using Avalonia.Styling;
using PathFlux.Application;
using PathFlux.Domain;
using PathFlux.Engine;
using PathFlux.Infrastructure;
using PathFlux.ViewModels;
using PathFlux.Views;

namespace PathFlux;

public partial class App : Avalonia.Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);
    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            foreach (var validator in BindingPlugins.DataValidators.OfType<DataAnnotationsValidationPlugin>().ToArray())
                BindingPlugins.DataValidators.Remove(validator);
            var traySmokeTest = desktop.Args?.Contains("--tray-smoke-test") == true;
            var smokeTest = desktop.Args?.Contains("--smoke-test") == true || traySmokeTest;
            string? acceptance = desktop.Args is { Length: 3 } arguments && arguments[0] == "--udp-acceptance" &&
                Path.IsPathFullyQualified(arguments[1]) && arguments[2] == "--allow-system-tun" ? arguments[1] : null;
            // Smoke mode uses in-memory sample data and never saves over the user's state.
            var dataDirectory = smokeTest ? Path.Combine(Path.GetTempPath(), "PathFlux-smoke-" + Guid.NewGuid().ToString("N"))
                : acceptance is not null ? Path.Combine(acceptance, "ui-data") : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PathFlux");
            if (acceptance is not null && Directory.Exists(dataDirectory)) throw new InvalidOperationException("Acceptance requires a new data directory.");
            var secretStore = new DpapiSecretStore(Path.Combine(dataDirectory, "secrets"));
            IConfigurationStore store = smokeTest ? new SmokeConfigurationStore()
                : new JsonConfigurationStore(Path.Combine(dataDirectory, "config.json"));
            var adapter = new SingBoxEngineAdapter(secretStore);
            IProxyEngineAdapter uiAdapter = smokeTest ? new SmokeEngineAdapter(adapter) : adapter;
            var viewModel = new MainWindowViewModel(store,
                secretStore, new ProcessDiscoveryService(), new ProxyDiagnostics(secretStore), uiAdapter,
                smokeTest || acceptance is not null ? null : new BundledEngineInstaller(Path.Combine(AppContext.BaseDirectory, "engine-package"), Path.Combine(dataDirectory, "engines")));
            viewModel.ThemeChanged += theme => RequestedThemeVariant = theme switch
                { "Light" => ThemeVariant.Light, "System" => ThemeVariant.Default, _ => ThemeVariant.Dark };
            var window = new MainWindow { DataContext = viewModel };
            if ((!smokeTest && acceptance is null) || traySmokeTest) window.EnableTray();
            desktop.ShutdownRequested += async (_, e) =>
            {
                if (window.ExitConfirmed) return;
                e.Cancel = true;
                await window.ExitAsync();
            };
            var opened = false;
            window.Opened += async (_, _) =>
            {
                // Show() after Hide() raises Opened again; never reload configuration or restart polling.
                if (opened) return;
                opened = true;
                try
                {
                    await viewModel.InitializeAsync();
                    if (traySmokeTest)
                    {
                        window.Close();
                        if (window.IsVisible) throw new InvalidOperationException("Close did not hide to tray.");
                        if (((SmokeEngineAdapter)uiAdapter).StopCalls != 0) throw new InvalidOperationException("Hide stopped the engine.");
                        window.RestoreFromTray();
                        if (!window.IsVisible || !viewModel.IsInitialized) throw new InvalidOperationException("Tray restore failed.");
                    }
                    if (acceptance is not null)
                    {
                        int acceptanceExit = await UiUdpAcceptance.RunAsync(viewModel, adapter, acceptance);
                        Environment.ExitCode = acceptanceExit;
                        desktop.Exit += (_, eventArgs) => eventArgs.ApplicationExitCode = acceptanceExit;
                        await window.ExitAsync();
                        return;
                    }
                    if (smokeTest)
                    {
                        var args = desktop.Args ?? [];
                        if (args.Contains("--install-engine-smoke"))
                        {
                            var installation = await new BundledEngineInstaller(Path.Combine(AppContext.BaseDirectory, "engine-package"), Path.Combine(dataDirectory, "engines")).InstallAsync(default);
                            await EngineBinary.VerifyAsync(installation.Path, installation.Sha256, default);
                        }
                        var snapshotFlag = Array.IndexOf(args, "--snapshot-dir");
                        var snapshots = snapshotFlag >= 0 && snapshotFlag + 1 < args.Length ? args[snapshotFlag + 1] : null;
                        if (snapshots is not null)
                        {
                            if (!Path.IsPathFullyQualified(snapshots)) throw new ArgumentException("Absolute snapshot path required.");
                            Directory.CreateDirectory(snapshots);
                        }
                        viewModel.SelectedProfile = viewModel.Profiles.FirstOrDefault();
                        viewModel.SelectedRule = viewModel.Rules.FirstOrDefault();
                        string[] tabs = ["overview", "profiles", "rules", "processes", "diagnostics", "settings"];
                        foreach (var theme in snapshots is null ? new[] { "Dark" } : new[] { "Dark", "Light" })
                        {
                            RequestedThemeVariant = theme == "Dark" ? ThemeVariant.Dark : ThemeVariant.Light;
                            for (var index = 0; index < tabs.Length; index++)
                            {
                                viewModel.SelectedTab = index;
                                if (index == 2) viewModel.NewRuleCommand.Execute(null);
                                await Task.Delay(200); // Allow native layout and each data template to render.
                                if (snapshots is null) continue;
                                var scale = window.RenderScaling;
                                var size = new PixelSize((int)Math.Ceiling(window.Bounds.Width * scale), (int)Math.Ceiling(window.Bounds.Height * scale));
                                using var bitmap = new RenderTargetBitmap(size, new Vector(96 * scale, 96 * scale));
                                bitmap.Render(window);
                                bitmap.Save(Path.Combine(snapshots, $"{theme.ToLowerInvariant()}-{index}-{tabs[index]}.png"));
                            }
                            if (snapshots is not null)
                            {
                                var guide = window.ShowGuide();
                                await Task.Delay(200);
                                var scale = guide.RenderScaling;
                                using var bitmap = new RenderTargetBitmap(new PixelSize((int)Math.Ceiling(guide.Bounds.Width * scale), (int)Math.Ceiling(guide.Bounds.Height * scale)), new Vector(96 * scale, 96 * scale));
                                bitmap.Render(guide);
                                bitmap.Save(Path.Combine(snapshots, $"{theme.ToLowerInvariant()}-guide.png"));
                                guide.Close();
                            }
                        }
                        Environment.ExitCode = viewModel.IsInitialized ? 0 : 2;
                        await window.ExitAsync();
                    }
                }
                catch
                {
                    Environment.ExitCode = 3;
                    if (smokeTest || acceptance is not null) await window.ExitAsync();
                }
            };
            desktop.MainWindow = window;
        }
        base.OnFrameworkInitializationCompleted();
    }

    // Rendering/lifecycle checks must never inspect or recover a real network session.
    private sealed class SmokeEngineAdapter(IProxyEngineAdapter capabilities) : IProxyEngineAdapter
    {
        public int StopCalls { get; private set; }
        public Task<EngineCapabilities> GetCapabilitiesAsync(CancellationToken ct) => capabilities.GetCapabilitiesAsync(ct);
        public Task<ConfigValidationResult> ValidateAsync(ProxyConfiguration config, CancellationToken ct) => Task.FromResult(ConfigurationValidator.Validate(config));
        public Task StartAsync(ProxyConfiguration config, CancellationToken ct) => throw new InvalidOperationException("Smoke mode cannot start a network engine.");
        public Task StopAsync(CancellationToken ct) { StopCalls++; return Task.CompletedTask; }
        public Task<EngineStatus> GetStatusAsync(CancellationToken ct) => Task.FromResult(new EngineStatus(EngineState.Stopped, "Движок остановлен."));
    }

    private sealed class SmokeConfigurationStore : IConfigurationStore
    {
        private readonly ProxyConfiguration _configuration;
        public SmokeConfigurationStore()
        {
            var profile = new ProxyProfile { Name = "Локальный SOCKS5", Host = "127.0.0.1", Port = 1080 };
            _configuration = new() { Profiles = [profile], Rules = [new() { Name = "Discord · TCP", ProfileId = profile.Id, Network = NetworkTransport.Tcp }] };
        }
        public Task<ProxyConfiguration> LoadAsync(CancellationToken ct) => Task.FromResult(_configuration);
        public Task SaveAsync(ProxyConfiguration configuration, CancellationToken ct) => throw new InvalidOperationException("Smoke configuration is read-only.");
    }
}
