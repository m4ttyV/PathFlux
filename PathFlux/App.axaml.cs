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
            var smokeTest = desktop.Args?.Contains("--smoke-test") == true;
            // Smoke mode uses in-memory sample data and never saves over the user's state.
            var dataDirectory = smokeTest ? Path.Combine(Path.GetTempPath(), "PathFlux-smoke-" + Guid.NewGuid().ToString("N"))
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PathFlux");
            var secretStore = new DpapiSecretStore(Path.Combine(dataDirectory, "secrets"));
            IConfigurationStore store = smokeTest ? new SmokeConfigurationStore()
                : new JsonConfigurationStore(Path.Combine(dataDirectory, "config.json"));
            var viewModel = new MainWindowViewModel(store,
                secretStore, new ProcessDiscoveryService(), new ProxyDiagnostics(secretStore), new SingBoxEngineAdapter(secretStore));
            viewModel.ThemeChanged += theme => RequestedThemeVariant = theme switch
                { "Light" => ThemeVariant.Light, "System" => ThemeVariant.Default, _ => ThemeVariant.Dark };
            var window = new MainWindow { DataContext = viewModel };
            window.Opened += async (_, _) =>
            {
                try
                {
                    await viewModel.InitializeAsync();
                    if (smokeTest)
                    {
                        var args = desktop.Args ?? [];
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
                                await Task.Delay(200); // Allow native layout and each data template to render.
                                if (snapshots is null) continue;
                                var scale = window.RenderScaling;
                                var size = new PixelSize((int)Math.Ceiling(window.Bounds.Width * scale), (int)Math.Ceiling(window.Bounds.Height * scale));
                                using var bitmap = new RenderTargetBitmap(size, new Vector(96 * scale, 96 * scale));
                                bitmap.Render(window);
                                bitmap.Save(Path.Combine(snapshots, $"{theme.ToLowerInvariant()}-{index}-{tabs[index]}.png"));
                            }
                        }
                        Environment.ExitCode = viewModel.IsInitialized ? 0 : 2;
                        window.Close();
                    }
                }
                catch
                {
                    Environment.ExitCode = 3;
                    if (smokeTest) window.Close();
                }
            };
            desktop.MainWindow = window;
        }
        base.OnFrameworkInitializationCompleted();
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
