using Avalonia.Controls;
using Avalonia.Platform;
using PathFlux.ViewModels;

namespace PathFlux.Views;

public partial class MainWindow : Window
{
    private bool _closing;
    private bool _closed;
    private TrayIcon? _tray;
    private GuideWindow? _guide;
    private void OpenGuide(object? sender, Avalonia.Interactivity.RoutedEventArgs e) => ShowGuide();
    public GuideWindow ShowGuide()
    {
        if (_guide is null)
        {
            _guide = new GuideWindow();
            _guide.Closed += (_, _) => _guide = null;
            _guide.Show(this);
        }
        _guide.Activate();
        return _guide;
    }
    public bool ExitConfirmed => _closed;
    public MainWindow()
    {
        InitializeComponent();
        Closing += async (_, e) =>
        {
            if (_closed) return;
            e.Cancel = true;
            if (_tray is not null && e.CloseReason is WindowCloseReason.WindowClosing or WindowCloseReason.Undefined)
            {
                if (!_closing) Hide();
                return;
            }
            await ExitAsync();
        };
        Closed += (_, _) => { _tray?.Dispose(); _tray = null; };
    }

    public void EnableTray()
    {
        var menu = new NativeMenu();
        var open = new NativeMenuItem("Открыть PathFlux");
        open.Click += (_, _) => RestoreFromTray();
        var exit = new NativeMenuItem("Выход");
        exit.Click += async (_, _) => await ExitAsync();
        menu.Items.Add(open);
        menu.Items.Add(new NativeMenuItemSeparator());
        menu.Items.Add(exit);
        using var stream = AssetLoader.Open(new Uri("avares://PathFlux/Assets/Branding/pathflux.ico"));
        _tray = new TrayIcon
        {
            Icon = new WindowIcon(stream), Menu = menu, IsVisible = true,
            ToolTipText = "PathFlux · открыть нажатием, выход через меню"
        };
        _tray.Clicked += (_, _) => RestoreFromTray();
    }

    public void RestoreFromTray()
    {
        Show();
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Activate();
    }

    public async Task ExitAsync()
    {
        if (_closing || _closed) return;
        _closing = true;
        IsEnabled = false;
        try
        {
            if (DataContext is MainWindowViewModel vm)
            {
                if (!await vm.TryStopForExitAsync()) { RestoreFromTray(); return; }
                await vm.DisposeAsync();
            }
            _closed = true;
            Close();
        }
        finally
        {
            if (!_closed) { IsEnabled = true; _closing = false; }
        }
    }
}
