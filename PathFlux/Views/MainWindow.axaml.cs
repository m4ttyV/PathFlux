using Avalonia.Controls;
using PathFlux.ViewModels;

namespace PathFlux.Views;

public partial class MainWindow : Window
{
    private bool _closing;
    private bool _closed;
    public MainWindow()
    {
        InitializeComponent();
        Closing += async (_, e) =>
        {
            if (_closed) return;
            e.Cancel = true;
            if (_closing) return;
            _closing = true;
            IsEnabled = false;
            if (DataContext is MainWindowViewModel vm) await vm.DisposeAsync();
            _closed = true;
            Close();
        };
    }
}
