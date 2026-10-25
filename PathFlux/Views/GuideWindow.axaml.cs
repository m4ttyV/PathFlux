using System.Reflection;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace PathFlux.Views;

public partial class GuideWindow : Window
{
    public GuideWindow()
    {
        InitializeComponent();
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("PathFlux.Resources.UserGuide.md")
            ?? throw new InvalidOperationException("User guide resource missing.");
        using var reader = new StreamReader(stream);
        foreach (var paragraph in reader.ReadToEnd().Replace("\r\n", "\n").Split("\n\n", StringSplitOptions.RemoveEmptyEntries))
        {
            if (paragraph.StartsWith("# ")) continue;
            var heading = paragraph.StartsWith("## ");
            GuideContent.Children.Add(new SelectableTextBlock
            {
                Text = heading ? paragraph[3..] : paragraph, TextWrapping = TextWrapping.Wrap,
                FontSize = heading ? 20 : 14, FontWeight = heading ? FontWeight.SemiBold : FontWeight.Normal,
                Margin = new Thickness(0, heading ? 14 : 0, 0, 0)
            });
        }
    }
}
