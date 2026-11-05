using Avalonia.Controls;
using RezenBackup.Application;

namespace RezenBackup.UI.Services;

/// <summary>
/// Sizes the main window to the screen it opens on: a modest default that never exceeds most of the usable area
/// (menu bar, Dock and taskbar excluded), the user's last size when there is one, and minimums that still fit.
/// </summary>
public static class WindowPlacement
{
    public const double DefaultWidth = 1100;
    public const double DefaultHeight = 720;
    public const double MinWidth = 900;   // Restore's three columns and the History table need this much
    public const double MinHeight = 560;

    /// <summary>Room for the title bar and window shadow, which are outside the client size.</summary>
    private const double FrameAllowance = 40;

    /// <param name="availableWidth">Usable screen width in device-independent units.</param>
    /// <param name="availableHeight">Usable screen height in device-independent units.</param>
    public static (double Width, double Height, double MinWidth, double MinHeight) Fit(
        double availableWidth, double availableHeight, double? savedWidth, double? savedHeight)
    {
        double maxW = Math.Max(1, availableWidth - 16);
        double maxH = Math.Max(1, availableHeight - FrameAllowance);
        double minW = Math.Min(MinWidth, maxW);
        double minH = Math.Min(MinHeight, maxH);
        double w = savedWidth is > 0 ? Math.Min(savedWidth.Value, maxW) : Math.Min(DefaultWidth, availableWidth * 0.9);
        double h = savedHeight is > 0 ? Math.Min(savedHeight.Value, maxH) : Math.Min(DefaultHeight, availableHeight * 0.8);
        return (Math.Max(w, minW), Math.Max(h, minH), minW, minH);
    }

    /// <summary>Applies the size before the window is first shown, and saves it again when the window closes.</summary>
    public static void Attach(Window window, RezenApp app)
    {
        var screen = window.Screens.Primary;
        if (screen is not null)
        {
            var area = screen.WorkingArea.Size.ToSize(screen.Scaling);
            var s = app.Settings;
            var (w, h, minW, minH) = Fit(area.Width, area.Height, s.WindowWidth, s.WindowHeight);
            window.MinWidth = minW;
            window.MinHeight = minH;
            window.Width = w;
            window.Height = h;
            window.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            if (s.WindowMaximized)
            {
                window.WindowState = WindowState.Maximized;
            }
        }

        window.Closing += (_, _) =>
        {
            var maximized = window.WindowState is WindowState.Maximized or WindowState.FullScreen;
            var settings = app.Settings with { WindowMaximized = maximized };
            if (window.WindowState == WindowState.Normal)
            {
                settings = settings with { WindowWidth = Math.Round(window.Bounds.Width), WindowHeight = Math.Round(window.Bounds.Height) };
            }

            if (settings != app.Settings)
            {
                app.SaveSettings(settings);
            }
        };
    }
}
