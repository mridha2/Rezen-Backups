using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Styling;
using RezenBackup.Application;
using RezenBackup.UI.Services;
using RezenBackup.UI.ViewModels;
using RezenBackup.UI.Views;

namespace RezenBackup.UI;

public partial class App : Avalonia.Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var rezen = RezenApp.Create(logPrefix: Program.AgentMode ? "agent" : "app");
            ApplyTheme(rezen.Settings.Theme);
            if (Program.AgentMode)
            {
                AgentTray.Start(rezen, desktop);
            }
            else if (!UiInstance.TryAcquire(rezen.Paths))
            {
                // Rezen Backup is already open: ask that window to come to the front, then exit.
                UiSignals.Send(rezen.Db, UiSignals.Show);
                rezen.Dispose();
                desktop.Shutdown();
            }
            else
            {
                var ui = new UiContext(rezen);
                var window = new MainWindow { DataContext = new MainWindowViewModel(ui) };
                ui.MainWindow = window;
                desktop.MainWindow = window;
                window.Closed += (_, _) =>
                {
                    UiInstance.Release();
                    ui.Dispose();
                    rezen.Dispose();
                    desktop.Shutdown();
                };
                window.Show();
                _ = AgentLauncher.EnsureRunningAsync(rezen);
            }
        }

        base.OnFrameworkInitializationCompleted();
    }

    public static void ApplyTheme(ThemePreference theme)
    {
        if (Current is { } app)
        {
            app.RequestedThemeVariant = theme switch
            {
                ThemePreference.Light => ThemeVariant.Light,
                ThemePreference.Dark => ThemeVariant.Dark,
                _ => ThemeVariant.Default,
            };
        }
    }
}
