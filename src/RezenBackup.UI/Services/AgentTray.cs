using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform;
using Avalonia.Threading;
using Microsoft.Extensions.Logging;
using RezenBackup.Agent;
using RezenBackup.Application;

namespace RezenBackup.UI.Services;

/// <summary>
/// Agent mode (<c>RezenBackup --agent</c>): no window, a tray / menu-bar icon, and the background scheduler.
/// Closing the main window never stops scheduled protection (spec §52).
/// </summary>
public static class AgentTray
{
    public static void Start(RezenApp app, IClassicDesktopStyleApplicationLifetime desktop)
    {
        var host = new AgentHost(app);
        if (!host.TryAcquireSingleInstance())
        {
            app.Logger.LogInformation("Agent already running; exiting duplicate.");
            app.Dispose();
            desktop.Shutdown();
            return;
        }

        TrayIcon? tray = null;
        if (app.Settings.ShowTrayIcon)
        {
            tray = BuildTray(app, host, desktop);
        }

        var cts = new CancellationTokenSource();
        var run = Task.Run(() => host.RunAsync(cts.Token));
        run.ContinueWith(
            _ => Dispatcher.UIThread.Post(() =>
            {
                tray?.Dispose();
                app.Dispose();
                desktop.Shutdown();
            }),
            TaskScheduler.Default);

        desktop.ShutdownRequested += (_, _) => cts.Cancel();
    }

    private static TrayIcon BuildTray(RezenApp app, AgentHost host, IClassicDesktopStyleApplicationLifetime desktop)
    {
        var statusItem = new NativeMenuItem("Rezen Backup — protecting your files") { IsEnabled = false };
        var open = new NativeMenuItem("Open Rezen Backup");
        open.Click += (_, _) => AgentLauncher.OpenMainWindow();
        var backup = new NativeMenuItem("Back Up Now");
        backup.Click += (_, _) => host.RunAll();
        var pause = new NativeMenuItem("Pause Backups");
        pause.Click += (_, _) =>
        {
            host.SetPausedAll(!host.PausedAll);
            pause.Header = host.PausedAll ? "Resume Backups" : "Pause Backups";
        };
        var settings = new NativeMenuItem("Settings…");
        settings.Click += (_, _) => AgentLauncher.OpenMainWindow();
        var quit = new NativeMenuItem("Quit Background Protection");
        quit.Click += (_, _) =>
        {
            app.Platform.Notifier.Notify("Scheduled protection stopped", "Scheduled backups will not run until you open Rezen Backup or sign in again.", Core.Platform.NotificationKind.Warning);
            host.Stop();
        };

        var menu = new NativeMenu
        {
            statusItem,
            new NativeMenuItemSeparator(),
            open,
            backup,
            pause,
            settings,
            new NativeMenuItemSeparator(),
            quit,
        };

        using var stream = AssetLoader.Open(new Uri("avares://RezenBackup/Assets/rezen-tray.png"));
        var tray = new TrayIcon
        {
            Icon = new WindowIcon(stream),
            ToolTipText = "Rezen Backup",
            Menu = menu,
            IsVisible = true,
        };
        tray.Clicked += (_, _) => AgentLauncher.OpenMainWindow();

        var timer = new DispatcherTimer(TimeSpan.FromSeconds(3), DispatcherPriority.Background, (_, _) =>
        {
            var runs = host.Runs;
            string text = runs.Count == 0
                ? (host.PausedAll ? "Backups paused" : "Rezen Backup — protecting your files")
                : string.Join(" · ", runs.Select(r => $"{r.JobName}: {r.PhaseText} {(r.BytesTotal > 0 ? (100.0 * r.BytesDone / r.BytesTotal).ToString("0", System.Globalization.CultureInfo.CurrentCulture) + "%" : string.Empty)}"));
            statusItem.Header = text;
            tray.ToolTipText = text;
        });
        timer.Start();
        _ = desktop;
        return tray;
    }
}
