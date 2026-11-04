using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RezenBackup.Application;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.UI.Services;

namespace RezenBackup.UI.ViewModels;

/// <summary>Settings (spec §82). Changes are saved immediately.</summary>
public sealed partial class SettingsViewModel : PageViewModel
{
    private bool _loading = true;

    public SettingsViewModel(UiContext ui)
        : base(ui)
    {
        var s = ui.App.Settings;
        StartWithSystem = s.StartWithSystem;
        RunBackgroundAgent = s.RunBackgroundAgent;
        ShowTrayIcon = s.ShowTrayIcon;
        RunMissed = s.RunMissedBackups;
        KeepAwake = s.KeepComputerAwake;
        FullVerificationDefault = s.DefaultVerification == VerificationLevel.Full;
        DriveConnectIndex = (int)s.OnDriveConnected;
        HideFileNames = s.HideFileNamesInLogs;
        NotifySuccess = s.NotifySuccess;
        NotifyFailure = s.NotifyFailure;
        NotifyWaiting = s.NotifyWaitingForDrive;
        NotifyIntegrity = s.NotifyIntegrity;
        NotifyLowSpace = s.NotifyLowSpace;
        ThemeIndex = (int)s.Theme;
        foreach (var j in ui.App.Jobs.All)
        {
            Jobs.Add(new JobChoice(j.Id, j.Name));
        }

        SelectedJob = Jobs.FirstOrDefault();
        _loading = false;
    }

    public IReadOnlyList<string> Themes { get; } = ["System", "Light", "Dark"];

    /// <summary>In <see cref="DriveConnectAction"/> order.</summary>
    public IReadOnlyList<string> DriveConnectOptions { get; } =
    [
        "Open Rezen Backup and ask whether to back up",
        "Back up automatically when a backup is due",
        "Do nothing (scheduled backups still run)",
    ];

    public System.Collections.ObjectModel.ObservableCollection<JobChoice> Jobs { get; } = [];

    [ObservableProperty]
    private JobChoice? _selectedJob;

    [ObservableProperty]
    private bool _startWithSystem;

    [ObservableProperty]
    private bool _runBackgroundAgent;

    [ObservableProperty]
    private bool _showTrayIcon;

    [ObservableProperty]
    private bool _runMissed;

    [ObservableProperty]
    private bool _keepAwake;

    [ObservableProperty]
    private bool _fullVerificationDefault;

    [ObservableProperty]
    private int _driveConnectIndex;

    [ObservableProperty]
    private bool _hideFileNames;

    [ObservableProperty]
    private bool _notifySuccess;

    [ObservableProperty]
    private bool _notifyFailure;

    [ObservableProperty]
    private bool _notifyWaiting;

    [ObservableProperty]
    private bool _notifyIntegrity;

    [ObservableProperty]
    private bool _notifyLowSpace;

    [ObservableProperty]
    private int _themeIndex;

    [ObservableProperty]
    private string? _status;

    public string DataFolder => Ui.App.Paths.Root;

    protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (_loading || e.PropertyName is nameof(Status) or nameof(SelectedJob))
        {
            return;
        }

        var theme = (ThemePreference)Math.Clamp(ThemeIndex, 0, 2);
        Ui.App.SaveSettings(Ui.App.Settings with
        {
            StartWithSystem = StartWithSystem,
            RunBackgroundAgent = RunBackgroundAgent,
            ShowTrayIcon = ShowTrayIcon,
            RunMissedBackups = RunMissed,
            KeepComputerAwake = KeepAwake,
            DefaultVerification = FullVerificationDefault ? VerificationLevel.Full : VerificationLevel.Standard,
            OnDriveConnected = (DriveConnectAction)Math.Clamp(DriveConnectIndex, 0, 2),
            HideFileNamesInLogs = HideFileNames,
            NotifySuccess = NotifySuccess,
            NotifyFailure = NotifyFailure,
            NotifyWaitingForDrive = NotifyWaiting,
            NotifyIntegrity = NotifyIntegrity,
            NotifyLowSpace = NotifyLowSpace,
            Theme = theme,
        });
        App.ApplyTheme(theme);
        if (e.PropertyName == nameof(StartWithSystem) && !StartWithSystem)
        {
            Ui.App.Platform.Autostart.Disable();
        }

        if (e.PropertyName is nameof(StartWithSystem) or nameof(RunBackgroundAgent) && StartWithSystem && RunBackgroundAgent)
        {
            _ = AgentLauncher.EnsureRunningAsync(Ui.App);
        }

        if (e.PropertyName == nameof(RunBackgroundAgent) && !RunBackgroundAgent)
        {
            _ = Ui.Agent.SendAsync(new AgentProtocol.Request("stop"));
            Status = "Background protection stopped. Scheduled backups will not run while Rezen Backup is closed.";
        }
        else
        {
            Status = "Settings saved.";
        }
    }

    public bool IsMac => OperatingSystem.IsMacOS();

    /// <summary>Opens System Settings → Privacy &amp; Security → Full Disk Access (a local settings pane).</summary>
    [RelayCommand]
    private static void OpenFullDiskAccess() => OsShell.Open("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles");

    [RelayCommand]
    private void OpenDataFolder() => OsShell.Open(Ui.App.Paths.Root);

    [RelayCommand]
    private void OpenLogsFolder() => OsShell.Open(Ui.App.Paths.LogsDirectory);

    [RelayCommand]
    private void BackupDatabase()
    {
        Ui.App.Db.BackupCopy();
        Status = "A backup copy of the local database was saved.";
    }

    [RelayCommand]
    private async Task RebuildCatalog()
    {
        if (SelectedJob is null)
        {
            return;
        }

        var session = await Ui.EnsureUnlockedAsync("Enter your password to rebuild the backup catalog from the drive.");
        if (session is null)
        {
            return;
        }

        using var busy = Ui.Locks.BeginBusy();
        try
        {
            var id = SelectedJob.Id;
            int n = await Task.Run(() => Ui.App.Import.RebuildCatalog(id, session));
            Status = $"Catalog rebuilt from the backup drive: {n} snapshot(s).";
        }
        catch (RezenException ex)
        {
            await Dialogs.MessageAsync(Ui.MainWindow!, "Rebuild failed", ex.Message, ex.TechnicalDetails, isError: true);
        }
    }

    [RelayCommand]
    private async Task ExportConfig()
    {
        var path = await Dialogs.SaveFileAsync(Ui.MainWindow!, "Export configuration", "RezenBackupConfig.json", "json");
        if (path is not null)
        {
            await File.WriteAllTextAsync(path, ConfigTransfer.Export(Ui.App));
            Status = "Configuration exported. It contains no passwords, keys or recovery keys.";
        }
    }

    [RelayCommand]
    private async Task ImportConfig()
    {
        var files = await Dialogs.PickFilesAsync(Ui.MainWindow!, "Import configuration");
        if (files.Count != 1)
        {
            return;
        }

        try
        {
            int n = ConfigTransfer.Import(Ui.App, await File.ReadAllTextAsync(files[0]));
            Status = $"Configuration imported. {n} job(s) added (disabled until their backup drive is re-attached).";
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException)
        {
            await Dialogs.MessageAsync(Ui.MainWindow!, "Import failed", "This is not a valid Rezen Backup configuration file.", ex.Message, isError: true);
        }
    }

    [RelayCommand]
    private static void ImportExisting() => Navigation.Go("import");
}

public static class OsShell
{
    public static void Open(string path)
    {
        try
        {
            var psi = OperatingSystem.IsWindows()
                ? new ProcessStartInfo("explorer.exe") { UseShellExecute = false }
                : new ProcessStartInfo(OperatingSystem.IsMacOS() ? "/usr/bin/open" : "xdg-open") { UseShellExecute = false };
            psi.ArgumentList.Add(path);
            Process.Start(psi);
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }
    }
}
