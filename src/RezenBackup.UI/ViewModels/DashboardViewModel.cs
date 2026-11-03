using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RezenBackup.Application;
using RezenBackup.Core.Domain;
using RezenBackup.UI.Services;

namespace RezenBackup.UI.ViewModels;

/// <summary>Live progress of one backup (spec §37).</summary>
public sealed partial class RunProgressViewModel : ObservableObject
{
    private readonly UiContext _ui;

    public RunProgressViewModel(UiContext ui, AgentProtocol.RunInfo info)
    {
        _ui = ui;
        JobId = info.JobId;
        Update(info);
    }

    public Guid JobId { get; }

    [ObservableProperty]
    private string _title = string.Empty;

    [ObservableProperty]
    private string _phaseText = string.Empty;

    [ObservableProperty]
    private string _filesText = string.Empty;

    [ObservableProperty]
    private string _processedText = string.Empty;

    [ObservableProperty]
    private string _currentFile = string.Empty;

    [ObservableProperty]
    private string _speedText = string.Empty;

    [ObservableProperty]
    private string _etaText = string.Empty;

    [ObservableProperty]
    private double _percent;

    [ObservableProperty]
    private bool _isPaused;

    [ObservableProperty]
    private bool _isIndeterminate;

    public void Update(AgentProtocol.RunInfo i)
    {
        Title = $"Securing {i.JobName}";
        PhaseText = i.Paused ? "Paused" : i.PhaseText;
        FilesText = i.FilesTotal > 0 ? $"{i.FilesDone.ToString("N0", CultureInfo.CurrentCulture)} / {i.FilesTotal.ToString("N0", CultureInfo.CurrentCulture)}" : i.FilesDone.ToString("N0", CultureInfo.CurrentCulture);
        ProcessedText = $"{Fmt.Bytes(i.BytesDone)} / {Fmt.Bytes(i.BytesTotal)}";
        CurrentFile = _ui.App.Settings.HideFileNamesInLogs && i.CurrentFile is null ? string.Empty : i.CurrentFile ?? string.Empty;
        SpeedText = i.BytesPerSecond > 0 ? $"{Fmt.Bytes((long)i.BytesPerSecond)}/s" : "—";
        EtaText = i.EtaSeconds is { } s ? (s < 60 ? "Less than a minute" : $"{(int)Math.Ceiling(s / 60)} minutes") : "—";
        IsIndeterminate = i.BytesTotal == 0 || i.Phase is "Preparing" or "Scanning";
        Percent = i.BytesTotal > 0 ? Math.Min(100, 100.0 * i.BytesDone / i.BytesTotal) : 0;
        IsPaused = i.Paused;
    }

    [RelayCommand]
    private Task Pause() => _ui.ControlRunAsync("pause", JobId);

    [RelayCommand]
    private Task Resume() => _ui.ControlRunAsync("resume", JobId);

    [RelayCommand]
    private Task Cancel() => _ui.ControlRunAsync("cancel", JobId);
}

public sealed record JobCard(Guid Id, string Name, string StatusText, string StatusClass, string LastBackup, string NextBackup, string DriveText, bool DriveConnected);

public sealed partial class DashboardViewModel : PageViewModel
{
    private DispatcherTimer? _timer;

    public DashboardViewModel(UiContext ui)
        : base(ui)
    {
    }

    [ObservableProperty]
    private string _headline = "Checking your backups…";

    [ObservableProperty]
    private string _headlineClass = "muted";

    [ObservableProperty]
    private bool _isProtected;

    [ObservableProperty]
    private string _encryptionText = StatusService.EncryptionDescription;

    [ObservableProperty]
    private string _driveText = "—";

    [ObservableProperty]
    private bool _driveConnected;

    [ObservableProperty]
    private string _lastBackupText = "Never";

    [ObservableProperty]
    private string _statusText = "—";

    [ObservableProperty]
    private string _statusClass = "muted";

    [ObservableProperty]
    private string _nextBackupText = "—";

    [ObservableProperty]
    private string _spaceText = "—";

    [ObservableProperty]
    private bool _hasJobs;

    [ObservableProperty]
    private bool _hasRuns;

    public ObservableCollection<string> Warnings { get; } = [];

    public ObservableCollection<JobCard> Jobs { get; } = [];

    public ObservableCollection<RunProgressViewModel> Runs { get; } = [];

    public override void OnActivated()
    {
        _ = RefreshAsync();
        _timer = new DispatcherTimer(TimeSpan.FromSeconds(1.5), DispatcherPriority.Background, async (_, _) => await RefreshAsync());
        _timer.Start();
    }

    public override void OnDeactivated() => _timer?.Stop();

    private bool _refreshing;
    private int _tick;

    private async Task RefreshAsync()
    {
        if (_refreshing)
        {
            return;
        }

        _refreshing = true;
        try
        {
            var runs = await Ui.ActiveRunsAsync();
            SyncRuns(runs);
            if (_tick++ % 3 != 0 && runs.Count > 0)
            {
                return; // refresh the (heavier) status less often while a backup runs
            }

            var running = runs.Select(r => r.JobId).ToHashSet();
            var status = await Task.Run(() => Ui.App.Status.Dashboard(running));
            Apply(status);
        }
        finally
        {
            _refreshing = false;
        }
    }

    private void SyncRuns(IReadOnlyList<AgentProtocol.RunInfo> runs)
    {
        foreach (var gone in Runs.Where(r => runs.All(x => x.JobId != r.JobId)).ToList())
        {
            Runs.Remove(gone);
        }

        foreach (var info in runs)
        {
            var existing = Runs.FirstOrDefault(r => r.JobId == info.JobId);
            if (existing is null)
            {
                Runs.Add(new RunProgressViewModel(Ui, info));
            }
            else
            {
                existing.Update(info);
            }
        }

        HasRuns = Runs.Count > 0;
    }

    private void Apply(DashboardStatus status)
    {
        Headline = status.Headline;
        IsProtected = status.AllProtected;
        HeadlineClass = status.AllProtected ? "good" : status.Jobs.Any(j => j.Security == SecurityStatus.IntegrityFailure) ? "bad" : "warn";
        HasJobs = status.Jobs.Count > 0;
        var enabled = status.Jobs.Where(j => j.Job.Enabled).ToList();
        var relevant = enabled.Count > 0 ? enabled : status.Jobs.ToList();

        DriveConnected = relevant.Count > 0 && relevant.All(j => j.DriveConnected);
        DriveText = relevant.Count == 0 ? "—" : DriveConnected ? "✓ Connected" : relevant.Any(j => j.DriveConnected) ? "Some drives connected" : "Not connected";
        var last = relevant.Select(j => j.LastSuccess?.StartedUtc).Where(t => t is not null).DefaultIfEmpty(null).Max();
        LastBackupText = Fmt.When(last);
        var worst = relevant.Count == 0 ? SecurityStatus.NoBackupYet : relevant.Select(j => j.Security).OrderByDescending(Severity).First();
        StatusText = (worst == SecurityStatus.EncryptedAndVerified ? "✓ " : string.Empty) + worst.ToDisplay();
        StatusClass = worst switch
        {
            SecurityStatus.EncryptedAndVerified => "good",
            SecurityStatus.IntegrityFailure or SecurityStatus.WrongPassword => "bad",
            _ => "warn",
        };
        var next = relevant.Select(j => j.NextRun).Where(t => t is not null).DefaultIfEmpty(null).Min();
        NextBackupText = next is null ? "Manual" : Fmt.When(next);
        var vol = relevant.Select(j => j.Volume).Where(v => v is not null).MinBy(v => v!.FreeBytes);
        SpaceText = vol is null ? "—" : $"{Fmt.Bytes(vol.FreeBytes)} free";

        Warnings.Clear();
        foreach (var w in status.Warnings.Distinct())
        {
            Warnings.Add(w);
        }

        Jobs.Clear();
        foreach (var j in status.Jobs)
        {
            Jobs.Add(new JobCard(
                j.Job.Id,
                j.Job.Name,
                j.Job.Enabled ? j.Security.ToDisplay() : "Restore only (disabled)",
                j.Security == SecurityStatus.EncryptedAndVerified ? "good" : j.Security == SecurityStatus.IntegrityFailure ? "bad" : "warn",
                Fmt.When(j.LastSuccess?.StartedUtc),
                j.NextRun is null ? "Manual" : Fmt.When(j.NextRun),
                j.DriveConnected ? $"✓ {j.DriveLabel}" : $"{j.DriveLabel} — not connected",
                j.DriveConnected));
        }
    }

    private static int Severity(SecurityStatus s) => s switch
    {
        SecurityStatus.IntegrityFailure => 9,
        SecurityStatus.WrongPassword => 8,
        SecurityStatus.RecoveryKeyRequired => 7,
        SecurityStatus.BackupLocked => 6,
        SecurityStatus.NoBackupYet => 5,
        SecurityStatus.EncryptedVerificationPending => 4,
        SecurityStatus.BackupDriveDisconnected => 3,
        _ => 0,
    };

    [RelayCommand]
    private async Task BackUpNow()
    {
        foreach (var job in Ui.App.Jobs.All.Where(j => j.Enabled))
        {
            if (!await Ui.BackUpNowAsync(job))
            {
                break;
            }
        }

        await RefreshAsync();
    }

    [RelayCommand]
    private async Task BackUpJob(Guid jobId)
    {
        if (Ui.App.Jobs.Get(jobId) is { } job)
        {
            await Ui.BackUpNowAsync(job);
            await RefreshAsync();
        }
    }

    [RelayCommand]
    private static void NewJob() => Navigation.Go("new-job");
}
