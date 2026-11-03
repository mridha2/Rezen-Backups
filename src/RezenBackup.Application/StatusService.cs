using System.Text.Json;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Platform;
using RezenBackup.Database;
using RezenBackup.Scheduler;

namespace RezenBackup.Application;

public sealed record JobStatus
{
    public required JobDefinition Job { get; init; }

    public RunRow? LastRun { get; init; }

    public RunRow? LastSuccess { get; init; }

    public SecurityStatus Security { get; init; }

    public bool DriveConnected { get; init; }

    public string? DriveLabel { get; init; }

    public VolumeInfo? Volume { get; init; }

    public long BackupBytesOnDrive { get; init; }

    public DateTimeOffset? NextRun { get; init; }

    public bool IsRunning { get; init; }

    public int SnapshotCount { get; init; }

    public IReadOnlyList<string> Warnings { get; init; } = [];

    public bool HasIncompleteSnapshot { get; init; }
}

public sealed record DashboardStatus(
    IReadOnlyList<JobStatus> Jobs,
    bool AllProtected,
    string Headline,
    string EncryptionText,
    IReadOnlyList<string> Warnings);

/// <summary>Answers the dashboard's questions (spec §84): protected? encrypted? verified? when? next? drive connected?</summary>
public sealed class StatusService
{
    private readonly RezenApp _app;

    internal StatusService(RezenApp app) => _app = app;

    public const string EncryptionDescription = "AES-256-GCM authenticated encryption · Argon2id";

    public JobStatus ForJob(JobDefinition job, IReadOnlyDictionary<Guid, DriveMonitor.ConnectedDrive>? connected = null, bool runningHint = false)
    {
        connected ??= _app.ConnectedDrives();
        var runs = _app.Db.Runs(job.Id, 50);
        var lastRun = runs.FirstOrDefault(r => r.Outcome != RunOutcome.Running);
        var lastSuccess = runs.FirstOrDefault(r => r.Outcome is RunOutcome.Success or RunOutcome.CompletedWithWarnings);
        var snapshots = _app.Db.Snapshots(job.Id);
        var repo = _app.Db.RepositoriesForJob(job.Id).FirstOrDefault();
        bool driveConnected = repo is not null && connected.ContainsKey(repo.DriveId);
        var drive = repo is null ? null : _app.Db.Drive(repo.DriveId);
        VolumeInfo? volume = null;
        string? repoPath = null;
        if (driveConnected)
        {
            var mount = connected[repo!.DriveId].MountPath;
            volume = _app.Platform.Volumes.GetVolumeForPath(mount) ?? FreeSpace.VolumeFor(mount);
            repoPath = Path.Combine(mount, repo.RelativePath);
        }

        var warnings = new List<string>();
        var security = snapshots.FirstOrDefault()?.Security ?? SecurityStatus.NoBackupYet;
        if (lastRun?.Security == SecurityStatus.IntegrityFailure || snapshots.Any(s => s.Security == SecurityStatus.IntegrityFailure))
        {
            security = SecurityStatus.IntegrityFailure;
            warnings.Add("Backup integrity verification failed.");
        }
        else if (lastRun?.Outcome == RunOutcome.WaitingForPassword)
        {
            security = SecurityStatus.BackupLocked;
            warnings.Add("Backup Locked — enter your password to run the backup.");
        }

        if (!driveConnected && job.Enabled)
        {
            warnings.Add(lastRun?.Outcome == RunOutcome.WaitingForDrive ? RunOutcome.WaitingForDrive.ToDisplay() : "Backup drive not connected.");
        }

        if (volume is { TotalBytes: > 0 } v && v.FreeBytes < v.TotalBytes / 10)
        {
            warnings.Add("Backup drive is low on space.");
        }

        if (lastRun is { Outcome: RunOutcome.Failed } f)
        {
            warnings.Add(f.Message ?? "The last backup failed.");
        }

        if (snapshots.FirstOrDefault()?.Anomaly == true)
        {
            warnings.Add("Unusual changes were detected in the last backup. Older snapshots are being kept.");
        }

        var keySet = _app.Db.KeySet(job.KeySetId);
        if (keySet is not null && repo is not null && repo.PasswordGeneration < keySet.PasswordGeneration)
        {
            warnings.Add("This backup drive still uses your previous password. Connect it to finish updating.");
        }

        bool incomplete = repoPath is not null && Directory.Exists(repoPath) && Directory.EnumerateDirectories(repoPath, "*.incomplete").Any();
        if (incomplete)
        {
            warnings.Add("An interrupted backup was found. Resume it or discard it.");
        }

        var lastAttempt = runs.FirstOrDefault()?.StartedUtc;
        return new JobStatus
        {
            Job = job,
            LastRun = lastRun,
            LastSuccess = lastSuccess,
            Security = !driveConnected && security == SecurityStatus.EncryptedAndVerified ? SecurityStatus.EncryptedAndVerified : security,
            DriveConnected = driveConnected,
            DriveLabel = drive?.Label,
            Volume = volume,
            NextRun = BackupScheduler.NextRun(job, lastAttempt, DateTimeOffset.Now),
            IsRunning = runningHint || runs.FirstOrDefault()?.Outcome == RunOutcome.Running,
            SnapshotCount = snapshots.Count(s => s.State == SnapshotState.Committed),
            Warnings = warnings,
            HasIncompleteSnapshot = incomplete,
        };
    }

    public DashboardStatus Dashboard(ISet<Guid>? runningJobs = null)
    {
        var connected = _app.ConnectedDrives();
        var jobs = _app.Db.Jobs().Select(j => ForJob(j, connected, runningJobs?.Contains(j.Id) == true)).ToList();
        var warnings = jobs.SelectMany(j => j.Warnings.Select(w => $"{j.Job.Name}: {w}")).ToList();
        var keySet = _app.KeySets.Default;
        if (keySet is { RecoveryKeyConfirmed: false })
        {
            warnings.Add("No recovery key has been saved. If you forget your password, your backups cannot be recovered.");
        }

        bool protectedAll = jobs.Count > 0 && jobs.Where(j => j.Job.Enabled).All(j =>
            j.Security == SecurityStatus.EncryptedAndVerified &&
            j.LastSuccess is { } s && DateTimeOffset.UtcNow - s.StartedUtc < TimeSpan.FromDays(8));
        string headline = jobs.Count == 0 ? "Set up your first backup."
            : jobs.Any(j => j.Security == SecurityStatus.IntegrityFailure) ? "Backup integrity verification failed."
            : protectedAll ? "Your files are protected."
            : jobs.Any(j => j.LastSuccess is null) ? "Your files are not backed up yet."
            : "Your backups need attention.";
        return new DashboardStatus(jobs, protectedAll, headline, EncryptionDescription, warnings);
    }
}

/// <summary>Configuration export/import (spec §66). Never includes passwords, keys, recovery keys or protected credentials.</summary>
public static class ConfigTransfer
{
    public sealed record ExportedConfig(string Format, string AppVersion, DateTimeOffset ExportedUtc, AppSettings Settings, IReadOnlyList<JobDefinition> Jobs);

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    public static string Export(RezenApp app) =>
        JsonSerializer.Serialize(new ExportedConfig("Rezen Backup Configuration v1", RezenApp.AppVersion, DateTimeOffset.UtcNow, app.Settings, app.Db.Jobs()), Json);

    /// <summary>Imports settings and job definitions. Imported jobs are disabled until their drive is re-attached.</summary>
    public static int Import(RezenApp app, string json)
    {
        var config = JsonSerializer.Deserialize<ExportedConfig>(json, Json) ?? throw new JsonException("Empty configuration.");
        if (config.Format != "Rezen Backup Configuration v1")
        {
            throw new JsonException("Not a Rezen Backup configuration file.");
        }

        app.SaveSettings(config.Settings with { SetupCompleted = app.Settings.SetupCompleted });
        int imported = 0;
        foreach (var job in config.Jobs)
        {
            if (app.Db.Job(job.Id) is null && app.Db.KeySet(job.KeySetId) is not null)
            {
                app.Db.UpsertJob(job with { Enabled = false });
                imported++;
            }
        }

        return imported;
    }
}

internal static class DbExtensions
{
    public static IReadOnlyList<SnapshotRow> CommittedSnapshots(this AppDatabase db, Guid jobId) =>
        db.Snapshots(jobId).Where(s => s.State == SnapshotState.Committed).ToList();
}
