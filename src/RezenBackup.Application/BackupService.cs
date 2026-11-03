using System.Collections.Concurrent;
using System.Text;
using Microsoft.Extensions.Logging;
using RezenBackup.BackupEngine;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Platform;
using RezenBackup.Crypto;
using RezenBackup.Format;
using RezenBackup.Logging;

namespace RezenBackup.Application;

/// <summary>A backup currently running (or waiting) in this process.</summary>
public sealed class ActiveRun
{
    internal ActiveRun(Guid runId, JobDefinition job, RunTrigger trigger)
    {
        RunId = runId;
        Job = job;
        Trigger = trigger;
        Progress = new BackupProgress { Phase = BackupPhase.Preparing };
    }

    public Guid RunId { get; }

    public JobDefinition Job { get; }

    public RunTrigger Trigger { get; }

    public BackupProgress Progress { get; internal set; }

    public bool Waiting { get; internal set; }

    public PauseGate Pause { get; } = new();

    internal CancellationTokenSource Cancellation { get; } = new();

    public void Cancel() => Cancellation.Cancel();
}

/// <summary>Runs backups end to end: prerequisites, engine, history, retention and notifications (spec §37, §55, §86).</summary>
public sealed class BackupService
{
    private readonly RezenApp _app;
    private readonly ConcurrentDictionary<Guid, ActiveRun> _active = new();
    private readonly Scheduler.JobQueue _queue = new();

    internal BackupService(RezenApp app) => _app = app;

    public IReadOnlyCollection<ActiveRun> ActiveRuns => _active.Values.ToList();

    public ActiveRun? Active(Guid jobId) => _active.Values.FirstOrDefault(r => r.Job.Id == jobId);

    public event Action<RunRow>? RunCompleted;

    /// <summary>
    /// Runs a job now. <paramref name="providedSecret"/> is used when the user typed the password for this run; otherwise
    /// the remembered credential is used. The secret is disposed when the run ends.
    /// </summary>
    public async Task<RunRow> RunAsync(Guid jobId, RunTrigger trigger, RootSecret? providedSecret = null, string? resumeFolder = null, CancellationToken ct = default)
    {
        var job = _app.Db.Job(jobId) ?? throw new RezenException(ErrorCode.InvalidConfiguration, "Unknown backup job.");
        var run = new ActiveRun(CryptoRandom.NewId(), job, trigger);
        if (!_active.TryAdd(run.RunId, run))
        {
            throw new InvalidOperationException();
        }

        try
        {
            RunRow? result = null;
            var record = _app.Db.RepositoriesForJob(jobId).FirstOrDefault();
            string diskKey = record is null ? jobId.ToString() : (_app.Drives.MountPath(record.DriveId) is { } m ? DiskKey(m) : record.DriveId.ToString());
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, run.Cancellation.Token);
            bool started = await _queue.RunAsync(jobId, diskKey, async token =>
            {
                run.Waiting = false;
                result = await ExecuteAsync(run, providedSecret, resumeFolder, token).ConfigureAwait(false);
            }, () => run.Waiting = true, linked.Token).ConfigureAwait(false);

            if (!started)
            {
                providedSecret?.Dispose();
                return Finish(NewRow(run) with { Outcome = RunOutcome.Cancelled, Message = "This backup is already running." }, persist: false);
            }

            return result!;
        }
        finally
        {
            _active.TryRemove(run.RunId, out _);
        }
    }

    private string DiskKey(string mountPath) => _app.Platform.Volumes.GetVolumeForPath(mountPath)?.RootPath ?? mountPath;

    private RunRow NewRow(ActiveRun run) => new()
    {
        Id = run.RunId,
        JobId = run.Job.Id,
        Trigger = run.Trigger,
        StartedUtc = DateTimeOffset.UtcNow,
        Outcome = RunOutcome.Running,
        Security = SecurityStatus.EncryptedVerificationPending,
    };

    private async Task<RunRow> ExecuteAsync(ActiveRun run, RootSecret? providedSecret, string? resumeFolder, CancellationToken ct)
    {
        var job = run.Job;
        var row = NewRow(run);
        var settings = _app.Settings;
        RootSecret? secret = providedSecret;
        try
        {
            var repoPath = _app.Jobs.RepositoryPath(job.Id);
            if (repoPath is null)
            {
                if (settings.NotifyWaitingForDrive && run.Trigger != RunTrigger.Manual)
                {
                    _app.Platform.Notifier.Notify("Backup drive is not connected.", $"\"{job.Name}\" will run when the drive is connected.", NotificationKind.WaitingForDrive);
                }

                return Finish(row with { Outcome = RunOutcome.WaitingForDrive, Security = SecurityStatus.BackupDriveDisconnected, Message = RunOutcome.WaitingForDrive.ToDisplay() });
            }

            if (job.SkipOnBattery && run.Trigger != RunTrigger.Manual && _app.Platform.Power.IsOnBattery)
            {
                return Finish(row with { Outcome = RunOutcome.Cancelled, Error = ErrorCode.OnBattery, Message = UserMessages.For(ErrorCode.OnBattery) });
            }

            secret ??= _app.KeySets.TryLoadRemembered(job.KeySetId);
            if (secret is null)
            {
                _app.Platform.Notifier.Notify("Backup Locked", $"Enter your password to back up \"{job.Name}\".", NotificationKind.Warning);
                return Finish(row with { Outcome = RunOutcome.WaitingForPassword, Security = SecurityStatus.BackupLocked, Message = UserMessages.For(ErrorCode.KeyUnavailable) });
            }

            _app.Db.UpsertRun(row);
            using var repo = Repository.Open(repoPath, secret, _app.Platform.Durable);

            // Finish a password change that happened while this drive was disconnected (DESIGN §8.2).
            var repoRecord = _app.Db.RepositoriesForJob(job.Id).First();
            var keySet = _app.Db.KeySet(job.KeySetId);
            if (keySet is not null && repoRecord.PasswordGeneration < keySet.PasswordGeneration)
            {
                _app.KeySets.ApplyKeyFileUpdate(repoRecord, repoPath, secret);
            }

            using var awake = settings.KeepComputerAwake ? _app.Platform.Power.KeepAwake("Rezen Backup is running") : null;
            var method = ChooseMethod(job);
            var options = new BackupOptions
            {
                Sources = job.Sources,
                Exclusions = job.Exclusions,
                Method = method,
                Verification = job.Verification,
                HostName = Environment.MachineName,
                AppVersion = RezenApp.AppVersion,
                IndexCachePath = _app.Jobs.IndexCachePath(job.Id),
                ResumeFolderName = resumeFolder,
            };
            var runner = new BackupRunner(repo, _app.Platform.Metadata, _app.Platform.Snapshots, _app.Loggers.CreateLogger("Backup"));
            _app.Logger.LogInformation("Backup of job {Job} started ({Trigger}, {Method})", job.Id, run.Trigger, method);
            var result = await runner.RunAsync(options, new SyncProgress(p => run.Progress = p with { Paused = run.Pause.IsPaused }), run.Pause, ct).ConfigureAwait(false);

            var snapshot = new SnapshotRow
            {
                Id = result.SnapshotId,
                RepositoryId = repo.RepositoryId,
                JobId = job.Id,
                FolderName = result.FolderName,
                StartedUtc = result.StartedUtc,
                CompletedUtc = result.CompletedUtc,
                State = SnapshotState.Committed,
                Security = SecurityStatus.EncryptedAndVerified,
                Verification = result.Verification,
                Files = result.Stats.Files,
                BytesScanned = result.Stats.BytesScanned,
                BytesNew = result.Stats.BytesNew,
                DurationMs = (long)(result.CompletedUtc - result.StartedUtc).TotalMilliseconds,
                CommitHash = result.CommitHash,
                Anomaly = result.AnomalyDetected,
            };
            _app.Db.UpsertSnapshot(snapshot);
            if (result.Warnings.Count > 0)
            {
                _app.Db.UpsertRun(row with { SnapshotId = result.SnapshotId });
                _app.Db.AddRunIssues(row.Id, result.Warnings.Select(w => (w.Kind, repo.Keys.SealSmall(Encoding.UTF8.GetBytes(w.Path), row.Id.ToByteArray()), w.Detail)));
            }

            _app.SecurityLog.Record(SecurityEvents.BackupCreated, job.Id, result.FolderName);
            _app.SecurityLog.Record(SecurityEvents.BackupVerified, job.Id, result.Verification.ToString());

            string retentionNote = string.Empty;
            if (result.AnomalyDetected)
            {
                _app.SecurityLog.Record(SecurityEvents.AnomalyDetected, job.Id, "retention suspended");
                _app.Platform.Notifier.Notify("Unusual changes detected", $"Many files in \"{job.Name}\" changed at once. Older backups are being kept. Check your files for ransomware.", NotificationKind.Warning);
            }
            else
            {
                retentionNote = ApplyRetention(job, repo);
            }

            var finished = Finish(row with
            {
                SnapshotId = result.SnapshotId,
                Outcome = result.Outcome,
                Security = SecurityStatus.EncryptedAndVerified,
                Files = result.Stats.Files,
                FilesWarned = result.Warnings.Count,
                BytesNew = result.Stats.BytesNew,
                BytesScanned = result.Stats.BytesScanned,
                SnapshotFolder = result.FolderName,
                Message = (result.Warnings.Count > 0 ? $"{result.Warnings.Count} file(s) could not be backed up." : "Encrypted backup completed and verified.") + retentionNote,
            });

            if (settings.NotifySuccess || result.Warnings.Count > 0)
            {
                var removable = _app.Platform.Volumes.GetVolumeForPath(repoPath)?.IsRemovable == true;
                var message = result.Warnings.Count > 0
                    ? $"{result.Warnings.Count} file(s) could not be backed up. Open Rezen Backup for details."
                    : removable ? "Backup complete. You may safely disconnect your backup drive." : "Encrypted backup completed and verified.";
                _app.Platform.Notifier.Notify(job.Name, message, result.Warnings.Count > 0 ? NotificationKind.Warning : NotificationKind.Success);
            }

            CheckLowSpace(repoPath);
            if (job.EjectAfterBackup)
            {
                repo.CloseReaders();
                var vol = _app.Platform.Volumes.GetVolumeForPath(repoPath);
                if (vol is not null && vol.IsRemovable)
                {
                    _app.Platform.Volumes.TryEject(vol.RootPath);
                }
            }

            return finished;
        }
        catch (RezenException ex)
        {
            var outcome = ex.Code == ErrorCode.Cancelled ? RunOutcome.Cancelled : ex.Code == ErrorCode.RepositoryLocked ? RunOutcome.Cancelled : RunOutcome.Failed;
            var security = ex.Code switch
            {
                ErrorCode.IntegrityFailure => SecurityStatus.IntegrityFailure,
                ErrorCode.WrongPassword => SecurityStatus.WrongPassword,
                ErrorCode.DestinationDisconnected => SecurityStatus.BackupDriveDisconnected,
                _ => SecurityStatus.EncryptedVerificationPending,
            };
            _app.Logger.LogError(ex, "Backup of job {Job} ended: {Code}", job.Id, ex.Code);
            if (ex.Code == ErrorCode.IntegrityFailure)
            {
                _app.SecurityLog.Record(SecurityEvents.IntegrityFailure, job.Id, "during backup");
                if (settings.NotifyIntegrity)
                {
                    _app.Platform.Notifier.Notify(job.Name, UserMessages.IntegrityFailed, NotificationKind.Integrity);
                }
            }
            else if (outcome == RunOutcome.Failed && settings.NotifyFailure)
            {
                _app.Platform.Notifier.Notify(job.Name, ex.Message, NotificationKind.Error);
            }

            return Finish(row with { Outcome = outcome, Security = security, Error = ex.Code, Message = ex.Message, TechnicalDetails = LogPrivacy.Scrub(ex.TechnicalDetails) });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptoException or InvalidOperationException)
        {
            _app.Logger.LogError(ex, "Backup of job {Job} failed unexpectedly", job.Id);
            if (settings.NotifyFailure)
            {
                _app.Platform.Notifier.Notify(job.Name, "The backup could not be completed.", NotificationKind.Error);
            }

            return Finish(row with { Outcome = RunOutcome.Failed, Message = "The backup could not be completed.", TechnicalDetails = LogPrivacy.Scrub(ex.Message) });
        }
        finally
        {
            secret?.Dispose();
        }
    }

    private static BackupMethod ChooseMethod(JobDefinition job) => job.Method;

    private RunRow Finish(RunRow row, bool persist = true)
    {
        var final = row with { EndedUtc = DateTimeOffset.UtcNow };
        if (persist)
        {
            _app.Db.UpsertRun(final);
        }

        RunCompleted?.Invoke(final);
        return final;
    }

    private string ApplyRetention(JobDefinition job, Repository repo)
    {
        try
        {
            var pinned = _app.Db.Snapshots(job.Id).Where(s => s.Pinned).Select(s => s.Id).ToHashSet();
            var runner = new RetentionRunner(repo, _app.Loggers.CreateLogger("Retention"));
            var plan = runner.Plan(job.Retention, pinned, DateTimeOffset.Now, _app.Jobs.IndexCachePath(job.Id));
            if (plan.IsBlocked)
            {
                _app.Logger.LogWarning("Retention suspended for job {Job}: {Reason}", job.Id, plan.BlockedReason);
                return " Old snapshots are being kept because a backup integrity problem needs attention.";
            }

            if (plan.ToDelete.Count == 0 && plan.PacksToDelete.Count == 0)
            {
                return string.Empty;
            }

            _app.SecurityLog.Record(SecurityEvents.RetentionDeletion, job.Id, string.Join(", ", plan.ToDelete.Select(s => s.Folder.FolderName)));
            var result = runner.Apply(plan, _app.Jobs.IndexCachePath(job.Id));
            foreach (var s in _app.Db.Snapshots(job.Id).Where(s => result.DeletedSnapshots.Contains(s.FolderName)))
            {
                _app.Db.MarkSnapshotDeleted(s.Id);
            }

            return result.DeletedSnapshots.Count > 0
                ? $" Removed {result.DeletedSnapshots.Count} snapshot(s) under the retention policy ({job.Retention.Describe()})."
                : string.Empty;
        }
        catch (Exception ex) when (ex is RezenException or IOException or CryptoException)
        {
            _app.Logger.LogWarning(ex, "Retention skipped for job {Job}", job.Id);
            return string.Empty;
        }
    }

    private void CheckLowSpace(string repoPath)
    {
        var vol = _app.Platform.Volumes.GetVolumeForPath(repoPath);
        if (vol is not null && vol.TotalBytes > 0 && vol.FreeBytes < vol.TotalBytes / 10 && _app.Settings.NotifyLowSpace)
        {
            _app.Platform.Notifier.Notify("Backup drive is low on space.", $"{Fmt.Bytes(vol.FreeBytes)} free on {vol.Label}.", NotificationKind.LowSpace);
        }
    }

    /// <summary>Incomplete snapshots of a job that can be resumed or discarded (spec §56).</summary>
    public IReadOnlyList<string> IncompleteSnapshots(Guid jobId)
    {
        var path = _app.Jobs.RepositoryPath(jobId);
        if (path is null)
        {
            return [];
        }

        return Directory.EnumerateDirectories(path, "*" + Core.Policies.SnapshotNaming.IncompleteSuffix)
            .Select(Path.GetFileName)
            .OfType<string>()
            .ToList();
    }

    /// <summary>Deletes an interrupted snapshot folder. Orphaned packs are reclaimed by the next retention run.</summary>
    public void DiscardIncomplete(Guid jobId, string folderName)
    {
        var path = _app.Jobs.RepositoryPath(jobId) ?? throw new RezenException(ErrorCode.DestinationDisconnected);
        if (!folderName.EndsWith(Core.Policies.SnapshotNaming.IncompleteSuffix, StringComparison.Ordinal) || folderName.Contains('/') || folderName.Contains('\\'))
        {
            throw new RezenException(ErrorCode.InvalidConfiguration, "Only incomplete snapshots can be discarded.");
        }

        var dir = Path.Combine(path, folderName);
        if (Directory.Exists(dir))
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>Synchronous IProgress so the latest progress is visible immediately to pollers.</summary>
    private sealed class SyncProgress(Action<BackupProgress> report) : IProgress<BackupProgress>
    {
        public void Report(BackupProgress value) => report(value);
    }
}
