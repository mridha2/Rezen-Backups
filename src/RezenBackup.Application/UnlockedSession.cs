using System.Text;
using Microsoft.Extensions.Logging;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Crypto;
using RezenBackup.Format;
using RezenBackup.Logging;
using RezenBackup.RestoreEngine;

namespace RezenBackup.Application;

/// <summary>
/// Everything that requires the password: browsing history, search, restore, verification, viewing file-level issue
/// details, recovery key and password changes. Disposing (lock / auto-lock) wipes the Root Secret and drops all
/// decrypted catalog data from memory (spec §46–47).
/// </summary>
public sealed class UnlockedSession : IDisposable
{
    private readonly RezenApp _app;
    private readonly Dictionary<Guid, (Repository Repo, CatalogSession Catalog)> _open = [];
    private RootSecret? _secret;

    private UnlockedSession(RezenApp app, Guid keySetId, RootSecret secret)
    {
        _app = app;
        KeySetId = keySetId;
        _secret = secret;
    }

    public Guid KeySetId { get; }

    public bool IsLocked => _secret is null;

    public RootSecret Secret => _secret ?? throw new RezenException(ErrorCode.KeyUnavailable);

    public static async Task<UnlockedSession> UnlockAsync(RezenApp app, Guid keySetId, string password, CancellationToken ct = default) =>
        new(app, keySetId, await app.KeySets.UnlockAsync(keySetId, password, ct).ConfigureAwait(false));

    public static UnlockedSession UnlockWithRecoveryKey(RezenApp app, Guid keySetId, string recoveryKey) =>
        new(app, keySetId, app.KeySets.UnlockWithRecoveryKey(keySetId, recoveryKey));

    /// <summary>Opens the job's catalog (drive must be connected). Integrity problems are reported per snapshot.</summary>
    public CatalogSession OpenCatalog(Guid jobId, IProgress<string>? progress = null)
    {
        if (_open.TryGetValue(jobId, out var existing))
        {
            return existing.Catalog;
        }

        var job = _app.Db.Job(jobId) ?? throw new RezenException(ErrorCode.InvalidConfiguration, "Unknown job.");
        if (job.KeySetId != KeySetId)
        {
            throw new RezenException(ErrorCode.WrongPassword);
        }

        var path = _app.Jobs.RepositoryPath(jobId) ?? throw new RezenException(ErrorCode.DestinationDisconnected, "Connect the backup drive to browse this backup.", null, null);
        var repo = Repository.Open(path, Secret, _app.Platform.Durable);
        try
        {
            repo.LoadIndex(_app.Jobs.IndexCachePath(jobId), progress);
            var catalog = new CatalogSession(repo);
            _open[jobId] = (repo, catalog);
            SyncSnapshotRows(jobId, repo.RepositoryId, catalog);
            return catalog;
        }
        catch
        {
            repo.Dispose();
            throw;
        }
    }

    /// <summary>Keeps local history in line with the drive and reports snapshots missing from the drive (DESIGN §15.6).</summary>
    private void SyncSnapshotRows(Guid jobId, Guid repositoryId, CatalogSession catalog)
    {
        var onDrive = catalog.Snapshots.Where(s => s.Record is not null).ToDictionary(s => s.SnapshotId);
        foreach (var s in onDrive.Values)
        {
            _app.Db.UpsertSnapshot(new SnapshotRow
            {
                Id = s.SnapshotId,
                RepositoryId = repositoryId,
                JobId = jobId,
                FolderName = s.FolderName,
                StartedUtc = s.StartedUtc,
                CompletedUtc = s.CompletedUtc,
                State = s.Validity == SnapshotValidity.Valid ? SnapshotState.Committed : SnapshotState.Incomplete,
                Security = s.Validity switch
                {
                    SnapshotValidity.Valid => SecurityStatus.EncryptedAndVerified,
                    SnapshotValidity.Invalid => SecurityStatus.IntegrityFailure,
                    _ => SecurityStatus.EncryptedVerificationPending,
                },
                Verification = s.Record!.Verification,
                Files = s.Record.Stats.Files,
                BytesScanned = s.Record.Stats.BytesScanned,
                BytesNew = s.Record.Stats.BytesNew,
                DurationMs = (long)(s.CompletedUtc - s.StartedUtc).TotalMilliseconds,
                Anomaly = s.Record.AnomalyDetected,
            });
        }

        var missing = _app.Db.Snapshots(jobId).Where(r => r.RepositoryId == repositoryId && !onDrive.ContainsKey(r.Id)).ToList();
        foreach (var m in missing)
        {
            _app.SecurityLog.Record(SecurityEvents.SnapshotMissing, jobId, m.FolderName);
            _app.Db.MarkSnapshotDeleted(m.Id);
        }

        if (missing.Count > 0)
        {
            _app.Platform.Notifier.Notify("Snapshots missing", $"{missing.Count} snapshot(s) are missing from the backup drive.", Core.Platform.NotificationKind.Integrity);
        }

        if (catalog.Snapshots.Any(s => s.Validity == SnapshotValidity.Invalid))
        {
            _app.SecurityLog.Record(SecurityEvents.IntegrityFailure, jobId, "snapshot failed authentication");
        }
    }

    public async Task<RestoreReport> RestoreAsync(Guid jobId, IReadOnlyList<CatalogItem> items, RestoreOptions options, IProgress<RestoreProgress>? progress = null, CancellationToken ct = default)
    {
        var catalog = OpenCatalog(jobId);
        var executor = new RestoreExecutor(catalog, _app.Loggers.CreateLogger("Restore"));
        var report = await executor.RestoreAsync(items, options, progress, ct).ConfigureAwait(false);
        _app.SecurityLog.Record(SecurityEvents.Restore, jobId, $"files: {report.FilesRestored}, failed: {report.FilesFailed}");
        if (report.IntegrityFailure)
        {
            _app.SecurityLog.Record(SecurityEvents.IntegrityFailure, jobId, "during restore");
            _app.Platform.Notifier.Notify("Rezen Backup", UserMessages.IntegrityFailed, Core.Platform.NotificationKind.Integrity);
        }

        return report;
    }

    public DeepVerifyReport DeepVerify(Guid jobId, IProgress<DeepVerifyProgress>? progress = null, CancellationToken ct = default)
    {
        var catalog = OpenCatalog(jobId);
        var report = new RepositoryVerifier(catalog.Repository).Verify(progress, ct);
        _app.Db.SetSetting($"job.{jobId}.lastDeepVerify", DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture));
        _app.SecurityLog.Record(report.Healthy ? SecurityEvents.BackupVerified : SecurityEvents.IntegrityFailure, jobId, report.Healthy ? "deep verification passed" : "deep verification found problems");
        return report;
    }

    /// <summary>Quarantines damaged packs so the next backup re-stores the affected data from the source files.</summary>
    public void RepairFromSource(Guid jobId, DeepVerifyReport report)
    {
        var catalog = OpenCatalog(jobId);
        var verifier = new RepositoryVerifier(catalog.Repository);
        foreach (var d in report.DamagedPacks.Where(d => !d.RecoveredFromCopy))
        {
            verifier.Quarantine(d.PackId, d.Kind, _app.Jobs.IndexCachePath(jobId));
        }

        Close(jobId);
    }

    /// <summary>Decrypts the file paths behind "3 files could not be backed up" (spec §68).</summary>
    public IReadOnlyList<(IssueKind Kind, string Path, string? Detail)> RunIssues(Guid jobId, Guid runId)
    {
        var catalog = OpenCatalog(jobId);
        var result = new List<(IssueKind, string, string?)>();
        foreach (var issue in _app.Db.RunIssues(runId))
        {
            string path;
            try
            {
                path = Encoding.UTF8.GetString(catalog.Repository.Keys.OpenSmall(issue.PathSealed, runId.ToByteArray()));
            }
            catch (CryptoException)
            {
                path = "(unavailable)";
            }

            result.Add((issue.Kind, path, issue.Detail));
        }

        return result;
    }

    public PasswordChangeResult ChangePassword(ReadOnlySpan<char> newPassword) => _app.KeySets.ChangePassword(KeySetId, Secret, newPassword);

    public string RevealRecoveryKey() => _app.KeySets.RevealRecoveryKey(Secret);

    public void SetRemember(bool remember) => _app.KeySets.SetRemember(KeySetId, Secret, remember);

    /// <summary>A copy of the secret for handing a run to the background agent; the caller must dispose it.</summary>
    public RootSecret CloneSecret() => Secret.Clone();

    public void Close(Guid jobId)
    {
        if (_open.Remove(jobId, out var entry))
        {
            entry.Catalog.Dispose();
            entry.Repo.Dispose();
        }
    }

    public void Dispose()
    {
        foreach (var id in _open.Keys.ToList())
        {
            Close(id);
        }

        _secret?.Dispose();
        _secret = null;
        _app.Logger.LogInformation("Session locked.");
    }
}
