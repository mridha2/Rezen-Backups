using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Policies;
using RezenBackup.Crypto;
using RezenBackup.Format;
using RezenBackup.Logging;
using RezenBackup.Security;

namespace RezenBackup.Application;

public sealed record FoundRepository(string Path, string ComputerFolder, string JobFolder, RepositoryInfo Info, int SnapshotFolders, bool AlreadyImported);

/// <summary>
/// "Import Existing Rezen Backup" and "Rebuild Backup Catalog" (spec §63–64): everything is reconstructed from the drive
/// plus the password or recovery key, so backups are recoverable even if the original PC is destroyed.
/// </summary>
public sealed class ImportService
{
    private readonly RezenApp _app;

    internal ImportService(RezenApp app) => _app = app;

    public IReadOnlyList<FoundRepository> FindRepositories(string destinationRoot)
    {
        var backupRoot = RepositoryLayout.BackupRootOnVolume(destinationRoot);
        if (!Directory.Exists(backupRoot))
        {
            return [];
        }

        var known = _app.Db.Repositories().Select(r => r.Id).ToHashSet();
        var result = new List<FoundRepository>();
        foreach (var computerDir in Directory.EnumerateDirectories(backupRoot))
        {
            foreach (var jobDir in Directory.EnumerateDirectories(computerDir))
            {
                if (!Repository.Exists(jobDir))
                {
                    continue;
                }

                try
                {
                    var info = Repository.ReadInfo(jobDir);
                    int snaps = Directory.EnumerateDirectories(jobDir).Count(d => SnapshotNaming.TryParse(Path.GetFileName(d), out _));
                    result.Add(new FoundRepository(jobDir, Path.GetFileName(computerDir), Path.GetFileName(jobDir), info, snaps, known.Contains(info.RepositoryId)));
                }
                catch (Exception ex) when (ex is RezenException or IOException or UnauthorizedAccessException)
                {
                }
            }
        }

        return result;
    }

    public JobDefinition ImportWithPassword(string repositoryPath, string password)
    {
        using var pw = PasswordEncoding.ToKeyMaterial(password);
        RootSecret secret;
        try
        {
            secret = Repository.UnlockWithPassword(repositoryPath, pw, _app.Platform.Durable, out _);
        }
        catch (RezenException ex) when (ex.Code == ErrorCode.WrongPassword)
        {
            _app.SecurityLog.Record(SecurityEvents.FailedUnlock, null, "import");
            throw;
        }

        using (secret)
        {
            var info = Repository.ReadInfo(repositoryPath);
            var best = Repository.ReadBestKeyFile(repositoryPath)!;
            InstallLocalKeyFile(info.KeySetId, best.ForRepository(info.KeySetId, secret), secret);
            return Adopt(repositoryPath, info, secret, viaRecoveryKey: false);
        }
    }

    /// <summary>
    /// Imports with the recovery key. Because the password is unknown, a new password is set; it replaces the key slots
    /// on this drive (other drives keep the old password until updated).
    /// </summary>
    public JobDefinition ImportWithRecoveryKey(string repositoryPath, string recoveryKey, string newPassword)
    {
        var assessment = PasswordPolicy.Assess(newPassword);
        if (!assessment.MeetsRequirements)
        {
            throw new RezenException(ErrorCode.PasswordTooWeak, string.Join(" ", assessment.Feedback));
        }

        RootSecret secret;
        try
        {
            secret = RecoveryKeyCodec.Decode(recoveryKey);
        }
        catch (CryptoException ex)
        {
            throw new RezenException(ErrorCode.RecoveryKeyMalformed, null, ex);
        }

        using (secret)
        {
            var info = Repository.ReadInfo(repositoryPath);
            using var repo = Repository.Open(repositoryPath, secret, _app.Platform.Durable); // throws WrongPassword if the key doesn't match
            var best = Repository.ReadBestKeyFile(repositoryPath);
            ulong generation = (best?.Generation ?? 0) + 1;
            var kdf = KdfPolicy.IsTestMode ? KdfPolicy.Current : Argon2id.Calibrate(TimeSpan.FromSeconds(1));
            using var pw = PasswordEncoding.ToKeyMaterial(newPassword);
            var local = KeyFile.CreateWithPassword(info.KeySetId, info.KeySetId, generation, secret, pw, kdf);
            InstallLocalKeyFile(info.KeySetId, local, secret);
            repo.ReplaceKeyFiles(local.ForRepository(repo.RepositoryId, secret), secret, f => f.Generation == generation);
            _app.SecurityLog.Record(SecurityEvents.RecoveryKeyUsed, null, "import");
            return Adopt(repositoryPath, info, secret, viaRecoveryKey: true);
        }
    }

    private void InstallLocalKeyFile(Guid keySetId, KeyFile local, RootSecret secret)
    {
        var existingFile = KeyFileStore.TryRead(_app.Paths.LocalKeyFile(keySetId), out _);
        if (existingFile is not null && existingFile.Generation > local.Generation && existingFile.MatchesKeyCheck(secret))
        {
            return; // this computer already has a newer password for this key set
        }

        KeyFileStore.WriteVerified(_app.Paths.LocalKeyFile(keySetId), local, _app.Platform.Durable, f => f.MatchesKeyCheck(secret));
        var existing = _app.Db.KeySet(keySetId);
        _app.Db.UpsertKeySet((existing ?? new KeySetInfo { Id = keySetId, CreatedUtc = DateTimeOffset.UtcNow }) with
        {
            PasswordGeneration = Math.Max(existing?.PasswordGeneration ?? 1, (int)local.Generation),
            RecoveryKeyConfirmed = existing?.RecoveryKeyConfirmed ?? false,
        });
    }

    private JobDefinition Adopt(string repositoryPath, RepositoryInfo info, RootSecret secret, bool viaRecoveryKey)
    {
        var jobDir = Path.GetFullPath(repositoryPath);
        var computerDir = Path.GetDirectoryName(jobDir)!;
        var backupRoot = Path.GetDirectoryName(computerDir)!;
        var destinationRoot = Path.GetDirectoryName(backupRoot)!;
        var drive = _app.Drives.Register(destinationRoot);

        using var repo = Repository.Open(repositoryPath, secret, _app.Platform.Durable);
        var existingRepo = _app.Db.Repositories().FirstOrDefault(r => r.Id == repo.RepositoryId);
        var job = existingRepo is not null ? _app.Db.Job(existingRepo.JobId) : null;
        bool sameComputer = string.Equals(repo.Config.HostName, Environment.MachineName, StringComparison.OrdinalIgnoreCase);
        job ??= new JobDefinition
        {
            Id = CryptoRandom.NewId(),
            KeySetId = info.KeySetId,
            Name = string.IsNullOrWhiteSpace(repo.Config.JobName) ? Path.GetFileName(jobDir) : repo.Config.JobName,
            Sources = repo.Config.Sources,
            // Imported backups start as restore-only; the user can enable backing up from this computer later.
            Enabled = false,
            Schedule = sameComputer ? Schedule.DailyAt(20) : Schedule.Manual,
            DriveId = drive.Id,
            ComputerFolder = Path.GetFileName(computerDir),
            JobFolder = Path.GetFileName(jobDir),
            CreatedUtc = DateTimeOffset.UtcNow,
        };
        _app.Db.UpsertJob(job);
        var keySet = _app.Db.KeySet(info.KeySetId);
        _app.Db.UpsertRepository(new RepositoryRecord
        {
            Id = repo.RepositoryId,
            JobId = job.Id,
            DriveId = drive.Id,
            RelativePath = Path.GetRelativePath(destinationRoot, jobDir),
            PasswordGeneration = keySet?.PasswordGeneration ?? 1,
            CreatedUtc = repo.Config.CreatedUtc,
        });

        RebuildCatalog(job.Id, repo);
        _app.SecurityLog.Record(SecurityEvents.Import, job.Id, viaRecoveryKey ? "recovery key" : "password");
        return job;
    }

    /// <summary>Rebuilds the local catalog (snapshot list and chunk index) for a job from its drive.</summary>
    public int RebuildCatalog(Guid jobId, UnlockedSession session)
    {
        session.Close(jobId);
        var path = _app.Jobs.RepositoryPath(jobId) ?? throw new RezenException(ErrorCode.DestinationDisconnected);
        using var repo = Repository.Open(path, session.Secret, _app.Platform.Durable);
        return RebuildCatalog(jobId, repo);
    }

    private int RebuildCatalog(Guid jobId, Repository repo)
    {
        var cache = _app.Jobs.IndexCachePath(jobId);
        EncryptedObjects.TryDelete(cache);
        repo.LoadIndex(cache);
        int count = 0;
        foreach (var s in repo.LoadAllSnapshots())
        {
            if (s.Record is not { } r)
            {
                continue;
            }

            _app.Db.UpsertSnapshot(new SnapshotRow
            {
                Id = r.SnapshotId,
                RepositoryId = repo.RepositoryId,
                JobId = jobId,
                FolderName = s.Folder.FolderName,
                StartedUtc = r.StartedUtc,
                CompletedUtc = r.CompletedUtc,
                State = s.IsRestorable ? SnapshotState.Committed : SnapshotState.Incomplete,
                Security = s.Validity switch
                {
                    SnapshotValidity.Valid => SecurityStatus.EncryptedAndVerified,
                    SnapshotValidity.Invalid => SecurityStatus.IntegrityFailure,
                    _ => SecurityStatus.EncryptedVerificationPending,
                },
                Verification = r.Verification,
                Files = r.Stats.Files,
                BytesScanned = r.Stats.BytesScanned,
                BytesNew = r.Stats.BytesNew,
                DurationMs = (long)(r.CompletedUtc - r.StartedUtc).TotalMilliseconds,
                CommitHash = s.CommitHash,
                Anomaly = r.AnomalyDetected,
            });
            count++;
        }

        _app.SecurityLog.Record(SecurityEvents.CatalogRebuild, jobId, $"snapshots: {count}");
        return count;
    }
}
