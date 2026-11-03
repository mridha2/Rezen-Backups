using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Policies;
using RezenBackup.Crypto;
using RezenBackup.Format;

namespace RezenBackup.Application;

/// <summary>Creates and maintains backup jobs (spec §28). Deleting a job never deletes backups on the drive.</summary>
public sealed class JobService
{
    private readonly RezenApp _app;

    internal JobService(RezenApp app) => _app = app;

    public IReadOnlyList<JobDefinition> All => _app.Db.Jobs();

    public JobDefinition? Get(Guid id) => _app.Db.Job(id);

    /// <summary>Validates the job's sources (overlap, existence) and destination.</summary>
    public IReadOnlyList<ValidationMessage> Validate(JobDefinition job, string? destinationRoot)
    {
        var messages = new List<ValidationMessage>();
        if (string.IsNullOrWhiteSpace(job.Name))
        {
            messages.Add(new(ValidationSeverity.Blocking, "Give the backup job a name."));
        }

        if (job.Sources.Count == 0)
        {
            messages.Add(new(ValidationSeverity.Blocking, "Select at least one folder to protect."));
        }

        for (int i = 0; i < job.Sources.Count; i++)
        {
            var s = job.Sources[i];
            if (!Directory.Exists(s) && !File.Exists(s))
            {
                messages.Add(new(ValidationSeverity.Warning, $"\"{s}\" was not found."));
            }

            var overlap = PathPolicy.CheckNewSource(s, job.Sources.Take(i));
            if (overlap.Kind != SourceOverlapKind.None)
            {
                messages.Add(new(ValidationSeverity.Warning, overlap.Kind switch
                {
                    SourceOverlapKind.Duplicate => $"\"{s}\" is selected twice.",
                    SourceOverlapKind.NewIsInsideExisting => $"\"{s}\" is already included in \"{overlap.ExistingSource}\".",
                    _ => $"\"{s}\" contains \"{overlap.ExistingSource}\", which is also selected.",
                }));
            }
        }

        if (job.Retention.IsMirrorLike)
        {
            messages.Add(new(ValidationSeverity.Warning, "Keeping only the latest snapshot means files you delete or that get damaged disappear from the backup after the next run. Not recommended."));
        }

        if (destinationRoot is not null)
        {
            messages.AddRange(_app.Drives.Validate(destinationRoot, job.Sources));
        }

        return messages;
    }

    /// <summary>
    /// Creates the job and its encrypted repository on the destination. Requires the unlocked Key Set secret, because
    /// the repository's key files are written immediately.
    /// </summary>
    public JobDefinition Create(JobDefinition draft, string destinationRoot, RootSecret secret)
    {
        var blocking = Validate(draft, destinationRoot).Where(m => m.Severity == ValidationSeverity.Blocking).ToList();
        if (blocking.Count > 0)
        {
            throw new RezenException(ErrorCode.UnsafeConfiguration, blocking[0].Message, string.Join(Environment.NewLine, blocking.Select(b => b.Message)), null);
        }

        var keyFile = _app.KeySets.LocalKeyFile(draft.KeySetId) ?? throw new RezenException(ErrorCode.KeyUnavailable, "The key file for this password is missing on this computer.");
        if (!keyFile.MatchesKeyCheck(secret))
        {
            throw new RezenException(ErrorCode.WrongPassword);
        }

        var drive = _app.Drives.Register(destinationRoot);
        var computer = draft.HideNamesOnDrive ? "R-" + Convert.ToHexString(CryptoRandom.Bytes(3)) : PathPolicy.SafeFolderName(Environment.MachineName);
        var jobFolder = draft.HideNamesOnDrive ? "J-" + Convert.ToHexString(CryptoRandom.Bytes(3)) : PathPolicy.SafeFolderName(draft.Name);
        var backupRoot = RepositoryLayout.BackupRootOnVolume(destinationRoot);
        var baseFolder = jobFolder;
        for (int i = 2; Directory.Exists(Path.Combine(backupRoot, computer, jobFolder)); i++)
        {
            jobFolder = $"{baseFolder} ({i})";
        }

        var job = draft with
        {
            Id = draft.Id == Guid.Empty ? CryptoRandom.NewId() : draft.Id,
            DriveId = drive.Id,
            ComputerFolder = computer,
            JobFolder = jobFolder,
            CreatedUtc = DateTimeOffset.UtcNow,
            Sources = draft.Sources.Select(PathPolicy.Normalize).ToList(),
        };
        var repoPath = RepositoryLayout.RepositoryPath(backupRoot, computer, jobFolder);
        using var repo = Repository.Create(repoPath, job.KeySetId, secret, keyFile, new RepositoryConfig
        {
            JobName = job.Name,
            HostName = Environment.MachineName,
            CreatedUtc = DateTimeOffset.UtcNow,
            AppVersion = RezenApp.AppVersion,
            Sources = job.Sources,
        }, _app.Platform.Durable);

        _app.Db.UpsertJob(job);
        _app.KeySets.OnRepositoryCreated(job.KeySetId, repo.RepositoryId, secret);
        _app.Db.UpsertRepository(new RepositoryRecord
        {
            Id = repo.RepositoryId,
            JobId = job.Id,
            DriveId = drive.Id,
            RelativePath = Path.GetRelativePath(destinationRoot, repoPath),
            PasswordGeneration = _app.Db.KeySet(job.KeySetId)?.PasswordGeneration ?? 1,
            CreatedUtc = DateTimeOffset.UtcNow,
        });
        return job;
    }

    /// <summary>Saves edits to sources, schedule, retention, exclusions and options. The destination is fixed.</summary>
    public void Update(JobDefinition job)
    {
        var existing = Get(job.Id) ?? throw new RezenException(ErrorCode.InvalidConfiguration, "Unknown job.");
        var updated = job with
        {
            DriveId = existing.DriveId,
            ComputerFolder = existing.ComputerFolder,
            JobFolder = existing.JobFolder,
            KeySetId = existing.KeySetId,
            CreatedUtc = existing.CreatedUtc,
            Sources = job.Sources.Select(PathPolicy.Normalize).ToList(),
        };
        if (Validate(updated, null).FirstOrDefault(m => m.Severity == ValidationSeverity.Blocking) is { } block)
        {
            throw new RezenException(ErrorCode.InvalidConfiguration, block.Message, null, null);
        }

        _app.Db.UpsertJob(updated);
    }

    public void SetEnabled(Guid jobId, bool enabled)
    {
        if (Get(jobId) is { } job)
        {
            _app.Db.UpsertJob(job with { Enabled = enabled });
        }
    }

    /// <summary>Removes the job from this computer only. Encrypted backups stay on the drive and can be imported again.</summary>
    public void Delete(Guid jobId) => _app.Db.DeleteJob(jobId);

    public RepositoryRecord? RepositoryFor(Guid jobId) => _app.Db.RepositoriesForJob(jobId).FirstOrDefault();

    /// <summary>The job's repositories whose drives are connected now (drive rotation: one per drive).</summary>
    public IReadOnlyList<(RepositoryRecord Record, string Path)> ConnectedRepositories(Guid jobId)
    {
        var connected = _app.ConnectedDrives();
        var result = new List<(RepositoryRecord, string)>();
        foreach (var rec in _app.Db.RepositoriesForJob(jobId))
        {
            if (!connected.TryGetValue(rec.DriveId, out var drive))
            {
                continue;
            }

            var record = _app.Db.Drive(rec.DriveId);
            if (record is not null && record.LastMountPath != drive.MountPath)
            {
                _app.Db.UpsertDrive(record with { LastMountPath = drive.MountPath, LastSeenUtc = DateTimeOffset.UtcNow });
            }

            var path = Path.Combine(drive.MountPath, rec.RelativePath);
            if (Repository.Exists(path))
            {
                result.Add((rec, path));
            }
        }

        return result;
    }

    /// <summary>Path of a connected repository of the job (a specific one, or the first connected).</summary>
    public string? RepositoryPath(Guid jobId, Guid? repositoryId = null) =>
        ConnectedRepositories(jobId).Where(r => repositoryId is null || r.Record.Id == repositoryId).Select(r => r.Path).FirstOrDefault();

    public string IndexCachePath(Guid repositoryId) => _app.Paths.IndexCachePath(repositoryId);

    public string DriveLabel(RepositoryRecord record) => _app.Db.Drive(record.DriveId)?.Label ?? "backup drive";

    /// <summary>
    /// Adds another backup drive to a job (drive rotation, DESIGN §21.2). The new drive gets its own repository under
    /// the same password; backups go to whichever of the job's drives are connected.
    /// </summary>
    public RepositoryRecord AddDestination(Guid jobId, string destinationRoot, RootSecret secret)
    {
        var job = Get(jobId) ?? throw new RezenException(ErrorCode.InvalidConfiguration, "Unknown job.");
        var blocking = _app.Drives.Validate(destinationRoot, job.Sources).FirstOrDefault(m => m.Severity == ValidationSeverity.Blocking);
        if (blocking is not null)
        {
            throw new RezenException(ErrorCode.UnsafeConfiguration, blocking.Message, null, null);
        }

        var keyFile = _app.KeySets.LocalKeyFile(job.KeySetId) ?? throw new RezenException(ErrorCode.KeyUnavailable, "The key file for this password is missing on this computer.");
        if (!keyFile.MatchesKeyCheck(secret))
        {
            throw new RezenException(ErrorCode.WrongPassword);
        }

        var drive = _app.Drives.Register(destinationRoot);
        if (_app.Db.RepositoriesForJob(jobId).Any(r => r.DriveId == drive.Id))
        {
            throw new RezenException(ErrorCode.InvalidConfiguration, "This drive is already used by this backup job.", null, null);
        }

        var backupRoot = RepositoryLayout.BackupRootOnVolume(destinationRoot);
        var jobFolder = job.JobFolder;
        for (int i = 2; Directory.Exists(Path.Combine(backupRoot, job.ComputerFolder, jobFolder)); i++)
        {
            jobFolder = $"{job.JobFolder} ({i})";
        }

        var repoPath = RepositoryLayout.RepositoryPath(backupRoot, job.ComputerFolder, jobFolder);
        using var repo = Repository.Create(repoPath, job.KeySetId, secret, keyFile, new RepositoryConfig
        {
            JobName = job.Name,
            HostName = Environment.MachineName,
            CreatedUtc = DateTimeOffset.UtcNow,
            AppVersion = RezenApp.AppVersion,
            Sources = job.Sources,
        }, _app.Platform.Durable);
        var record = new RepositoryRecord
        {
            Id = repo.RepositoryId,
            JobId = jobId,
            DriveId = drive.Id,
            RelativePath = Path.GetRelativePath(destinationRoot, repoPath),
            PasswordGeneration = _app.Db.KeySet(job.KeySetId)?.PasswordGeneration ?? 1,
            CreatedUtc = DateTimeOffset.UtcNow,
        };
        _app.Db.UpsertRepository(record);
        _app.KeySets.OnRepositoryCreated(job.KeySetId, record.Id, secret);
        return record;
    }

    /// <summary>Stops using a drive for this job on this computer. Its backups stay on the drive and can be imported.</summary>
    public void RemoveDestination(Guid jobId, Guid repositoryId)
    {
        var repos = _app.Db.RepositoriesForJob(jobId);
        if (repos.Count <= 1)
        {
            throw new RezenException(ErrorCode.InvalidConfiguration, "A backup job needs at least one backup drive.", null, null);
        }

        _app.Db.DeleteRepository(repositoryId);
    }
}
