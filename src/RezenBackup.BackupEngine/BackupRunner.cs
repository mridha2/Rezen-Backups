using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Platform;
using RezenBackup.Core.Policies;
using RezenBackup.Crypto;
using RezenBackup.Format;

namespace RezenBackup.BackupEngine;

/// <summary>
/// Runs one backup into an unlocked repository following the commit protocol of DESIGN §16.1. A snapshot is only
/// renamed to its final, completed name after its data was flushed, read back, verified and an authenticated commit
/// record was written.
/// </summary>
public sealed class BackupRunner
{
    private readonly Repository _repo;
    private readonly IFileMetadataProvider _meta;
    private readonly ISourceSnapshotProvider _snapshots;
    private readonly ILogger _logger;
    private readonly IClock _clock;

    public BackupRunner(Repository repo, IFileMetadataProvider? meta = null, ISourceSnapshotProvider? snapshots = null, ILogger? logger = null, IClock? clock = null)
    {
        _repo = repo;
        _meta = meta ?? PortableFileMetadataProvider.Instance;
        _snapshots = snapshots ?? LiveSourceSnapshotProvider.Instance;
        _logger = logger ?? NullLogger.Instance;
        _clock = clock ?? SystemClock.Instance;
    }

    public async Task<BackupResult> RunAsync(BackupOptions options, IProgress<BackupProgress>? progress = null, PauseGate? pause = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Sources.Count == 0)
        {
            throw new RezenException(ErrorCode.InvalidConfiguration, "No source folders selected.");
        }

        var sources = options.Sources.Select(PathPolicy.Normalize).ToList();
        if (PathPolicy.FindRecursiveSource(_repo.Layout.Root, sources) is { } bad)
        {
            throw new RezenException(ErrorCode.UnsafeConfiguration, $"The backup destination is inside the source '{bad}'.");
        }

        using var view = await _snapshots.CreateViewAsync(sources, ct).ConfigureAwait(false);
        return await Task.Run(() => Run(options with { Sources = sources }, view, progress, pause ?? new PauseGate(), ct), ct).ConfigureAwait(false);
    }

    private BackupResult Run(BackupOptions options, ISourceView view, IProgress<BackupProgress>? sink, PauseGate pause, CancellationToken ct)
    {
        var tracker = new ProgressTracker(sink);
        tracker.StartPhase(BackupPhase.Preparing);
        var started = _clock.Now;
        var runId = CryptoRandom.NewId();
        var layout = _repo.Layout;

        using var repoLock = RepositoryLock.Acquire(layout, runId);
        try
        {
            CleanTemp(layout);
            _repo.LoadIndex(options.IndexCachePath, null, ct);
            FinalizePending();

            var all = _repo.LoadAllSnapshots();
            var previous = all.Where(s => s.IsRestorable && s.Record is not null).OrderBy(s => s.Record!.StartedUtc).LastOrDefault();

            // Snapshot folder: new, or resume an interrupted one.
            Guid snapshotId;
            string baseName;
            DateTimeOffset startedUtc;
            JournalRecord journal;
            string incompleteDir;
            if (options.ResumeFolderName is { } resume)
            {
                var folder = all.FirstOrDefault(s => s.Folder.FolderName == resume && s.Validity == SnapshotValidity.Incomplete)
                    ?? throw new RezenException(ErrorCode.InvalidConfiguration, "The incomplete snapshot to resume was not found.");
                incompleteDir = folder.Folder.FullPath;
                baseName = folder.Folder.Parsed.BaseName;
                var jp = RepositoryLayout.JournalPath(incompleteDir);
                journal = File.Exists(jp) ? JournalRecord.Decode(EncryptedObjects.ReadObject(jp, _repo.Keys, ObjectType.Journal)) : new JournalRecord { SnapshotId = CryptoRandom.NewId(), FolderBaseName = baseName, StartedUtc = started.ToUniversalTime() };
                snapshotId = journal.SnapshotId;
                startedUtc = journal.StartedUtc;
            }
            else
            {
                var local = options.SnapshotLocalTime ?? started.LocalDateTime;
                (baseName, _) = SnapshotNaming.ChooseUnique(local, all.Select(s => s.Folder.FolderName));
                snapshotId = CryptoRandom.NewId();
                startedUtc = started.ToUniversalTime();
                incompleteDir = layout.SnapshotDirectory(baseName + SnapshotNaming.IncompleteSuffix);
                Directory.CreateDirectory(incompleteDir);
                journal = new JournalRecord { SnapshotId = snapshotId, FolderBaseName = baseName, StartedUtc = startedUtc };
            }

            SnapshotMeta.For(snapshotId, _repo.RepositoryId, SnapshotState.Incomplete).Write(incompleteDir, _repo.Ops);
            var writer = new SnapshotWriter(_repo, options, RepositoryLayout.JournalPath(incompleteDir), journal);
            writer.WriteJournal();
            writer.EnsureSpace(0);

            // Scan and encrypt.
            var cdc = new FastCdc(_repo.Keys, _repo.Config.ChunkMin, _repo.Config.ChunkAvg, _repo.Config.ChunkMax);
            var walker = new TreeWalker(_repo, writer, cdc, options, _meta, view, tracker, pause, _logger, previous?.Record?.SnapshotId, ct);
            tracker.StartPhase(BackupPhase.Scanning);
            walker.PreScan(options.Sources);
            tracker.StartPhase(BackupPhase.Encrypting);

            var snapshotSources = new List<SnapshotSource>();
            foreach (var source in options.Sources)
            {
                var prev = previous?.Record?.Sources.FirstOrDefault(s => string.Equals(PathPolicy.Normalize(s.OriginalPath), source, PathPolicy.Comparison));
                var result = walker.ProcessSource(source, prev);
                if (result is not null)
                {
                    snapshotSources.Add(result);
                }
            }

            if (snapshotSources.Count == 0)
            {
                throw new RezenException(ErrorCode.SourceMissing, "None of the selected source folders could be read.");
            }

            tracker.StartPhase(BackupPhase.Committing);
            writer.FlushAll();
            options.FaultInjection?.Invoke("after-data");

            bool anomaly = DetectAnomaly(walker, writer, previous);
            var completed = _clock.Now;
            var record = new SnapshotRecord
            {
                SnapshotId = snapshotId,
                RepositoryId = _repo.RepositoryId,
                FolderBaseName = baseName,
                StartedUtc = startedUtc,
                CompletedUtc = completed.ToUniversalTime(),
                UtcOffsetMinutes = (int)started.Offset.TotalMinutes,
                HostName = options.HostName,
                AppVersion = options.AppVersion,
                Platform = RuntimeInformation.OSDescription,
                Method = options.Method,
                Sources = snapshotSources,
                Stats = new SnapshotStats
                {
                    Files = walker.Files,
                    Directories = walker.Directories,
                    BytesScanned = walker.BytesScanned,
                    BytesNew = writer.NewRawBytes,
                    BytesStored = writer.BytesStored,
                    FilesNew = walker.FilesNew,
                    FilesChanged = walker.FilesChanged,
                    FilesUnchanged = walker.FilesUnchanged,
                    FilesWithWarnings = walker.Warnings.Count,
                },
                Warnings = walker.Warnings,
                ParentSnapshotId = previous?.Record?.SnapshotId,
                PreviousCommitHash = previous?.CommitHash,
                Verification = options.Verification,
                AnomalyDetected = anomaly,
            };

            var recordPath = RepositoryLayout.SnapshotRecordPath(incompleteDir);
            var writtenRecord = EncryptedObjects.WriteObject(recordPath, _repo.Keys, ObjectType.Snapshot, record.Encode(), _repo.Ops);
            options.FaultInjection?.Invoke("after-snapshot-record");

            // Verify (DESIGN §15.2).
            tracker.StartPhase(BackupPhase.Verifying);
            SnapshotVerifier.Verify(_repo, record, recordPath, writer, walker, options.Verification, tracker, ct);
            options.FaultInjection?.Invoke("after-verify");

            // Commit record (authenticated "complete" state).
            tracker.StartPhase(BackupPhase.Committing);
            var packs = ReferencedPacks(walker, writer);
            var commit = new CommitRecord
            {
                SnapshotId = snapshotId,
                RepositoryId = _repo.RepositoryId,
                FolderBaseName = baseName,
                SnapshotRecordSha256 = writtenRecord.Sha256,
                Packs = packs,
                Verification = options.Verification,
                VerificationResult = "passed",
                VerifiedUtc = _clock.Now.ToUniversalTime(),
                PreviousCommitHash = previous?.CommitHash,
            };
            ct.ThrowIfCancellationRequested();
            var commitPath = RepositoryLayout.CommitRecordPath(incompleteDir);
            var writtenCommit = EncryptedObjects.WriteObject(commitPath, _repo.Keys, ObjectType.Commit, commit.Encode(), _repo.Ops);
            var commitBack = CommitRecord.Decode(EncryptedObjects.Decrypt(_repo.Keys, ObjectType.Commit, EncryptedObjects.ReadAllForVerification(commitPath, _repo.Ops)));
            if (commitBack.SnapshotId != snapshotId)
            {
                throw new RezenException(ErrorCode.CommitFailed, "Commit record read-back mismatch.");
            }

            options.FaultInjection?.Invoke("after-commit-record");

            // Finalize: rename <ts>.incomplete → <ts>.
            var finalDir = Finalize(incompleteDir, baseName, snapshotId);
            options.FaultInjection?.Invoke("after-finalize");

            _repo.Index.SaveCache(options.IndexCachePath, _repo.Keys, _repo.Ops);
            tracker.StartPhase(BackupPhase.Done);
            _logger.LogInformation("Snapshot {Snapshot} committed: {Files} files, {New} new bytes, {Warnings} warnings", baseName, walker.Files, writer.NewRawBytes, walker.Warnings.Count);

            return new BackupResult
            {
                SnapshotId = snapshotId,
                FolderName = Path.GetFileName(finalDir),
                Outcome = walker.Warnings.Count > 0 ? RunOutcome.CompletedWithWarnings : RunOutcome.Success,
                Stats = record.Stats,
                Warnings = walker.Warnings,
                Verification = options.Verification,
                CommitHash = writtenCommit.Sha256,
                StartedUtc = startedUtc,
                CompletedUtc = _clock.Now.ToUniversalTime(),
                AnomalyDetected = anomaly,
                PacksWritten = writer.WrittenPacks.Count,
            };
        }
        catch (OperationCanceledException)
        {
            throw new RezenException(ErrorCode.Cancelled);
        }
        catch (IOException ex)
        {
            throw IoErrors.Translate(ex);
        }
        catch (CryptoException ex)
        {
            throw new RezenException(ErrorCode.IntegrityFailure, ex.Message, ex);
        }
        finally
        {
            _repo.CloseReaders();
            _repo.Keys.ForgetWrittenObjectKeys();
        }
    }

    private string Finalize(string incompleteDir, string baseName, Guid snapshotId)
    {
        SnapshotMeta.For(snapshotId, _repo.RepositoryId, SnapshotState.Committed).Write(incompleteDir, _repo.Ops);
        EncryptedObjects.TryDelete(RepositoryLayout.JournalPath(incompleteDir));
        var finalDir = _repo.Layout.SnapshotDirectory(baseName);
        Directory.Move(incompleteDir, finalDir);
        _repo.Ops.FlushDirectory(_repo.Layout.Root);
        return finalDir;
    }

    /// <summary>Completes snapshots whose commit record authenticated but whose folder rename was interrupted.</summary>
    private void FinalizePending()
    {
        foreach (var folder in _repo.ListSnapshotFolders().Where(f => f.Parsed.State == SnapshotState.Incomplete))
        {
            var loaded = _repo.LoadSnapshot(folder);
            if (loaded.Validity == SnapshotValidity.CommittedPendingFinalize && loaded.Record is { } r)
            {
                var target = _repo.Layout.SnapshotDirectory(folder.Parsed.BaseName);
                if (!Directory.Exists(target))
                {
                    Finalize(folder.FullPath, folder.Parsed.BaseName, r.SnapshotId);
                    _logger.LogInformation("Finalized interrupted snapshot {Snapshot}", folder.Parsed.BaseName);
                }
            }
        }
    }

    private static List<CommittedPack> ReferencedPacks(TreeWalker walker, SnapshotWriter writer)
    {
        var packIds = new HashSet<Guid>();
        foreach (var id in walker.Referenced)
        {
            packIds.Add(writer.LocationFor(id) ?? throw new RezenException(ErrorCode.IntegrityFailure, $"Block {id} has no location."));
        }

        var result = new List<CommittedPack>();
        foreach (var pid in packIds)
        {
            var written = writer.WrittenPacks.FirstOrDefault(p => p.PackId == pid);
            if (written is not null)
            {
                result.Add(written);
            }
            else
            {
                result.Add(writer.PackRecordFor(pid));
            }
        }

        return result;
    }

    /// <summary>
    /// Ransomware heuristic (DESIGN §21.2): a large share of files changed and the new data became incompressible.
    /// The snapshot is still committed, but retention is suspended by the caller.
    /// </summary>
    private static bool DetectAnomaly(TreeWalker walker, SnapshotWriter writer, LoadedSnapshot? previous)
    {
        if (previous?.Record is null || previous.Record.Stats.Files < 50)
        {
            return false;
        }

        long compared = walker.FilesChanged + walker.FilesUnchanged;
        if (compared < 50)
        {
            return false;
        }

        double changedRatio = (double)walker.FilesChanged / compared;
        double incompressible = writer.NewRawBytes == 0 ? 0 : (double)writer.IncompressibleNewBytes / writer.NewRawBytes;
        return changedRatio > 0.30 && incompressible > 0.90;
    }

    private static void CleanTemp(RepositoryLayout layout)
    {
        if (!Directory.Exists(layout.TempDirectory))
        {
            return;
        }

        foreach (var f in Directory.EnumerateFiles(layout.TempDirectory))
        {
            EncryptedObjects.TryDelete(f);
        }
    }
}
