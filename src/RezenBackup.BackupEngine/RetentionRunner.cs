using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Policies;
using RezenBackup.Crypto;
using RezenBackup.Format;

namespace RezenBackup.BackupEngine;

public sealed record RetentionPlan(
    IReadOnlyList<LoadedSnapshot> ToDelete,
    IReadOnlyList<Guid> PacksToDelete,
    IReadOnlyList<Guid> PacksToRepack,
    long BytesReclaimable,
    RetentionPolicy Policy,
    IReadOnlySet<Guid> Pinned,
    DateTimeOffset Now,
    string? BlockedReason = null)
{
    /// <summary>True when retention must not delete anything (unresolved integrity problems).</summary>
    public bool IsBlocked => BlockedReason is not null;

    public static RetentionPlan Blocked(RetentionPolicy policy, IReadOnlySet<Guid> pinned, DateTimeOffset now, string reason) =>
        new([], [], [], 0, policy, pinned, now, reason);
}

public sealed record RetentionResult(IReadOnlyList<string> DeletedSnapshots, int PacksDeleted, int PacksRepacked, long BytesReclaimed);

/// <summary>
/// Applies a retention policy safely (DESIGN §20). Retention is the only component that deletes anything on the
/// drive. It runs only after a verified snapshot, keeps a minimum number of recent snapshots, never deletes pinned
/// snapshots, confirms the plan against the decrypted trees on the drive, and deletes in two phases (<c>.deleting</c>).
/// </summary>
public sealed class RetentionRunner
{
    private readonly Repository _repo;
    private readonly ILogger _logger;

    public RetentionRunner(Repository repo, ILogger? logger = null)
    {
        _repo = repo;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Computes what the policy would remove. This is a preview: <see cref="Apply"/> recomputes the plan under the
    /// repository lock so a backup committed in the meantime by another process is never affected.
    /// </summary>
    public RetentionPlan Plan(RetentionPolicy policy, IReadOnlySet<Guid> pinned, DateTimeOffset now, string? indexCachePath = null, CancellationToken ct = default)
    {
        if (_repo.Index.Count == 0)
        {
            _repo.LoadIndex(indexCachePath, null, ct);
        }

        try
        {
            return PlanCore(policy, pinned, now, ct);
        }
        catch (Exception ex) when (ex is RezenException or CryptoException or IOException)
        {
            // A tree that cannot be read means the live set is unknown: never delete anything (DESIGN §20.2).
            return RetentionPlan.Blocked(policy, pinned, now, "Backup data could not be fully read: " + ex.Message);
        }
    }

    private RetentionPlan PlanCore(RetentionPolicy policy, IReadOnlySet<Guid> pinned, DateTimeOffset now, CancellationToken ct)
    {
        var snapshots = _repo.LoadAllSnapshots();
        if (snapshots.FirstOrDefault(s => s.Validity == SnapshotValidity.Invalid) is { } bad)
        {
            return RetentionPlan.Blocked(policy, pinned, now, $"Snapshot {bad.Folder.FolderName} failed verification; nothing is removed until it is resolved.");
        }

        var valid = snapshots.Where(s => s.IsRestorable && s.Record is not null).ToList();
        var candidates = valid.Select(s => new RetentionCandidate(s.Record!.SnapshotId, s.Record.StartedUtc, pinned.Contains(s.Record.SnapshotId), true)).ToList();
        var deleteIds = RetentionCalculator.SelectForDeletion(candidates, policy, now).ToHashSet();
        var toDelete = valid.Where(s => deleteIds.Contains(s.Record!.SnapshotId)).ToList();

        // Live set: every blob referenced by snapshots that remain (valid, incomplete-resumable, and pending finalize).
        var keep = snapshots.Where(s => s.Record is not null && !deleteIds.Contains(s.Record.SnapshotId) && s.Validity != SnapshotValidity.Invalid).ToList();
        var live = new HashSet<ChunkId>();
        foreach (var s in keep)
        {
            foreach (var src in s.Record!.Sources)
            {
                CollectLive(src.RootTree, live, ct);
            }
        }

        // Packs written by interrupted (resumable) runs are kept so Resume can reuse them, and every pack named in the
        // commit record of a kept snapshot is kept as a second line of defence.
        var protectedPacks = new HashSet<Guid>(keep.Where(s => s.Commit is not null).SelectMany(s => s.Commit!.Packs.Select(p => p.PackId)));
        foreach (var s in snapshots.Where(s => s.Validity == SnapshotValidity.Incomplete))
        {
            var jp = RepositoryLayout.JournalPath(s.Folder.FullPath);
            try
            {
                if (File.Exists(jp))
                {
                    foreach (var p in JournalRecord.Decode(EncryptedObjects.ReadObject(jp, _repo.Keys, ObjectType.Journal)).Packs)
                    {
                        protectedPacks.Add(p.PackId);
                    }
                }
            }
            catch (CryptoException)
            {
            }
        }

        var packsToDelete = new List<Guid>();
        var packsToRepack = new List<Guid>();
        long reclaim = 0;
        foreach (var pack in _repo.Index.Packs.Values)
        {
            if (protectedPacks.Contains(pack.PackId))
            {
                continue;
            }

            var blobs = _repo.Index.BlobsInPack(pack.PackId).ToList();
            int liveCount = blobs.Count(live.Contains);
            if (liveCount == 0)
            {
                packsToDelete.Add(pack.PackId);
                reclaim += pack.Length * (pack.Kind == PackKind.Meta ? 2 : 1);
            }
            else if (blobs.Count > 0 && liveCount * 2 < blobs.Count && (pack.Kind == PackKind.Meta || _repo.Keys.CanReadContent))
            {
                // Repacking a data pack needs to read its contents, which a backup-only key cannot do; the space is
                // reclaimed by the next retention run that has the full key.
                packsToRepack.Add(pack.PackId);
            }
        }

        return new RetentionPlan(toDelete, packsToDelete, packsToRepack, reclaim, policy, pinned, now);
    }

    private void CollectLive(ChunkId treeId, HashSet<ChunkId> live, CancellationToken ct)
    {
        if (!live.Add(treeId))
        {
            return; // identical subtree already visited
        }

        ct.ThrowIfCancellationRequested();
        // Reading from the drive (not just the cache) confirms the plan against authenticated trees.
        var tree = _repo.ReadTree(treeId);
        foreach (var e in tree.Entries)
        {
            foreach (var c in e.Chunks)
            {
                live.Add(c);
            }

            if (e.Subtree is { } st)
            {
                CollectLive(st, live, ct);
            }
        }
    }

    public RetentionResult Apply(RetentionPlan preview, string? indexCachePath, Action<string>? faultInjection = null, CancellationToken ct = default)
    {
        using var repoLock = RepositoryLock.Acquire(_repo.Layout, CryptoRandom.NewId());

        // Re-plan under the lock against the drive as it is now (another process may have committed a backup).
        _repo.Index.Reconcile(_repo.Layout, _repo.Keys, null, ct);
        var plan = Plan(preview.Policy, preview.Pinned, preview.Now, indexCachePath, ct);
        if (plan.IsBlocked)
        {
            _logger.LogWarning("Retention skipped: {Reason}", plan.BlockedReason);
            return new RetentionResult([], 0, 0, 0);
        }

        var deleted = new List<string>();

        // Phase 1: mark snapshots as being deleted (never offered for restore from now on).
        var renamed = new List<string>();
        foreach (var s in plan.ToDelete)
        {
            var target = s.Folder.FullPath + SnapshotNaming.DeletingSuffix;
            Directory.Move(s.Folder.FullPath, target);
            renamed.Add(target);
            deleted.Add(s.Folder.FolderName);
        }

        _repo.Ops.FlushDirectory(_repo.Layout.Root);
        faultInjection?.Invoke("after-mark-deleting");

        // Phase 2: repack mostly-dead packs (copy live blobs into a new verified pack before removing the old one).
        int repacked = 0;
        long reclaimed = 0;
        foreach (var packId in plan.PacksToRepack)
        {
            ct.ThrowIfCancellationRequested();
            reclaimed += Repack(packId, plan);
            repacked++;
        }

        // Phase 3: delete packs with no live blobs.
        int packsDeleted = 0;
        foreach (var packId in plan.PacksToDelete)
        {
            if (!_repo.Index.Packs.TryGetValue(packId, out var rec))
            {
                continue;
            }

            foreach (bool copy in rec.Kind == PackKind.Meta ? new[] { false, true } : new[] { false })
            {
                EncryptedObjects.TryDelete(_repo.Layout.PackPath(rec.Kind, packId, copy));
            }

            _repo.Index.RemovePack(packId);
            reclaimed += rec.Length * (rec.Kind == PackKind.Meta ? 2 : 1);
            packsDeleted++;
        }

        // Phase 4: remove the snapshot folders.
        foreach (var dir in renamed)
        {
            Directory.Delete(dir, recursive: true);
        }

        CompleteInterruptedDeletions();
        _repo.Index.SaveCache(indexCachePath, _repo.Keys, _repo.Ops);
        _logger.LogInformation("Retention removed {Count} snapshots, {Packs} packs, repacked {Repacked}", deleted.Count, packsDeleted, repacked);
        return new RetentionResult(deleted, packsDeleted, repacked, reclaimed);
    }

    /// <summary>Finishes deletions interrupted by a crash (folders left as <c>.deleting</c>).</summary>
    public void CompleteInterruptedDeletions()
    {
        foreach (var f in _repo.ListSnapshotFolders().Where(f => f.Parsed.State == SnapshotState.Deleting))
        {
            try
            {
                Directory.Delete(f.FullPath, recursive: true);
            }
            catch (IOException)
            {
            }
        }
    }

    private long Repack(Guid packId, RetentionPlan plan)
    {
        if (!_repo.Index.Packs.TryGetValue(packId, out var rec))
        {
            return 0;
        }

        // Collect the live blobs again from the remaining snapshots to stay conservative.
        var live = new HashSet<ChunkId>();
        foreach (var s in _repo.LoadAllSnapshots().Where(s => s.Record is not null && s.Validity != SnapshotValidity.Invalid && s.Validity != SnapshotValidity.Deleting))
        {
            if (plan.ToDelete.Any(d => d.Record?.SnapshotId == s.Record!.SnapshotId))
            {
                continue;
            }

            foreach (var src in s.Record!.Sources)
            {
                CollectLive(src.RootTree, live, CancellationToken.None);
            }
        }

        var builder = new PackBuilder(rec.Kind);
        foreach (var id in _repo.Index.BlobsInPack(packId).Where(live.Contains))
        {
            var entry = _repo.Index.Locations(id).First(e => e.PackId == packId);
            var raw = _repo.ReadBlobAt(id, entry);
            var (stored, codec) = BlobCompression.Compress(raw);
            builder.Add(id, entry.Kind, stored, raw.Length, codec);
        }

        if (builder.Count > 0)
        {
            var info = PackFormat.Write(_repo.Layout, _repo.Keys, builder, _repo.Ops); // verified before use
            _repo.Index.AddPack(info);
        }

        _repo.CloseReaders();
        foreach (bool copy in rec.Kind == PackKind.Meta ? new[] { false, true } : new[] { false })
        {
            EncryptedObjects.TryDelete(_repo.Layout.PackPath(rec.Kind, packId, copy));
        }

        _repo.Index.RemovePack(packId);
        return rec.Length;
    }
}
