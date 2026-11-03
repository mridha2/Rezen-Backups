using System.Security.Cryptography;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Crypto;
using RezenBackup.Format;

namespace RezenBackup.RestoreEngine;

public sealed record DeepVerifyProgress(int PacksDone, int PacksTotal, int SnapshotsDone, int SnapshotsTotal);

public sealed record DamagedPack(Guid PackId, PackKind Kind, string Reason, bool RecoveredFromCopy);

public sealed record SnapshotVerifyResult(string FolderName, SnapshotValidity Validity, bool AllDataPresent, string? Problem);

public sealed record DeepVerifyReport
{
    public int PacksChecked { get; init; }

    public IReadOnlyList<DamagedPack> DamagedPacks { get; init; } = [];

    public IReadOnlyList<SnapshotVerifyResult> Snapshots { get; init; } = [];

    public IReadOnlyList<string> MissingSnapshotsInChain { get; init; } = [];

    public bool Healthy => DamagedPacks.All(d => d.RecoveredFromCopy) && Snapshots.All(s => s.Validity is SnapshotValidity.Valid or SnapshotValidity.Incomplete && s.AllDataPresent) && MissingSnapshotsInChain.Count == 0;
}

/// <summary>
/// Deep verification of an entire repository (DESIGN §15.2, §15.5): every pack is read, every segment authenticated,
/// every pack hash compared with the index, and every committed snapshot's trees and data references resolved.
/// Damaged data packs can be quarantined so the next backup re-stores those chunks from the source files.
/// </summary>
public sealed class RepositoryVerifier
{
    private readonly Repository _repo;

    public RepositoryVerifier(Repository repo) => _repo = repo;

    public DeepVerifyReport Verify(IProgress<DeepVerifyProgress>? progress = null, CancellationToken ct = default)
    {
        var packs = _repo.Layout.EnumeratePacks().ToList();
        var damaged = new List<DamagedPack>();
        var damagedIds = new HashSet<Guid>();
        int done = 0;
        foreach (var (packId, kind, path) in packs)
        {
            ct.ThrowIfCancellationRequested();
            var problem = CheckPack(path, packId, kind);
            if (problem is not null)
            {
                bool recovered = false;
                if (kind == PackKind.Meta)
                {
                    recovered = CheckPack(_repo.Layout.PackPath(kind, packId, copy: true), packId, kind) is null;
                }

                damaged.Add(new DamagedPack(packId, kind, problem, recovered));
                if (!recovered)
                {
                    damagedIds.Add(packId);
                }
            }

            progress?.Report(new DeepVerifyProgress(++done, packs.Count, 0, 0));
        }

        var snapshots = _repo.LoadAllSnapshots();
        var results = new List<SnapshotVerifyResult>();
        var knownCommitHashes = new HashSet<string>(snapshots.Where(s => s.CommitHash is not null).Select(s => Convert.ToHexString(s.CommitHash!)));
        var missingInChain = new List<string>();
        int sdone = 0;
        foreach (var snap in snapshots)
        {
            ct.ThrowIfCancellationRequested();
            if (!snap.IsRestorable)
            {
                results.Add(new SnapshotVerifyResult(snap.Folder.FolderName, snap.Validity, snap.Validity == SnapshotValidity.Incomplete, snap.Problem));
                continue;
            }

            if (snap.Record!.PreviousCommitHash is { } prev && !knownCommitHashes.Contains(Convert.ToHexString(prev)))
            {
                missingInChain.Add(snap.Folder.FolderName);
            }

            string? problem = null;
            bool allPresent = true;
            try
            {
                foreach (var src in snap.Record.Sources)
                {
                    CheckTree(src.RootTree, damagedIds, ct);
                }
            }
            catch (RezenException ex)
            {
                allPresent = false;
                problem = UserMessages.IntegrityFailed + " " + ex.TechnicalDetails;
            }

            results.Add(new SnapshotVerifyResult(snap.Folder.FolderName, snap.Validity, allPresent, problem));
            progress?.Report(new DeepVerifyProgress(done, packs.Count, ++sdone, snapshots.Count));
        }

        _repo.CloseReaders();
        return new DeepVerifyReport
        {
            PacksChecked = packs.Count,
            DamagedPacks = damaged,
            Snapshots = results,
            MissingSnapshotsInChain = missingInChain,
        };
    }

    private string? CheckPack(string path, Guid packId, PackKind kind)
    {
        try
        {
            if (!File.Exists(path))
            {
                return "missing";
            }

            var bytes = File.ReadAllBytes(path);
            if (_repo.Index.Packs.TryGetValue(packId, out var rec) && !rec.Sha256.AsSpan().SequenceEqual(SHA256.HashData(bytes)))
            {
                return "content changed since it was written";
            }

            using var ms = new MemoryStream(bytes, writable: false);
            using var reader = new PackReader(ms, _repo.Keys, kind);
            reader.VerifyAllSegments();
            return null;
        }
        catch (CryptoException ex)
        {
            return ex.Message;
        }
        catch (IOException ex)
        {
            return ex.Message;
        }
    }

    private void CheckTree(ChunkId treeId, HashSet<Guid> damagedPacks, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var tree = _repo.ReadTree(treeId);
        foreach (var e in tree.Entries)
        {
            foreach (var c in e.Chunks)
            {
                var locations = _repo.Index.Locations(c).ToList();
                if (locations.Count == 0 || locations.All(l => damagedPacks.Contains(l.PackId)))
                {
                    throw new RezenException(ErrorCode.IntegrityFailure, $"Data for '{e.Name}' is missing or damaged.");
                }
            }

            if (e.Kind == EntryKind.Directory && e.Subtree is { } st)
            {
                CheckTree(st, damagedPacks, ct);
            }
        }
    }

    /// <summary>
    /// Moves a damaged pack to <c>store/quarantine</c> (never deletes it) and removes it from the index, so the next
    /// backup re-stores those chunks from the source files (repair from source, DESIGN §15.5).
    /// </summary>
    public void Quarantine(Guid packId, PackKind kind, string? indexCachePath)
    {
        Directory.CreateDirectory(_repo.Layout.QuarantineDirectory);
        var path = _repo.Layout.PackPath(kind, packId);
        if (File.Exists(path))
        {
            File.Move(path, Path.Combine(_repo.Layout.QuarantineDirectory, Path.GetFileName(path)), overwrite: true);
        }

        _repo.Index.RemovePack(packId);
        _repo.Index.SaveCache(indexCachePath, _repo.Keys, _repo.Ops);
    }
}
