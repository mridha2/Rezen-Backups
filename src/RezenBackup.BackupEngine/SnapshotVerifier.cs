using System.Security.Cryptography;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Crypto;
using RezenBackup.Format;

namespace RezenBackup.BackupEngine;

/// <summary>
/// Post-backup verification before commit (DESIGN §15.2). New packs were already read back from the device and fully
/// authenticated as they were written; this pass checks the snapshot as a whole.
/// </summary>
internal static class SnapshotVerifier
{
    public static void Verify(
        Repository repo,
        SnapshotRecord record,
        string recordPath,
        SnapshotWriter writer,
        TreeWalker walker,
        VerificationLevel level,
        ProgressTracker progress,
        CancellationToken ct)
    {
        // 1. The snapshot record on the device decrypts, authenticates and matches what we intended to write.
        var onDisk = EncryptedObjects.ReadAllForVerification(recordPath, repo.Ops);
        var decoded = SnapshotRecord.Decode(EncryptedObjects.Decrypt(repo.Keys, ObjectType.Snapshot, onDisk));
        if (decoded.SnapshotId != record.SnapshotId || decoded.Sources.Count != record.Sources.Count)
        {
            throw Fail("Snapshot record read back does not match.");
        }

        // 2. Every referenced blob resolves to a pack file that exists with the expected length.
        var packLengths = new Dictionary<Guid, bool>();
        foreach (var id in walker.Referenced)
        {
            ct.ThrowIfCancellationRequested();
            var loc = writer.LocationFor(id) ?? throw Fail($"Referenced block {id} is not stored.");
            if (!packLengths.TryGetValue(loc, out bool ok))
            {
                ok = repo.Index.Packs.TryGetValue(loc, out var rec) && PackFileOk(repo, rec);
                packLengths[loc] = ok;
            }

            if (!ok)
            {
                throw Fail($"Pack {loc} is missing or has the wrong size.");
            }
        }

        // 3. All trees of the new snapshot decrypt and authenticate from the drive; counts are consistent.
        long files = 0;
        long dirs = 0;
        foreach (var source in record.Sources)
        {
            CountTree(repo, source.RootTree, ref files, ref dirs, ct);
        }

        if (files != record.Stats.Files || dirs != record.Stats.Directories)
        {
            throw Fail($"File count mismatch (expected {record.Stats.Files}/{record.Stats.Directories}, found {files}/{dirs}).");
        }

        if (level != VerificationLevel.Full)
        {
            return;
        }

        // 4. Full: every file read in this run is reassembled from the drive and its SHA-256 compared with the hash
        //    computed while reading the source.
        progress.FilesTotal = walker.FilesRead.Count;
        progress.FilesDone = 0;
        progress.BytesTotal = walker.FilesRead.Sum(f => f.Size);
        progress.BytesDone = 0;
        foreach (var file in walker.FilesRead)
        {
            ct.ThrowIfCancellationRequested();

            // A backup-only key can read back what this run wrote, but not older data it deduplicated against; that
            // older data was verified when it was written, and this file still gets Standard verification.
            if (!repo.Keys.CanReadContent && file.Chunks.Any(c => !writer.ThisRunLocations.ContainsKey(c)))
            {
                progress.FilesDone++;
                continue;
            }

            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long size = 0;
            foreach (var chunkId in file.Chunks)
            {
                var data = ReadPreferThisRun(repo, writer, chunkId);
                hash.AppendData(data);
                size += data.Length;
                progress.BytesDone += data.Length;
                CryptographicOperations.ZeroMemory(data);
            }

            if (size != file.Size || !CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), file.Sha256))
            {
                throw Fail("A file reconstructed from the backup does not match its source hash.");
            }

            progress.FilesDone++;
            progress.Report();
        }
    }

    private static byte[] ReadPreferThisRun(Repository repo, SnapshotWriter writer, ChunkId id)
    {
        if (writer.ThisRunLocations.TryGetValue(id, out var packId))
        {
            var entry = repo.Index.Locations(id).FirstOrDefault(e => e.PackId == packId);
            if (entry.PackId == packId)
            {
                return repo.ReadBlobAt(id, entry);
            }
        }

        return repo.ReadBlob(id);
    }

    private static bool PackFileOk(Repository repo, PackRecord rec)
    {
        var path = repo.Layout.PackPath(rec.Kind, rec.PackId);
        try
        {
            var fi = new FileInfo(path);
            return fi.Exists && fi.Length == rec.Length;
        }
        catch (IOException)
        {
            return false;
        }
    }

    private static void CountTree(Repository repo, ChunkId treeId, ref long files, ref long dirs, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var node = repo.ReadTree(treeId);
        foreach (var e in node.Entries)
        {
            switch (e.Kind)
            {
                case EntryKind.File:
                    files++;
                    break;
                case EntryKind.Directory when e.Subtree is { } st:
                    if (e.Status != EntryStatus.CarriedForward)
                    {
                        dirs++;
                    }

                    CountTreeFilesOnly(repo, st, e.Status == EntryStatus.CarriedForward, ref files, ref dirs, ct);
                    break;
            }
        }
    }

    private static void CountTreeFilesOnly(Repository repo, ChunkId treeId, bool carried, ref long files, ref long dirs, CancellationToken ct)
    {
        if (carried)
        {
            // Carried-forward folders were not counted by the walker; just confirm they authenticate.
            long ignoredFiles = 0;
            long ignoredDirs = 0;
            CountTree(repo, treeId, ref ignoredFiles, ref ignoredDirs, ct);
            return;
        }

        CountTree(repo, treeId, ref files, ref dirs, ct);
    }

    private static RezenException Fail(string detail) =>
        new(ErrorCode.IntegrityFailure, detail);
}
