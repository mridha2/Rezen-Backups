using System.Security.Cryptography;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Platform;
using RezenBackup.Core.Policies;
using RezenBackup.Crypto;

namespace RezenBackup.Format;

public enum SnapshotValidity
{
    /// <summary>Committed and authenticated — restorable.</summary>
    Valid,

    /// <summary>Interrupted before commit — never restorable until resumed and verified.</summary>
    Incomplete,

    /// <summary>Commit record authenticated but folder not yet renamed (crash between DESIGN §16.1 steps 7 and 8).</summary>
    CommittedPendingFinalize,

    /// <summary>Being removed by retention.</summary>
    Deleting,

    /// <summary>Authentication or consistency failure.</summary>
    Invalid,
}

public sealed record SnapshotFolder(string FolderName, SnapshotFolderName Parsed, string FullPath);

public sealed record LoadedSnapshot(
    SnapshotFolder Folder,
    SnapshotValidity Validity,
    SnapshotRecord? Record,
    CommitRecord? Commit,
    byte[]? CommitHash,
    string? Problem)
{
    public bool IsRestorable => Validity == SnapshotValidity.Valid;
}

public sealed record UnlockReport(int CopiesTried, int DamagedCopies, int RepairedCopies);

/// <summary>An unlocked repository: format-level access to snapshots and blobs. Holds key material until disposed.</summary>
public sealed class Repository : IDisposable
{
    private readonly Dictionary<(Guid, bool), PackReader> _readers = [];
    private readonly LinkedList<(Guid, bool)> _readerOrder = new();
    private const int MaxOpenReaders = 8;

    private Repository(RepositoryLayout layout, RepositoryInfo info, RepositoryKeys keys, RepositoryConfig config, IDurableFileOps ops)
    {
        Layout = layout;
        Info = info;
        Keys = keys;
        Config = config;
        Ops = ops;
        Index = new ChunkIndex();
    }

    public RepositoryLayout Layout { get; }

    public RepositoryInfo Info { get; }

    public RepositoryKeys Keys { get; }

    public RepositoryConfig Config { get; }

    public IDurableFileOps Ops { get; }

    public ChunkIndex Index { get; private set; }

    public Guid RepositoryId => Info.RepositoryId;

    public static bool Exists(string path) => File.Exists(new RepositoryLayout(path).ConfigPath);

    public static RepositoryInfo ReadInfo(string path)
    {
        var layout = new RepositoryLayout(path);
        if (!File.Exists(layout.ConfigPath))
        {
            throw new RezenException(ErrorCode.RepositoryNotFound);
        }

        return RepositoryConfigFile.ReadInfo(layout.ConfigPath);
    }

    /// <summary>
    /// Creates a new repository. Key files are written (twice) before the configuration, so the presence of
    /// <c>repository.rzc</c> implies usable key files.
    /// </summary>
    public static Repository Create(string path, Guid keySetId, RootSecret secret, KeyFile keySetKeyFile, RepositoryConfig config, IDurableFileOps ops)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentNullException.ThrowIfNull(keySetKeyFile);
        var layout = new RepositoryLayout(path);
        if (File.Exists(layout.ConfigPath))
        {
            throw new RezenException(ErrorCode.UnsafeConfiguration, "A Rezen Backup repository already exists here; it will not be overwritten.", null, null);
        }

        if (keySetKeyFile.KeySetId != keySetId)
        {
            throw new ArgumentException("Key file belongs to another key set.", nameof(keySetKeyFile));
        }

        var repositoryId = CryptoRandom.NewId();
        var info = new RepositoryInfo(repositoryId, keySetId, RepositoryLayout.FormatVersion, 1);
        layout.EnsureDirectories();
        var keyFile = keySetKeyFile.ForRepository(repositoryId, secret);
        foreach (var kf in layout.KeyFiles)
        {
            KeyFileStore.WriteVerified(kf, keyFile, ops, f => f.KeySetId == keySetId && f.RepositoryId == repositoryId && f.MatchesKeyCheck(secret));
        }

        var keys = secret.DeriveRepositoryKeys(repositoryId);
        try
        {
            RepositoryConfigFile.Write(layout.ConfigPath, info, config, keys, ops);
            return new Repository(layout, info, keys, config, ops);
        }
        catch
        {
            keys.Dispose();
            throw;
        }
    }

    /// <summary>Opens a repository with the Key Set's Root Secret. A wrong secret fails with a generic unlock error.</summary>
    public static Repository Open(string path, RootSecret secret, IDurableFileOps ops)
    {
        var layout = new RepositoryLayout(path);
        var info = ReadInfo(path);
        var keys = secret.DeriveRepositoryKeys(info.RepositoryId);
        try
        {
            RepositoryConfig config;
            try
            {
                config = RepositoryConfigFile.ReadConfig(layout.ConfigPath, keys);
            }
            catch (CryptoException ex) when (ex.Error == CryptoError.AuthenticationFailed)
            {
                throw new RezenException(ErrorCode.WrongPassword, null, ex);
            }

            return new Repository(layout, info, keys, config, ops);
        }
        catch
        {
            keys.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Unlocks the Root Secret from the repository's key files using a password. Tries every copy; repairs damaged,
    /// missing or out-of-date copies from the one that worked (DESIGN §8.1).
    /// </summary>
    public static RootSecret UnlockWithPassword(string path, SecretBuffer passwordBytes, IDurableFileOps ops, out UnlockReport report)
    {
        var layout = new RepositoryLayout(path);
        var info = ReadInfo(path);
        var candidates = new List<(string Path, KeyFile File)>();
        int damaged = 0;
        foreach (var p in layout.KeyFiles)
        {
            var kf = KeyFileStore.TryRead(p, out bool isDamaged);
            if (isDamaged || kf is null || kf.RepositoryId != info.RepositoryId || kf.KeySetId != info.KeySetId)
            {
                damaged++;
                continue;
            }

            candidates.Add((p, kf));
        }

        if (candidates.Count == 0)
        {
            throw new RezenException(ErrorCode.RecoveryKeyRequired);
        }

        foreach (var (p, kf) in candidates.OrderByDescending(c => c.File.Generation))
        {
            RootSecret secret;
            try
            {
                secret = kf.Unlock(passwordBytes);
            }
            catch (CryptoException ex) when (ex.Error is CryptoError.WrongKey or CryptoError.InvalidFormat)
            {
                continue;
            }

            int repaired = RepairKeyFiles(layout, kf, secret, ops);
            report = new UnlockReport(layout.KeyFiles.Count, damaged, repaired);
            return secret;
        }

        throw new RezenException(ErrorCode.WrongPassword);
    }

    /// <summary>Reads the best available key file (highest generation that parses).</summary>
    public static KeyFile? ReadBestKeyFile(string path)
    {
        var layout = new RepositoryLayout(path);
        return layout.KeyFiles.Select(p => KeyFileStore.TryRead(p, out _)).Where(k => k is not null).OrderByDescending(k => k!.Generation).FirstOrDefault();
    }

    /// <summary>Rewrites any key file copy that is damaged, missing or older than <paramref name="good"/>.</summary>
    public static int RepairKeyFiles(RepositoryLayout layout, KeyFile good, RootSecret secret, IDurableFileOps ops)
    {
        int repaired = 0;
        foreach (var p in layout.KeyFiles)
        {
            var existing = KeyFileStore.TryRead(p, out _);
            if (existing is not null && existing.Generation >= good.Generation)
            {
                continue;
            }

            try
            {
                KeyFileStore.WriteVerified(p, good, ops, f => f.MatchesKeyCheck(secret));
                repaired++;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or RezenException)
            {
                // Read-only media or a failing drive: keep going with the copy that works.
            }
        }

        return repaired;
    }

    /// <summary>Replaces both key file copies (password change). Each copy is written, read back and verified first.</summary>
    public void ReplaceKeyFiles(KeyFile newFile, RootSecret secret, Func<KeyFile, bool> verify)
    {
        if (newFile.RepositoryId != RepositoryId)
        {
            throw new ArgumentException("Key file targets a different repository.", nameof(newFile));
        }

        foreach (var p in Layout.KeyFiles)
        {
            KeyFileStore.WriteVerified(p, newFile, Ops, f => f.MatchesKeyCheck(secret) && verify(f));
        }
    }

    public void LoadIndex(string? cachePath, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        Index = ChunkIndex.LoadCache(cachePath, Keys);
        int read = Index.Reconcile(Layout, Keys, progress, ct);
        if (read > 0 || !File.Exists(cachePath ?? string.Empty))
        {
            Index.SaveCache(cachePath, Keys, Ops);
        }
    }

    public IReadOnlyList<SnapshotFolder> ListSnapshotFolders()
    {
        if (!Directory.Exists(Layout.Root))
        {
            return [];
        }

        var result = new List<SnapshotFolder>();
        foreach (var dir in Directory.EnumerateDirectories(Layout.Root))
        {
            var name = Path.GetFileName(dir);
            if (SnapshotNaming.TryParse(name, out var parsed) && parsed is not null)
            {
                result.Add(new SnapshotFolder(name, parsed, dir));
            }
        }

        return result.OrderBy(f => f.Parsed.LocalTime).ThenBy(f => f.Parsed.Sequence).ToList();
    }

    /// <summary>Loads and validates a snapshot (DESIGN §11, §15.4). Never throws for damaged snapshots.</summary>
    public LoadedSnapshot LoadSnapshot(SnapshotFolder folder)
    {
        if (folder.Parsed.State == SnapshotState.Deleting)
        {
            return new LoadedSnapshot(folder, SnapshotValidity.Deleting, null, null, null, null);
        }

        var recordPath = RepositoryLayout.SnapshotRecordPath(folder.FullPath);
        var commitPath = RepositoryLayout.CommitRecordPath(folder.FullPath);
        SnapshotRecord? record = null;
        CommitRecord? commit = null;
        byte[]? recordSha = null;
        byte[]? commitHash = null;
        try
        {
            if (File.Exists(recordPath))
            {
                var bytes = File.ReadAllBytes(recordPath);
                recordSha = SHA256.HashData(bytes);
                record = SnapshotRecord.Decode(EncryptedObjects.Decrypt(Keys, ObjectType.Snapshot, bytes));
            }

            if (File.Exists(commitPath))
            {
                var bytes = File.ReadAllBytes(commitPath);
                commitHash = SHA256.HashData(bytes);
                commit = CommitRecord.Decode(EncryptedObjects.Decrypt(Keys, ObjectType.Commit, bytes));
            }
        }
        catch (CryptoException ex)
        {
            return new LoadedSnapshot(folder, SnapshotValidity.Invalid, record, commit, commitHash, UserMessages.IntegrityFailed + " " + ex.Message);
        }
        catch (IOException ex)
        {
            return new LoadedSnapshot(folder, SnapshotValidity.Invalid, record, commit, commitHash, ex.Message);
        }

        if (commit is null || record is null)
        {
            var validity = folder.Parsed.State == SnapshotState.Incomplete ? SnapshotValidity.Incomplete : SnapshotValidity.Invalid;
            return new LoadedSnapshot(folder, validity, record, null, null, validity == SnapshotValidity.Invalid ? "Snapshot has no commit record." : null);
        }

        string baseName = folder.Parsed.BaseName;
        bool consistent = commit.State == CommitRecord.CommittedState
            && commit.SnapshotId == record.SnapshotId
            && commit.RepositoryId == RepositoryId
            && record.RepositoryId == RepositoryId
            && string.Equals(commit.FolderBaseName, baseName, StringComparison.Ordinal)
            && string.Equals(record.FolderBaseName, baseName, StringComparison.Ordinal)
            && recordSha is not null && CryptographicOperations.FixedTimeEquals(recordSha, commit.SnapshotRecordSha256);
        if (!consistent)
        {
            return new LoadedSnapshot(folder, SnapshotValidity.Invalid, record, commit, commitHash, UserMessages.IntegrityFailed + " Snapshot records do not match.");
        }

        return new LoadedSnapshot(
            folder,
            folder.Parsed.State == SnapshotState.Incomplete ? SnapshotValidity.CommittedPendingFinalize : SnapshotValidity.Valid,
            record,
            commit,
            commitHash,
            null);
    }

    public IReadOnlyList<LoadedSnapshot> LoadAllSnapshots() => ListSnapshotFolders().Select(LoadSnapshot).ToList();

    /// <summary>
    /// Reads, authenticates, decompresses and re-identifies a blob. Plaintext is returned only if the keyed identifier
    /// of the decompressed bytes equals the requested identifier.
    /// </summary>
    public byte[] ReadBlob(ChunkId id)
    {
        var locations = Index.Locations(id).ToList();
        if (locations.Count == 0)
        {
            throw new RezenException(ErrorCode.IntegrityFailure, $"Missing data block {id}.");
        }

        Exception? lastError = null;
        foreach (var entry in locations)
        {
            foreach (bool copy in entry.PackKind == PackKind.Meta ? new[] { false, true } : new[] { false })
            {
                try
                {
                    return ReadBlobAt(id, entry, copy);
                }
                catch (CryptoException ex)
                {
                    lastError = ex;
                    DropReader(entry.PackId, copy);
                }
                catch (IOException ex)
                {
                    lastError = ex;
                    DropReader(entry.PackId, copy);
                }
            }
        }

        throw new RezenException(ErrorCode.IntegrityFailure, $"Block {id} failed verification.", lastError);
    }

    /// <summary>Reads a blob from one specific location (used by verification of a specific pack).</summary>
    public byte[] ReadBlobAt(ChunkId id, IndexEntry entry, bool copy = false)
    {
        var reader = GetReader(entry.PackId, entry.PackKind, copy);
        var stored = reader.ReadStored(new PackEntry(id, entry.Kind, entry.Offset, entry.StoredLength, entry.RawLength, entry.Codec));
        var raw = BlobCompression.Decompress(stored, entry.Codec, entry.RawLength);
        var actual = entry.Kind == BlobKind.Tree ? Keys.ComputeTreeId(raw) : Keys.ComputeChunkId(raw);
        if (actual != id)
        {
            CryptographicOperations.ZeroMemory(raw);
            throw new CryptoException(CryptoError.AuthenticationFailed, "Block identifier mismatch.");
        }

        return raw;
    }

    public TreeNode ReadTree(ChunkId id) => TreeNode.Decode(ReadBlob(id));

    private PackReader GetReader(Guid packId, PackKind kind, bool copy)
    {
        var key = (packId, copy);
        if (_readers.TryGetValue(key, out var r))
        {
            _readerOrder.Remove(key);
            _readerOrder.AddFirst(key);
            return r;
        }

        var reader = PackReader.Open(Layout.PackPath(kind, packId, copy), Keys, kind);
        _readers[key] = reader;
        _readerOrder.AddFirst(key);
        while (_readerOrder.Count > MaxOpenReaders)
        {
            var last = _readerOrder.Last!.Value;
            _readerOrder.RemoveLast();
            _readers.Remove(last, out var old);
            old?.Dispose();
        }

        return reader;
    }

    private void DropReader(Guid packId, bool copy)
    {
        if (_readers.Remove((packId, copy), out var r))
        {
            _readerOrder.Remove((packId, copy));
            r.Dispose();
        }
    }

    public void CloseReaders()
    {
        foreach (var r in _readers.Values)
        {
            r.Dispose();
        }

        _readers.Clear();
        _readerOrder.Clear();
    }

    public void Dispose()
    {
        CloseReaders();
        Keys.Dispose();
    }
}
