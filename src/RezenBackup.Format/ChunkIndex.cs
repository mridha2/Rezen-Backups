using System.Formats.Cbor;
using System.Security.Cryptography;
using RezenBackup.Core.Platform;
using RezenBackup.Crypto;

namespace RezenBackup.Format;

public readonly record struct IndexEntry(Guid PackId, PackKind PackKind, BlobKind Kind, long Offset, int StoredLength, int RawLength, BlobCodec Codec);

public sealed record PackRecord(Guid PackId, PackKind Kind, long Length, byte[] Sha256, int EntryCount);

/// <summary>
/// Maps chunk/tree identifiers to their location in packs (DESIGN §14.5). Rebuildable at any time from the pack
/// indexes on the drive; optionally cached locally as an encrypted, authenticated object.
/// </summary>
public sealed class ChunkIndex
{
    private readonly Dictionary<ChunkId, IndexEntry> _entries = [];
    private readonly Dictionary<ChunkId, List<IndexEntry>> _alternates = [];
    private readonly Dictionary<Guid, PackRecord> _packs = [];

    public int Count => _entries.Count;

    /// <summary>Data packs the last <see cref="Reconcile"/> could not index because the key is backup-only.</summary>
    public int SkippedUnreadable { get; private set; }

    public IReadOnlyDictionary<Guid, PackRecord> Packs => _packs;

    public bool Contains(ChunkId id) => _entries.ContainsKey(id);

    public bool TryGet(ChunkId id, out IndexEntry entry) => _entries.TryGetValue(id, out entry);

    /// <summary>All known locations of a blob: primary first, then redundant copies (e.g. from Full snapshots).</summary>
    public IEnumerable<IndexEntry> Locations(ChunkId id)
    {
        if (_entries.TryGetValue(id, out var primary))
        {
            yield return primary;
        }

        if (_alternates.TryGetValue(id, out var list))
        {
            foreach (var e in list)
            {
                yield return e;
            }
        }
    }

    public IEnumerable<KeyValuePair<ChunkId, IndexEntry>> AllPrimary => _entries;

    /// <summary>Returns the identifiers of all blobs stored in a pack (primary or alternate).</summary>
    public IEnumerable<ChunkId> BlobsInPack(Guid packId)
    {
        foreach (var kv in _entries)
        {
            if (kv.Value.PackId == packId)
            {
                yield return kv.Key;
            }
        }

        foreach (var kv in _alternates)
        {
            if (kv.Value.Any(e => e.PackId == packId))
            {
                yield return kv.Key;
            }
        }
    }

    public void AddPack(PackInfo pack)
    {
        _packs[pack.PackId] = new PackRecord(pack.PackId, pack.Kind, pack.Length, pack.Sha256, pack.Entries.Count);
        foreach (var e in pack.Entries)
        {
            var entry = new IndexEntry(pack.PackId, pack.Kind, e.Kind, e.Offset, e.StoredLength, e.RawLength, e.Codec);
            if (!_entries.TryAdd(e.Id, entry) && _entries[e.Id].PackId != pack.PackId)
            {
                // Redundant copy (Full snapshot or repair): kept as an alternate location.
                if (!_alternates.TryGetValue(e.Id, out var list))
                {
                    list = [];
                    _alternates[e.Id] = list;
                }

                if (!list.Any(x => x.PackId == pack.PackId))
                {
                    list.Add(entry);
                }
            }
        }
    }

    public void RemovePack(Guid packId)
    {
        if (!_packs.Remove(packId))
        {
            return;
        }

        foreach (var kv in _alternates.ToList())
        {
            kv.Value.RemoveAll(e => e.PackId == packId);
            if (kv.Value.Count == 0)
            {
                _alternates.Remove(kv.Key);
            }
        }

        var stale = _entries.Where(kv => kv.Value.PackId == packId).Select(kv => kv.Key).ToList();
        foreach (var id in stale)
        {
            _entries.Remove(id);
            if (_alternates.TryGetValue(id, out var list) && list.Count > 0)
            {
                // Promote a surviving copy.
                _entries[id] = list[0];
                list.RemoveAt(0);
                if (list.Count == 0)
                {
                    _alternates.Remove(id);
                }
            }
        }
    }

    /// <summary>
    /// Brings the index in line with the packs present on the drive: unknown packs are read, authenticated in full and
    /// hashed; packs that vanished are removed. Returns the number of packs read.
    /// </summary>
    public int Reconcile(RepositoryLayout layout, RepositoryKeys keys, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var onDisk = layout.EnumeratePacks().ToDictionary(p => p.PackId);
        foreach (var gone in _packs.Keys.Where(id => !onDisk.ContainsKey(id)).ToList())
        {
            RemovePack(gone);
        }

        int read = 0;
        SkippedUnreadable = 0;
        foreach (var (id, (packId, kind, path)) in onDisk)
        {
            ct.ThrowIfCancellationRequested();
            if (_packs.ContainsKey(id))
            {
                continue;
            }

            if (kind == PackKind.Data && !keys.CanReadContent)
            {
                // A backup-only key cannot read data packs it did not write; don't re-read them on every run.
                SkippedUnreadable++;
                continue;
            }

            PackInfo? info = TryReadPack(layout, keys, packId, kind, path);
            if (info is null && kind == PackKind.Meta)
            {
                info = TryReadPack(layout, keys, packId, kind, layout.PackPath(kind, packId, copy: true));
            }

            if (info is not null)
            {
                AddPack(info);
                read++;
                progress?.Report(path);
            }
        }

        return read;
    }

    private static PackInfo? TryReadPack(RepositoryLayout layout, RepositoryKeys keys, Guid packId, PackKind kind, string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            var bytes = File.ReadAllBytes(path);
            using var ms = new MemoryStream(bytes, writable: false);
            using var reader = new PackReader(ms, keys, kind);
            reader.VerifyAllSegments();
            return new PackInfo(packId, kind, bytes.LongLength, SHA256.HashData(bytes), reader.Entries.ToList());
        }
        catch (CryptoException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    public byte[] Serialize()
    {
        var w = Cbor.NewWriter();
        var all = _entries.Select(kv => (kv.Key, kv.Value))
            .Concat(_alternates.SelectMany(kv => kv.Value.Select(v => (kv.Key, v))));
        var byPack = all.GroupBy(x => x.Item2.PackId).ToDictionary(g => g.Key, g => g.ToList());
        w.WriteStartArray(_packs.Count);
        foreach (var p in _packs.Values)
        {
            w.WriteStartArray(5);
            w.WriteGuid(p.PackId);
            w.WriteInt32((int)p.Kind);
            w.WriteInt64(p.Length);
            w.WriteByteString(p.Sha256);
            var list = byPack.TryGetValue(p.PackId, out var l) ? l : [];
            w.WriteStartArray(list.Count);
            foreach (var (id, e) in list)
            {
                w.WriteStartArray(6);
                w.WriteChunkId(id);
                w.WriteInt32((int)e.Kind);
                w.WriteInt64(e.Offset);
                w.WriteInt32(e.StoredLength);
                w.WriteInt32(e.RawLength);
                w.WriteInt32((int)e.Codec);
                w.WriteEndArray();
            }

            w.WriteEndArray();
            w.WriteEndArray();
        }

        w.WriteEndArray();
        return w.Encode();
    }

    public static ChunkIndex Deserialize(byte[] data)
    {
        var index = new ChunkIndex();
        var r = Cbor.NewReader(data);
        int packs = r.ReadStartArray() ?? 0;
        for (int i = 0; i < packs; i++)
        {
            r.ReadStartArray();
            var packId = r.ReadGuid();
            var kind = (PackKind)r.ReadInt32();
            long length = r.ReadInt64();
            var sha = r.ReadByteString();
            int n = r.ReadStartArray() ?? 0;
            var entries = new List<PackEntry>(n);
            for (int j = 0; j < n; j++)
            {
                r.ReadStartArray();
                entries.Add(new PackEntry(r.ReadChunkId(), (BlobKind)r.ReadInt32(), r.ReadInt64(), r.ReadInt32(), r.ReadInt32(), (BlobCodec)r.ReadInt32()));
                r.ReadEndArray();
            }

            r.ReadEndArray();
            r.ReadEndArray();
            index.AddPack(new PackInfo(packId, kind, length, sha, entries));
        }

        r.ReadEndArray();
        return index;
    }

    /// <summary>Loads the local cache. Returns an empty index if missing, tampered or unreadable (it is always rebuildable).</summary>
    public static ChunkIndex LoadCache(string? cachePath, RepositoryKeys keys)
    {
        if (cachePath is null || !File.Exists(cachePath))
        {
            return new ChunkIndex();
        }

        try
        {
            var plain = EncryptedObjects.ReadObject(cachePath, keys, ObjectType.CatalogCache, 2L * 1024 * 1024 * 1024);
            return Deserialize(plain);
        }
        catch (Exception ex) when (ex is CryptoException or IOException or CborContentException or InvalidOperationException or FormatException)
        {
            return new ChunkIndex();
        }
    }

    public void SaveCache(string? cachePath, RepositoryKeys keys, IDurableFileOps ops)
    {
        if (cachePath is null)
        {
            return;
        }

        try
        {
            EncryptedObjects.WriteObject(cachePath, keys, ObjectType.CatalogCache, Serialize(), ops);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Core.RezenException)
        {
            // The cache is an optimisation; failure to save it never affects backup correctness.
        }
    }
}
