using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Crypto;
using RezenBackup.Format;

namespace RezenBackup.BackupEngine;

/// <summary>
/// Accumulates new blobs into data and metadata packs, writes packs durably, records them in the journal and tracks
/// which pack each blob of this run lives in (DESIGN §16.1 steps 3–4).
/// </summary>
internal sealed class SnapshotWriter
{
    private readonly Repository _repo;
    private readonly BackupOptions _options;
    private readonly string _journalPath;
    private readonly JournalRecord _journalBase;
    private readonly List<CommittedPack> _written = [];
    private readonly Dictionary<ChunkId, Guid> _thisRunLocation = [];
    private PackBuilder _data = new(PackKind.Data);
    private PackBuilder _meta = new(PackKind.Meta);

    public SnapshotWriter(Repository repo, BackupOptions options, string journalPath, JournalRecord journalBase)
    {
        _repo = repo;
        _options = options;
        _journalPath = journalPath;
        _journalBase = journalBase;
        _written.AddRange(journalBase.Packs);
    }

    public IReadOnlyList<CommittedPack> WrittenPacks => _written;

    public IReadOnlyDictionary<ChunkId, Guid> ThisRunLocations => _thisRunLocation;

    public long BytesStored { get; private set; }

    public long IncompressibleNewBytes { get; private set; }

    public long NewRawBytes { get; private set; }

    /// <summary>
    /// True if the blob is already stored and may be referenced. For Full snapshots only blobs written in this run count,
    /// so the snapshot shares no data with earlier ones (DESIGN §13.3).
    /// </summary>
    public bool IsStored(ChunkId id)
    {
        if (_thisRunLocation.ContainsKey(id) || _data.Contains(id) || _meta.Contains(id))
        {
            return true;
        }

        return _options.Method == BackupMethod.Incremental && _repo.Index.Contains(id);
    }

    public void AddData(ChunkId id, ReadOnlySpan<byte> raw)
    {
        if (IsStored(id))
        {
            return;
        }

        var (stored, codec) = BlobCompression.Compress(raw);
        _data.Add(id, BlobKind.Data, stored, raw.Length, codec);
        NewRawBytes += raw.Length;
        if (codec == BlobCodec.None)
        {
            IncompressibleNewBytes += raw.Length;
        }

        if (_data.Size >= _repo.Config.PackTargetSize)
        {
            Flush(PackKind.Data);
        }
    }

    public ChunkId AddTree(TreeNode tree)
    {
        var raw = tree.Encode();
        var id = _repo.Keys.ComputeTreeId(raw);
        if (!IsStored(id))
        {
            var (stored, codec) = BlobCompression.Compress(raw);
            _meta.Add(id, BlobKind.Tree, stored, raw.Length, codec);
            if (_meta.Size >= _repo.Config.PackTargetSize / 4)
            {
                Flush(PackKind.Meta);
            }
        }

        return id;
    }

    public void FlushAll()
    {
        Flush(PackKind.Data);
        Flush(PackKind.Meta);
    }

    private void Flush(PackKind kind)
    {
        var builder = kind == PackKind.Data ? _data : _meta;
        if (builder.Count == 0)
        {
            return;
        }

        EnsureSpace(builder.Size * (kind == PackKind.Meta ? 2 : 1));
        _options.FaultInjection?.Invoke("before-pack-write");
        var info = PackFormat.Write(_repo.Layout, _repo.Keys, builder, _repo.Ops);
        _options.FaultInjection?.Invoke("after-pack-write");
        _repo.Index.AddPack(info);
        foreach (var e in info.Entries)
        {
            _thisRunLocation[e.Id] = info.PackId;
        }

        BytesStored += info.Length * (kind == PackKind.Meta ? 2 : 1);
        _written.Add(new CommittedPack(info.PackId, info.Kind, info.Length, info.Sha256));
        WriteJournal();
        builder.Clear();
        if (kind == PackKind.Data)
        {
            _data = new PackBuilder(PackKind.Data);
        }
        else
        {
            _meta = new PackBuilder(PackKind.Meta);
        }
    }

    public void WriteJournal()
    {
        var journal = _journalBase with { Packs = _written.ToList() };
        EncryptedObjects.WriteObject(_journalPath, _repo.Keys, ObjectType.Journal, journal.Encode(), _repo.Ops);
    }

    public void EnsureSpace(long upcoming)
    {
        long free = (_options.FreeSpaceProbe ?? (() => Core.Platform.FreeSpace.ForPath(_repo.Layout.Root)))();
        if (free - upcoming < _options.ReserveBytes)
        {
            throw new RezenException(ErrorCode.DestinationFull, $"Free space {free} bytes; reserve {_options.ReserveBytes} bytes.");
        }
    }

    public CommittedPack PackRecordFor(Guid packId)
    {
        if (!_repo.Index.Packs.TryGetValue(packId, out var rec))
        {
            throw new RezenException(ErrorCode.IntegrityFailure, $"Pack {packId} is not in the index.");
        }

        return new CommittedPack(rec.PackId, rec.Kind, rec.Length, rec.Sha256);
    }

    /// <summary>The pack a blob should be attributed to for this snapshot's commit record.</summary>
    public Guid? LocationFor(ChunkId id)
    {
        if (_thisRunLocation.TryGetValue(id, out var p))
        {
            return p;
        }

        return _repo.Index.TryGet(id, out var e) ? e.PackId : null;
    }
}
