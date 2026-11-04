using System.Collections.Concurrent;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Crypto;
using RezenBackup.Format;

namespace RezenBackup.BackupEngine;

/// <summary>
/// Accumulates new blobs into data and metadata packs, writes packs durably, records them in the journal and tracks
/// which pack each blob of this run lives in (DESIGN §16.1 steps 3–4).
/// <para>
/// Pipeline (DESIGN §30): the walker thread splits and hashes files and calls <see cref="AddData"/>. Compression runs on
/// the thread pool (bounded, so memory stays small), and full packs go to one background writer thread that encrypts,
/// writes, flushes, reads back and verifies them while the walker keeps reading. The chunk index and the "where is this
/// blob" map are only touched on the walker thread: finished packs are handed back and applied there.
/// </para>
/// </summary>
internal sealed class SnapshotWriter : IDisposable
{
    /// <summary>Raw bytes waiting for compression at most (backpressure on the walker).</summary>
    private const long MaxInflightBytes = 64L << 20;

    private readonly Repository _repo;
    private readonly BackupOptions _options;
    private readonly string _journalPath;
    private readonly JournalRecord _journalBase;
    private readonly int _maxInflight = Math.Clamp(Environment.ProcessorCount * 2, 2, 64);

    // Walker thread only.
    private readonly Dictionary<ChunkId, Guid> _thisRunLocation = [];
    private readonly HashSet<ChunkId> _pending = [];
    private readonly Queue<PendingBlob> _inflight = new();
    private long _inflightBytes;
    private PackBuilder _data;
    private PackBuilder _meta = new(PackKind.Meta);

    // Shared with the writer thread.
    private readonly object _writtenGate = new();
    private readonly List<CommittedPack> _written = [];
    private readonly ConcurrentQueue<PackInfo> _completed = new();
    private readonly ConcurrentBag<PackBuilder> _spareData = [];
    private BlockingCollection<PackBuilder>? _toWrite;
    private Thread? _writerThread;
    private volatile ExceptionDispatchInfo? _writerFailure;
    private volatile bool _abort;
    private long _bytesStored;

    public SnapshotWriter(Repository repo, BackupOptions options, string journalPath, JournalRecord journalBase)
    {
        _repo = repo;
        _options = options;
        _journalPath = journalPath;
        _journalBase = journalBase;
        _written.AddRange(journalBase.Packs);
        _data = NewDataBuilder();
    }

    /// <summary>Data packs are pre-sized (a full pack plus one chunk) and their buffers are reused between packs.</summary>
    private PackBuilder NewDataBuilder() =>
        _spareData.TryTake(out var spare) ? spare : new PackBuilder(PackKind.Data, (int)Math.Min(int.MaxValue / 2, _repo.Config.PackTargetSize + _repo.Config.ChunkMax + 4096));

    private sealed record PendingBlob(ChunkId Id, int RawLength, Task<(byte[] Stored, BlobCodec Codec)> Work);

    /// <summary>Complete after <see cref="FlushAll"/>.</summary>
    public IReadOnlyList<CommittedPack> WrittenPacks
    {
        get
        {
            lock (_writtenGate)
            {
                return _written.ToList();
            }
        }
    }

    public IReadOnlyDictionary<ChunkId, Guid> ThisRunLocations => _thisRunLocation;

    public long BytesStored => Interlocked.Read(ref _bytesStored);

    public long IncompressibleNewBytes { get; private set; }

    public long NewRawBytes { get; private set; }

    /// <summary>
    /// True if the blob is already stored, or will be by this run, and may be referenced. For Full snapshots only blobs
    /// written in this run count, so the snapshot shares no data with earlier ones (DESIGN §13.3).
    /// </summary>
    public bool IsStored(ChunkId id)
    {
        ApplyCompleted();
        if (_thisRunLocation.ContainsKey(id) || _pending.Contains(id) || _data.Contains(id) || _meta.Contains(id))
        {
            return true;
        }

        return _options.Method == BackupMethod.Incremental && _repo.Index.Contains(id);
    }

    public void AddData(ChunkId id, ReadOnlySpan<byte> raw)
    {
        ThrowIfWriterFailed();
        if (IsStored(id))
        {
            return;
        }

        // The caller's buffer is reused for the next chunk, so compression works on a copy.
        var copy = raw.ToArray();
        _pending.Add(id);
        _inflight.Enqueue(new PendingBlob(id, copy.Length, Task.Run(() =>
        {
            try
            {
                return BlobCompression.Compress(copy);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(copy);
            }
        })));
        _inflightBytes += copy.Length;
        while (_inflight.Count >= _maxInflight || _inflightBytes >= MaxInflightBytes)
        {
            DrainOne();
        }
    }

    public ChunkId AddTree(TreeNode tree)
    {
        ThrowIfWriterFailed();
        var raw = tree.Encode();
        var id = _repo.Keys.ComputeTreeId(raw);
        if (!IsStored(id))
        {
            var (stored, codec) = BlobCompression.Compress(raw);
            _meta.Add(id, BlobKind.Tree, stored, raw.Length, codec);
            _pending.Add(id);
            if (_meta.Size >= _repo.Config.PackTargetSize / 4)
            {
                HandOff(PackKind.Meta);
            }
        }

        return id;
    }

    /// <summary>Writes everything still buffered and waits until every pack of this run is durable and verified.</summary>
    public void FlushAll()
    {
        while (_inflight.Count > 0)
        {
            DrainOne();
        }

        HandOff(PackKind.Data);
        HandOff(PackKind.Meta);
        StopWriter();
        ThrowIfWriterFailed();
        ApplyCompleted();
    }

    public void WriteJournal()
    {
        lock (_writtenGate)
        {
            var journal = _journalBase with { Packs = _written.ToList() };
            EncryptedObjects.WriteObject(_journalPath, _repo.Keys, ObjectType.Journal, journal.Encode(), _repo.Ops);
        }
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
        ApplyCompleted();
        if (_thisRunLocation.TryGetValue(id, out var p))
        {
            return p;
        }

        return _repo.Index.TryGet(id, out var e) ? e.PackId : null;
    }

    /// <summary>
    /// Stops background work after a failure or cancellation: the writer finishes (or abandons) the pack in hand and
    /// exits, so nothing touches the repository once the run has ended. Unwritten packs leave the snapshot incomplete.
    /// </summary>
    public void Dispose()
    {
        _abort = true;
        StopWriter();
        while (_inflight.TryDequeue(out var p))
        {
            try
            {
                p.Work.Wait();
            }
            catch (AggregateException)
            {
                // Compression failures do not matter once the run is being abandoned.
            }
        }

        _data.Clear();
        _meta.Clear();
    }

    private void DrainOne()
    {
        var p = _inflight.Dequeue();
        _inflightBytes -= p.RawLength;
        var (stored, codec) = p.Work.GetAwaiter().GetResult();
        _data.Add(p.Id, BlobKind.Data, stored, p.RawLength, codec);
        NewRawBytes += p.RawLength;
        if (codec == BlobCodec.None)
        {
            IncompressibleNewBytes += p.RawLength;
        }

        if (_data.Size >= _repo.Config.PackTargetSize)
        {
            HandOff(PackKind.Data);
        }
    }

    /// <summary>Gives a full (or final) pack to the writer thread. Blocks while the writer is a pack behind.</summary>
    private void HandOff(PackKind kind)
    {
        var builder = kind == PackKind.Data ? _data : _meta;
        if (builder.Count == 0)
        {
            return;
        }

        if (kind == PackKind.Data)
        {
            _data = NewDataBuilder();
        }
        else
        {
            _meta = new PackBuilder(PackKind.Meta);
        }

        if (_toWrite is null)
        {
            _toWrite = new BlockingCollection<PackBuilder>(boundedCapacity: 1);
            var queue = _toWrite;
            _writerThread = new Thread(() => WriterLoop(queue)) { IsBackground = true, Name = "Rezen pack writer" };
            _writerThread.Start();
        }

        try
        {
            _toWrite.Add(builder);
        }
        catch (InvalidOperationException)
        {
            // The writer stopped accepting work because it failed: report its error.
            builder.Clear();
            ThrowIfWriterFailed();
            throw;
        }
    }

    private void WriterLoop(BlockingCollection<PackBuilder> queue)
    {
        foreach (var builder in queue.GetConsumingEnumerable())
        {
            try
            {
                if (!_abort && _writerFailure is null)
                {
                    _completed.Enqueue(WritePack(builder));
                }
            }
            catch (Exception ex)
            {
                _writerFailure = ExceptionDispatchInfo.Capture(ex);
                queue.CompleteAdding();
            }
            finally
            {
                builder.Reset();
                if (builder.Kind == PackKind.Data && _spareData.Count < 2)
                {
                    _spareData.Add(builder);
                }
            }
        }
    }

    /// <summary>Runs on the writer thread.</summary>
    private PackInfo WritePack(PackBuilder builder)
    {
        bool meta = builder.Kind == PackKind.Meta;
        EnsureSpace(builder.Size * (meta ? 2 : 1));
        _options.FaultInjection?.Invoke("before-pack-write");
        var info = PackFormat.Write(_repo.Layout, _repo.Keys, builder, _repo.Ops);
        _options.FaultInjection?.Invoke("after-pack-write");
        Interlocked.Add(ref _bytesStored, info.Length * (meta ? 2 : 1));
        lock (_writtenGate)
        {
            _written.Add(new CommittedPack(info.PackId, info.Kind, info.Length, info.Sha256));
        }

        WriteJournal();
        return info;
    }

    private void StopWriter()
    {
        if (_toWrite is null)
        {
            return;
        }

        if (!_toWrite.IsAddingCompleted)
        {
            _toWrite.CompleteAdding();
        }

        _writerThread?.Join();
        _toWrite.Dispose();
        _toWrite = null;
        _writerThread = null;
    }

    /// <summary>Applies packs finished by the writer to the index (walker thread only).</summary>
    private void ApplyCompleted()
    {
        while (_completed.TryDequeue(out var info))
        {
            _repo.Index.AddPack(info);
            foreach (var e in info.Entries)
            {
                _thisRunLocation[e.Id] = info.PackId;
                _pending.Remove(e.Id);
            }
        }
    }

    private void ThrowIfWriterFailed() => _writerFailure?.Throw();
}
