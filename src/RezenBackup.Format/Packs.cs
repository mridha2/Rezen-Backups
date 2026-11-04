using System.Buffers;
using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using RezenBackup.Core;
using RezenBackup.Core.Platform;
using RezenBackup.Crypto;

namespace RezenBackup.Format;

public enum BlobKind : byte
{
    Data = 1,
    Tree = 2,
}

/// <summary>Location of one blob inside a pack (plaintext coordinates).</summary>
public readonly record struct PackEntry(ChunkId Id, BlobKind Kind, long Offset, int StoredLength, int RawLength, BlobCodec Codec);

/// <summary>A finished, verified pack.</summary>
public sealed record PackInfo(Guid PackId, PackKind Kind, long Length, byte[] Sha256, IReadOnlyList<PackEntry> Entries);

/// <summary>Accumulates compressed blobs in memory until the pack is written.</summary>
public sealed class PackBuilder
{
    private static readonly byte[] Zeros = new byte[64 * 1024];

    private readonly MemoryStream _blobs;
    private readonly List<PackEntry> _entries = [];
    private readonly HashSet<ChunkId> _ids = [];

    /// <param name="capacity">Expected size in bytes; pre-sizing avoids repeated buffer growth for full packs.</param>
    public PackBuilder(PackKind kind, int capacity = 0)
    {
        Kind = kind;
        PackId = CryptoRandom.NewId();
        _blobs = new MemoryStream(capacity);
    }

    public Guid PackId { get; private set; }

    public PackKind Kind { get; }

    public long Size => _blobs.Length;

    public int Count => _entries.Count;

    public IReadOnlyList<PackEntry> Entries => _entries;

    public bool Contains(ChunkId id) => _ids.Contains(id);

    public PackEntry Add(ChunkId id, BlobKind kind, ReadOnlySpan<byte> stored, int rawLength, BlobCodec codec)
    {
        if (!_ids.Add(id))
        {
            return _entries.First(e => e.Id == id);
        }

        var entry = new PackEntry(id, kind, _blobs.Length, stored.Length, rawLength, codec);
        _blobs.Write(stored);
        _entries.Add(entry);
        return entry;
    }

    /// <summary>Returns the blob bytes as stored (compressed), used to read back unflushed data.</summary>
    public ReadOnlySpan<byte> GetStored(PackEntry entry) => _blobs.GetBuffer().AsSpan((int)entry.Offset, entry.StoredLength);

    /// <summary>Padded plaintext length: blobs, zero padding, index, trailer.</summary>
    internal long PlaintextLength(byte[] index) => Padme.Pad(_blobs.Length + index.Length + PackFormat.TrailerSize);

    /// <summary>
    /// Streams the pack plaintext (blobs, zero padding, index, trailer) into the encryptor without building a
    /// contiguous copy of it in memory.
    /// </summary>
    internal void WritePlaintext(AeadStreamWriter writer, byte[] index)
    {
        long padded = PlaintextLength(index);
        writer.Write(_blobs.GetBuffer().AsSpan(0, (int)_blobs.Length));
        // zero padding sits between blobs and index
        for (long zeros = padded - _blobs.Length - index.Length - PackFormat.TrailerSize; zeros > 0;)
        {
            int n = (int)Math.Min(zeros, Zeros.Length);
            writer.Write(Zeros.AsSpan(0, n));
            zeros -= n;
        }

        writer.Write(index);
        Span<byte> trailer = stackalloc byte[PackFormat.TrailerSize];
        BinaryPrimitives.WriteInt32LittleEndian(trailer, index.Length);
        PackFormat.Magic.CopyTo(trailer[4..]);
        writer.Write(trailer);
    }

    public void Clear()
    {
        CryptographicOperations.ZeroMemory(_blobs.GetBuffer());
        _blobs.SetLength(0);
        _entries.Clear();
        _ids.Clear();
    }

    /// <summary>Clears the builder and gives it a new pack id, so its buffer can be reused for the next pack.</summary>
    public void Reset()
    {
        Clear();
        PackId = CryptoRandom.NewId();
    }
}

/// <summary>Pack file format and durable write/verify (DESIGN §10.3, §16.1 step 3).</summary>
public static class PackFormat
{
    public const int TrailerSize = 4 + 8;
    public const long TargetPackSize = 32L * 1024 * 1024;

    internal static ReadOnlySpan<byte> Magic => "RZNPACK1"u8;

    public static ObjectType ObjectTypeFor(PackKind kind) => kind == PackKind.Data ? ObjectType.DataPack : ObjectType.MetaPack;

    internal static byte[] EncodeIndex(IReadOnlyList<PackEntry> entries)
    {
        var w = Cbor.NewWriter();
        w.WriteStartArray(entries.Count);
        foreach (var e in entries)
        {
            w.WriteStartArray(6);
            w.WriteChunkId(e.Id);
            w.WriteInt32((int)e.Kind);
            w.WriteInt64(e.Offset);
            w.WriteInt32(e.StoredLength);
            w.WriteInt32(e.RawLength);
            w.WriteInt32((int)e.Codec);
            w.WriteEndArray();
        }

        w.WriteEndArray();
        return w.Encode();
    }

    internal static List<PackEntry> DecodeIndex(byte[] data, long blobAreaLimit)
    {
        var r = Cbor.NewReader(data);
        int count = r.ReadStartArray() ?? 0;
        var list = new List<PackEntry>(count);
        for (int i = 0; i < count; i++)
        {
            r.ReadStartArray();
            var id = r.ReadChunkId();
            var kind = (BlobKind)r.ReadInt32();
            long offset = r.ReadInt64();
            int stored = r.ReadInt32();
            int raw = r.ReadInt32();
            var codec = (BlobCodec)r.ReadInt32();
            r.ReadEndArray();
            if (offset < 0 || stored < 0 || raw < 0 || offset + stored > blobAreaLimit || !Enum.IsDefined(kind) || !Enum.IsDefined(codec))
            {
                throw new FormatException("Pack index entry out of range.");
            }

            list.Add(new PackEntry(id, kind, offset, stored, raw, codec));
        }

        r.ReadEndArray();
        return list;
    }

    /// <summary>
    /// Encrypts and durably writes a pack: temp file → flush to device → uncached read-back → authenticate every
    /// segment and re-parse the index → atomic rename into the store. Meta packs are written twice.
    /// </summary>
    /// <summary>Ciphertext buffer reused across packs written on the same thread (ciphertext is not secret).</summary>
    [ThreadStatic]
    private static byte[]? t_cipherBuffer;

    public static PackInfo Write(RepositoryLayout layout, RepositoryKeys keys, PackBuilder builder, IDurableFileOps ops)
    {
        var index = EncodeIndex(builder.Entries);
        long plainLength = builder.PlaintextLength(index);
        // Upper bound: header + plaintext + one tag per segment (plus a possible empty final segment).
        long bound = ObjectHeader.Size + plainLength + ((plainLength / ObjectHeader.DefaultSegmentSize + 2) * 16 /* AES-GCM tag */) + 64;
        if (bound > int.MaxValue)
        {
            throw new RezenException(ErrorCode.EncryptionFailure, "Pack is too large.");
        }

        if (t_cipherBuffer is null || t_cipherBuffer.Length < bound)
        {
            t_cipherBuffer = GC.AllocateUninitializedArray<byte>((int)bound);
        }

        var buffer = t_cipherBuffer;
        int cipherLength;
        try
        {
            using var ms = new MemoryStream(buffer, 0, buffer.Length, writable: true, publiclyVisible: true);
            using (var w = new AeadStreamWriter(ms, keys, keys.NewObjectHeader(ObjectTypeFor(builder.Kind))))
            {
                builder.WritePlaintext(w, index);
                w.Complete();
            }

            cipherLength = (int)ms.Position;
        }
        catch (CryptographicException ex)
        {
            throw new RezenException(ErrorCode.EncryptionFailure, ex.Message, ex);
        }

        var sha = SHA256.HashData(buffer.AsSpan(0, cipherLength));
        WriteVerifiedCopy(layout, keys, builder, buffer, cipherLength, layout.PackPath(builder.Kind, builder.PackId), ops);
        if (builder.Kind == PackKind.Meta)
        {
            WriteVerifiedCopy(layout, keys, builder, buffer, cipherLength, layout.PackPath(builder.Kind, builder.PackId, copy: true), ops);
        }

        return new PackInfo(builder.PackId, builder.Kind, cipherLength, sha, builder.Entries.ToList());
    }

    private static void WriteVerifiedCopy(RepositoryLayout layout, RepositoryKeys keys, PackBuilder builder, byte[] buffer, int length, string finalPath, IDurableFileOps ops)
    {
        var cipher = buffer.AsSpan(0, length);
        Directory.CreateDirectory(layout.TempDirectory);
        var tmp = Path.Combine(layout.TempDirectory, Path.GetFileName(finalPath) + "." + CryptoRandom.NextInt(int.MaxValue) + ".tmp");
        try
        {
            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, bufferSize: 0))
            {
                fs.Write(cipher);
                ops.FlushToDevice(fs);
            }

            // Uncached read-back, compared piece by piece with what was written.
            var piece = ArrayPool<byte>.Shared.Rent(1 << 20);
            try
            {
                using var vs = ops.OpenForVerification(tmp);
                int pos = 0;
                int n;
                while ((n = vs.Read(piece, 0, piece.Length)) > 0)
                {
                    if (pos + n > cipher.Length || !piece.AsSpan(0, n).SequenceEqual(cipher.Slice(pos, n)))
                    {
                        throw new RezenException(ErrorCode.CommitFailed, "Pack read-back did not match what was written.");
                    }

                    pos += n;
                }

                if (pos != cipher.Length)
                {
                    throw new RezenException(ErrorCode.CommitFailed, "Pack read-back did not match what was written.");
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(piece);
            }

            // The device holds exactly these bytes: authenticate them and confirm the index parses identically.
            using (var rs = new MemoryStream(buffer, 0, length, writable: false))
            using (var reader = new PackReader(rs, keys, builder.Kind))
            {
                reader.VerifyAllSegments();
                if (reader.Entries.Count != builder.Count)
                {
                    throw new RezenException(ErrorCode.IntegrityFailure, "Pack index mismatch after write.");
                }
            }

            Directory.CreateDirectory(Path.GetDirectoryName(finalPath)!);
            ops.AtomicMove(tmp, finalPath, overwrite: false);
            ops.FlushDirectory(Path.GetDirectoryName(finalPath)!);
        }
        catch (IOException ex)
        {
            EncryptedObjects.TryDelete(tmp);
            throw IoErrors.Translate(ex);
        }
        catch
        {
            EncryptedObjects.TryDelete(tmp);
            throw;
        }
    }
}

/// <summary>Reads blobs from an encrypted pack. Every segment touched is authenticated before use.</summary>
public sealed class PackReader : IDisposable
{
    private readonly Stream _stream;
    private readonly AeadStreamReader _reader;
    private readonly bool _ownsStream;

    public PackReader(Stream stream, RepositoryKeys keys, PackKind kind, bool ownsStream = false)
    {
        _stream = stream;
        _ownsStream = ownsStream;
        _reader = new AeadStreamReader(stream, keys, PackFormat.ObjectTypeFor(kind));
        long len = _reader.PlaintextLength;
        if (len < PackFormat.TrailerSize)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Pack is too small.");
        }

        Span<byte> trailer = stackalloc byte[PackFormat.TrailerSize];
        _reader.ReadRange(len - PackFormat.TrailerSize, trailer);
        if (!trailer[4..].SequenceEqual(PackFormat.Magic))
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Pack trailer is invalid.");
        }

        int indexLength = BinaryPrimitives.ReadInt32LittleEndian(trailer);
        if (indexLength < 0 || indexLength > len - PackFormat.TrailerSize)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Pack index length is invalid.");
        }

        var index = new byte[indexLength];
        long indexOffset = len - PackFormat.TrailerSize - indexLength;
        _reader.ReadRange(indexOffset, index);
        try
        {
            Entries = PackFormat.DecodeIndex(index, indexOffset);
        }
        catch (Exception ex) when (ex is CborContentException or InvalidOperationException or FormatException)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Pack index is invalid.", ex);
        }
    }

    public static PackReader Open(string path, RepositoryKeys keys, PackKind kind)
    {
        var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, FileOptions.RandomAccess);
        try
        {
            return new PackReader(fs, keys, kind, ownsStream: true);
        }
        catch
        {
            fs.Dispose();
            throw;
        }
    }

    public IReadOnlyList<PackEntry> Entries { get; }

    public byte[] ReadStored(PackEntry entry)
    {
        var buffer = new byte[entry.StoredLength];
        _reader.ReadRange(entry.Offset, buffer);
        return buffer;
    }

    public void VerifyAllSegments() => _reader.VerifyAll();

    public void Dispose()
    {
        _reader.Dispose();
        if (_ownsStream)
        {
            _stream.Dispose();
        }
    }
}

/// <summary>Padmé padding (Nikitin et al., 2019): leaks at most O(log log L) bits of the length, ≤ ~12% overhead.</summary>
public static class Padme
{
    public static long Pad(long length)
    {
        if (length < 2)
        {
            return Math.Max(length, 1);
        }

        int e = 63 - System.Numerics.BitOperations.LeadingZeroCount((ulong)length);
        int s = 64 - System.Numerics.BitOperations.LeadingZeroCount((ulong)e);
        int lastBits = e - s;
        long mask = (1L << lastBits) - 1;
        return (length + mask) & ~mask;
    }
}
