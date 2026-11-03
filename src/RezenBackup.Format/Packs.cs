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
    private readonly MemoryStream _blobs = new();
    private readonly List<PackEntry> _entries = [];
    private readonly HashSet<ChunkId> _ids = [];

    public PackBuilder(PackKind kind)
    {
        Kind = kind;
        PackId = CryptoRandom.NewId();
    }

    public Guid PackId { get; }

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

    internal byte[] BuildPlaintext()
    {
        var index = PackFormat.EncodeIndex(_entries);
        long unpadded = _blobs.Length + index.Length + PackFormat.TrailerSize;
        long padded = Padme.Pad(unpadded);
        var plain = new byte[padded];
        _blobs.GetBuffer().AsSpan(0, (int)_blobs.Length).CopyTo(plain);
        // zero padding sits between blobs and index
        long indexOffset = padded - PackFormat.TrailerSize - index.Length;
        index.CopyTo(plain, indexOffset);
        BinaryPrimitives.WriteInt32LittleEndian(plain.AsSpan((int)(padded - PackFormat.TrailerSize)), index.Length);
        PackFormat.Magic.CopyTo(plain.AsSpan((int)(padded - 8)));
        return plain;
    }

    public void Clear()
    {
        CryptographicOperations.ZeroMemory(_blobs.GetBuffer());
        _blobs.SetLength(0);
        _entries.Clear();
        _ids.Clear();
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
    public static PackInfo Write(RepositoryLayout layout, RepositoryKeys keys, PackBuilder builder, IDurableFileOps ops)
    {
        var plain = builder.BuildPlaintext();
        byte[] cipher;
        try
        {
            using var ms = new MemoryStream(plain.Length + (plain.Length / ObjectHeader.DefaultSegmentSize * 16) + 256);
            using (var w = new AeadStreamWriter(ms, keys, keys.NewObjectHeader(ObjectTypeFor(builder.Kind))))
            {
                w.Write(plain);
                w.Complete();
            }

            cipher = ms.ToArray();
        }
        catch (CryptographicException ex)
        {
            throw new RezenException(ErrorCode.EncryptionFailure, ex.Message, ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }

        var sha = SHA256.HashData(cipher);
        WriteVerifiedCopy(layout, keys, builder, cipher, layout.PackPath(builder.Kind, builder.PackId), ops);
        if (builder.Kind == PackKind.Meta)
        {
            WriteVerifiedCopy(layout, keys, builder, cipher, layout.PackPath(builder.Kind, builder.PackId, copy: true), ops);
        }

        return new PackInfo(builder.PackId, builder.Kind, cipher.LongLength, sha, builder.Entries.ToList());
    }

    private static void WriteVerifiedCopy(RepositoryLayout layout, RepositoryKeys keys, PackBuilder builder, byte[] cipher, string finalPath, IDurableFileOps ops)
    {
        Directory.CreateDirectory(layout.TempDirectory);
        var tmp = Path.Combine(layout.TempDirectory, Path.GetFileName(finalPath) + "." + CryptoRandom.NextInt(int.MaxValue) + ".tmp");
        try
        {
            using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 20))
            {
                fs.Write(cipher);
                ops.FlushToDevice(fs);
            }

            var readBack = EncryptedObjects.ReadAllForVerification(tmp, ops);
            if (!CryptographicOperations.FixedTimeEquals(readBack, cipher))
            {
                throw new RezenException(ErrorCode.CommitFailed, "Pack read-back did not match what was written.");
            }

            // Authenticate the bytes that are actually on the device and confirm the index parses identically.
            using (var rs = new MemoryStream(readBack, writable: false))
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
