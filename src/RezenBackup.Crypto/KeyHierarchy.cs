using System.Security.Cryptography;
using System.Text;

namespace RezenBackup.Crypto;

/// <summary>Key classes from which per-object keys are derived (DESIGN §6.1).</summary>
public enum KeyClass : byte
{
    Content = 1,
    Metadata = 2,
}

/// <summary>
/// The 256-bit Root Secret of a Key Set (DESIGN §6). The recovery key is a human encoding of this value.
/// </summary>
public sealed class RootSecret : IDisposable
{
    public const int Length = 32;

    private readonly SecretBuffer _secret;

    private RootSecret(SecretBuffer secret)
    {
        _secret = secret;
    }

    public static RootSecret Generate() => new(SecretBuffer.Random(Length));

    /// <summary>Takes ownership of a copy of the supplied bytes.</summary>
    public static RootSecret FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Length)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Invalid root secret length.");
        }

        return new RootSecret(SecretBuffer.CopyFrom(bytes));
    }

    public ReadOnlySpan<byte> Bytes => _secret.ReadOnlySpan;

    public bool IsDisposed => _secret.IsDisposed;

    public RootSecret Clone() => new(_secret.Clone());

    public bool ContentEquals(RootSecret other) => _secret.ContentEquals(other._secret);

    /// <summary>Derives the key material of one repository (job on one drive).</summary>
    public RepositoryKeys DeriveRepositoryKeys(Guid repositoryId) => RepositoryKeys.Derive(this, repositoryId);

    public override string ToString() => "[REDACTED]";

    public void Dispose() => _secret.Dispose();
}

/// <summary>
/// All keys of a single repository, derived with HKDF-SHA256 from the Root Secret and repository ID.
/// </summary>
public sealed class RepositoryKeys : IDisposable
{
    private const string InfoPrefix = "RezenBackup/v1/";

    private readonly SecretBuffer _master;
    private readonly SecretBuffer _content;
    private readonly SecretBuffer _meta;
    private readonly SecretBuffer _chunkId;
    private readonly SecretBuffer _cdcSeed;
    private readonly SecretBuffer _check;

    private RepositoryKeys(Guid repositoryId, SecretBuffer master)
    {
        RepositoryId = repositoryId;
        _master = master;
        _content = Expand(master, "content");
        _meta = Expand(master, "metadata");
        _chunkId = Expand(master, "chunk-id");
        _cdcSeed = Expand(master, "cdc-seed");
        _check = Expand(master, "key-check");
    }

    public Guid RepositoryId { get; }

    internal static RepositoryKeys Derive(RootSecret root, Guid repositoryId)
    {
        var master = new SecretBuffer(32);
        Span<byte> salt = stackalloc byte[16];
        repositoryId.TryWriteBytes(salt);
        HKDF.DeriveKey(HashAlgorithmName.SHA256, root.Bytes, master.Span, salt, Encoding.ASCII.GetBytes(InfoPrefix + "repository-master"));
        return new RepositoryKeys(repositoryId, master);
    }

    private static SecretBuffer Expand(SecretBuffer prk, string label)
    {
        var output = new SecretBuffer(32);
        HKDF.Expand(HashAlgorithmName.SHA256, prk.ReadOnlySpan, output.Span, Encoding.ASCII.GetBytes(InfoPrefix + label));
        return output;
    }

    /// <summary>
    /// Derives the unique key of one encrypted object (DESIGN §4.2):
    /// HKDF(IKM = K_class, salt = objectSalt, info = "RezenBackup/v1/object" ‖ type ‖ repositoryId).
    /// </summary>
    public void DeriveObjectKey(KeyClass keyClass, byte objectType, ReadOnlySpan<byte> objectSalt, Span<byte> destination)
    {
        if (objectSalt.Length != 32)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Invalid object salt length.");
        }

        var ikm = keyClass switch
        {
            KeyClass.Content => _content,
            KeyClass.Metadata => _meta,
            _ => throw new ArgumentOutOfRangeException(nameof(keyClass)),
        };

        Span<byte> info = stackalloc byte[InfoObject.Length + 1 + 16];
        InfoObject.CopyTo(info);
        info[InfoObject.Length] = objectType;
        RepositoryId.TryWriteBytes(info[(InfoObject.Length + 1)..]);
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm.ReadOnlySpan, destination, objectSalt, info);
    }

    private static ReadOnlySpan<byte> InfoObject => "RezenBackup/v1/object"u8;

    /// <summary>Keyed chunk identifier: HMAC-SHA256(K_chunkid, data). Reveals nothing without the key (DESIGN §14).</summary>
    public ChunkId ComputeChunkId(ReadOnlySpan<byte> data)
    {
        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(_chunkId.ReadOnlySpan, data, mac);
        return new ChunkId(mac);
    }

    /// <summary>Keyed identifier for tree objects, domain-separated from data chunks.</summary>
    public ChunkId ComputeTreeId(ReadOnlySpan<byte> canonicalTree)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _chunkId.ReadOnlySpan);
        hmac.AppendData("tree"u8);
        hmac.AppendData(canonicalTree);
        Span<byte> mac = stackalloc byte[32];
        hmac.GetHashAndReset(mac);
        return new ChunkId(mac);
    }

    /// <summary>Produces the gear table seed for keyed content-defined chunking.</summary>
    public void DeriveCdcGearTable(Span<byte> destination)
    {
        HKDF.Expand(HashAlgorithmName.SHA256, _cdcSeed.ReadOnlySpan, destination, "RezenBackup/v1/gear-table"u8);
    }

    /// <summary>16-byte tag letting a key holder confirm a key file belongs to this repository.</summary>
    public byte[] ComputeKeyCheck()
    {
        Span<byte> data = stackalloc byte[9 + 16];
        "key-check"u8.CopyTo(data);
        RepositoryId.TryWriteBytes(data[9..]);
        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(_check.ReadOnlySpan, data, mac);
        return mac[..16].ToArray();
    }

    /// <summary>Encrypts a small value (for example a path in the local database) under the metadata key class.</summary>
    public byte[] SealSmall(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        Span<byte> salt = stackalloc byte[32];
        CryptoRandom.Fill(salt);
        Span<byte> key = stackalloc byte[32];
        try
        {
            DeriveObjectKey(KeyClass.Metadata, 0xF0, salt, key);
            var output = new byte[32 + 12 + plaintext.Length + 16];
            salt.CopyTo(output);
            // Unique key per sealed value, so a fixed zero nonce is safe.
            using var gcm = new AesGcm(key, 16);
            gcm.Encrypt(new byte[12], plaintext, output.AsSpan(44, plaintext.Length), output.AsSpan(44 + plaintext.Length, 16), associatedData);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public byte[] OpenSmall(ReadOnlySpan<byte> sealedValue, ReadOnlySpan<byte> associatedData)
    {
        if (sealedValue.Length < 32 + 12 + 16)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Sealed value too short.");
        }

        Span<byte> key = stackalloc byte[32];
        try
        {
            DeriveObjectKey(KeyClass.Metadata, 0xF0, sealedValue[..32], key);
            int ptLen = sealedValue.Length - 32 - 12 - 16;
            var plaintext = new byte[ptLen];
            using var gcm = new AesGcm(key, 16);
            try
            {
                gcm.Decrypt(sealedValue.Slice(32, 12), sealedValue.Slice(44, ptLen), sealedValue.Slice(44 + ptLen, 16), plaintext, associatedData);
            }
            catch (AuthenticationTagMismatchException ex)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw new CryptoException(CryptoError.AuthenticationFailed, "Integrity verification failed.", ex);
            }

            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public override string ToString() => "[REDACTED]";

    public void Dispose()
    {
        _master.Dispose();
        _content.Dispose();
        _meta.Dispose();
        _chunkId.Dispose();
        _cdcSeed.Dispose();
        _check.Dispose();
    }
}

/// <summary>32-byte keyed identifier of a data chunk or tree object.</summary>
public readonly struct ChunkId : IEquatable<ChunkId>, IComparable<ChunkId>
{
    public const int Length = 32;

    private readonly ulong _a;
    private readonly ulong _b;
    private readonly ulong _c;
    private readonly ulong _d;

    public ChunkId(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Length)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Invalid chunk identifier length.");
        }

        _a = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(bytes);
        _b = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(bytes[8..]);
        _c = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(bytes[16..]);
        _d = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(bytes[24..]);
    }

    public void WriteTo(Span<byte> destination)
    {
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(destination, _a);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(destination[8..], _b);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(destination[16..], _c);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(destination[24..], _d);
    }

    public byte[] ToArray()
    {
        var bytes = new byte[Length];
        WriteTo(bytes);
        return bytes;
    }

    public string ToHex() => Convert.ToHexStringLower(ToArray());

    public static ChunkId FromHex(string hex) => new(Convert.FromHexString(hex));

    public bool Equals(ChunkId other) => _a == other._a && _b == other._b && _c == other._c && _d == other._d;

    public override bool Equals(object? obj) => obj is ChunkId other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(_a, _b, _c, _d);

    public int CompareTo(ChunkId other)
    {
        int c = _a.CompareTo(other._a);
        if (c != 0) return c;
        c = _b.CompareTo(other._b);
        if (c != 0) return c;
        c = _c.CompareTo(other._c);
        return c != 0 ? c : _d.CompareTo(other._d);
    }

    public static bool operator ==(ChunkId left, ChunkId right) => left.Equals(right);

    public static bool operator !=(ChunkId left, ChunkId right) => !left.Equals(right);

    public static bool operator <(ChunkId left, ChunkId right) => left.CompareTo(right) < 0;

    public static bool operator >(ChunkId left, ChunkId right) => left.CompareTo(right) > 0;

    public static bool operator <=(ChunkId left, ChunkId right) => left.CompareTo(right) <= 0;

    public static bool operator >=(ChunkId left, ChunkId right) => left.CompareTo(right) >= 0;

    public override string ToString() => ToHex()[..16];
}
