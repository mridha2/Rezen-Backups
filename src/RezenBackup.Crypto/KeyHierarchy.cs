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

    private const byte BackupOnlyBlobVersion = 1;
    private const int BackupOnlyBlobLength = 1 + 16 + (32 * 6);

    // Null in a backup-only key: such a key can add backups but cannot read file contents (DESIGN §9.5).
    private readonly SecretBuffer? _master;
    private readonly SecretBuffer? _content;
    private readonly SecretBuffer? _contentPrivate;
    private readonly byte[] _contentPublic;
    private readonly SecretBuffer _meta;
    private readonly SecretBuffer _chunkId;
    private readonly SecretBuffer _treeId;
    private readonly SecretBuffer _cdcSeed;
    private readonly SecretBuffer _check;
    // 32-byte pinned arrays (wiped when forgotten): one locked sodium allocation per pack would exhaust locked memory
    // on large first backups.
    private readonly Dictionary<string, byte[]> _ownObjectKeys = [];
    private readonly object _ownGate = new();

    private RepositoryKeys(Guid repositoryId, SecretBuffer master)
    {
        RepositoryId = repositoryId;
        _master = master;
        _content = Expand(master, "content");
        _contentPrivate = Expand(master, "content-x25519");
        _contentPublic = X25519.PublicFromPrivate(_contentPrivate.ReadOnlySpan);
        _meta = Expand(master, "metadata");
        _chunkId = Expand(master, "chunk-id");
        _treeId = Expand(master, "tree-id");
        _cdcSeed = Expand(master, "cdc-seed");
        _check = Expand(master, "key-check");
    }

    private RepositoryKeys(Guid repositoryId, ReadOnlySpan<byte> blob)
    {
        RepositoryId = repositoryId;
        int o = 1 + 16;
        _meta = SecretBuffer.CopyFrom(blob.Slice(o, 32));
        _chunkId = SecretBuffer.CopyFrom(blob.Slice(o + 32, 32));
        _treeId = SecretBuffer.CopyFrom(blob.Slice(o + 64, 32));
        _cdcSeed = SecretBuffer.CopyFrom(blob.Slice(o + 96, 32));
        _check = SecretBuffer.CopyFrom(blob.Slice(o + 128, 32));
        _contentPublic = blob.Slice(o + 160, 32).ToArray();
    }

    public Guid RepositoryId { get; }

    /// <summary>False for a backup-only key: it can write new backups but cannot decrypt stored file contents.</summary>
    public bool CanReadContent => _contentPrivate is not null;

    /// <summary>The repository's X25519 public key that data packs are encrypted to.</summary>
    public ReadOnlySpan<byte> ContentPublicKey => _contentPublic;

    /// <summary>
    /// Exports the keys a scheduled backup needs and nothing more: metadata, identifier, chunking and check keys plus the
    /// content <em>public</em> key. The holder can add backups and read names/history, but not file contents.
    /// </summary>
    public SecretBuffer ExportBackupOnly()
    {
        var blob = new SecretBuffer(BackupOnlyBlobLength);
        var b = blob.Span;
        b[0] = BackupOnlyBlobVersion;
        RepositoryId.TryWriteBytes(b.Slice(1, 16));
        int o = 1 + 16;
        _meta.ReadOnlySpan.CopyTo(b.Slice(o, 32));
        _chunkId.ReadOnlySpan.CopyTo(b.Slice(o + 32, 32));
        _treeId.ReadOnlySpan.CopyTo(b.Slice(o + 64, 32));
        _cdcSeed.ReadOnlySpan.CopyTo(b.Slice(o + 96, 32));
        _check.ReadOnlySpan.CopyTo(b.Slice(o + 128, 32));
        _contentPublic.CopyTo(b.Slice(o + 160, 32));
        return blob;
    }

    public static RepositoryKeys FromBackupOnly(ReadOnlySpan<byte> blob)
    {
        if (blob.Length != BackupOnlyBlobLength || blob[0] != BackupOnlyBlobVersion)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Backup-only key is not valid.");
        }

        return new RepositoryKeys(new Guid(blob.Slice(1, 16)), blob);
    }

    /// <summary>
    /// Creates the header of a new object. Data packs use X25519 (algorithm 2) with a fresh ephemeral key, so that even
    /// a backup-only key can write them; the per-object key is remembered so this run can read back what it wrote.
    /// </summary>
    public ObjectHeader NewObjectHeader(ObjectType type)
    {
        if (type != ObjectType.DataPack)
        {
            return ObjectHeader.CreateNew(type, RepositoryId);
        }

        using var ephemeral = SecretBuffer.Random(32);
        var ephemeralPublic = X25519.PublicFromPrivate(ephemeral.ReadOnlySpan);
        var header = new ObjectHeader(type, RepositoryId, ephemeralPublic, ObjectHeader.DefaultSegmentSize, ObjectHeader.AlgorithmX25519Aes256GcmStream);
        var key = SecureMemory.AllocatePinned(32);
        DeriveAsymmetricObjectKey(ephemeral.ReadOnlySpan, _contentPublic, header, key);
        lock (_ownGate)
        {
            _ownObjectKeys[Convert.ToHexString(ephemeralPublic)] = key;
        }

        return header;
    }

    /// <summary>
    /// Forgets the keys of data packs written by this instance. Called when a backup run ends, so a backup-only key
    /// cannot read back contents afterwards.
    /// </summary>
    public void ForgetWrittenObjectKeys()
    {
        lock (_ownGate)
        {
            foreach (var k in _ownObjectKeys.Values)
            {
                CryptographicOperations.ZeroMemory(k);
            }

            _ownObjectKeys.Clear();
        }
    }

    /// <summary>Derives the key of an existing object (read path; also used by writers after <see cref="NewObjectHeader"/>).</summary>
    public void DeriveObjectKeyForRead(ObjectHeader header, Span<byte> destination)
    {
        if (header.RepositoryId != RepositoryId)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Header does not match repository keys.");
        }

        if (header.AlgorithmId == ObjectHeader.AlgorithmAes256GcmStream)
        {
            DeriveObjectKey(header.KeyClass, (byte)header.Type, header.ObjectSalt, destination);
            return;
        }

        lock (_ownGate)
        {
            if (_ownObjectKeys.TryGetValue(Convert.ToHexString(header.ObjectSalt), out var own))
            {
                own.CopyTo(destination);
                return;
            }
        }

        if (_contentPrivate is null)
        {
            throw new CryptoException(CryptoError.WrongKey, "A backup-only key cannot read backed-up file contents. Enter your password.");
        }

        // Shared secret is symmetric: X25519(contentPrivate, ephemeralPublic) == X25519(ephemeralPrivate, contentPublic).
        DeriveAsymmetricObjectKey(_contentPrivate.ReadOnlySpan, header.ObjectSalt, header, destination);
    }

    private void DeriveAsymmetricObjectKey(ReadOnlySpan<byte> privateScalar, ReadOnlySpan<byte> peerPublic, ObjectHeader header, Span<byte> destination)
    {
        Span<byte> shared = stackalloc byte[32];
        try
        {
            X25519.SharedSecret(privateScalar, peerPublic, shared);
            Span<byte> salt = stackalloc byte[64];
            header.ObjectSalt.CopyTo(salt);
            _contentPublic.CopyTo(salt[32..]);
            Span<byte> info = stackalloc byte[InfoObjectX25519.Length + 1 + 16];
            InfoObjectX25519.CopyTo(info);
            info[InfoObjectX25519.Length] = (byte)header.Type;
            RepositoryId.TryWriteBytes(info[(InfoObjectX25519.Length + 1)..]);
            HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, destination, salt, info);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(shared);
        }
    }

    private static ReadOnlySpan<byte> InfoObjectX25519 => "RezenBackup/v1/object-x25519"u8;

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
            KeyClass.Content => _content ?? throw new CryptoException(CryptoError.WrongKey, "A backup-only key cannot read backed-up file contents. Enter your password."),
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

    /// <summary>
    /// Keyed identifier for tree objects. Uses its own key (not just a prefix under the chunk key), so no file content can
    /// ever produce the identifier of a tree, and vice versa.
    /// </summary>
    public ChunkId ComputeTreeId(ReadOnlySpan<byte> canonicalTree)
    {
        Span<byte> mac = stackalloc byte[32];
        HMACSHA256.HashData(_treeId.ReadOnlySpan, canonicalTree, mac);
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
        lock (_ownGate)
        {
            foreach (var k in _ownObjectKeys.Values)
            {
                CryptographicOperations.ZeroMemory(k);
            }

            _ownObjectKeys.Clear();
        }

        _master?.Dispose();
        _content?.Dispose();
        _contentPrivate?.Dispose();
        _meta.Dispose();
        _chunkId.Dispose();
        _treeId.Dispose();
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


/// <summary>X25519 (RFC 7748) via libsodium.</summary>
internal static class X25519
{
    public static unsafe byte[] PublicFromPrivate(ReadOnlySpan<byte> privateScalar)
    {
        Native.Sodium.EnsureInitialized();
        var pub = new byte[32];
        fixed (byte* q = pub)
        fixed (byte* n = privateScalar)
        {
            if (Native.Sodium.crypto_scalarmult_base(q, n) != 0)
            {
                throw new CryptoException(CryptoError.InvalidFormat, "X25519 key generation failed.");
            }
        }

        return pub;
    }

    public static unsafe void SharedSecret(ReadOnlySpan<byte> privateScalar, ReadOnlySpan<byte> peerPublic, Span<byte> destination)
    {
        if (privateScalar.Length != 32 || peerPublic.Length != 32 || destination.Length != 32)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Invalid X25519 input length.");
        }

        Native.Sodium.EnsureInitialized();
        fixed (byte* q = destination)
        fixed (byte* n = privateScalar)
        fixed (byte* p = peerPublic)
        {
            // Rejects low-order points (all-zero shared secret) supplied by a tampered header.
            if (Native.Sodium.crypto_scalarmult(q, n, p) != 0)
            {
                destination.Clear();
                throw new CryptoException(CryptoError.AuthenticationFailed, "Backup integrity verification failed.");
            }
        }
    }
}
