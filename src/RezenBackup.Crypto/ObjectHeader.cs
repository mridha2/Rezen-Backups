using System.Buffers.Binary;

namespace RezenBackup.Crypto;

/// <summary>Types of encrypted objects stored on a backup drive (DESIGN §4.4).</summary>
public enum ObjectType : byte
{
    DataPack = 1,
    MetaPack = 2,
    Snapshot = 3,
    Commit = 4,
    Journal = 5,
    RepositoryConfig = 6,
    CatalogCache = 7,
}

/// <summary>
/// Plaintext 72-byte header of every encrypted object. The full header is authenticated as the AAD of every
/// segment, so any change to it is detected.
/// </summary>
public sealed class ObjectHeader
{
    public const int Size = 72;
    public const ushort CurrentFormatVersion = 1;
    public const byte AlgorithmAes256GcmStream = 1;
    public const int DefaultSegmentSize = 1024 * 1024;
    public const int MinSegmentSize = 4 * 1024;
    public const int MaxSegmentSize = 16 * 1024 * 1024;

    private static ReadOnlySpan<byte> Magic => "RZNBKOBJ"u8;

    public ObjectHeader(ObjectType type, Guid repositoryId, byte[] objectSalt, int segmentSize = DefaultSegmentSize)
    {
        if (objectSalt.Length != 32)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Invalid object salt length.");
        }

        Type = type;
        RepositoryId = repositoryId;
        ObjectSalt = objectSalt;
        SegmentSize = segmentSize;
        FormatVersion = CurrentFormatVersion;
        AlgorithmId = AlgorithmAes256GcmStream;
    }

    public ushort FormatVersion { get; private init; }

    public ObjectType Type { get; }

    public byte AlgorithmId { get; private init; }

    public int SegmentSize { get; }

    public Guid RepositoryId { get; }

    public byte[] ObjectSalt { get; }

    public KeyClass KeyClass => Type == ObjectType.DataPack ? KeyClass.Content : KeyClass.Metadata;

    public static ObjectHeader CreateNew(ObjectType type, Guid repositoryId) =>
        new(type, repositoryId, CryptoRandom.Bytes(32));

    public byte[] ToBytes()
    {
        var bytes = new byte[Size];
        Magic.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(8), FormatVersion);
        bytes[10] = (byte)Type;
        bytes[11] = AlgorithmId;
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(12), SegmentSize);
        RepositoryId.TryWriteBytes(bytes.AsSpan(16, 16));
        ObjectSalt.CopyTo(bytes.AsSpan(32, 32));
        // bytes 64..71 reserved (zero).
        return bytes;
    }

    /// <summary>
    /// Parses and validates a header. Rejects unknown versions/algorithms rather than guessing (DESIGN §4.7).
    /// </summary>
    public static ObjectHeader Parse(ReadOnlySpan<byte> bytes, ObjectType? expectedType = null, Guid? expectedRepository = null)
    {
        if (bytes.Length < Size || !bytes[..8].SequenceEqual(Magic))
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Not a Rezen Backup object.");
        }

        ushort version = BinaryPrimitives.ReadUInt16LittleEndian(bytes[8..]);
        if (version != CurrentFormatVersion)
        {
            throw new CryptoException(CryptoError.UnsupportedVersion, "This backup was created by a newer version of Rezen Backup.");
        }

        var type = (ObjectType)bytes[10];
        if (!Enum.IsDefined(type))
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Unknown object type.");
        }

        byte algorithm = bytes[11];
        if (algorithm != AlgorithmAes256GcmStream)
        {
            throw new CryptoException(CryptoError.UnsupportedVersion, "This backup uses an encryption algorithm this version does not support.");
        }

        int segmentSize = BinaryPrimitives.ReadInt32LittleEndian(bytes[12..]);
        if (segmentSize is < MinSegmentSize or > MaxSegmentSize)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Invalid segment size.");
        }

        for (int i = 64; i < Size; i++)
        {
            if (bytes[i] != 0)
            {
                throw new CryptoException(CryptoError.InvalidFormat, "Reserved header bytes are not zero.");
            }
        }

        var repositoryId = new Guid(bytes.Slice(16, 16));
        if (expectedType is { } t && t != type)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Unexpected object type.");
        }

        if (expectedRepository is { } r && r != repositoryId)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Object belongs to a different repository.");
        }

        return new ObjectHeader(type, repositoryId, bytes.Slice(32, 32).ToArray(), segmentSize)
        {
            FormatVersion = version,
            AlgorithmId = algorithm,
        };
    }
}
