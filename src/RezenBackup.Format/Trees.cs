using System.Formats.Cbor;
using RezenBackup.Core.Domain;
using RezenBackup.Crypto;

namespace RezenBackup.Format;

/// <summary>
/// One entry in a directory tree (DESIGN §10.4). File and folder names only ever exist inside encrypted trees.
/// </summary>
public sealed record TreeEntry
{
    public required string Name { get; init; }

    public EntryKind Kind { get; init; }

    public long Size { get; init; }

    public long ModifiedTicksUtc { get; init; }

    public long CreatedTicksUtc { get; init; }

    public long? ChangeTicksUtc { get; init; }

    public int Attributes { get; init; }

    public int? UnixMode { get; init; }

    public EntryStatus Status { get; init; }

    public string? StatusDetail { get; init; }

    /// <summary>Snapshot from which a carried-forward version originates.</summary>
    public Guid? CarriedFromSnapshot { get; init; }

    /// <summary>SHA-256 of the whole plaintext file.</summary>
    public byte[]? Sha256 { get; init; }

    public IReadOnlyList<ChunkId> Chunks { get; init; } = [];

    public ChunkId? Subtree { get; init; }

    public string? LinkTarget { get; init; }

    /// <summary>Platform file identity used for change detection (NTFS file ID / inode). Never shown to users.</summary>
    public string? FileId { get; init; }

    public DateTime ModifiedUtc => new(ModifiedTicksUtc, DateTimeKind.Utc);

    public DateTime CreatedUtc => new(CreatedTicksUtc, DateTimeKind.Utc);
}

public sealed class TreeNode
{
    private const int Version = 1;

    public TreeNode(IEnumerable<TreeEntry> entries)
    {
        Entries = entries.OrderBy(e => e.Name, StringComparer.Ordinal).ToList();
    }

    public IReadOnlyList<TreeEntry> Entries { get; }

    /// <summary>Canonical encoding: entries sorted by ordinal name, positional arrays, canonical CBOR.</summary>
    public byte[] Encode()
    {
        var w = Cbor.NewWriter();
        w.WriteStartArray(2);
        w.WriteInt32(Version);
        w.WriteStartArray(Entries.Count);
        foreach (var e in Entries)
        {
            w.WriteStartArray(17);
            w.WriteTextStringSafe(e.Name);
            w.WriteInt32((int)e.Kind);
            w.WriteInt64(e.Size);
            w.WriteInt64(e.ModifiedTicksUtc);
            w.WriteInt64(e.CreatedTicksUtc);
            w.WriteNullableLong(e.ChangeTicksUtc);
            w.WriteInt32(e.Attributes);
            w.WriteNullableLong(e.UnixMode);
            w.WriteInt32((int)e.Status);
            w.WriteNullableText(e.StatusDetail);
            w.WriteNullableGuid(e.CarriedFromSnapshot);
            w.WriteNullableBytes(e.Sha256);
            w.WriteStartArray(e.Chunks.Count);
            foreach (var c in e.Chunks)
            {
                w.WriteChunkId(c);
            }

            w.WriteEndArray();
            w.WriteNullableBytes(e.Subtree?.ToArray());
            w.WriteNullableText(e.LinkTarget);
            w.WriteNullableText(e.FileId);
            w.WriteNull(); // reserved for future extension (ACLs / alternate data streams)
            w.WriteEndArray();
        }

        w.WriteEndArray();
        w.WriteEndArray();
        return w.Encode();
    }

    public static TreeNode Decode(byte[] data)
    {
        try
        {
            var r = Cbor.NewReader(data);
            r.ReadStartArray();
            int version = r.ReadInt32();
            if (version != Version)
            {
                throw new CryptoException(CryptoError.UnsupportedVersion, "Unsupported tree version.");
            }

            int count = r.ReadStartArray() ?? 0;
            var entries = new List<TreeEntry>(count);
            for (int i = 0; i < count; i++)
            {
                r.ReadStartArray();
                var name = r.ReadTextStringSafe();
                var kind = (EntryKind)r.ReadInt32();
                long size = r.ReadInt64();
                long mtime = r.ReadInt64();
                long ctime = r.ReadInt64();
                long? change = r.ReadNullableLong();
                int attrs = r.ReadInt32();
                long? mode = r.ReadNullableLong();
                var status = (EntryStatus)r.ReadInt32();
                var detail = r.ReadNullableText();
                var carried = r.ReadNullableGuid();
                var sha = r.ReadNullableBytes();
                int chunkCount = r.ReadStartArray() ?? 0;
                var chunks = new List<ChunkId>(chunkCount);
                for (int c = 0; c < chunkCount; c++)
                {
                    chunks.Add(r.ReadChunkId());
                }

                r.ReadEndArray();
                var subtree = r.ReadNullableBytes();
                var link = r.ReadNullableText();
                var fileId = r.ReadNullableText();
                r.SkipValue();
                r.ReadEndArray();

                if (name.Length == 0 || name.Contains('/') || name is "." or ".." || (OperatingSystem.IsWindows() && name.Contains('\\')))
                {
                    throw new CryptoException(CryptoError.InvalidFormat, "Invalid entry name in tree.");
                }

                entries.Add(new TreeEntry
                {
                    Name = name,
                    Kind = kind,
                    Size = size,
                    ModifiedTicksUtc = mtime,
                    CreatedTicksUtc = ctime,
                    ChangeTicksUtc = change,
                    Attributes = attrs,
                    UnixMode = (int?)mode,
                    Status = status,
                    StatusDetail = detail,
                    CarriedFromSnapshot = carried,
                    Sha256 = sha,
                    Chunks = chunks,
                    Subtree = subtree is null ? null : new ChunkId(subtree),
                    LinkTarget = link,
                    FileId = fileId,
                });
            }

            r.ReadEndArray();
            r.ReadEndArray();
            return new TreeNode(entries);
        }
        catch (Exception ex) when (ex is CborContentException or InvalidOperationException or FormatException or ArgumentException)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Tree object is invalid.", ex);
        }
    }
}
