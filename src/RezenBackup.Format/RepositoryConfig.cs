using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Text.Json;
using System.Text.Json.Serialization;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Platform;
using RezenBackup.Crypto;

namespace RezenBackup.Format;

/// <summary>Plaintext, non-secret preamble of <c>repository.rzc</c>: enough to know which key set to ask for.</summary>
public sealed record RepositoryInfo(Guid RepositoryId, Guid KeySetId, int FormatVersion, int MinReaderVersion);

/// <summary>Encrypted repository configuration body.</summary>
public sealed record RepositoryConfig
{
    private const int Version = 1;

    public string JobName { get; init; } = string.Empty;

    public string HostName { get; init; } = string.Empty;

    public DateTimeOffset CreatedUtc { get; init; }

    public string AppVersion { get; init; } = string.Empty;

    public int ChunkMin { get; init; } = 256 * 1024;

    public int ChunkAvg { get; init; } = 1024 * 1024;

    public int ChunkMax { get; init; } = 4 * 1024 * 1024;

    public long PackTargetSize { get; init; } = PackFormat.TargetPackSize;

    public IReadOnlyList<string> Sources { get; init; } = [];

    public byte[] Encode()
    {
        var w = Cbor.NewWriter();
        w.WriteStartArray(10);
        w.WriteInt32(Version);
        w.WriteTextStringSafe(JobName);
        w.WriteTextStringSafe(HostName);
        w.WriteInt64(CreatedUtc.UtcTicks);
        w.WriteTextString(AppVersion);
        w.WriteInt32(ChunkMin);
        w.WriteInt32(ChunkAvg);
        w.WriteInt32(ChunkMax);
        w.WriteInt64(PackTargetSize);
        w.WriteStartArray(Sources.Count);
        foreach (var s in Sources)
        {
            w.WriteTextStringSafe(s);
        }

        w.WriteEndArray();
        w.WriteEndArray();
        return w.Encode();
    }

    public static RepositoryConfig Decode(byte[] data)
    {
        try
        {
            var r = Cbor.NewReader(data);
            r.ReadStartArray();
            if (r.ReadInt32() != Version)
            {
                throw new RezenException(ErrorCode.UnsupportedVersion);
            }

            var cfg = new RepositoryConfig
            {
                JobName = r.ReadTextStringSafe(),
                HostName = r.ReadTextStringSafe(),
                CreatedUtc = new DateTimeOffset(r.ReadInt64(), TimeSpan.Zero),
                AppVersion = r.ReadTextString(),
                ChunkMin = r.ReadInt32(),
                ChunkAvg = r.ReadInt32(),
                ChunkMax = r.ReadInt32(),
                PackTargetSize = r.ReadInt64(),
            };
            int n = r.ReadStartArray() ?? 0;
            var sources = new List<string>(n);
            for (int i = 0; i < n; i++)
            {
                sources.Add(r.ReadTextStringSafe());
            }

            r.ReadEndArray();
            r.ReadEndArray();
            if (cfg.ChunkMin < 64 * 1024 || cfg.ChunkMax > 16 * 1024 * 1024 || cfg.ChunkMin > cfg.ChunkAvg || cfg.ChunkAvg > cfg.ChunkMax)
            {
                throw new CryptoException(CryptoError.InvalidFormat, "Repository chunking parameters are out of range.");
            }

            return cfg with { Sources = sources };
        }
        catch (Exception ex) when (ex is CborContentException or InvalidOperationException or FormatException)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Repository configuration is invalid.", ex);
        }
    }
}

public static class RepositoryConfigFile
{
    private static ReadOnlySpan<byte> Magic => "RZNBKREP"u8;
    private const int PreambleSize = 8 + 2 + 2 + 16 + 16;

    public static void Write(string path, RepositoryInfo info, RepositoryConfig config, RepositoryKeys keys, IDurableFileOps ops)
    {
        var encrypted = EncryptedObjects.Encrypt(keys, ObjectType.RepositoryConfig, config.Encode());
        var file = new byte[PreambleSize + encrypted.Length];
        Magic.CopyTo(file);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(8), (ushort)info.FormatVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(10), (ushort)info.MinReaderVersion);
        info.RepositoryId.TryWriteBytes(file.AsSpan(12, 16));
        info.KeySetId.TryWriteBytes(file.AsSpan(28, 16));
        encrypted.CopyTo(file, PreambleSize);
        EncryptedObjects.WriteDurable(path, file, ops);
    }

    public static RepositoryInfo ReadInfo(string path)
    {
        Span<byte> pre = stackalloc byte[PreambleSize];
        using (var fs = File.OpenRead(path))
        {
            if (fs.Read(pre) != PreambleSize || !pre[..8].SequenceEqual(Magic))
            {
                throw new RezenException(ErrorCode.RepositoryNotFound, "Repository configuration header is invalid.");
            }
        }

        var info = new RepositoryInfo(
            new Guid(pre.Slice(12, 16)),
            new Guid(pre.Slice(28, 16)),
            BinaryPrimitives.ReadUInt16LittleEndian(pre[8..]),
            BinaryPrimitives.ReadUInt16LittleEndian(pre[10..]));
        if (info.MinReaderVersion > RepositoryLayout.FormatVersion)
        {
            throw new RezenException(ErrorCode.UnsupportedVersion);
        }

        return info;
    }

    /// <summary>Decrypts the configuration; a wrong Root Secret fails authentication here.</summary>
    public static RepositoryConfig ReadConfig(string path, RepositoryKeys keys)
    {
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length <= PreambleSize)
        {
            throw new RezenException(ErrorCode.RepositoryNotFound, "Repository configuration is truncated.");
        }

        var plain = EncryptedObjects.Decrypt(keys, ObjectType.RepositoryConfig, bytes[PreambleSize..], 16 * 1024 * 1024);
        return RepositoryConfig.Decode(plain);
    }
}

/// <summary>Plaintext <c>snapshot.meta</c> — advisory only, never trusted for completeness (DESIGN §10.2).</summary>
public sealed record SnapshotMeta
{
    [JsonPropertyName("format")]
    public string Format { get; init; } = RepositoryLayout.FormatName;

    [JsonPropertyName("formatVersion")]
    public int FormatVersion { get; init; } = RepositoryLayout.FormatVersion;

    [JsonPropertyName("snapshotId")]
    public Guid SnapshotId { get; init; }

    [JsonPropertyName("repositoryId")]
    public Guid RepositoryId { get; init; }

    [JsonPropertyName("state")]
    public string State { get; init; } = "incomplete";

    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public void Write(string snapshotDir, IDurableFileOps ops)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(this, Options);
        EncryptedObjects.WriteDurable(RepositoryLayout.SnapshotMetaPath(snapshotDir), bytes, ops);
    }

    public static SnapshotMeta? TryRead(string snapshotDir)
    {
        try
        {
            var path = RepositoryLayout.SnapshotMetaPath(snapshotDir);
            return File.Exists(path) ? JsonSerializer.Deserialize<SnapshotMeta>(File.ReadAllBytes(path), Options) : null;
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public static SnapshotMeta For(Guid snapshotId, Guid repositoryId, SnapshotState state) => new()
    {
        SnapshotId = snapshotId,
        RepositoryId = repositoryId,
        State = state == SnapshotState.Committed ? "committed" : "incomplete",
    };
}
