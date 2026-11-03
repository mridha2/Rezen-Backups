using System.Formats.Cbor;
using RezenBackup.Core.Domain;
using RezenBackup.Crypto;

namespace RezenBackup.Format;

/// <summary>A backed-up source. For a single-file source the root tree holds exactly that file.</summary>
public sealed record SnapshotSource(string OriginalPath, ChunkId RootTree, bool IsFile = false);

public sealed record SnapshotWarning(string Path, IssueKind Kind, string? Detail);

public sealed record SnapshotStats
{
    public long Files { get; init; }

    public long Directories { get; init; }

    public long BytesScanned { get; init; }

    public long BytesNew { get; init; }

    public long BytesStored { get; init; }

    public long FilesNew { get; init; }

    public long FilesChanged { get; init; }

    public long FilesUnchanged { get; init; }

    public long FilesWithWarnings { get; init; }
}

/// <summary>Encrypted snapshot record <c>snapshot.rzb</c> (DESIGN §10.5).</summary>
public sealed record SnapshotRecord
{
    private const int Version = 1;

    public required Guid SnapshotId { get; init; }

    public required Guid RepositoryId { get; init; }

    public required string FolderBaseName { get; init; }

    public DateTimeOffset StartedUtc { get; init; }

    public DateTimeOffset CompletedUtc { get; init; }

    public int UtcOffsetMinutes { get; init; }

    public string HostName { get; init; } = string.Empty;

    public string AppVersion { get; init; } = string.Empty;

    public string Platform { get; init; } = string.Empty;

    public BackupMethod Method { get; init; }

    public IReadOnlyList<SnapshotSource> Sources { get; init; } = [];

    public SnapshotStats Stats { get; init; } = new();

    public IReadOnlyList<SnapshotWarning> Warnings { get; init; } = [];

    public Guid? ParentSnapshotId { get; init; }

    public byte[]? PreviousCommitHash { get; init; }

    public VerificationLevel Verification { get; init; }

    public bool AnomalyDetected { get; init; }

    public byte[] Encode()
    {
        var w = Cbor.NewWriter();
        w.WriteStartArray(19);
        w.WriteInt32(Version);
        w.WriteGuid(SnapshotId);
        w.WriteGuid(RepositoryId);
        w.WriteTextString(FolderBaseName);
        w.WriteInt64(StartedUtc.UtcTicks);
        w.WriteInt64(CompletedUtc.UtcTicks);
        w.WriteInt32(UtcOffsetMinutes);
        w.WriteTextStringSafe(HostName);
        w.WriteTextString(AppVersion);
        w.WriteTextString(Platform);
        w.WriteInt32((int)Method);
        w.WriteStartArray(Sources.Count);
        foreach (var s in Sources)
        {
            w.WriteStartArray(3);
            w.WriteTextStringSafe(s.OriginalPath);
            w.WriteChunkId(s.RootTree);
            w.WriteBoolean(s.IsFile);
            w.WriteEndArray();
        }

        w.WriteEndArray();
        w.WriteStartArray(9);
        w.WriteInt64(Stats.Files);
        w.WriteInt64(Stats.Directories);
        w.WriteInt64(Stats.BytesScanned);
        w.WriteInt64(Stats.BytesNew);
        w.WriteInt64(Stats.BytesStored);
        w.WriteInt64(Stats.FilesNew);
        w.WriteInt64(Stats.FilesChanged);
        w.WriteInt64(Stats.FilesUnchanged);
        w.WriteInt64(Stats.FilesWithWarnings);
        w.WriteEndArray();
        w.WriteStartArray(Warnings.Count);
        foreach (var warning in Warnings)
        {
            w.WriteStartArray(3);
            w.WriteTextStringSafe(warning.Path);
            w.WriteInt32((int)warning.Kind);
            w.WriteNullableText(warning.Detail);
            w.WriteEndArray();
        }

        w.WriteEndArray();
        w.WriteNullableGuid(ParentSnapshotId);
        w.WriteNullableBytes(PreviousCommitHash);
        w.WriteInt32((int)Verification);
        w.WriteBoolean(AnomalyDetected);
        w.WriteNull(); // reserved
        w.WriteEndArray();
        return w.Encode();
    }

    public static SnapshotRecord Decode(byte[] data)
    {
        try
        {
            var r = Cbor.NewReader(data);
            r.ReadStartArray();
            if (r.ReadInt32() != Version)
            {
                throw new CryptoException(CryptoError.UnsupportedVersion, "Unsupported snapshot record version.");
            }

            var id = r.ReadGuid();
            var repo = r.ReadGuid();
            var folder = r.ReadTextString();
            var started = new DateTimeOffset(r.ReadInt64(), TimeSpan.Zero);
            var completed = new DateTimeOffset(r.ReadInt64(), TimeSpan.Zero);
            int offset = r.ReadInt32();
            var host = r.ReadTextStringSafe();
            var app = r.ReadTextString();
            var platform = r.ReadTextString();
            var method = (BackupMethod)r.ReadInt32();
            int sourceCount = r.ReadStartArray() ?? 0;
            var sources = new List<SnapshotSource>(sourceCount);
            for (int i = 0; i < sourceCount; i++)
            {
                r.ReadStartArray();
                sources.Add(new SnapshotSource(r.ReadTextStringSafe(), r.ReadChunkId(), r.ReadBoolean()));
                r.ReadEndArray();
            }

            r.ReadEndArray();
            r.ReadStartArray();
            var stats = new SnapshotStats
            {
                Files = r.ReadInt64(),
                Directories = r.ReadInt64(),
                BytesScanned = r.ReadInt64(),
                BytesNew = r.ReadInt64(),
                BytesStored = r.ReadInt64(),
                FilesNew = r.ReadInt64(),
                FilesChanged = r.ReadInt64(),
                FilesUnchanged = r.ReadInt64(),
                FilesWithWarnings = r.ReadInt64(),
            };
            r.ReadEndArray();
            int warnCount = r.ReadStartArray() ?? 0;
            var warnings = new List<SnapshotWarning>(warnCount);
            for (int i = 0; i < warnCount; i++)
            {
                r.ReadStartArray();
                warnings.Add(new SnapshotWarning(r.ReadTextStringSafe(), (IssueKind)r.ReadInt32(), r.ReadNullableText()));
                r.ReadEndArray();
            }

            r.ReadEndArray();
            var parent = r.ReadNullableGuid();
            var prevHash = r.ReadNullableBytes();
            var verification = (VerificationLevel)r.ReadInt32();
            bool anomaly = r.ReadBoolean();
            r.SkipValue();
            r.ReadEndArray();
            return new SnapshotRecord
            {
                SnapshotId = id,
                RepositoryId = repo,
                FolderBaseName = folder,
                StartedUtc = started,
                CompletedUtc = completed,
                UtcOffsetMinutes = offset,
                HostName = host,
                AppVersion = app,
                Platform = platform,
                Method = method,
                Sources = sources,
                Stats = stats,
                Warnings = warnings,
                ParentSnapshotId = parent,
                PreviousCommitHash = prevHash,
                Verification = verification,
                AnomalyDetected = anomaly,
            };
        }
        catch (Exception ex) when (ex is CborContentException or InvalidOperationException or FormatException)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Snapshot record is invalid.", ex);
        }
    }
}

public sealed record CommittedPack(Guid PackId, PackKind Kind, long Length, byte[] Sha256);

/// <summary>
/// Encrypted, authenticated commit record <c>integrity.dat</c> (DESIGN §15.3). A snapshot is complete only if this
/// record authenticates and matches the snapshot record.
/// </summary>
public sealed record CommitRecord
{
    private const int Version = 1;
    public const string CommittedState = "committed";

    public required Guid SnapshotId { get; init; }

    public required Guid RepositoryId { get; init; }

    public required string FolderBaseName { get; init; }

    public required byte[] SnapshotRecordSha256 { get; init; }

    public IReadOnlyList<CommittedPack> Packs { get; init; } = [];

    public VerificationLevel Verification { get; init; }

    public string VerificationResult { get; init; } = "passed";

    public DateTimeOffset VerifiedUtc { get; init; }

    public byte[]? PreviousCommitHash { get; init; }

    public string State { get; init; } = CommittedState;

    public byte[] Encode()
    {
        var w = Cbor.NewWriter();
        w.WriteStartArray(11);
        w.WriteInt32(Version);
        w.WriteGuid(SnapshotId);
        w.WriteGuid(RepositoryId);
        w.WriteTextString(FolderBaseName);
        w.WriteByteString(SnapshotRecordSha256);
        w.WriteStartArray(Packs.Count);
        foreach (var p in Packs)
        {
            w.WriteStartArray(4);
            w.WriteGuid(p.PackId);
            w.WriteInt32((int)p.Kind);
            w.WriteInt64(p.Length);
            w.WriteByteString(p.Sha256);
            w.WriteEndArray();
        }

        w.WriteEndArray();
        w.WriteInt32((int)Verification);
        w.WriteTextString(VerificationResult);
        w.WriteInt64(VerifiedUtc.UtcTicks);
        w.WriteNullableBytes(PreviousCommitHash);
        w.WriteTextString(State);
        w.WriteEndArray();
        return w.Encode();
    }

    public static CommitRecord Decode(byte[] data)
    {
        try
        {
            var r = Cbor.NewReader(data);
            r.ReadStartArray();
            if (r.ReadInt32() != Version)
            {
                throw new CryptoException(CryptoError.UnsupportedVersion, "Unsupported commit record version.");
            }

            var id = r.ReadGuid();
            var repo = r.ReadGuid();
            var folder = r.ReadTextString();
            var sha = r.ReadByteString();
            int packCount = r.ReadStartArray() ?? 0;
            var packs = new List<CommittedPack>(packCount);
            for (int i = 0; i < packCount; i++)
            {
                r.ReadStartArray();
                packs.Add(new CommittedPack(r.ReadGuid(), (PackKind)r.ReadInt32(), r.ReadInt64(), r.ReadByteString()));
                r.ReadEndArray();
            }

            r.ReadEndArray();
            var level = (VerificationLevel)r.ReadInt32();
            var result = r.ReadTextString();
            var verified = new DateTimeOffset(r.ReadInt64(), TimeSpan.Zero);
            var prev = r.ReadNullableBytes();
            var state = r.ReadTextString();
            r.ReadEndArray();
            return new CommitRecord
            {
                SnapshotId = id,
                RepositoryId = repo,
                FolderBaseName = folder,
                SnapshotRecordSha256 = sha,
                Packs = packs,
                Verification = level,
                VerificationResult = result,
                VerifiedUtc = verified,
                PreviousCommitHash = prev,
                State = state,
            };
        }
        catch (Exception ex) when (ex is CborContentException or InvalidOperationException or FormatException)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Commit record is invalid.", ex);
        }
    }
}

/// <summary>Encrypted progress journal for resuming an interrupted backup (DESIGN §16).</summary>
public sealed record JournalRecord
{
    private const int Version = 1;

    public required Guid SnapshotId { get; init; }

    public required string FolderBaseName { get; init; }

    public DateTimeOffset StartedUtc { get; init; }

    public IReadOnlyList<CommittedPack> Packs { get; init; } = [];

    public byte[] Encode()
    {
        var w = Cbor.NewWriter();
        w.WriteStartArray(5);
        w.WriteInt32(Version);
        w.WriteGuid(SnapshotId);
        w.WriteTextString(FolderBaseName);
        w.WriteInt64(StartedUtc.UtcTicks);
        w.WriteStartArray(Packs.Count);
        foreach (var p in Packs)
        {
            w.WriteStartArray(4);
            w.WriteGuid(p.PackId);
            w.WriteInt32((int)p.Kind);
            w.WriteInt64(p.Length);
            w.WriteByteString(p.Sha256);
            w.WriteEndArray();
        }

        w.WriteEndArray();
        w.WriteEndArray();
        return w.Encode();
    }

    public static JournalRecord Decode(byte[] data)
    {
        var r = Cbor.NewReader(data);
        r.ReadStartArray();
        if (r.ReadInt32() != Version)
        {
            throw new CryptoException(CryptoError.UnsupportedVersion, "Unsupported journal version.");
        }

        var id = r.ReadGuid();
        var folder = r.ReadTextString();
        var started = new DateTimeOffset(r.ReadInt64(), TimeSpan.Zero);
        int count = r.ReadStartArray() ?? 0;
        var packs = new List<CommittedPack>(count);
        for (int i = 0; i < count; i++)
        {
            r.ReadStartArray();
            packs.Add(new CommittedPack(r.ReadGuid(), (PackKind)r.ReadInt32(), r.ReadInt64(), r.ReadByteString()));
            r.ReadEndArray();
        }

        r.ReadEndArray();
        r.ReadEndArray();
        return new JournalRecord { SnapshotId = id, FolderBaseName = folder, StartedUtc = started, Packs = packs };
    }
}
