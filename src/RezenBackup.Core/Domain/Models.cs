using RezenBackup.Core.Policies;

namespace RezenBackup.Core.Domain;

/// <summary>A Key Set: one password + one recovery key + one Root Secret (DESIGN §6.2). Holds flags only, never key material.</summary>
public sealed record KeySetInfo
{
    public required Guid Id { get; init; }

    public string DisplayName { get; init; } = "Rezen Backup password";

    public DateTimeOffset CreatedUtc { get; init; }

    /// <summary>Incremented on every password change; repositories with a lower value need their key files updated.</summary>
    public int PasswordGeneration { get; init; } = 1;

    public bool RecoveryKeyConfirmed { get; init; }

    public bool RememberOnThisPc { get; init; }

    public string? KdfDescription { get; init; }
}

/// <summary>A backup job (spec §28).</summary>
public sealed record JobDefinition
{
    public required Guid Id { get; init; }

    public required Guid KeySetId { get; init; }

    public required string Name { get; init; }

    public bool Enabled { get; init; } = true;

    public IReadOnlyList<string> Sources { get; init; } = [];

    public IReadOnlyList<ExclusionRule> Exclusions { get; init; } = ExclusionMatcher.Defaults;

    public Guid? DriveId { get; init; }

    public BackupMethod Method { get; init; } = BackupMethod.Incremental;

    public VerificationLevel Verification { get; init; } = VerificationLevel.Standard;

    public RetentionPolicy Retention { get; init; } = RetentionPolicy.Smart;

    public Schedule Schedule { get; init; } = Schedule.DailyAt(20);

    /// <summary>Use opaque folder names instead of computer and job names on the drive (DESIGN §12.4).</summary>
    public bool HideNamesOnDrive { get; init; }

    /// <summary>Run a pending backup automatically when the registered drive is connected (spec §53, §62).</summary>
    public bool AutoRunOnConnect { get; init; } = true;

    public bool EjectAfterBackup { get; init; }

    public bool RunMissed { get; init; } = true;

    public bool SkipOnBattery { get; init; }

    /// <summary>Folder names on the drive: <c>Rezen Backup/&lt;ComputerFolder&gt;/&lt;JobFolder&gt;</c>.</summary>
    public string ComputerFolder { get; init; } = string.Empty;

    public string JobFolder { get; init; } = string.Empty;

    public DateTimeOffset CreatedUtc { get; init; }

    public int FullSnapshotEveryDays { get; init; }
}

public sealed record DriveRecord
{
    public required Guid Id { get; init; }

    public string Label { get; init; } = string.Empty;

    public string? VolumeIdentifier { get; init; }

    public string FileSystem { get; init; } = string.Empty;

    public long CapacityBytes { get; init; }

    public DateTimeOffset LastSeenUtc { get; init; }

    public string? LastMountPath { get; init; }
}

public sealed record RepositoryRecord
{
    public required Guid Id { get; init; }

    public required Guid JobId { get; init; }

    public required Guid DriveId { get; init; }

    public required string RelativePath { get; init; }

    public int PasswordGeneration { get; init; } = 1;

    public DateTimeOffset CreatedUtc { get; init; }
}

public sealed record SnapshotRow
{
    public required Guid Id { get; init; }

    public required Guid RepositoryId { get; init; }

    public required Guid JobId { get; init; }

    public required string FolderName { get; init; }

    public DateTimeOffset StartedUtc { get; init; }

    public DateTimeOffset? CompletedUtc { get; init; }

    public SnapshotState State { get; init; }

    public SecurityStatus Security { get; init; }

    public VerificationLevel Verification { get; init; }

    public long Files { get; init; }

    public long BytesScanned { get; init; }

    public long BytesNew { get; init; }

    public long DurationMs { get; init; }

    public byte[]? CommitHash { get; init; }

    public bool Pinned { get; init; }

    public bool Anomaly { get; init; }

    public bool Deleted { get; init; }
}

public sealed record RunRow
{
    public required Guid Id { get; init; }

    public required Guid JobId { get; init; }

    public Guid? SnapshotId { get; init; }

    public RunTrigger Trigger { get; init; }

    public DateTimeOffset StartedUtc { get; init; }

    public DateTimeOffset? EndedUtc { get; init; }

    public RunOutcome Outcome { get; init; }

    public SecurityStatus Security { get; init; }

    public ErrorCode? Error { get; init; }

    public string? Message { get; init; }

    public string? TechnicalDetails { get; init; }

    public long Files { get; init; }

    public long FilesWarned { get; init; }

    public long BytesNew { get; init; }

    public long BytesScanned { get; init; }

    public string? SnapshotFolder { get; init; }

    public TimeSpan? Duration => EndedUtc is { } e ? e - StartedUtc : null;
}

public sealed record RunIssueRow(long Id, Guid RunId, IssueKind Kind, byte[] PathSealed, string? Detail);

public sealed record SecurityEventRow(long Id, DateTimeOffset Utc, string Type, Guid? JobId, string Detail, byte[] PrevHash, byte[] Mac);
