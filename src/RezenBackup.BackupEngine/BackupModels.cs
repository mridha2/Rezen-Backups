using RezenBackup.Core.Domain;
using RezenBackup.Core.Policies;
using RezenBackup.Format;

namespace RezenBackup.BackupEngine;

public sealed record BackupOptions
{
    public required IReadOnlyList<string> Sources { get; init; }

    public IReadOnlyList<ExclusionRule> Exclusions { get; init; } = ExclusionMatcher.Defaults;

    public BackupMethod Method { get; init; } = BackupMethod.Incremental;

    public VerificationLevel Verification { get; init; } = VerificationLevel.Standard;

    public string HostName { get; init; } = Environment.MachineName;

    public string AppVersion { get; init; } = "1.0.0";

    /// <summary>Free space always kept so the commit can finish (DESIGN §16.3).</summary>
    public long ReserveBytes { get; init; } = 256L * 1024 * 1024;

    public int MaxRetriesOnChange { get; init; } = 3;

    /// <summary>Local cache file for the chunk index (null: no cache).</summary>
    public string? IndexCachePath { get; init; }

    /// <summary>Resume this incomplete snapshot folder instead of starting a new one.</summary>
    public string? ResumeFolderName { get; init; }

    /// <summary>Local time used for the snapshot folder name. Defaults to now.</summary>
    public DateTime? SnapshotLocalTime { get; init; }

    /// <summary>Returns free bytes on the destination volume.</summary>
    public Func<long>? FreeSpaceProbe { get; init; }

    /// <summary>Test hook: invoked at named points of the commit protocol (crash-injection harness).</summary>
    public Action<string>? FaultInjection { get; init; }
}

public enum BackupPhase
{
    Preparing,
    Scanning,
    Encrypting,
    Verifying,
    Committing,
    Done,
}

public sealed record BackupProgress
{
    public BackupPhase Phase { get; init; }

    public long FilesTotal { get; init; }

    public long FilesDone { get; init; }

    public long BytesTotal { get; init; }

    public long BytesDone { get; init; }

    /// <summary>Name only (not full path) of the file being processed; may be hidden by the UI's privacy setting.</summary>
    public string? CurrentFile { get; init; }

    public double BytesPerSecond { get; init; }

    public TimeSpan? EstimatedRemaining { get; init; }

    public bool Paused { get; init; }

    public string PhaseText => Phase switch
    {
        BackupPhase.Preparing => "Preparing…",
        BackupPhase.Scanning => "Scanning…",
        BackupPhase.Encrypting => "Encrypting…",
        BackupPhase.Verifying => "Verifying…",
        BackupPhase.Committing => "Writing encrypted backup…",
        BackupPhase.Done => "Done",
        _ => Phase.ToString(),
    };
}

public sealed record BackupResult
{
    public required Guid SnapshotId { get; init; }

    public required string FolderName { get; init; }

    public required RunOutcome Outcome { get; init; }

    public required SnapshotStats Stats { get; init; }

    public IReadOnlyList<SnapshotWarning> Warnings { get; init; } = [];

    public VerificationLevel Verification { get; init; }

    public required byte[] CommitHash { get; init; }

    public DateTimeOffset StartedUtc { get; init; }

    public DateTimeOffset CompletedUtc { get; init; }

    public bool AnomalyDetected { get; init; }

    public int PacksWritten { get; init; }
}

/// <summary>Cooperative pause gate checked between chunks (spec §37).</summary>
public sealed class PauseGate
{
    private readonly ManualResetEventSlim _running = new(initialState: true);

    public bool IsPaused => !_running.IsSet;

    public void Pause() => _running.Reset();

    public void Resume() => _running.Set();

    public void WaitIfPaused(CancellationToken ct) => _running.Wait(ct);
}
