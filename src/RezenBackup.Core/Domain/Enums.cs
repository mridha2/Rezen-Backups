namespace RezenBackup.Core.Domain;

/// <summary>Backup methods (spec §34). Mirror is offered only as the "latest only" retention preset (DESIGN §13.3).</summary>
public enum BackupMethod
{
    /// <summary>Default. Only new or changed data is stored; every run is a complete logical snapshot.</summary>
    Incremental = 0,

    /// <summary>Re-reads every file and writes an independent copy that shares no packs with other snapshots.</summary>
    FullSnapshot = 1,
}

/// <summary>Post-backup verification depth (spec §57).</summary>
public enum VerificationLevel
{
    Standard = 0,
    Full = 1,
}

/// <summary>On-drive state of a snapshot folder.</summary>
public enum SnapshotState
{
    Incomplete = 0,
    Committed = 1,
    Deleting = 2,
}

/// <summary>Security statuses shown to the user (spec §27). Never a generic "Success".</summary>
public enum SecurityStatus
{
    EncryptedAndVerified,
    EncryptedVerificationPending,
    BackupLocked,
    WrongPassword,
    IntegrityFailure,
    RecoveryKeyRequired,
    BackupDriveDisconnected,
    NoBackupYet,
}

public enum RunOutcome
{
    Running = 0,
    Success = 1,
    CompletedWithWarnings = 2,
    Failed = 3,
    Cancelled = 4,
    WaitingForDrive = 5,
    WaitingForPassword = 6,
}

public enum RunTrigger
{
    Manual = 0,
    Scheduled = 1,
    DriveConnected = 2,
    Missed = 3,
    Resume = 4,
}

/// <summary>Per-file status recorded in the encrypted manifest (DESIGN §10.4).</summary>
public enum EntryStatus : byte
{
    Ok = 0,
    ChangedDuringBackup = 1,
    CarriedForward = 2,
    Unreadable = 3,
}

public enum EntryKind : byte
{
    File = 0,
    Directory = 1,
    Link = 2,
}

/// <summary>Why a file could not be backed up, shown in the "files could not be backed up" details (spec §68).</summary>
public enum IssueKind
{
    Locked = 1,
    PermissionDenied = 2,
    ChangedDuringBackup = 3,
    OnlineOnlyCloudFile = 4,
    NotFound = 5,
    ReadError = 6,
    PathTooLong = 7,
    SourceMissing = 8,
}

public static class SecurityStatusText
{
    public static string ToDisplay(this SecurityStatus status) => status switch
    {
        SecurityStatus.EncryptedAndVerified => "Encrypted & Verified",
        SecurityStatus.EncryptedVerificationPending => "Encrypted — Verification Pending",
        SecurityStatus.BackupLocked => "Backup Locked",
        SecurityStatus.WrongPassword => "Wrong Password",
        SecurityStatus.IntegrityFailure => "Integrity Failure",
        SecurityStatus.RecoveryKeyRequired => "Recovery Key Required",
        SecurityStatus.BackupDriveDisconnected => "Backup Drive Disconnected",
        SecurityStatus.NoBackupYet => "No Backup Yet",
        _ => status.ToString(),
    };

    public static string ToDisplay(this RunOutcome outcome) => outcome switch
    {
        RunOutcome.Running => "Running",
        RunOutcome.Success => "Success",
        RunOutcome.CompletedWithWarnings => "Completed with warnings",
        RunOutcome.Failed => "Failed",
        RunOutcome.Cancelled => "Stopped",
        RunOutcome.WaitingForDrive => "Backup Pending — Secure Backup Drive Not Connected",
        RunOutcome.WaitingForPassword => "Waiting for password",
        _ => outcome.ToString(),
    };

    public static string ToDisplay(this IssueKind kind) => kind switch
    {
        IssueKind.Locked => "File is in use by another program",
        IssueKind.PermissionDenied => "Permission denied",
        IssueKind.ChangedDuringBackup => "File kept changing during backup",
        IssueKind.OnlineOnlyCloudFile => "Online-only cloud file — not downloaded (offline mode)",
        IssueKind.NotFound => "File disappeared during backup",
        IssueKind.ReadError => "Read error",
        IssueKind.PathTooLong => "Path too long",
        IssueKind.SourceMissing => "Source folder not found",
        _ => kind.ToString(),
    };
}
