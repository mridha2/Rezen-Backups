namespace RezenBackup.Core;

/// <summary>Stable error codes. Each maps to a plain-language message (spec §85).</summary>
public enum ErrorCode
{
    Unknown = 0,
    DestinationFull,
    DestinationDisconnected,
    DestinationNotWritable,
    DestinationInvalid,
    DriveNotRegistered,
    IntegrityFailure,
    WrongPassword,
    RecoveryKeyRequired,
    RecoveryKeyMalformed,
    KeyUnavailable,
    RepositoryLocked,
    RepositoryNotFound,
    UnsupportedVersion,
    InvalidConfiguration,
    SourceMissing,
    Cancelled,
    EncryptionFailure,
    CommitFailed,
    InsufficientSpace,
    PasswordTooWeak,
    UnsafeConfiguration,
    RestoreConflict,
    OnBattery,
}

/// <summary>
/// Application error with a user-facing message and separate technical details ("View Technical Details").
/// Never carries secrets.
/// </summary>
public class RezenException : Exception
{
    public RezenException(ErrorCode code, string? technical = null, Exception? inner = null)
        : base(UserMessages.For(code), inner)
    {
        Code = code;
        TechnicalDetails = technical ?? inner?.Message;
    }

    public RezenException(ErrorCode code, string userMessage, string? technical, Exception? inner)
        : base(userMessage, inner)
    {
        Code = code;
        TechnicalDetails = technical ?? inner?.Message;
    }

    public ErrorCode Code { get; }

    public string? TechnicalDetails { get; }

    /// <summary>True if the failure must stop the backup immediately (spec §86).</summary>
    public bool IsFatalForRun => Code is ErrorCode.DestinationFull or ErrorCode.DestinationDisconnected or ErrorCode.IntegrityFailure
        or ErrorCode.EncryptionFailure or ErrorCode.CommitFailed or ErrorCode.DestinationNotWritable or ErrorCode.Cancelled
        or ErrorCode.InsufficientSpace or ErrorCode.KeyUnavailable or ErrorCode.RepositoryLocked;
}

public static class UserMessages
{
    public const string UnlockFailed = "Unable to unlock backup. Check your password or recovery key.";
    public const string IntegrityFailed = "Backup integrity verification failed.";

    public static string For(ErrorCode code) => code switch
    {
        ErrorCode.DestinationFull => "Backup could not continue because the destination drive is full.",
        ErrorCode.DestinationDisconnected => "Backup stopped because the backup drive was disconnected.",
        ErrorCode.DestinationNotWritable => "Rezen Backup cannot write to the selected backup drive.",
        ErrorCode.DestinationInvalid => "The selected backup destination cannot be used.",
        ErrorCode.DriveNotRegistered => "This drive is not registered as a Rezen Backup drive.",
        ErrorCode.IntegrityFailure => IntegrityFailed,
        ErrorCode.WrongPassword => UnlockFailed,
        ErrorCode.RecoveryKeyRequired => "The backup's key files could not be read. Use your recovery key to unlock it.",
        ErrorCode.RecoveryKeyMalformed => "The recovery key is not valid. Check for typing mistakes.",
        ErrorCode.KeyUnavailable => "Backup Locked — enter your password to continue.",
        ErrorCode.RepositoryLocked => "Waiting for another Rezen Backup job.",
        ErrorCode.RepositoryNotFound => "No Rezen Backup was found at this location.",
        ErrorCode.UnsupportedVersion => "This backup was created by a newer version of Rezen Backup.",
        ErrorCode.InvalidConfiguration => "The backup job settings are not valid.",
        ErrorCode.SourceMissing => "A source folder could not be found.",
        ErrorCode.Cancelled => "The backup was stopped safely.",
        ErrorCode.EncryptionFailure => "Backup stopped because encryption could not be completed safely.",
        ErrorCode.CommitFailed => "Backup stopped because the snapshot could not be safely completed on the drive.",
        ErrorCode.InsufficientSpace => "There is not enough free space on the backup drive.",
        ErrorCode.PasswordTooWeak => "Choose a stronger password.",
        ErrorCode.UnsafeConfiguration => "This configuration is unsafe and cannot be used.",
        ErrorCode.RestoreConflict => "A file already exists at the restore location.",
        ErrorCode.OnBattery => "Backup postponed because the computer is running on battery.",
        _ => "An unexpected problem occurred.",
    };
}
