using RezenBackup.Crypto;

namespace RezenBackup.Core.Platform;

/// <summary>
/// OS-protected storage for the Root Secret, used only for unattended scheduled backups (DESIGN §9).
/// Windows: DPAPI CurrentUser. macOS: login Keychain.
/// </summary>
public interface ICredentialStore
{
    bool IsSupported { get; }

    string MechanismName { get; }

    void Save(Guid keySetId, RootSecret secret);

    /// <summary>Returns null if no credential is stored or it cannot be decrypted.</summary>
    RootSecret? TryLoad(Guid keySetId);

    /// <summary>Stores an arbitrary secret blob (used for backup-only repository keys).</summary>
    void SaveBytes(Guid id, ReadOnlySpan<byte> secret);

    /// <summary>Returns null if nothing is stored or it cannot be decrypted.</summary>
    SecretBuffer? TryLoadBytes(Guid id);

    bool Exists(Guid keySetId);

    void Delete(Guid keySetId);
}

/// <summary>Durability primitives (DESIGN §16, §29).</summary>
public interface IDurableFileOps
{
    /// <summary>Flushes file data all the way to the device (FlushFileBuffers / F_FULLFSYNC).</summary>
    void FlushToDevice(FileStream stream);

    /// <summary>Opens a file for reading, bypassing the OS cache where supported, to verify what is really on the device.</summary>
    Stream OpenForVerification(string path);

    /// <summary>Flushes directory metadata (renames) where the platform supports it.</summary>
    void FlushDirectory(string directory);

    /// <summary>Atomically replaces or moves <paramref name="source"/> to <paramref name="destination"/>.</summary>
    void AtomicMove(string source, string destination, bool overwrite);
}

/// <summary>Metadata of a source file used for change detection and special-file handling.</summary>
public sealed record SourceFileInfo(
    long Size,
    DateTime LastWriteUtc,
    DateTime CreationUtc,
    DateTime? ChangeTimeUtc,
    string? FileId,
    FileAttributes Attributes,
    bool IsLink,
    bool IsCloudPlaceholder,
    int? UnixMode);

public interface IFileMetadataProvider
{
    SourceFileInfo GetInfo(string path, FileSystemInfo? entry = null);
}

/// <summary>A consistent (point-in-time where supported) view of the sources being backed up.</summary>
public interface ISourceView : IDisposable
{
    /// <summary>True if this path is read from a point-in-time snapshot (VSS) rather than the live file.</summary>
    bool IsPointInTimeFor(string originalPath);

    /// <summary>Maps an original absolute path to the path that should actually be read.</summary>
    string MapForReading(string originalPath);
}

public interface ISourceSnapshotProvider
{
    Task<ISourceView> CreateViewAsync(IReadOnlyList<string> sourceRoots, CancellationToken cancellationToken);
}

public interface IPowerManager
{
    IDisposable KeepAwake(string reason);

    bool IsOnBattery { get; }
}

public enum NotificationKind
{
    Success,
    Info,
    Warning,
    Error,
    Integrity,
    WaitingForDrive,
    LowSpace,
}

public interface INotifier
{
    void Notify(string title, string message, NotificationKind kind);
}

/// <summary>Starts the background agent at sign-in (Task Scheduler logon task / LaunchAgent).</summary>
public interface IAutostart
{
    bool IsEnabled { get; }

    void Enable(string agentExecutablePath);

    void Disable();
}

public sealed record VolumeInfo(
    string RootPath,
    string Label,
    string FileSystem,
    long TotalBytes,
    long FreeBytes,
    bool IsRemovable,
    string? VolumeIdentifier);

public interface IVolumeInspector
{
    IReadOnlyList<VolumeInfo> GetVolumes();

    VolumeInfo? GetVolumeForPath(string path);

    /// <summary>Requests a safe eject of the volume. Returns false if the OS refused (files in use).</summary>
    bool TryEject(string rootPath);
}

public interface IClock
{
    DateTimeOffset Now { get; }
}

public sealed class SystemClock : IClock
{
    public static readonly SystemClock Instance = new();

    public DateTimeOffset Now => DateTimeOffset.Now;
}

/// <summary>Reports whether the operating-system session is locked (spec §48).</summary>
public interface ISessionStateMonitor
{
    bool IsSystemLocked();
}

/// <summary>All OS-specific services, selected at runtime for Windows or macOS.</summary>
public sealed record PlatformServices(
    ICredentialStore Credentials,
    IDurableFileOps Durable,
    IFileMetadataProvider Metadata,
    ISourceSnapshotProvider Snapshots,
    IPowerManager Power,
    INotifier Notifier,
    IAutostart Autostart,
    IVolumeInspector Volumes,
    ISessionStateMonitor Session,
    string PlatformName);
