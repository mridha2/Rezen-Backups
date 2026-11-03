using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Platform;
using RezenBackup.Core.Policies;
using RezenBackup.Format;

namespace RezenBackup.Application;

public enum ValidationSeverity
{
    Info,
    Warning,
    Blocking,
}

public sealed record ValidationMessage(ValidationSeverity Severity, string Message);

public sealed record DestinationCandidate(VolumeInfo Volume, Guid? RegisteredDriveId, bool HasRezenBackups);

/// <summary>Backup destination discovery, validation (spec §72) and registration (spec §32).</summary>
public sealed class DriveService
{
    private readonly RezenApp _app;

    internal DriveService(RezenApp app) => _app = app;

    public IReadOnlyList<DestinationCandidate> Candidates()
    {
        var registered = _app.Db.Drives().ToDictionary(d => d.Id);
        return _app.Platform.Volumes.GetVolumes()
            .Where(v => !IsSystemRoot(v.RootPath))
            .Select(v =>
            {
                var marker = DriveMarker.TryRead(v.RootPath);
                return new DestinationCandidate(v, marker is not null && registered.ContainsKey(marker.DriveId) ? marker.DriveId : null, marker is not null);
            })
            .OrderByDescending(c => c.Volume.IsRemovable)
            .ToList();
    }

    private static bool IsSystemRoot(string root) =>
        root == "/" || (OperatingSystem.IsWindows() && string.Equals(Path.GetPathRoot(Environment.SystemDirectory), root, StringComparison.OrdinalIgnoreCase));

    /// <summary>Validates a destination root (a volume root, or any folder used as a "secondary local drive").</summary>
    public IReadOnlyList<ValidationMessage> Validate(string destinationRoot, IReadOnlyList<string> sources, long estimatedBytes = 0)
    {
        var messages = new List<ValidationMessage>();
        if (!Directory.Exists(destinationRoot))
        {
            messages.Add(new(ValidationSeverity.Blocking, "The destination is not connected or does not exist."));
            return messages;
        }

        var backupRoot = RepositoryLayout.BackupRootOnVolume(destinationRoot);
        if (PathPolicy.FindRecursiveSource(backupRoot, sources) is { } recursive)
        {
            messages.Add(new(ValidationSeverity.Blocking, $"The backup destination is inside the source folder \"{recursive}\". This would back up the backup."));
        }

        try
        {
            Directory.CreateDirectory(backupRoot);
            var probe = Path.Combine(backupRoot, ".write-test-" + Crypto.CryptoRandom.NewId().ToString("N"));
            File.WriteAllBytes(probe, [1, 2, 3]);
            File.Delete(probe);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            messages.Add(new(ValidationSeverity.Blocking, "Rezen Backup cannot write to this destination."));
        }

        var volume = _app.Platform.Volumes.GetVolumeForPath(destinationRoot);
        var fs = (volume?.FileSystem ?? string.Empty).ToUpperInvariant();
        if (fs.Contains("FAT32", StringComparison.Ordinal) || fs is "FAT" or "MSDOS" || fs.Contains("MS-DOS", StringComparison.Ordinal))
        {
            messages.Add(new(ValidationSeverity.Blocking, "FAT32 drives are not supported. Reformat the drive as NTFS (Windows) or APFS (Mac), or exFAT to use it with both."));
        }
        else if (fs.Contains("EXFAT", StringComparison.Ordinal))
        {
            messages.Add(new(ValidationSeverity.Warning, "exFAT has no journal. Always eject the drive safely; NTFS (Windows) or APFS (Mac) is more robust."));
        }
        else if (OperatingSystem.IsMacOS() && fs.Contains("NTFS", StringComparison.Ordinal))
        {
            messages.Add(new(ValidationSeverity.Blocking, "macOS cannot write to NTFS drives. Use an APFS or exFAT drive."));
        }

        foreach (var source in sources)
        {
            var sv = _app.Platform.Volumes.GetVolumeForPath(source);
            if (sv is not null && volume is not null && string.Equals(sv.RootPath, volume.RootPath, StringComparison.OrdinalIgnoreCase))
            {
                messages.Add(new(ValidationSeverity.Warning, "The destination is on the same disk as your files. This won't protect you if that disk fails."));
                break;
            }
        }

        long free = volume?.FreeBytes ?? FreeSpace.ForPath(destinationRoot);
        if (estimatedBytes > 0 && free < estimatedBytes + (512L * 1024 * 1024))
        {
            messages.Add(new(ValidationSeverity.Warning, $"The destination may not have enough free space ({Fmt.Bytes(free)} free, about {Fmt.Bytes(estimatedBytes)} needed)."));
        }

        return messages;
    }

    /// <summary>Registers a drive: writes the non-secret marker and records its identity.</summary>
    public DriveRecord Register(string destinationRoot)
    {
        var volume = _app.Platform.Volumes.GetVolumeForPath(destinationRoot);
        var marker = DriveMarker.Create(destinationRoot, volume?.Label);
        var record = new DriveRecord
        {
            Id = marker.DriveId,
            Label = string.IsNullOrWhiteSpace(volume?.Label) ? Path.GetFileName(destinationRoot.TrimEnd('/', '\\')) : volume.Label,
            VolumeIdentifier = volume?.VolumeIdentifier,
            FileSystem = volume?.FileSystem ?? "unknown",
            CapacityBytes = volume?.TotalBytes ?? 0,
            LastSeenUtc = DateTimeOffset.UtcNow,
            LastMountPath = destinationRoot,
        };
        _app.Db.UpsertDrive(record);
        return record;
    }

    /// <summary>Current mount path of a registered drive, or null when disconnected.</summary>
    public string? MountPath(Guid driveId)
    {
        var connected = _app.ConnectedDrives();
        if (!connected.TryGetValue(driveId, out var d))
        {
            return null;
        }

        var record = _app.Db.Drive(driveId);
        if (record is not null && record.LastMountPath != d.MountPath)
        {
            _app.Db.UpsertDrive(record with { LastMountPath = d.MountPath, LastSeenUtc = DateTimeOffset.UtcNow });
        }

        return d.MountPath;
    }
}

public static class Fmt
{
    public static string Bytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB", "PB"];
        double v = bytes;
        int u = 0;
        while (v >= 1000 && u < units.Length - 1)
        {
            v /= 1000;
            u++;
        }

        return u == 0 ? $"{bytes} B" : $"{v:0.#} {units[u]}";
    }

    public static string Duration(TimeSpan d) =>
        d.TotalHours >= 1 ? $"{(int)d.TotalHours}h {d.Minutes}m" :
        d.TotalMinutes >= 1 ? $"{d.Minutes}m {d.Seconds:00}s" :
        $"{Math.Max(0, d.Seconds)}s";

    public static string When(DateTimeOffset? t)
    {
        if (t is not { } v)
        {
            return "Never";
        }

        var local = v.ToLocalTime();
        var today = DateTime.Today;
        string time = local.ToString("h:mm tt", System.Globalization.CultureInfo.CurrentCulture);
        if (local.Date == today)
        {
            return "Today, " + time;
        }

        if (local.Date == today.AddDays(-1))
        {
            return "Yesterday, " + time;
        }

        if (local.Date == today.AddDays(1))
        {
            return "Tomorrow, " + time;
        }

        return local.ToString("MMM d, yyyy", System.Globalization.CultureInfo.CurrentCulture) + ", " + time;
    }
}
