namespace RezenBackup.Core.Platform;

/// <summary>Cross-platform metadata baseline. The platform layer adds change time, file IDs and cloud-placeholder flags.</summary>
public class PortableFileMetadataProvider : IFileMetadataProvider
{
    public static readonly PortableFileMetadataProvider Instance = new();

    // Windows cloud-file attributes (OneDrive Files On-Demand) — reading such a file would download it.
    private const FileAttributes RecallOnDataAccess = (FileAttributes)0x00400000;
    private const FileAttributes RecallOnOpen = (FileAttributes)0x00040000;

    public virtual SourceFileInfo GetInfo(string path, FileSystemInfo? entry = null)
    {
        var info = entry ?? new FileInfo(path);
        info.Refresh();
        var attrs = info.Attributes;
        bool isLink = info.LinkTarget is not null;
        bool cloud = (attrs & (RecallOnDataAccess | RecallOnOpen | FileAttributes.Offline)) != 0;
        int? mode = OperatingSystem.IsWindows() ? null : (int)info.UnixFileMode;
        long size = info is FileInfo fi && !isLink ? fi.Length : 0;
        return new SourceFileInfo(size, info.LastWriteTimeUtc, info.CreationTimeUtc, null, null, attrs, isLink, cloud, mode);
    }
}

/// <summary>Reads files in place (no point-in-time snapshot). Used on macOS and when VSS is unavailable.</summary>
public sealed class LiveSourceView : ISourceView
{
    public bool IsPointInTime => false;

    public string MapForReading(string originalPath) => originalPath;

    public void Dispose()
    {
    }
}

public sealed class LiveSourceSnapshotProvider : ISourceSnapshotProvider
{
    public static readonly LiveSourceSnapshotProvider Instance = new();

    public Task<ISourceView> CreateViewAsync(IReadOnlyList<string> sourceRoots, CancellationToken cancellationToken) =>
        Task.FromResult<ISourceView>(new LiveSourceView());
}

public static class FreeSpace
{
    /// <summary>Free bytes on the volume containing <paramref name="path"/> (longest matching mount point).</summary>
    public static long ForPath(string path)
    {
        var full = Path.GetFullPath(path);
        DriveInfo? best = null;
        foreach (var d in DriveInfo.GetDrives())
        {
            try
            {
                if (!d.IsReady)
                {
                    continue;
                }

                var root = d.RootDirectory.FullName;
                if (full.StartsWith(root, StringComparison.OrdinalIgnoreCase) && (best is null || root.Length > best.RootDirectory.FullName.Length))
                {
                    best = d;
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        try
        {
            return best?.AvailableFreeSpace ?? long.MaxValue;
        }
        catch (IOException)
        {
            return long.MaxValue;
        }
    }
}
