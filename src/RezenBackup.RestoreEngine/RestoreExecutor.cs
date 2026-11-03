using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Policies;
using RezenBackup.Format;

namespace RezenBackup.RestoreEngine;

public enum ConflictChoice
{
    Replace,
    KeepBoth,
    Skip,
}

public sealed record RestoreConflict(string TargetPath, long ExistingSize, DateTime ExistingModifiedUtc, long BackupSize, DateTime BackupModifiedUtc);

public sealed record ConflictResolution(ConflictChoice Choice, bool ApplyToAll);

public sealed record RestoreOptions
{
    /// <summary>Null restores to the original location; otherwise items are recreated under this folder.</summary>
    public string? TargetRoot { get; init; }

    /// <summary>Asked for every existing file unless an "apply to all" answer was given. Never overwrites silently.</summary>
    public required Func<RestoreConflict, ConflictResolution> ResolveConflict { get; init; }

    public bool RestoreTimestamps { get; init; } = true;

    public bool RestoreAttributes { get; init; } = true;
}

public sealed record RestoreProgress(long FilesDone, long FilesTotal, long BytesDone, long BytesTotal, string? CurrentFile);

public sealed record RestoreIssue(string Path, string Message);

public sealed record RestoreReport
{
    public int FilesRestored { get; init; }

    public int FilesSkipped { get; init; }

    public int FilesFailed { get; init; }

    public long BytesRestored { get; init; }

    public IReadOnlyList<RestoreIssue> Issues { get; init; } = [];

    /// <summary>Names changed because they are not valid on this operating system (DESIGN §29).</summary>
    public IReadOnlyList<(string Original, string Restored)> Renamed { get; init; } = [];

    public bool IntegrityFailure { get; init; }
}

/// <summary>
/// Restores files (DESIGN §18.1): every segment is authenticated, each chunk re-identified, and the whole-file SHA-256
/// checked before the restored file is moved into place. Unverified data is never left at the destination.
/// </summary>
public sealed class RestoreExecutor
{
    public const string TempSuffix = ".rzrestore-tmp";

    private readonly CatalogSession _catalog;
    private readonly ILogger _logger;

    public RestoreExecutor(CatalogSession catalog, ILogger? logger = null)
    {
        _catalog = catalog;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>True if the item's original location can be used on this operating system.</summary>
    public static bool CanRestoreToOriginal(CatalogItem item) => Path.IsPathFullyQualified(item.OriginalFullPath) &&
        (OperatingSystem.IsWindows() ? item.OriginalFullPath.Contains('\\') || item.OriginalFullPath.Length >= 2 && item.OriginalFullPath[1] == ':' : item.OriginalFullPath.StartsWith('/'));

    public Task<RestoreReport> RestoreAsync(IReadOnlyList<CatalogItem> items, RestoreOptions options, IProgress<RestoreProgress>? progress = null, CancellationToken ct = default) =>
        Task.Run(() => Restore(items, options, progress, ct), ct);

    private RestoreReport Restore(IReadOnlyList<CatalogItem> items, RestoreOptions options, IProgress<RestoreProgress>? progress, CancellationToken ct)
    {
        long totalFiles = 0;
        long totalBytes = 0;
        foreach (var item in items)
        {
            var (f, b) = _catalog.Measure(item);
            totalFiles += f;
            totalBytes += b;
        }

        var state = new State(options, progress, totalFiles, totalBytes);
        foreach (var item in items)
        {
            ct.ThrowIfCancellationRequested();
            string target = TargetFor(item, options);
            RestoreItem(item.Entry, target, state, ct);
        }

        // Links are created last, so no file of this restore can ever be written through one of them.
        foreach (var (linkPath, linkTarget) in state.PendingLinks)
        {
            CreateLink(linkPath, linkTarget, state);
        }

        progress?.Report(new RestoreProgress(state.FilesDone, totalFiles, state.BytesDone, totalBytes, null));
        return new RestoreReport
        {
            FilesRestored = state.Restored,
            FilesSkipped = state.Skipped,
            FilesFailed = state.Failed,
            BytesRestored = state.BytesDone,
            Issues = state.Issues,
            Renamed = state.Renamed,
            IntegrityFailure = state.IntegrityFailure,
        };
    }

    private static string TargetFor(CatalogItem item, RestoreOptions options)
    {
        if (options.TargetRoot is null)
        {
            if (!CanRestoreToOriginal(item))
            {
                throw new RezenException(ErrorCode.InvalidConfiguration, "This backup was made on a different operating system. Choose another restore location.", null, null);
            }

            return item.OriginalFullPath;
        }

        // Recreate the source folder name and the relative path below the chosen folder.
        var parts = new List<string>();
        var root = Path.GetFullPath(options.TargetRoot);
        // The item's path relative to its source's parent: [sourceName, ...components]
        var sourceName = CatalogSession.LastComponent(SourcePath(item));
        if (!IsFileSourceRoot(item))
        {
            parts.Add(sourceName);
        }

        parts.AddRange(item.Path.Components);
        if (item.Path.Components.Count == 0 && IsFileSourceRoot(item))
        {
            parts.Add(item.Entry.Name);
        }

        return Path.Combine([root, .. parts.Select(SafeName)]);
    }

    private static string SourcePath(CatalogItem item)
    {
        // OriginalFullPath = sourcePath + components; strip the components to get the source path.
        var path = item.OriginalFullPath;
        for (int i = 0; i < item.Path.Components.Count; i++)
        {
            path = CatalogSession.ParentOf(path);
        }

        return path;
    }

    private static bool IsFileSourceRoot(CatalogItem item) => item.Entry.Kind != EntryKind.Directory && item.Path.Components.Count == 0;

    private static string SafeName(string name) => OperatingSystem.IsWindows() ? WindowsNames.MakeValid(name) : name.Replace('/', ':');

    private sealed class State(RestoreOptions options, IProgress<RestoreProgress>? progress, long totalFiles, long totalBytes)
    {
        public RestoreOptions Options { get; } = options;

        public IProgress<RestoreProgress>? Progress { get; } = progress;

        public long TotalFiles { get; } = totalFiles;

        public long TotalBytes { get; } = totalBytes;

        public ConflictChoice? ApplyToAll { get; set; }

        public long FilesDone { get; set; }

        public long BytesDone { get; set; }

        public int Restored { get; set; }

        public int Skipped { get; set; }

        public int Failed { get; set; }

        public bool IntegrityFailure { get; set; }

        public List<RestoreIssue> Issues { get; } = [];

        public List<(string, string)> Renamed { get; } = [];

        public List<(string Path, string Target)> PendingLinks { get; } = [];
    }

    private void RestoreItem(TreeEntry entry, string target, State state, CancellationToken ct)
    {
        switch (entry.Kind)
        {
            case EntryKind.Directory when entry.Subtree is { } st:
                RestoreDirectory(entry, st, target, state, ct);
                break;
            case EntryKind.File:
                RestoreFile(entry, target, state, ct);
                break;
            case EntryKind.Link when entry.LinkTarget is { } linkTarget:
                state.PendingLinks.Add((target, linkTarget));
                break;
        }
    }

    private void RestoreDirectory(TreeEntry entry, Crypto.ChunkId subtree, string target, State state, CancellationToken ct)
    {
        TreeNode tree;
        try
        {
            tree = _catalog.ReadTree(subtree);
        }
        catch (RezenException ex)
        {
            state.IntegrityFailure = true;
            state.Failed++;
            state.Issues.Add(new RestoreIssue(target, UserMessages.IntegrityFailed + " " + ex.TechnicalDetails));
            return;
        }

        if (IsSymbolicLink(target))
        {
            // Never descend into an existing link: it could point outside the restore destination.
            state.Failed++;
            state.Issues.Add(new RestoreIssue(target, "A symbolic link exists here; it was not followed and this folder was not restored."));
            return;
        }

        try
        {
            Directory.CreateDirectory(target);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            state.Failed++;
            state.Issues.Add(new RestoreIssue(target, ex.Message));
            return;
        }

        foreach (var child in tree.Entries)
        {
            ct.ThrowIfCancellationRequested();
            var name = SafeName(child.Name);
            if (!string.Equals(name, child.Name, StringComparison.Ordinal))
            {
                state.Renamed.Add((child.Name, name));
            }

            RestoreItem(child, Path.Combine(target, name), state, ct);
        }

        if (state.Options.RestoreTimestamps)
        {
            TrySetTimes(target, entry, isDirectory: true);
        }
    }

    private void RestoreFile(TreeEntry entry, string target, State state, CancellationToken ct)
    {
        state.Progress?.Report(new RestoreProgress(state.FilesDone, state.TotalFiles, state.BytesDone, state.TotalBytes, entry.Name));
        string finalPath = target;
        bool replace = false;
        if (File.Exists(target) || Directory.Exists(target))
        {
            var choice = state.ApplyToAll;
            if (choice is null)
            {
                var fi = new FileInfo(target);
                var resolution = state.Options.ResolveConflict(new RestoreConflict(target, fi.Exists ? fi.Length : 0, fi.Exists ? fi.LastWriteTimeUtc : default, entry.Size, entry.ModifiedUtc));
                choice = resolution.Choice;
                if (resolution.ApplyToAll)
                {
                    state.ApplyToAll = resolution.Choice;
                }
            }

            switch (choice)
            {
                case ConflictChoice.Skip:
                    state.Skipped++;
                    state.FilesDone++;
                    return;
                case ConflictChoice.KeepBoth:
                    finalPath = KeepBothName(target);
                    break;
                case ConflictChoice.Replace:
                    if (Directory.Exists(target))
                    {
                        state.Failed++;
                        state.Issues.Add(new RestoreIssue(target, "A folder with this name exists; it was not replaced."));
                        return;
                    }

                    replace = true;
                    break;
            }
        }

        var dir = Path.GetDirectoryName(finalPath)!;
        var tmp = Path.Combine(dir, "." + Path.GetFileName(finalPath) + "." + Crypto.CryptoRandom.NextInt(1_000_000).ToString(CultureInfo.InvariantCulture) + TempSuffix);
        try
        {
            Directory.CreateDirectory(dir);
            using (var output = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 20))
            using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                long written = 0;
                foreach (var chunkId in entry.Chunks)
                {
                    ct.ThrowIfCancellationRequested();
                    var data = _catalog.Repository.ReadBlob(chunkId); // authenticated + identifier-checked
                    hash.AppendData(data);
                    output.Write(data);
                    written += data.Length;
                    state.BytesDone += data.Length;
                    CryptographicOperations.ZeroMemory(data);
                    state.Progress?.Report(new RestoreProgress(state.FilesDone, state.TotalFiles, state.BytesDone, state.TotalBytes, entry.Name));
                }

                var digest = hash.GetHashAndReset();
                if (written != entry.Size || entry.Sha256 is null || !CryptographicOperations.FixedTimeEquals(digest, entry.Sha256))
                {
                    throw new RezenException(ErrorCode.IntegrityFailure, "Restored file does not match the hash recorded at backup time.");
                }

                output.Flush(flushToDisk: true);
            }

            File.Move(tmp, finalPath, overwrite: replace);
            if (state.Options.RestoreTimestamps)
            {
                TrySetTimes(finalPath, entry, isDirectory: false);
            }

            if (state.Options.RestoreAttributes)
            {
                TrySetAttributes(finalPath, entry);
            }

            state.Restored++;
        }
        catch (RezenException ex) when (ex.Code == ErrorCode.IntegrityFailure)
        {
            state.IntegrityFailure = true;
            state.Failed++;
            state.Issues.Add(new RestoreIssue(target, UserMessages.IntegrityFailed));
            _logger.LogError("Integrity failure restoring a file: {Detail}", ex.TechnicalDetails);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            state.Failed++;
            state.Issues.Add(new RestoreIssue(target, ex.Message));
        }
        finally
        {
            EncryptedObjects.TryDelete(tmp);
            state.FilesDone++;
        }
    }

    private static bool IsSymbolicLink(string path)
    {
        try
        {
            return new FileInfo(path).LinkTarget is not null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static void CreateLink(string target, string linkTarget, State state)
    {
        if (File.Exists(target) || Directory.Exists(target) || IsSymbolicLink(target))
        {
            state.Skipped++;
            return;
        }

        try
        {
            File.CreateSymbolicLink(target, linkTarget);
            state.Restored++;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            state.Failed++;
            state.Issues.Add(new RestoreIssue(target, "Symbolic link could not be recreated: " + ex.Message));
        }
    }

    internal static string KeepBothName(string target)
    {
        var dir = Path.GetDirectoryName(target)!;
        var stem = Path.GetFileNameWithoutExtension(target);
        var ext = Path.GetExtension(target);
        var date = DateTime.Now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        for (int i = 1; ; i++)
        {
            var suffix = i == 1 ? $" (Restored {date})" : $" (Restored {date} {i})";
            var candidate = Path.Combine(dir, stem + suffix + ext);
            if (!File.Exists(candidate) && !Directory.Exists(candidate))
            {
                return candidate;
            }
        }
    }

    private static void TrySetTimes(string path, TreeEntry entry, bool isDirectory)
    {
        try
        {
            if (entry.ModifiedTicksUtc > 0)
            {
                if (isDirectory)
                {
                    Directory.SetLastWriteTimeUtc(path, entry.ModifiedUtc);
                }
                else
                {
                    File.SetLastWriteTimeUtc(path, entry.ModifiedUtc);
                }
            }

            if (entry.CreatedTicksUtc > 0 && (OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()))
            {
                if (isDirectory)
                {
                    Directory.SetCreationTimeUtc(path, entry.CreatedUtc);
                }
                else
                {
                    File.SetCreationTimeUtc(path, entry.CreatedUtc);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or PlatformNotSupportedException)
        {
        }
    }

    private static void TrySetAttributes(string path, TreeEntry entry)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                const FileAttributes restorable = FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.Archive;
                var attrs = (FileAttributes)entry.Attributes & restorable;
                if (attrs != 0)
                {
                    File.SetAttributes(path, File.GetAttributes(path) | attrs);
                }
            }
            else if (entry.UnixMode is { } mode)
            {
                // Never restore setuid/setgid/sticky bits.
                File.SetUnixFileMode(path, (UnixFileMode)(mode & 0x1FF));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or PlatformNotSupportedException)
        {
        }
    }
}
