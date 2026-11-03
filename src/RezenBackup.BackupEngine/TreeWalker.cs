using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Platform;
using RezenBackup.Core.Policies;
using RezenBackup.Crypto;
using RezenBackup.Format;

namespace RezenBackup.BackupEngine;

/// <summary>A file whose contents were read in this run (verified end-to-end by Full verification).</summary>
internal sealed record FileReadRecord(IReadOnlyList<ChunkId> Chunks, byte[] Sha256, long Size);

/// <summary>Progress bookkeeping with throttled reporting.</summary>
internal sealed class ProgressTracker
{
    private readonly IProgress<BackupProgress>? _sink;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private long _lastReportMs = -1000;

    public ProgressTracker(IProgress<BackupProgress>? sink) => _sink = sink;

    public BackupPhase Phase { get; set; }

    public long FilesTotal { get; set; }

    public long BytesTotal { get; set; }

    public long FilesDone { get; set; }

    public long BytesDone { get; set; }

    public string? CurrentFile { get; set; }

    public bool Paused { get; set; }

    private long _bytesAtPhaseStart;
    private long _phaseStartMs;

    public void StartPhase(BackupPhase phase)
    {
        Phase = phase;
        _bytesAtPhaseStart = BytesDone;
        _phaseStartMs = _clock.ElapsedMilliseconds;
        Report(force: true);
    }

    public void Report(bool force = false)
    {
        if (_sink is null)
        {
            return;
        }

        long now = _clock.ElapsedMilliseconds;
        if (!force && now - _lastReportMs < 200)
        {
            return;
        }

        _lastReportMs = now;
        double seconds = Math.Max(0.001, (now - _phaseStartMs) / 1000.0);
        double rate = (BytesDone - _bytesAtPhaseStart) / seconds;
        TimeSpan? eta = rate > 1 && BytesTotal > BytesDone && Phase == BackupPhase.Encrypting
            ? TimeSpan.FromSeconds((BytesTotal - BytesDone) / rate)
            : null;
        _sink.Report(new BackupProgress
        {
            Phase = Phase,
            FilesTotal = FilesTotal,
            FilesDone = FilesDone,
            BytesTotal = BytesTotal,
            BytesDone = BytesDone,
            CurrentFile = CurrentFile,
            BytesPerSecond = rate,
            EstimatedRemaining = eta,
            Paused = Paused,
        });
    }
}

/// <summary>
/// Walks the sources depth-first, building encrypted tree objects bottom-up. Files are compared with the previous
/// snapshot and only re-read when changed (DESIGN §13.2). Source files are opened read-only and never modified
/// (spec §70).
/// </summary>
internal sealed class TreeWalker
{
    private const int SharingViolation = unchecked((int)0x80070020);
    private const int LockViolation = unchecked((int)0x80070021);

    private readonly Repository _repo;
    private readonly SnapshotWriter _writer;
    private readonly FastCdc _cdc;
    private readonly BackupOptions _options;
    private readonly IFileMetadataProvider _meta;
    private readonly ISourceView _view;
    private readonly ExclusionMatcher _exclusions;
    private readonly ProgressTracker _progress;
    private readonly PauseGate _pause;
    private readonly ILogger _logger;
    private readonly Guid? _previousSnapshotId;
    private readonly CancellationToken _ct;

    public TreeWalker(
        Repository repo,
        SnapshotWriter writer,
        FastCdc cdc,
        BackupOptions options,
        IFileMetadataProvider meta,
        ISourceView view,
        ProgressTracker progress,
        PauseGate pause,
        ILogger logger,
        Guid? previousSnapshotId,
        CancellationToken ct)
    {
        _repo = repo;
        _writer = writer;
        _cdc = cdc;
        _options = options;
        _meta = meta;
        _view = view;
        _exclusions = new ExclusionMatcher(options.Exclusions);
        _progress = progress;
        _pause = pause;
        _logger = logger;
        _previousSnapshotId = previousSnapshotId;
        _ct = ct;
    }

    public List<SnapshotWarning> Warnings { get; } = [];

    public HashSet<ChunkId> Referenced { get; } = [];

    public List<FileReadRecord> FilesRead { get; } = [];

    public long Files { get; private set; }

    public long Directories { get; private set; }

    public long BytesScanned { get; private set; }

    public long FilesNew { get; private set; }

    public long FilesChanged { get; private set; }

    public long FilesUnchanged { get; private set; }

    /// <summary>Counts files and bytes so progress can show "2,431 / 7,822".</summary>
    public (long Files, long Bytes) PreScan(IEnumerable<string> sources)
    {
        long files = 0;
        long bytes = 0;
        var stack = new Stack<string>();
        foreach (var s in sources)
        {
            if (File.Exists(s))
            {
                files++;
                bytes += SafeLength(s);
            }
            else if (Directory.Exists(s))
            {
                stack.Push(s);
            }
        }

        var opts = new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = false, AttributesToSkip = 0, ReturnSpecialDirectories = false };
        while (stack.Count > 0)
        {
            _ct.ThrowIfCancellationRequested();
            var dir = stack.Pop();
            IEnumerable<FileSystemInfo> entries;
            try
            {
                entries = new DirectoryInfo(dir).EnumerateFileSystemInfos("*", opts).ToList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var e in entries)
            {
                if (e.LinkTarget is not null)
                {
                    continue;
                }

                if (e is DirectoryInfo d)
                {
                    if (!_exclusions.IsExcludedDirectory(d.FullName, d.Name))
                    {
                        stack.Push(d.FullName);
                    }
                }
                else if (e is FileInfo f && !_exclusions.IsExcludedFile(f.FullName, f.Name))
                {
                    files++;
                    try
                    {
                        bytes += f.Length;
                    }
                    catch (IOException)
                    {
                    }
                }
            }

            _progress.FilesTotal = files;
            _progress.BytesTotal = bytes;
            _progress.Report();
        }

        return (files, bytes);
    }

    private static long SafeLength(string path)
    {
        try
        {
            return new FileInfo(path).Length;
        }
        catch (IOException)
        {
            return 0;
        }
    }

    public SnapshotSource? ProcessSource(string source, SnapshotSource? previous)
    {
        var normalized = PathPolicy.Normalize(source);
        TreeNode? prevTree = previous is null ? null : TryReadTree(previous.RootTree);

        if (File.Exists(normalized))
        {
            var fi = new FileInfo(normalized);
            var prevEntry = previous is { IsFile: true } ? prevTree?.Entries.FirstOrDefault(e => e.Name == fi.Name) : null;
            var entry = ProcessFile(fi, prevEntry);
            var node = new TreeNode(entry is null ? [] : [entry]);
            var id = _writer.AddTree(node);
            Referenced.Add(id);
            return new SnapshotSource(normalized, id, IsFile: true);
        }

        if (!Directory.Exists(normalized))
        {
            Warn(normalized, IssueKind.SourceMissing, null);
            return null;
        }

        var rootId = ProcessDirectory(new DirectoryInfo(normalized), previous is { IsFile: false } ? prevTree : null);
        return rootId is { } r ? new SnapshotSource(normalized, r) : null;
    }

    private ChunkId? ProcessDirectory(DirectoryInfo dir, TreeNode? previous)
    {
        _ct.ThrowIfCancellationRequested();
        List<FileSystemInfo> children;
        try
        {
            var opts = new EnumerationOptions { IgnoreInaccessible = false, RecurseSubdirectories = false, AttributesToSkip = 0, ReturnSpecialDirectories = false };
            children = dir.EnumerateFileSystemInfos("*", opts).ToList();
        }
        catch (UnauthorizedAccessException ex)
        {
            Warn(dir.FullName, IssueKind.PermissionDenied, ex.Message);
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            Warn(dir.FullName, IssueKind.NotFound, null);
            return null;
        }
        catch (IOException ex)
        {
            Warn(dir.FullName, IssueKind.ReadError, ex.Message);
            return null;
        }

        var prevByName = previous?.Entries.ToDictionary(e => e.Name, StringComparer.Ordinal) ?? [];
        var entries = new List<TreeEntry>(children.Count);
        foreach (var child in children.OrderBy(c => c.Name, StringComparer.Ordinal))
        {
            _pause.WaitIfPaused(_ct);
            prevByName.TryGetValue(child.Name, out var prevEntry);
            TreeEntry? entry;
            if (child.LinkTarget is not null)
            {
                entry = LinkEntry(child);
            }
            else if (child is DirectoryInfo sub)
            {
                if (_exclusions.IsExcludedDirectory(sub.FullName, sub.Name))
                {
                    continue;
                }

                entry = DirectoryEntry(sub, prevEntry);
            }
            else if (child is FileInfo file)
            {
                if (_exclusions.IsExcludedFile(file.FullName, file.Name))
                {
                    continue;
                }

                entry = ProcessFile(file, prevEntry);
            }
            else
            {
                entry = null;
            }

            if (entry is not null)
            {
                entries.Add(entry);
            }
        }

        var node = new TreeNode(entries);
        var id = _writer.AddTree(node);
        Referenced.Add(id);
        return id;
    }

    private TreeEntry? DirectoryEntry(DirectoryInfo sub, TreeEntry? prevEntry)
    {
        TreeNode? prevSubtree = prevEntry is { Kind: EntryKind.Directory, Subtree: { } st } ? TryReadTree(st) : null;
        var subId = ProcessDirectory(sub, prevSubtree);
        if (subId is null)
        {
            // Could not list the folder: keep the previous version, clearly flagged (never silently dropped).
            if (prevEntry is { Kind: EntryKind.Directory, Subtree: { } prev } && _writer.IsStored(prev))
            {
                MarkReferencedTree(prev);
                return prevEntry with { Status = EntryStatus.CarriedForward, CarriedFromSnapshot = prevEntry.CarriedFromSnapshot ?? _previousSnapshotId };
            }

            return null;
        }

        Directories++;
        var info = SafeInfo(sub.FullName, sub);
        return new TreeEntry
        {
            Name = sub.Name,
            Kind = EntryKind.Directory,
            Subtree = subId,
            ModifiedTicksUtc = info?.LastWriteUtc.Ticks ?? 0,
            CreatedTicksUtc = info?.CreationUtc.Ticks ?? 0,
            ChangeTicksUtc = info?.ChangeTimeUtc?.Ticks,
            Attributes = (int)(info?.Attributes ?? FileAttributes.Directory),
            UnixMode = info?.UnixMode,
        };
    }

    private TreeEntry LinkEntry(FileSystemInfo link)
    {
        var info = SafeInfo(link.FullName, link);
        return new TreeEntry
        {
            Name = link.Name,
            Kind = EntryKind.Link,
            LinkTarget = link.LinkTarget,
            ModifiedTicksUtc = info?.LastWriteUtc.Ticks ?? 0,
            CreatedTicksUtc = info?.CreationUtc.Ticks ?? 0,
            Attributes = (int)(info?.Attributes ?? 0),
            UnixMode = info?.UnixMode,
        };
    }

    private SourceFileInfo? SafeInfo(string path, FileSystemInfo? entry)
    {
        try
        {
            return _meta.GetInfo(path, entry);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private TreeEntry? ProcessFile(FileInfo file, TreeEntry? previous)
    {
        _progress.CurrentFile = file.Name;
        SourceFileInfo info;
        try
        {
            // With a point-in-time view, metadata must come from the same snapshot as the content that is read.
            info = _view.IsPointInTimeFor(file.FullName)
                ? _meta.GetInfo(_view.MapForReading(file.FullName))
                : _meta.GetInfo(file.FullName, file);
        }
        catch (FileNotFoundException)
        {
            return null; // deleted between listing and reading
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return CarryForwardOrWarn(file, previous, IssueKind.ReadError, ex.Message);
        }

        if (info.IsCloudPlaceholder)
        {
            // Reading would trigger a cloud download — never do that in an offline product (DESIGN §1.4).
            return CarryForwardOrWarn(file, previous, IssueKind.OnlineOnlyCloudFile, null);
        }

        Files++;
        BytesScanned += info.Size;

        if (_options.Method == BackupMethod.Incremental && IsUnchanged(info, previous))
        {
            FilesUnchanged++;
            foreach (var c in previous!.Chunks)
            {
                Referenced.Add(c);
            }

            _progress.FilesDone++;
            _progress.BytesDone += info.Size;
            _progress.Report();
            return previous with
            {
                Name = file.Name,
                Status = previous.Status == EntryStatus.CarriedForward ? EntryStatus.Ok : previous.Status,
                CarriedFromSnapshot = null,
            };
        }

        var result = ReadFile(file, info);
        _progress.FilesDone++;
        _progress.Report();
        if (result.Entry is null)
        {
            Files--;
            BytesScanned -= info.Size;
            return CarryForwardOrWarn(file, previous, result.Issue, result.Detail);
        }

        if (previous is null)
        {
            FilesNew++;
        }
        else
        {
            FilesChanged++;
        }

        return result.Entry;
    }

    private bool IsUnchanged(SourceFileInfo info, TreeEntry? previous)
    {
        if (previous is not { Kind: EntryKind.File } || previous.Status is EntryStatus.ChangedDuringBackup or EntryStatus.Unreadable || previous.Sha256 is null)
        {
            return false;
        }

        if (previous.Size != info.Size || previous.ModifiedTicksUtc != info.LastWriteUtc.Ticks)
        {
            return false;
        }

        if (previous.ChangeTicksUtc is { } pc && info.ChangeTimeUtc is { } ic && pc != ic.Ticks)
        {
            return false;
        }

        if (previous.FileId is { } pf && info.FileId is { } f && !string.Equals(pf, f, StringComparison.Ordinal))
        {
            return false;
        }

        // Only reuse if every referenced chunk is still present in the repository.
        foreach (var c in previous.Chunks)
        {
            if (!_writer.IsStored(c))
            {
                return false;
            }
        }

        return true;
    }

    private readonly record struct ReadOutcome(TreeEntry? Entry, IssueKind Issue, string? Detail);

    private ReadOutcome ReadFile(FileInfo file, SourceFileInfo before)
    {
        var readPath = _view.MapForReading(file.FullName);
        bool pointInTime = _view.IsPointInTimeFor(file.FullName);
        for (int attempt = 0; ; attempt++)
        {
            var chunks = new List<ChunkId>();
            byte[] sha;
            long size = 0;
            long bytesBefore = _progress.BytesDone;
            try
            {
                using var stream = new FileStream(readPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 20, FileOptions.SequentialScan);
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                _cdc.Split(stream, chunk =>
                {
                    _pause.WaitIfPaused(_ct);
                    hash.AppendData(chunk);
                    var id = _repo.Keys.ComputeChunkId(chunk);
                    _writer.AddData(id, chunk);
                    chunks.Add(id);
                    size += chunk.Length;
                    _progress.BytesDone += chunk.Length;
                    _progress.Report();
                }, _ct);
                sha = hash.GetHashAndReset();
            }
            catch (FileNotFoundException)
            {
                return new ReadOutcome(null, IssueKind.NotFound, null);
            }
            catch (DirectoryNotFoundException)
            {
                return new ReadOutcome(null, IssueKind.NotFound, null);
            }
            catch (UnauthorizedAccessException ex)
            {
                return new ReadOutcome(null, IssueKind.PermissionDenied, ex.Message);
            }
            catch (PathTooLongException ex)
            {
                return new ReadOutcome(null, IssueKind.PathTooLong, ex.Message);
            }
            catch (IOException ex) when (ex is not EndOfStreamException)
            {
                bool locked = ex.HResult is SharingViolation or LockViolation;
                if (locked && attempt < _options.MaxRetriesOnChange)
                {
                    Thread.Sleep(200 * (attempt + 1));
                    continue;
                }

                return new ReadOutcome(null, locked ? IssueKind.Locked : IssueKind.ReadError, ex.Message);
            }

            SourceFileInfo after;
            try
            {
                after = _meta.GetInfo(pointInTime ? readPath : file.FullName);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return new ReadOutcome(null, IssueKind.NotFound, ex.Message);
            }

            bool stable = (pointInTime && after.Size == size && after.LastWriteUtc == before.LastWriteUtc) || (after.Size == size && after.LastWriteUtc == before.LastWriteUtc && after.ChangeTimeUtc == before.ChangeTimeUtc && before.Size == size);
            if (!stable && attempt < _options.MaxRetriesOnChange)
            {
                _progress.BytesDone = bytesBefore;
                Thread.Sleep(250 * (attempt + 1));
                before = after;
                continue;
            }

            foreach (var c in chunks)
            {
                Referenced.Add(c);
            }

            var status = stable ? EntryStatus.Ok : EntryStatus.ChangedDuringBackup;
            if (!stable)
            {
                Warn(file.FullName, IssueKind.ChangedDuringBackup, null);
            }

            FilesRead.Add(new FileReadRecord(chunks, sha, size));
            return new ReadOutcome(
                new TreeEntry
                {
                    Name = file.Name,
                    Kind = EntryKind.File,
                    Size = size,
                    ModifiedTicksUtc = before.LastWriteUtc.Ticks,
                    CreatedTicksUtc = before.CreationUtc.Ticks,
                    ChangeTicksUtc = before.ChangeTimeUtc?.Ticks,
                    Attributes = (int)before.Attributes,
                    UnixMode = before.UnixMode,
                    Status = status,
                    Sha256 = sha,
                    Chunks = chunks,
                    FileId = before.FileId,
                },
                IssueKind.ReadError,
                null);
        }
    }

    private TreeEntry? CarryForwardOrWarn(FileInfo file, TreeEntry? previous, IssueKind issue, string? detail)
    {
        if (issue == IssueKind.NotFound)
        {
            return null;
        }

        Warn(file.FullName, issue, detail);
        if (previous is { Kind: EntryKind.File } && previous.Chunks.All(_writer.IsStored))
        {
            foreach (var c in previous.Chunks)
            {
                Referenced.Add(c);
            }

            Files++;
            BytesScanned += previous.Size;
            return previous with
            {
                Name = file.Name,
                Status = EntryStatus.CarriedForward,
                StatusDetail = issue.ToDisplay(),
                CarriedFromSnapshot = previous.CarriedFromSnapshot ?? _previousSnapshotId,
            };
        }

        return null;
    }

    private void MarkReferencedTree(ChunkId treeId)
    {
        Referenced.Add(treeId);
        var node = TryReadTree(treeId);
        if (node is null)
        {
            return;
        }

        foreach (var e in node.Entries)
        {
            foreach (var c in e.Chunks)
            {
                Referenced.Add(c);
            }

            if (e.Subtree is { } st)
            {
                MarkReferencedTree(st);
            }
        }
    }

    private TreeNode? TryReadTree(ChunkId id)
    {
        try
        {
            return _repo.ReadTree(id);
        }
        catch (RezenException ex)
        {
            _logger.LogWarning("Previous tree {TreeId} unavailable: {Message}", id, ex.Message);
            return null;
        }
        catch (CryptoException ex)
        {
            _logger.LogWarning("Previous tree {TreeId} invalid: {Message}", id, ex.Message);
            return null;
        }
    }

    private void Warn(string path, IssueKind kind, string? detail)
    {
        Warnings.Add(new SnapshotWarning(path, kind, detail));
    }
}
