using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Crypto;
using RezenBackup.Format;

namespace RezenBackup.RestoreEngine;

/// <summary>A snapshot as presented in Restore / History after unlocking.</summary>
public sealed record SnapshotSummary(
    Guid SnapshotId,
    string FolderName,
    DateTimeOffset StartedUtc,
    DateTimeOffset CompletedUtc,
    SnapshotValidity Validity,
    SnapshotRecord? Record,
    string? Problem)
{
    public DateTimeOffset LocalTime => StartedUtc.ToLocalTime();

    public bool IsRestorable => Validity == SnapshotValidity.Valid;
}

/// <summary>A location inside a snapshot, independent of the path separator of the OS that made the backup.</summary>
public sealed record CatalogPath(Guid SnapshotId, int SourceIndex, IReadOnlyList<string> Components)
{
    public string Name => Components.Count == 0 ? string.Empty : Components[^1];

    public CatalogPath Child(string name) => this with { Components = [.. Components, name] };

    public CatalogPath? Parent => Components.Count == 0 ? null : this with { Components = Components.Take(Components.Count - 1).ToList() };
}

/// <summary>An entry shown in the restore browser or search results.</summary>
public sealed record CatalogItem(CatalogPath Path, TreeEntry Entry, string OriginalFullPath)
{
    public string Name => Entry.Name;

    public bool IsDirectory => Entry.Kind == EntryKind.Directory;
}

public sealed record FileVersion(SnapshotSummary Snapshot, CatalogItem Item);

public sealed record SearchQuery
{
    /// <summary>Case-insensitive substring of the file or folder name.</summary>
    public string? NameContains { get; init; }

    /// <summary>Case-insensitive substring of the folder path.</summary>
    public string? FolderContains { get; init; }

    /// <summary>Extension with or without the leading dot.</summary>
    public string? Extension { get; init; }

    public DateTime? ModifiedFromUtc { get; init; }

    public DateTime? ModifiedToUtc { get; init; }

    public bool IncludeDirectories { get; init; }

    public int MaxResults { get; init; } = 5000;
}

/// <summary>
/// Unlocked, in-memory view of a repository's snapshots for browsing, search and version history (DESIGN §18.2).
/// Decrypted names exist only in memory; disposing the session (lock / auto-lock) drops them.
/// </summary>
public sealed class CatalogSession : IDisposable
{
    private readonly Repository _repo;
    private readonly Dictionary<ChunkId, TreeNode> _treeCache = [];
    private readonly LinkedList<ChunkId> _treeOrder = new();
    private const int MaxCachedTrees = 20_000;
    private bool _disposed;

    public CatalogSession(Repository repo)
    {
        _repo = repo;
        Snapshots = repo.LoadAllSnapshots()
            .Select(s => new SnapshotSummary(
                s.Record?.SnapshotId ?? Guid.Empty,
                s.Folder.FolderName,
                s.Record?.StartedUtc ?? new DateTimeOffset(s.Folder.Parsed.LocalTime),
                s.Record?.CompletedUtc ?? default,
                s.Validity,
                s.Record,
                s.Problem))
            .OrderByDescending(s => s.StartedUtc)
            .ToList();
    }

    public Repository Repository => _repo;

    public IReadOnlyList<SnapshotSummary> Snapshots { get; }

    public IEnumerable<SnapshotSummary> RestorableSnapshots => Snapshots.Where(s => s.IsRestorable);

    public SnapshotSummary GetSnapshot(Guid id) =>
        Snapshots.FirstOrDefault(s => s.SnapshotId == id && s.IsRestorable) ?? throw new RezenException(ErrorCode.IntegrityFailure, "Snapshot is not available for restore.");

    public TreeNode ReadTree(ChunkId id)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_treeCache.TryGetValue(id, out var node))
        {
            return node;
        }

        node = _repo.ReadTree(id);
        _treeCache[id] = node;
        _treeOrder.AddFirst(id);
        if (_treeOrder.Count > MaxCachedTrees)
        {
            _treeCache.Remove(_treeOrder.Last!.Value);
            _treeOrder.RemoveLast();
        }

        return node;
    }

    /// <summary>The source roots of a snapshot, as top-level browse items.</summary>
    public IReadOnlyList<CatalogItem> Roots(Guid snapshotId)
    {
        var snap = GetSnapshot(snapshotId);
        var result = new List<CatalogItem>();
        for (int i = 0; i < snap.Record!.Sources.Count; i++)
        {
            var src = snap.Record.Sources[i];
            if (src.IsFile)
            {
                var node = ReadTree(src.RootTree);
                foreach (var e in node.Entries)
                {
                    result.Add(new CatalogItem(new CatalogPath(snapshotId, i, []), e, src.OriginalPath));
                }
            }
            else
            {
                var name = LastComponent(src.OriginalPath);
                var entry = new TreeEntry { Name = name, Kind = EntryKind.Directory, Subtree = src.RootTree };
                result.Add(new CatalogItem(new CatalogPath(snapshotId, i, []), entry, src.OriginalPath));
            }
        }

        return result;
    }

    /// <summary>Lists the children of a folder. An empty component list addresses the source root.</summary>
    public IReadOnlyList<CatalogItem> ListChildren(CatalogPath folder)
    {
        var (tree, basePath) = ResolveFolder(folder);
        return tree.Entries.Select(e => new CatalogItem(folder.Child(e.Name), e, Combine(basePath, e.Name))).ToList();
    }

    public CatalogItem? Find(CatalogPath path)
    {
        if (path.Components.Count == 0)
        {
            return Roots(path.SnapshotId).FirstOrDefault(r => r.Path.SourceIndex == path.SourceIndex);
        }

        try
        {
            var parent = path.Parent!;
            var (tree, basePath) = ResolveFolder(parent);
            var entry = tree.Entries.FirstOrDefault(e => e.Name == path.Name);
            return entry is null ? null : new CatalogItem(path, entry, Combine(basePath, entry.Name));
        }
        catch (RezenException)
        {
            return null;
        }
    }

    private (TreeNode Tree, string BasePath) ResolveFolder(CatalogPath folder)
    {
        var snap = GetSnapshot(folder.SnapshotId);
        var src = snap.Record!.Sources[folder.SourceIndex];
        var tree = ReadTree(src.RootTree);
        string basePath = src.IsFile ? ParentOf(src.OriginalPath) : src.OriginalPath;
        foreach (var name in folder.Components)
        {
            var entry = tree.Entries.FirstOrDefault(e => e.Name == name && e.Kind == EntryKind.Directory && e.Subtree is not null)
                ?? throw new RezenException(ErrorCode.IntegrityFailure, "Folder not found in snapshot.");
            tree = ReadTree(entry.Subtree!.Value);
            basePath = Combine(basePath, name);
        }

        return (tree, basePath);
    }

    /// <summary>Searches one snapshot (spec §43). Runs entirely in memory on decrypted trees.</summary>
    public IReadOnlyList<CatalogItem> Search(Guid snapshotId, SearchQuery query, CancellationToken ct = default)
    {
        var results = new List<CatalogItem>();
        string? ext = query.Extension is { Length: > 0 } x ? (x.StartsWith('.') ? x : "." + x) : null;
        foreach (var root in Roots(snapshotId))
        {
            if (root.Path.Components.Count == 0 && root.Entry.Kind == EntryKind.Directory)
            {
                Walk(root.Path, root.OriginalFullPath, root.Entry.Subtree!.Value);
            }
            else if (Matches(root))
            {
                results.Add(root);
            }
        }

        return results;

        void Walk(CatalogPath path, string basePath, ChunkId treeId)
        {
            if (results.Count >= query.MaxResults)
            {
                return;
            }

            ct.ThrowIfCancellationRequested();
            var tree = ReadTree(treeId);
            foreach (var e in tree.Entries)
            {
                var item = new CatalogItem(path.Child(e.Name), e, Combine(basePath, e.Name));
                if (Matches(item) && results.Count < query.MaxResults)
                {
                    results.Add(item);
                }

                if (e.Kind == EntryKind.Directory && e.Subtree is { } st)
                {
                    Walk(item.Path, item.OriginalFullPath, st);
                }
            }
        }

        bool Matches(CatalogItem item)
        {
            var e = item.Entry;
            if (e.Kind == EntryKind.Directory && !query.IncludeDirectories)
            {
                return false;
            }

            if (query.NameContains is { Length: > 0 } n && !e.Name.Contains(n, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (query.FolderContains is { Length: > 0 } f && !ParentOf(item.OriginalFullPath).Contains(f, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (ext is not null && !e.Name.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (query.ModifiedFromUtc is { } from && e.ModifiedUtc < from)
            {
                return false;
            }

            if (query.ModifiedToUtc is { } to && e.ModifiedUtc > to)
            {
                return false;
            }

            return true;
        }
    }

    /// <summary>
    /// All distinct versions of a file across snapshots, newest first (spec §42). Snapshots in which the file is
    /// unchanged are collapsed into the version's earliest appearance.
    /// </summary>
    public IReadOnlyList<FileVersion> VersionsOf(CatalogItem item)
    {
        var snap = GetSnapshot(item.Path.SnapshotId);
        var originalSource = snap.Record!.Sources[item.Path.SourceIndex].OriginalPath;
        var found = new List<FileVersion>();
        foreach (var s in RestorableSnapshots.OrderBy(s => s.StartedUtc))
        {
            int idx = -1;
            for (int i = 0; i < s.Record!.Sources.Count; i++)
            {
                if (string.Equals(s.Record.Sources[i].OriginalPath, originalSource, StringComparison.Ordinal))
                {
                    idx = i;
                    break;
                }
            }

            if (idx < 0)
            {
                continue;
            }

            var candidate = Find(new CatalogPath(s.SnapshotId, idx, item.Path.Components));
            if (candidate is null || candidate.Entry.Kind != item.Entry.Kind)
            {
                continue;
            }

            if (found.Count > 0 && SameContent(found[^1].Item.Entry, candidate.Entry))
            {
                continue;
            }

            found.Add(new FileVersion(s, candidate));
        }

        found.Reverse();
        return found;
    }

    private static bool SameContent(TreeEntry a, TreeEntry b) =>
        a.Kind == EntryKind.File && b.Kind == EntryKind.File && a.Sha256 is not null && b.Sha256 is not null
            ? a.Sha256.AsSpan().SequenceEqual(b.Sha256) && a.ModifiedTicksUtc == b.ModifiedTicksUtc
            : a.Subtree == b.Subtree;

    /// <summary>Total size and file count beneath an item (for restore confirmation).</summary>
    public (long Files, long Bytes) Measure(CatalogItem item)
    {
        if (item.Entry.Kind == EntryKind.File)
        {
            return (1, item.Entry.Size);
        }

        if (item.Entry.Subtree is not { } st)
        {
            return (0, 0);
        }

        long files = 0;
        long bytes = 0;
        var stack = new Stack<ChunkId>();
        stack.Push(st);
        while (stack.Count > 0)
        {
            foreach (var e in ReadTree(stack.Pop()).Entries)
            {
                if (e.Kind == EntryKind.File)
                {
                    files++;
                    bytes += e.Size;
                }
                else if (e.Subtree is { } sub)
                {
                    stack.Push(sub);
                }
            }
        }

        return (files, bytes);
    }

    internal static string LastComponent(string path)
    {
        var trimmed = path.TrimEnd('/', '\\');
        int i = Math.Max(trimmed.LastIndexOf('/'), trimmed.LastIndexOf('\\'));
        var name = i >= 0 ? trimmed[(i + 1)..] : trimmed;
        return name.Length == 0 ? trimmed : name;
    }

    internal static string ParentOf(string path)
    {
        var trimmed = path.TrimEnd('/', '\\');
        int i = Math.Max(trimmed.LastIndexOf('/'), trimmed.LastIndexOf('\\'));
        return i > 0 ? trimmed[..i] : trimmed;
    }

    /// <summary>Joins using the separator style of the original path (backups made on another OS keep their style).</summary>
    internal static string Combine(string basePath, string name)
    {
        char sep = basePath.Contains('\\') && !basePath.Contains('/') ? '\\' : '/';
        if (basePath.Length > 0 && basePath[^1] is '/' or '\\')
        {
            return basePath + name;
        }

        return basePath + sep + name;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _treeCache.Clear();
        _treeOrder.Clear();
        _repo.CloseReaders();
    }
}
