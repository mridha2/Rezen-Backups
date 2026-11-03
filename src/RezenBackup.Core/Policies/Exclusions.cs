using System.Text.RegularExpressions;

namespace RezenBackup.Core.Policies;

public enum ExclusionKind
{
    /// <summary>An exact absolute file path.</summary>
    File = 0,

    /// <summary>An absolute folder path, or a folder name matched anywhere (e.g. <c>node_modules</c>).</summary>
    Folder = 1,

    /// <summary>A file extension such as <c>.tmp</c>.</summary>
    Extension = 2,

    /// <summary>A glob pattern on the file or folder name (<c>*</c>, <c>?</c>).</summary>
    Pattern = 3,
}

public sealed record ExclusionRule(ExclusionKind Kind, string Value, bool IsDefault = false)
{
    public override string ToString() => Kind switch
    {
        ExclusionKind.Extension => "*" + (Value.StartsWith('.') ? Value : "." + Value),
        _ => Value,
    };
}

/// <summary>Evaluates exclusion rules. Every rule is visible to the user; nothing is excluded silently (spec §67).</summary>
public sealed class ExclusionMatcher
{
    private readonly List<string> _filePaths = [];
    private readonly List<string> _folderPaths = [];
    private readonly HashSet<string> _folderNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _extensions = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Regex> _patterns = [];

    public ExclusionMatcher(IEnumerable<ExclusionRule> rules)
    {
        foreach (var rule in rules)
        {
            switch (rule.Kind)
            {
                case ExclusionKind.File:
                    _filePaths.Add(PathPolicy.Normalize(rule.Value));
                    break;
                case ExclusionKind.Folder when Path.IsPathRooted(rule.Value):
                    _folderPaths.Add(PathPolicy.Normalize(rule.Value));
                    break;
                case ExclusionKind.Folder:
                    _folderNames.Add(rule.Value.Trim('/', '\\'));
                    break;
                case ExclusionKind.Extension:
                    _extensions.Add(rule.Value.StartsWith('.') ? rule.Value : "." + rule.Value);
                    break;
                case ExclusionKind.Pattern:
                    _patterns.Add(GlobToRegex(rule.Value));
                    break;
            }
        }
    }

    public static IReadOnlyList<ExclusionRule> Defaults { get; } =
    [
        new(ExclusionKind.Folder, "$RECYCLE.BIN", true),
        new(ExclusionKind.Folder, "System Volume Information", true),
        new(ExclusionKind.Folder, ".Trashes", true),
        new(ExclusionKind.Folder, ".Spotlight-V100", true),
        new(ExclusionKind.Folder, ".fseventsd", true),
        new(ExclusionKind.Pattern, "Thumbs.db", true),
        new(ExclusionKind.Pattern, ".DS_Store", true),
        new(ExclusionKind.Pattern, "~$*", true),
        new(ExclusionKind.Extension, ".tmp", true),
        new(ExclusionKind.Pattern, "pagefile.sys", true),
        new(ExclusionKind.Pattern, "hiberfil.sys", true),
        new(ExclusionKind.Pattern, "swapfile.sys", true),
    ];

    public bool IsExcludedDirectory(string fullPath, string name)
    {
        if (_folderNames.Contains(name) || MatchesPattern(name))
        {
            return true;
        }

        foreach (var p in _folderPaths)
        {
            if (PathPolicy.IsSameOrUnder(fullPath, p))
            {
                return true;
            }
        }

        return false;
    }

    public bool IsExcludedFile(string fullPath, string name)
    {
        if (_extensions.Count > 0 && _extensions.Contains(Path.GetExtension(name)))
        {
            return true;
        }

        if (MatchesPattern(name))
        {
            return true;
        }

        foreach (var f in _filePaths)
        {
            if (string.Equals(f, fullPath, PathPolicy.Comparison))
            {
                return true;
            }
        }

        foreach (var p in _folderPaths)
        {
            if (PathPolicy.IsSameOrUnder(fullPath, p))
            {
                return true;
            }
        }

        return false;
    }

    private bool MatchesPattern(string name)
    {
        foreach (var r in _patterns)
        {
            if (r.IsMatch(name))
            {
                return true;
            }
        }

        return false;
    }

    private static Regex GlobToRegex(string glob)
    {
        var escaped = Regex.Escape(glob).Replace("\\*", ".*", StringComparison.Ordinal).Replace("\\?", ".", StringComparison.Ordinal);
        return new Regex("^" + escaped + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    }
}
