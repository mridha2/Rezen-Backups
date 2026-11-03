namespace RezenBackup.Core.Policies;

public enum SourceOverlapKind
{
    None,
    Duplicate,
    NewIsInsideExisting,
    NewContainsExisting,
}

public sealed record SourceOverlap(SourceOverlapKind Kind, string ExistingSource);

/// <summary>Path safety rules: overlapping sources (spec §29) and recursive destinations (spec §71).</summary>
public static class PathPolicy
{
    /// <summary>Windows and default macOS volumes are case-insensitive; compare conservatively.</summary>
    public static StringComparison Comparison => StringComparison.OrdinalIgnoreCase;

    public static string Normalize(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full) ?? string.Empty;
        if (full.Length > root.Length)
        {
            full = full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }

        return full;
    }

    public static bool IsSameOrUnder(string candidate, string parent)
    {
        var c = Normalize(candidate);
        var p = Normalize(parent);
        if (string.Equals(c, p, Comparison))
        {
            return true;
        }

        var prefix = p.EndsWith(Path.DirectorySeparatorChar) ? p : p + Path.DirectorySeparatorChar;
        return c.StartsWith(prefix, Comparison);
    }

    public static SourceOverlap CheckNewSource(string newSource, IEnumerable<string> existingSources)
    {
        foreach (var existing in existingSources)
        {
            if (string.Equals(Normalize(existing), Normalize(newSource), Comparison))
            {
                return new SourceOverlap(SourceOverlapKind.Duplicate, existing);
            }

            if (IsSameOrUnder(newSource, existing))
            {
                return new SourceOverlap(SourceOverlapKind.NewIsInsideExisting, existing);
            }

            if (IsSameOrUnder(existing, newSource))
            {
                return new SourceOverlap(SourceOverlapKind.NewContainsExisting, existing);
            }
        }

        return new SourceOverlap(SourceOverlapKind.None, string.Empty);
    }

    /// <summary>
    /// Returns the first source that would recursively include the destination, or null when safe.
    /// A destination inside a source would back up the backup (spec §71).
    /// </summary>
    public static string? FindRecursiveSource(string destinationRoot, IEnumerable<string> sources)
    {
        foreach (var source in sources)
        {
            if (IsSameOrUnder(destinationRoot, source) || IsSameOrUnder(source, destinationRoot))
            {
                return source;
            }
        }

        return null;
    }

    /// <summary>Makes a single path component safe for use as a folder name on both Windows and macOS.</summary>
    public static string SafeFolderName(string name)
    {
        var invalid = new HashSet<char>("<>:\"/\\|?*");
        var chars = name.Trim().Select(c => invalid.Contains(c) || char.IsControl(c) ? '_' : c).ToArray();
        var result = new string(chars).TrimEnd('.', ' ');
        if (result.Length == 0)
        {
            result = "Backup";
        }

        if (WindowsNames.IsReserved(result))
        {
            result = "_" + result;
        }

        return result.Length > 100 ? result[..100] : result;
    }
}

/// <summary>Restoring macOS-created names onto Windows (DESIGN §29).</summary>
public static class WindowsNames
{
    private static readonly HashSet<string> Reserved = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    public static bool IsReserved(string name)
    {
        var stem = name.Split('.')[0];
        return Reserved.Contains(stem);
    }

    /// <summary>Returns a Windows-valid version of a file name, or the same instance if it is already valid.</summary>
    public static string MakeValid(string name)
    {
        bool changed = false;
        var chars = name.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            char replacement = c switch
            {
                '<' => '＜',
                '>' => '＞',
                ':' => '：',
                '"' => '＂',
                '|' => '｜',
                '?' => '？',
                '*' => '＊',
                '\\' => '＼',
                _ => char.IsControl(c) ? '_' : c,
            };
            if (replacement != c)
            {
                chars[i] = replacement;
                changed = true;
            }
        }

        var result = changed ? new string(chars) : name;
        if (result.EndsWith('.') || result.EndsWith(' '))
        {
            result = result.TrimEnd('.', ' ') + "_";
            changed = true;
        }

        if (IsReserved(result))
        {
            result = "_" + result;
            changed = true;
        }

        return changed ? result : name;
    }
}
