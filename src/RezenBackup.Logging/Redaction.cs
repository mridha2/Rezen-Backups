using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace RezenBackup.Logging;

/// <summary>
/// Privacy controls for technical logs (spec §75). With "Hide filenames from logs" (default on), paths are replaced by
/// a keyed hash (<c>path#3f9a12c4</c>) so related entries can be correlated without revealing names.
/// </summary>
public static partial class LogPrivacy
{
    private static byte[] _salt = RandomNumberGenerator.GetBytes(32);

    public static bool HideFileNames { get; set; } = true;

    /// <summary>Per-installation salt so hashes are stable across runs on this PC but meaningless elsewhere.</summary>
    public static void SetSalt(byte[] salt) => _salt = salt;

    public static string Path(string? path)
    {
        if (path is null)
        {
            return "(none)";
        }

        if (!HideFileNames)
        {
            return path;
        }

        var mac = HMACSHA256.HashData(_salt, Encoding.UTF8.GetBytes(path));
        return "path#" + Convert.ToHexStringLower(mac.AsSpan(0, 4));
    }

    // Windows drive paths, UNC paths, and Unix absolute paths under common roots.
    [GeneratedRegex(@"([A-Za-z]:\\[^\s""'<>|*?]+|\\\\[^\s""'<>|*?]+|/(?:Users|Volumes|home|private|tmp|var|mnt|media)/[^\s""'<>|*?]+)", RegexOptions.CultureInvariant)]
    private static partial Regex PathPattern();

    /// <summary>Redacts anything that looks like a path inside free text (exception messages).</summary>
    public static string Scrub(string? text)
    {
        if (string.IsNullOrEmpty(text) || !HideFileNames)
        {
            return text ?? string.Empty;
        }

        return PathPattern().Replace(text, m => Path(m.Value));
    }
}
