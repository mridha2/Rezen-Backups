using System.Globalization;
using System.Text.RegularExpressions;
using RezenBackup.Core.Domain;

namespace RezenBackup.Core.Policies;

/// <summary>Parsed snapshot folder name: <c>YYYY-MM-DD_HH-MM-SS[_N][.incomplete|.deleting]</c> (DESIGN §11).</summary>
public sealed record SnapshotFolderName(string FolderName, DateTime LocalTime, int Sequence, SnapshotState State)
{
    public string BaseName => SnapshotNaming.BaseName(LocalTime, Sequence);
}

public static partial class SnapshotNaming
{
    public const string TimestampFormat = "yyyy-MM-dd_HH-mm-ss";
    public const string IncompleteSuffix = ".incomplete";
    public const string DeletingSuffix = ".deleting";

    [GeneratedRegex(@"^(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})(?:_(\d{1,4}))?(\.incomplete|\.deleting)?$", RegexOptions.CultureInvariant)]
    private static partial Regex Pattern();

    public static string BaseName(DateTime localTime, int sequence = 1)
    {
        string ts = localTime.ToString(TimestampFormat, CultureInfo.InvariantCulture);
        return sequence <= 1 ? ts : ts + "_" + sequence.ToString(CultureInfo.InvariantCulture);
    }

    public static string FolderName(DateTime localTime, int sequence, SnapshotState state) =>
        BaseName(localTime, sequence) + state switch
        {
            SnapshotState.Incomplete => IncompleteSuffix,
            SnapshotState.Deleting => DeletingSuffix,
            _ => string.Empty,
        };

    public static bool TryParse(string folderName, out SnapshotFolderName? parsed)
    {
        parsed = null;
        var m = Pattern().Match(folderName);
        if (!m.Success)
        {
            return false;
        }

        if (!DateTime.TryParseExact(m.Groups[1].Value, TimestampFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out var time))
        {
            return false;
        }

        int seq = m.Groups[2].Success ? int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture) : 1;
        var state = m.Groups[3].Value switch
        {
            IncompleteSuffix => SnapshotState.Incomplete,
            DeletingSuffix => SnapshotState.Deleting,
            _ => SnapshotState.Committed,
        };
        parsed = new SnapshotFolderName(folderName, time, seq, state);
        return true;
    }

    /// <summary>
    /// Picks a base name that does not collide with existing folders in any state (handles the DST fall-back hour
    /// and two runs within the same second).
    /// </summary>
    public static (string BaseName, int Sequence) ChooseUnique(DateTime localTime, IEnumerable<string> existingFolderNames)
    {
        var taken = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in existingFolderNames)
        {
            if (TryParse(name, out var p) && p is not null)
            {
                taken.Add(p.BaseName);
            }
        }

        var truncated = new DateTime(localTime.Year, localTime.Month, localTime.Day, localTime.Hour, localTime.Minute, localTime.Second, DateTimeKind.Unspecified);
        for (int seq = 1; seq < 10_000; seq++)
        {
            var candidate = BaseName(truncated, seq);
            if (!taken.Contains(candidate))
            {
                return (candidate, seq);
            }
        }

        throw new InvalidOperationException("Unable to choose a unique snapshot folder name.");
    }
}
