using System.Text.Json;
using System.Text.Json.Serialization;

namespace RezenBackup.Format;

/// <summary>
/// Non-secret drive marker at <c>&lt;volume&gt;/Rezen Backup/.rezenbackup</c> (spec §32). Contains no password,
/// key or recovery key — only an identifier that lets Rezen recognise the drive under any drive letter or mount point.
/// </summary>
public sealed record DriveMarker
{
    public const string FileName = ".rezenbackup";
    public const string FormatName = "Rezen Backup Drive Marker v1";

    [JsonPropertyName("format")]
    public string Format { get; init; } = FormatName;

    [JsonPropertyName("formatVersion")]
    public int FormatVersion { get; init; } = 1;

    [JsonPropertyName("driveId")]
    public Guid DriveId { get; init; }

    [JsonPropertyName("createdUtc")]
    public DateTimeOffset CreatedUtc { get; init; }

    [JsonPropertyName("label")]
    public string? Label { get; init; }

    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public static string PathOnVolume(string volumeRoot) => Path.Combine(RepositoryLayout.BackupRootOnVolume(volumeRoot), FileName);

    public static DriveMarker? TryRead(string volumeRoot)
    {
        var path = PathOnVolume(volumeRoot);
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            var info = new FileInfo(path);
            if (info.Length > 64 * 1024)
            {
                return null;
            }

            var marker = JsonSerializer.Deserialize<DriveMarker>(File.ReadAllText(path), Options);
            return marker is { DriveId: var id, Format: FormatName } && id != Guid.Empty ? marker : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    public static DriveMarker Create(string volumeRoot, string? label)
    {
        var existing = TryRead(volumeRoot);
        if (existing is not null)
        {
            return existing;
        }

        var marker = new DriveMarker
        {
            DriveId = Crypto.CryptoRandom.NewId(),
            CreatedUtc = DateTimeOffset.UtcNow,
            Label = label,
        };
        Directory.CreateDirectory(RepositoryLayout.BackupRootOnVolume(volumeRoot));
        var path = PathOnVolume(volumeRoot);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(marker, Options));
        File.Move(tmp, path, overwrite: true);
        return marker;
    }
}
