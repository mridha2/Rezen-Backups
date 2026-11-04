using System.Globalization;
using System.Text.Json;
using RezenBackup.Core.Platform;
using RezenBackup.Database;

namespace RezenBackup.UI.Services;

/// <summary>Keeps a single main window per user and data folder.</summary>
public static class UiInstance
{
    private static FileStream? _lock;

    public static bool TryAcquire(AppPaths paths)
    {
        try
        {
            _lock = new FileStream(Path.Combine(paths.Root, "ui.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
    }

    public static void Release()
    {
        _lock?.Dispose();
        _lock = null;
    }
}

/// <summary>
/// Simple requests from the tray (agent process) or a second launch to the open window, carried through the local
/// database: "show yourself" and "lock now". Contains no secrets.
/// </summary>
public static class UiSignals
{
    public const string Show = "ui.showRequested";
    public const string Lock = "ui.lockRequested";

    public static void Send(AppDatabase db, string signal) =>
        db.SetSetting(signal, DateTimeOffset.UtcNow.UtcTicks.ToString(CultureInfo.InvariantCulture));

    public static string? Read(AppDatabase db, string signal) => db.GetSetting(signal);

    /// <summary>Set by the agent when a backup drive is connected and the user wants to be asked.</summary>
    public const string DrivePrompt = "ui.drivePrompt";

    /// <summary>A request to ask "Back up now?" for the jobs that back up to a drive that was just connected.</summary>
    public sealed record DrivePromptRequest(long UtcTicks, string DriveName, IReadOnlyList<Guid> JobIds);

    public static void SendDrivePrompt(AppDatabase db, string driveName, IReadOnlyList<Guid> jobIds) =>
        db.SetSetting(DrivePrompt, JsonSerializer.Serialize(new DrivePromptRequest(DateTimeOffset.UtcNow.UtcTicks, driveName, jobIds)));

    public static DrivePromptRequest? ReadDrivePrompt(AppDatabase db)
    {
        try
        {
            return db.GetSetting(DrivePrompt) is { } raw ? JsonSerializer.Deserialize<DrivePromptRequest>(raw) : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
