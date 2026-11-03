using System.Globalization;
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
}
