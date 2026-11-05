using System.Text.Json;
using System.Text.Json.Serialization;
using RezenBackup.Core.Domain;
using RezenBackup.Database;
using RezenBackup.Security;

namespace RezenBackup.Application;

public enum ThemePreference
{
    System,
    Light,
    Dark,
}

/// <summary>What Rezen Backup does when a registered backup drive is connected.</summary>
public enum DriveConnectAction
{
    /// <summary>Open Rezen Backup and ask whether to back up now.</summary>
    Ask = 0,

    /// <summary>Back up without asking, but only when a backup is due or the last one failed.</summary>
    BackUpIfDue = 1,

    /// <summary>Do nothing; scheduled backups still run.</summary>
    DoNothing = 2,
}

/// <summary>User settings (spec §82). Stored in the local database; contains no secrets.</summary>
public sealed record AppSettings
{
    // General
    public bool StartWithSystem { get; init; } = true;

    public bool RunBackgroundAgent { get; init; } = true;

    public bool ShowTrayIcon { get; init; } = true;

    public bool RunMissedBackups { get; init; } = true;

    public bool KeepComputerAwake { get; init; } = true;

    // Backup
    public VerificationLevel DefaultVerification { get; init; } = VerificationLevel.Standard;

    /// <summary>What happens when a drive that holds one of this computer's backups is plugged in.</summary>
    public DriveConnectAction OnDriveConnected { get; init; } = DriveConnectAction.Ask;

    /// <summary>Replaced by <see cref="OnDriveConnected"/>; only read to carry over an explicit "off" from older versions.</summary>
    public bool AutoBackupOnDriveConnect { get; init; } = true;

    public int DeepVerifyEveryDays { get; init; } = 30;

    // Security
    public AutoLockMode AutoLock { get; init; } = AutoLockMode.After15Minutes;

    public bool LockWhenSystemLocks { get; init; } = true;

    public bool HideFileNamesInLogs { get; init; } = true;

    // Notifications
    public bool NotifySuccess { get; init; } = true;

    public bool NotifyFailure { get; init; } = true;

    public bool NotifyWaitingForDrive { get; init; } = true;

    public bool NotifyIntegrity { get; init; } = true;

    public bool NotifyLowSpace { get; init; } = true;

    // Appearance
    public ThemePreference Theme { get; init; } = ThemePreference.System;

    /// <summary>Last main-window size chosen by the user (device-independent units); null until the window is first closed.</summary>
    public double? WindowWidth { get; init; }

    public double? WindowHeight { get; init; }

    public bool WindowMaximized { get; init; }

    public bool SetupCompleted { get; init; }

    private const string Key = "app.settings";

    private static readonly JsonSerializerOptions Json = new() { Converters = { new JsonStringEnumConverter() } };

    public static AppSettings Load(AppDatabase db)
    {
        var raw = db.GetSetting(Key);
        if (raw is null)
        {
            return new AppSettings();
        }

        try
        {
            var settings = JsonSerializer.Deserialize<AppSettings>(raw, Json) ?? new AppSettings();
            // Settings saved before OnDriveConnected existed: someone who had turned drive-connect backups off keeps them off.
            if (!raw.Contains("\"OnDriveConnected\"", StringComparison.Ordinal) && !settings.AutoBackupOnDriveConnect)
            {
                settings = settings with { OnDriveConnected = DriveConnectAction.DoNothing };
            }

            return settings;
        }
        catch (JsonException)
        {
            return new AppSettings();
        }
    }

    public void Save(AppDatabase db) => db.SetSetting(Key, JsonSerializer.Serialize(this, Json));

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static AppSettings? FromJson(string json) => JsonSerializer.Deserialize<AppSettings>(json, Json);
}
