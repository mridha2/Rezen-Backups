using System.Reflection;
using Microsoft.Extensions.Logging;
using RezenBackup.Core.Platform;
using RezenBackup.Crypto;
using RezenBackup.Database;
using RezenBackup.DriveMonitor;
using RezenBackup.Logging;
using RezenBackup.Platform;

namespace RezenBackup.Application;

/// <summary>
/// Composition root shared by the desktop app, the background agent and the command-line tool. Owns the database,
/// logging, platform services and application services.
/// </summary>
public sealed class RezenApp : IDisposable
{
    private RezenApp(AppPaths paths, PlatformServices? platformOverride, string logPrefix)
    {
        Paths = paths;
        paths.EnsureCreated();
        LogProvider = new FileLoggerProvider(paths.LogsDirectory, logPrefix);
        Loggers = LoggerFactory.Create(b => b.AddProvider(LogProvider).SetMinimumLevel(LogLevel.Information));
        Logger = Loggers.CreateLogger("RezenBackup");
        Platform = platformOverride ?? PlatformFactory.Create(paths, Loggers);
        Db = new AppDatabase(paths.Database);
        if (Db.RecoveredFromBackup)
        {
            Logger.LogWarning("Local database was damaged and restored from its backup copy.");
        }

        Settings = AppSettings.Load(Db);
        LogPrivacy.HideFileNames = Settings.HideFileNamesInLogs;
        LogPrivacy.SetSalt(InstallationSecret("log-salt"));
        SecurityLog = new SecurityLog(Db, InstallationSecret("security-log"));

        KeySets = new KeySetService(this);
        Drives = new DriveService(this);
        Jobs = new JobService(this);
        Backups = new BackupService(this);
        Import = new ImportService(this);
        Status = new StatusService(this);
    }

    public static string AppVersion { get; } =
        typeof(RezenApp).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "1.0.0";

    public AppPaths Paths { get; }

    public AppDatabase Db { get; }

    public PlatformServices Platform { get; }

    public FileLoggerProvider LogProvider { get; }

    public ILoggerFactory Loggers { get; }

    public ILogger Logger { get; }

    public SecurityLog SecurityLog { get; }

    public AppSettings Settings { get; private set; }

    public KeySetService KeySets { get; }

    public DriveService Drives { get; }

    public JobService Jobs { get; }

    public BackupService Backups { get; }

    public ImportService Import { get; }

    public StatusService Status { get; }

    public static RezenApp Create(AppPaths? paths = null, PlatformServices? platform = null, string logPrefix = "rezen") =>
        new(paths ?? new AppPaths(), platform, logPrefix);

    public void SaveSettings(AppSettings settings)
    {
        Settings = settings;
        settings.Save(Db);
        LogPrivacy.HideFileNames = settings.HideFileNamesInLogs;
    }

    public void ReloadSettings() => Settings = AppSettings.Load(Db);

    /// <summary>
    /// A per-installation random value (log salt, security-log MAC key). Kept in the OS credential store when available,
    /// otherwise in a user-only file. It protects log integrity, not backup data.
    /// </summary>
    private byte[] InstallationSecret(string purpose)
    {
        var id = new Guid(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("rezen-installation/" + purpose))[..16]);
        try
        {
            if (Platform.Credentials.IsSupported)
            {
                using var existing = Platform.Credentials.TryLoad(id);
                if (existing is not null)
                {
                    return existing.Bytes.ToArray();
                }

                using var created = RootSecret.Generate();
                Platform.Credentials.Save(id, created);
                return created.Bytes.ToArray();
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or PlatformNotSupportedException or IOException or System.Security.Cryptography.CryptographicException)
        {
            Logger.LogWarning("OS credential store unavailable for {Purpose}: {Message}", purpose, ex.Message);
        }

        var file = Path.Combine(Paths.CredentialsDirectory, purpose + ".bin");
        if (File.Exists(file) && new FileInfo(file).Length == 32)
        {
            return File.ReadAllBytes(file);
        }

        var bytes = CryptoRandom.Bytes(32);
        File.WriteAllBytes(file, bytes);
        return bytes;
    }

    /// <summary>All registered drives currently connected (recognised by marker, under any drive letter).</summary>
    public IReadOnlyDictionary<Guid, ConnectedDrive> ConnectedDrives() =>
        DriveWatcher.Scan(Platform.Volumes, Db.Drives().Select(d => d.LastMountPath).OfType<string>());

    public void Dispose()
    {
        Db.Dispose();
        Loggers.Dispose();
        LogProvider.Dispose();
    }
}
