using Microsoft.Extensions.Logging;
using RezenBackup.Core.Platform;
using RezenBackup.Crypto;
using RezenBackup.Platform.MacOS;
using RezenBackup.Platform.Windows;

namespace RezenBackup.Platform;

/// <summary>Selects the Windows or macOS implementations at runtime (DESIGN §1.2, §29).</summary>
public static class PlatformFactory
{
    public static PlatformServices Create(AppPaths paths, ILoggerFactory loggers)
    {
        ArgumentNullException.ThrowIfNull(paths);
        ArgumentNullException.ThrowIfNull(loggers);
        var log = loggers.CreateLogger("Platform");

        // Developer/test override: never touch the real OS credential store (Keychain/DPAPI).
        bool noOsCredentials = Environment.GetEnvironmentVariable("REZEN_DISABLE_OS_CREDENTIALS") == "1";
        if (noOsCredentials)
        {
            var p = Create(paths, loggers, allowOsCredentials: false);
            return p;
        }

        return Create(paths, loggers, allowOsCredentials: true);
    }

    private static PlatformServices Create(AppPaths paths, ILoggerFactory loggers, bool allowOsCredentials)
    {
        var log = loggers.CreateLogger("Platform");
        if (OperatingSystem.IsWindows())
        {
            return new PlatformServices(
                allowOsCredentials ? new DpapiCredentialStore(paths.CredentialsDirectory) : new UnsupportedCredentialStore(),
                new WindowsDurableFileOps(log),
                new WindowsFileMetadataProvider(),
                new VssSourceSnapshotProvider(log),
                new WindowsPowerManager(),
                new WindowsNotifier(log),
                new WindowsAutostart(),
                new WindowsVolumeInspector(),
                new WindowsSessionStateMonitor(),
                "Windows");
        }

        if (OperatingSystem.IsMacOS())
        {
            return new PlatformServices(
                allowOsCredentials ? new KeychainCredentialStore() : new UnsupportedCredentialStore(),
                new MacDurableFileOps(),
                new MacFileMetadataProvider(),
                LiveSourceSnapshotProvider.Instance,
                new MacPowerManager(),
                new MacNotifier(log),
                new MacAutostart(),
                new MacVolumeInspector(),
                new MacSessionStateMonitor(),
                "macOS");
        }

        // Other platforms: core backup/restore works; OS integration features are unavailable.
        return new PlatformServices(
            new UnsupportedCredentialStore(),
            PortableDurableFileOps.Instance,
            PortableFileMetadataProvider.Instance,
            LiveSourceSnapshotProvider.Instance,
            new NoopPower(),
            new LogNotifier(log),
            new NoopAutostart(),
            new PortableVolumeInspector(),
            new NeverLocked(),
            "Other");
    }

    private sealed class UnsupportedCredentialStore : ICredentialStore
    {
        public bool IsSupported => false;

        public string MechanismName => "Not available on this platform";

        public void Save(Guid keySetId, RootSecret secret) => throw new PlatformNotSupportedException("Remembering the password is not supported on this platform.");

        public RootSecret? TryLoad(Guid keySetId) => null;

        public void SaveBytes(Guid id, ReadOnlySpan<byte> secret) => throw new PlatformNotSupportedException("Remembering keys is not supported on this platform.");

        public SecretBuffer? TryLoadBytes(Guid id) => null;

        public bool Exists(Guid keySetId) => false;

        public void Delete(Guid keySetId)
        {
        }
    }

    private sealed class NoopPower : IPowerManager
    {
        public IDisposable KeepAwake(string reason) => new Noop();

        public bool IsOnBattery => false;

        private sealed class Noop : IDisposable
        {
            public void Dispose()
            {
            }
        }
    }

    private sealed class LogNotifier(ILogger log) : INotifier
    {
        public void Notify(string title, string message, NotificationKind kind) => log.LogInformation("{Title}: {Message}", title, message);
    }

    private sealed class NoopAutostart : IAutostart
    {
        public bool IsEnabled => false;

        public void Enable(string agentExecutablePath)
        {
        }

        public void Disable()
        {
        }
    }

    private sealed class NeverLocked : ISessionStateMonitor
    {
        public bool IsSystemLocked() => false;
    }
}

/// <summary>Volume listing via <see cref="DriveInfo"/> only.</summary>
public sealed class PortableVolumeInspector : IVolumeInspector
{
    public IReadOnlyList<VolumeInfo> GetVolumes() => DriveInfo.GetDrives()
        .Where(d => d.IsReady)
        .Select(d => new VolumeInfo(d.RootDirectory.FullName, d.VolumeLabel, d.DriveFormat, d.TotalSize, d.AvailableFreeSpace, d.DriveType == DriveType.Removable, null))
        .ToList();

    public VolumeInfo? GetVolumeForPath(string path)
    {
        var full = Path.GetFullPath(path);
        return GetVolumes().Where(v => full.StartsWith(v.RootPath, StringComparison.Ordinal)).MaxBy(v => v.RootPath.Length);
    }

    public bool TryEject(string rootPath) => false;
}
