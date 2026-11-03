using RezenBackup.Application;
using RezenBackup.Core.Platform;
using RezenBackup.Crypto;

namespace RezenBackup.Tests.Application;

internal sealed class InMemoryCredentialStore : ICredentialStore
{
    private readonly Dictionary<Guid, byte[]> _items = [];

    public bool IsSupported => true;

    public string MechanismName => "test";

    public bool Unavailable { get; set; }

    public void Save(Guid keySetId, RootSecret secret) => _items[keySetId] = secret.Bytes.ToArray();

    public RootSecret? TryLoad(Guid keySetId) => !Unavailable && _items.TryGetValue(keySetId, out var b) ? RootSecret.FromBytes(b) : null;

    public bool Exists(Guid keySetId) => _items.ContainsKey(keySetId);

    public void Delete(Guid keySetId) => _items.Remove(keySetId);
}

internal sealed class FakeVolumes(string driveRoot) : IVolumeInspector
{
    public bool Connected { get; set; } = true;

    public IReadOnlyList<VolumeInfo> GetVolumes() =>
        Connected ? [new VolumeInfo(driveRoot, "TEST-DRIVE", "APFS", 1L << 40, 1L << 39, true, "uuid-1")] : [];

    public VolumeInfo? GetVolumeForPath(string path) =>
        Connected && Path.GetFullPath(path).StartsWith(driveRoot, StringComparison.Ordinal) ? GetVolumes()[0] : null;

    public bool TryEject(string rootPath) => true;
}

internal sealed class RecordingNotifier : INotifier
{
    public List<(string Title, string Message, NotificationKind Kind)> Sent { get; } = [];

    public void Notify(string title, string message, NotificationKind kind) => Sent.Add((title, message, kind));
}

/// <summary>A complete application instance against temporary folders: "this PC" plus a removable "drive".</summary>
internal sealed class AppFixture : IDisposable
{
    public const string Password = "orange tractor singing quietly 42";

    public AppFixture(string? sharedDrive = null)
    {
        Root = Path.Combine(Path.GetTempPath(), "rezen-app-" + Guid.NewGuid().ToString("N")[..10]);
        Drive = sharedDrive ?? Path.Combine(Root, "drive");
        Source = Path.Combine(Root, "Documents");
        Directory.CreateDirectory(Drive);
        Directory.CreateDirectory(Source);
        Credentials = new InMemoryCredentialStore();
        Volumes = new FakeVolumes(Drive);
        Notifier = new RecordingNotifier();
        var platform = new PlatformServices(
            Credentials,
            PortableDurableFileOps.Instance,
            PortableFileMetadataProvider.Instance,
            LiveSourceSnapshotProvider.Instance,
            new NoPower(),
            Notifier,
            new NoAutostart(),
            Volumes,
            new Unlocked(),
            "test");
        App = RezenApp.Create(new AppPaths(Path.Combine(Root, "appdata")), platform);
    }

    public string Root { get; }

    public string Drive { get; }

    public string Source { get; }

    public InMemoryCredentialStore Credentials { get; }

    public FakeVolumes Volumes { get; }

    public RecordingNotifier Notifier { get; }

    public RezenApp App { get; }

    public void Dispose()
    {
        App.Dispose();
        try
        {
            Directory.Delete(Root, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private sealed class NoPower : IPowerManager
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

    private sealed class NoAutostart : IAutostart
    {
        public bool IsEnabled => false;

        public void Enable(string agentExecutablePath)
        {
        }

        public void Disable()
        {
        }
    }

    private sealed class Unlocked : ISessionStateMonitor
    {
        public bool IsSystemLocked() => false;
    }
}
