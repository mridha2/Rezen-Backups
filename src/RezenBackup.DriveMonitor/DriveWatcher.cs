using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RezenBackup.Core.Platform;
using RezenBackup.Format;

namespace RezenBackup.DriveMonitor;

public sealed record ConnectedDrive(Guid DriveId, string MountPath, VolumeInfo? Volume);

/// <summary>
/// Recognises registered backup drives by the <c>.rezenbackup</c> marker, not by drive letter (spec §31), and raises
/// arrival/removal events. Polling is used on both Windows and macOS for robustness (DESIGN §17.2).
/// </summary>
public sealed class DriveWatcher : IDisposable
{
    private readonly IVolumeInspector _volumes;
    private readonly Func<IEnumerable<string>> _extraRoots;
    private readonly ILogger _logger;
    private readonly object _gate = new();
    private Dictionary<Guid, ConnectedDrive> _connected = [];
    private Timer? _timer;

    public DriveWatcher(IVolumeInspector volumes, Func<IEnumerable<string>>? extraRoots = null, ILogger? logger = null)
    {
        _volumes = volumes;
        _extraRoots = extraRoots ?? (() => []);
        _logger = logger ?? NullLogger.Instance;
    }

    public event Action<ConnectedDrive>? Arrived;

    public event Action<ConnectedDrive>? Removed;

    public IReadOnlyCollection<ConnectedDrive> Connected
    {
        get
        {
            lock (_gate)
            {
                return _connected.Values.ToList();
            }
        }
    }

    public ConnectedDrive? Find(Guid driveId)
    {
        lock (_gate)
        {
            return _connected.GetValueOrDefault(driveId);
        }
    }

    public void Start(TimeSpan interval)
    {
        Poll();
        _timer = new Timer(_ => Poll(), null, interval, interval);
    }

    /// <summary>Scans now and raises events for changes.</summary>
    public void Poll()
    {
        var found = Scan(_volumes, _extraRoots());
        List<ConnectedDrive> arrived;
        List<ConnectedDrive> removed;
        lock (_gate)
        {
            arrived = found.Values.Where(d => !_connected.ContainsKey(d.DriveId)).ToList();
            removed = _connected.Values.Where(d => !found.ContainsKey(d.DriveId)).ToList();
            _connected = found;
        }

        foreach (var d in removed)
        {
            _logger.LogInformation("Backup drive disconnected: {Drive}", d.DriveId);
            Removed?.Invoke(d);
        }

        foreach (var d in arrived)
        {
            _logger.LogInformation("Backup drive connected: {Drive}", d.DriveId);
            Arrived?.Invoke(d);
        }
    }

    /// <summary>Finds every mounted volume (and extra folder destinations) carrying a Rezen drive marker.</summary>
    public static Dictionary<Guid, ConnectedDrive> Scan(IVolumeInspector volumes, IEnumerable<string> extraRoots)
    {
        var result = new Dictionary<Guid, ConnectedDrive>();
        IReadOnlyList<VolumeInfo> list;
        try
        {
            list = volumes.GetVolumes();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            list = [];
        }

        foreach (var v in list)
        {
            if (DriveMarker.TryRead(v.RootPath) is { } marker)
            {
                result.TryAdd(marker.DriveId, new ConnectedDrive(marker.DriveId, v.RootPath, v));
            }
        }

        foreach (var root in extraRoots)
        {
            if (Directory.Exists(root) && DriveMarker.TryRead(root) is { } marker)
            {
                result.TryAdd(marker.DriveId, new ConnectedDrive(marker.DriveId, root, volumes.GetVolumeForPath(root)));
            }
        }

        return result;
    }

    public void Dispose()
    {
        _timer?.Dispose();
        _timer = null;
    }
}
