using System.Diagnostics;
using System.Text.Json;
using RezenBackup.Core;

namespace RezenBackup.Format;

/// <summary>
/// Exclusive writer lock for a repository (DESIGN §16.1 step 1). Stale locks left by a crashed process on this
/// computer are broken automatically; locks held by another computer are never broken silently.
/// </summary>
public sealed class RepositoryLock : IDisposable
{
    private readonly FileStream _stream;
    private readonly string _path;
    private bool _disposed;

    private RepositoryLock(FileStream stream, string path)
    {
        _stream = stream;
        _path = path;
    }

    public sealed record LockInfo(string Host, int ProcessId, long ProcessStartTicks, DateTimeOffset AcquiredUtc, Guid RunId);

    public static RepositoryLock Acquire(RepositoryLayout layout, Guid runId, bool breakForeignLock = false)
    {
        var path = layout.LockPath;
        for (int attempt = 0; attempt < 2; attempt++)
        {
            try
            {
                var fs = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 4096, FileOptions.WriteThrough);
                using var current = Process.GetCurrentProcess();
                var info = new LockInfo(Environment.MachineName, Environment.ProcessId, current.StartTime.ToUniversalTime().Ticks, DateTimeOffset.UtcNow, runId);
                JsonSerializer.Serialize(fs, info);
                fs.Flush(flushToDisk: true);
                return new RepositoryLock(fs, path);
            }
            catch (IOException) when (File.Exists(path) && attempt == 0)
            {
                var existing = TryReadInfo(path);
                if (existing is null || IsStale(existing) || breakForeignLock)
                {
                    TryDelete(path);
                    continue;
                }

                throw new RezenException(ErrorCode.RepositoryLocked, $"Locked by {existing.Host} (process {existing.ProcessId}).");
            }
            catch (IOException ex)
            {
                throw IoErrors.Translate(ex);
            }
        }

        throw new RezenException(ErrorCode.RepositoryLocked);
    }

    public static LockInfo? TryReadInfo(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return JsonSerializer.Deserialize<LockInfo>(fs);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static bool IsStale(LockInfo info)
    {
        if (!string.Equals(info.Host, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
        {
            // Another computer: only stale if very old (a crashed run more than a day ago).
            return DateTimeOffset.UtcNow - info.AcquiredUtc > TimeSpan.FromDays(1);
        }

        try
        {
            using var p = Process.GetProcessById(info.ProcessId);
            return p.HasExited || p.StartTime.ToUniversalTime().Ticks != info.ProcessStartTicks;
        }
        catch (ArgumentException)
        {
            return true;
        }
        catch (InvalidOperationException)
        {
            return true;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _stream.Dispose();
        TryDelete(_path);
    }
}
