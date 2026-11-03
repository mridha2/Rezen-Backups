using System.Diagnostics;
using System.Text.Json;
using RezenBackup.Core;

namespace RezenBackup.Format;

/// <summary>
/// Exclusive writer lock for a repository (DESIGN §16.1 step 1).
/// </summary>
/// <remarks>
/// The lock is an operating-system lock on <c>repository.lock</c>: the holder keeps the file open with
/// <see cref="FileShare.None"/> (a sharing lock on Windows, <c>flock(LOCK_EX)</c> on macOS). The OS releases it the
/// moment the holder exits or crashes, so there is no guessing about stale locks and no window in which two writers
/// both believe they hold it. The JSON inside is informational only.
/// </remarks>
public sealed class RepositoryLock : IDisposable
{
    private readonly FileStream _stream;
    private bool _disposed;

    private RepositoryLock(FileStream stream)
    {
        _stream = stream;
    }

    public sealed record LockInfo(string Host, int ProcessId, long ProcessStartTicks, DateTimeOffset AcquiredUtc, Guid RunId);

    public static RepositoryLock Acquire(RepositoryLayout layout, Guid runId)
    {
        var path = layout.LockPath;
        FileStream fs;
        try
        {
            // OpenOrCreate + FileShare.None: succeeds only if nobody holds the lock. A file left behind by a crashed run
            // is simply taken over (its holder is gone, so the OS lock is free).
            fs = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.WriteThrough | FileOptions.DeleteOnClose);
        }
        catch (IOException ex) when (File.Exists(path) && !IoErrors.IsDeviceGone(ex) && !IoErrors.IsDiskFull(ex))
        {
            throw new RezenException(ErrorCode.RepositoryLocked, "Another Rezen Backup process is writing to this backup.");
        }
        catch (IOException ex)
        {
            throw IoErrors.Translate(ex);
        }

        try
        {
            using var current = Process.GetCurrentProcess();
            var info = new LockInfo(Environment.MachineName, Environment.ProcessId, current.StartTime.ToUniversalTime().Ticks, DateTimeOffset.UtcNow, runId);
            fs.SetLength(0);
            JsonSerializer.Serialize(fs, info);
            fs.Flush(flushToDisk: true);
            return new RepositoryLock(fs);
        }
        catch
        {
            fs.Dispose();
            throw;
        }
    }

    /// <summary>True if another process currently holds the lock.</summary>
    public static bool IsHeld(RepositoryLayout layout)
    {
        if (!File.Exists(layout.LockPath))
        {
            return false;
        }

        try
        {
            using var probe = new FileStream(layout.LockPath, FileMode.Open, FileAccess.Read, FileShare.None);
            return false;
        }
        catch (IOException)
        {
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return true;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        // DeleteOnClose removes the file as the handle closes; no other process could have taken it over meanwhile.
        _stream.Dispose();
    }
}
