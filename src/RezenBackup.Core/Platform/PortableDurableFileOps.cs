namespace RezenBackup.Core.Platform;

/// <summary>
/// Portable durability baseline used when no OS-specific implementation is registered (and in tests).
/// <see cref="FileStream.Flush(bool)"/> with <c>true</c> maps to FlushFileBuffers on Windows and fsync on Unix.
/// The platform layer upgrades this to F_FULLFSYNC and uncached reads.
/// </summary>
public class PortableDurableFileOps : IDurableFileOps
{
    public static readonly PortableDurableFileOps Instance = new();

    public virtual void FlushToDevice(FileStream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        stream.Flush(flushToDisk: true);
    }

    public virtual Stream OpenForVerification(string path) =>
        new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, FileOptions.SequentialScan);

    public virtual void FlushDirectory(string directory)
    {
        // Not supported portably; NTFS/APFS journal directory updates. Overridden on Unix to fsync the directory.
    }

    public virtual void AtomicMove(string source, string destination, bool overwrite) =>
        File.Move(source, destination, overwrite);
}
