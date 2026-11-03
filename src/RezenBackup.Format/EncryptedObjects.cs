using System.Security.Cryptography;
using RezenBackup.Core;
using RezenBackup.Core.Platform;
using RezenBackup.Crypto;

namespace RezenBackup.Format;

/// <summary>Result of writing an encrypted object file.</summary>
public sealed record WrittenObject(string Path, long Length, byte[] Sha256);

/// <summary>Helpers for whole-file encrypted objects (snapshot records, commit records, journals, config, caches).</summary>
public static class EncryptedObjects
{
    public static byte[] Encrypt(RepositoryKeys keys, ObjectType type, ReadOnlySpan<byte> plaintext)
    {
        using var ms = new MemoryStream();
        using (var w = new AeadStreamWriter(ms, keys, ObjectHeader.CreateNew(type, keys.RepositoryId)))
        {
            w.Write(plaintext);
            w.Complete();
        }

        return ms.ToArray();
    }

    public static byte[] Decrypt(RepositoryKeys keys, ObjectType type, byte[] ciphertext, long maxLength = 512L * 1024 * 1024)
    {
        using var ms = new MemoryStream(ciphertext, writable: false);
        using var r = new AeadStreamReader(ms, keys, type);
        return r.ReadAll(maxLength);
    }

    /// <summary>
    /// Writes ciphertext durably: temp file → flush to device → uncached read-back compare → atomic rename → flush dir.
    /// </summary>
    public static WrittenObject WriteDurable(string path, byte[] ciphertext, IDurableFileOps ops)
    {
        var dir = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(dir);
        var tmp = path + ".tmp";
        try
        {
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16))
            {
                fs.Write(ciphertext);
                ops.FlushToDevice(fs);
            }

            var readBack = ReadAllForVerification(tmp, ops);
            if (!CryptographicOperations.FixedTimeEquals(readBack, ciphertext))
            {
                throw new RezenException(ErrorCode.CommitFailed, "Read-back after write did not match.");
            }

            ops.AtomicMove(tmp, path, overwrite: true);
            ops.FlushDirectory(dir);
            return new WrittenObject(path, ciphertext.LongLength, SHA256.HashData(ciphertext));
        }
        catch (IOException ex)
        {
            TryDelete(tmp);
            throw IoErrors.Translate(ex);
        }
    }

    public static WrittenObject WriteObject(string path, RepositoryKeys keys, ObjectType type, ReadOnlySpan<byte> plaintext, IDurableFileOps ops) =>
        WriteDurable(path, Encrypt(keys, type, plaintext), ops);

    public static byte[] ReadObject(string path, RepositoryKeys keys, ObjectType type, long maxLength = 512L * 1024 * 1024)
    {
        var bytes = File.ReadAllBytes(path);
        return Decrypt(keys, type, bytes, maxLength);
    }

    public static byte[] ReadAllForVerification(string path, IDurableFileOps ops)
    {
        using var vs = ops.OpenForVerification(path);
        using var ms = new MemoryStream();
        vs.CopyTo(ms);
        return ms.ToArray();
    }

    public static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

/// <summary>Maps OS I/O errors to stable error codes (disk full, device gone).</summary>
public static class IoErrors
{
    // Windows HRESULTs (0x8007xxxx) and POSIX errno values surfaced through IOException.HResult.
    private const int WinDiskFull = unchecked((int)0x80070070);
    private const int WinHandleDiskFull = unchecked((int)0x80070027);
    private const int WinDeviceNotConnected = unchecked((int)0x8007048F);
    private const int WinNotReady = unchecked((int)0x80070015);
    private const int WinPathNotFound = unchecked((int)0x80070003);
    private const int WinNoSuchDevice = unchecked((int)0x800701B1);
    private const int PosixEnospc = 28;
    private const int PosixEnxio = 6;
    private const int PosixEio = 5;
    private const int PosixEnodev = 19;

    public static bool IsDiskFull(IOException ex) =>
        ex.HResult is WinDiskFull or WinHandleDiskFull || (ex.HResult & 0xFFFF) == PosixEnospc ||
        ex.Message.Contains("No space left", StringComparison.OrdinalIgnoreCase);

    public static bool IsDeviceGone(IOException ex) =>
        ex.HResult is WinDeviceNotConnected or WinNotReady or WinNoSuchDevice ||
        (ex.HResult & 0xFFFF) is PosixEnxio or PosixEnodev or PosixEio;

    public static Exception Translate(IOException ex)
    {
        if (IsDiskFull(ex))
        {
            return new RezenException(ErrorCode.DestinationFull, ex.Message, ex);
        }

        if (IsDeviceGone(ex) || ex is DirectoryNotFoundException || ex.HResult == WinPathNotFound)
        {
            return new RezenException(ErrorCode.DestinationDisconnected, ex.Message, ex);
        }

        return new RezenException(ErrorCode.CommitFailed, ex.Message, ex);
    }
}
