using System.Runtime.InteropServices;
using RezenBackup.Crypto.Native;

namespace RezenBackup.Crypto;

/// <summary>
/// Fixed-size buffer for secret material (root secrets, repository keys, password bytes).
/// Backed by libsodium guarded memory (<c>sodium_malloc</c>): locked so it is not swapped to disk,
/// surrounded by guard pages, and zeroed on <see cref="Dispose"/>.
/// </summary>
/// <remarks>
/// The buffer never appears in logs: <see cref="ToString"/> returns a redaction marker.
/// Disposal is idempotent and thread-safe. Accessing a disposed buffer throws.
/// </remarks>
public sealed unsafe class SecretBuffer : IDisposable
{
    private nint _ptr;
    private readonly int _length;
    private int _disposed;

    public SecretBuffer(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
        Sodium.EnsureInitialized();
        _ptr = Sodium.sodium_malloc((nuint)length);
        if (_ptr == 0)
        {
            throw new OutOfMemoryException("Unable to allocate protected memory for key material.");
        }

        _length = length;
        Sodium.sodium_memzero(_ptr, (nuint)length);
    }

    /// <summary>Creates a buffer holding a copy of <paramref name="source"/>. The caller remains responsible for wiping the source.</summary>
    public static SecretBuffer CopyFrom(ReadOnlySpan<byte> source)
    {
        var buffer = new SecretBuffer(source.Length);
        source.CopyTo(buffer.Span);
        return buffer;
    }

    /// <summary>Creates a buffer filled with cryptographically secure random bytes.</summary>
    public static SecretBuffer Random(int length)
    {
        var buffer = new SecretBuffer(length);
        CryptoRandom.Fill(buffer.Span);
        return buffer;
    }

    public int Length => _length;

    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    public Span<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            return new Span<byte>((void*)_ptr, _length);
        }
    }

    public ReadOnlySpan<byte> ReadOnlySpan => Span;

    /// <summary>Constant-time comparison.</summary>
    public bool ContentEquals(SecretBuffer other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ReadOnlySpan, other.ReadOnlySpan);
    }

    public SecretBuffer Clone() => CopyFrom(ReadOnlySpan);

    public override string ToString() => "[REDACTED]";

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        // sodium_free zeroes the memory before releasing it.
        Sodium.sodium_free(_ptr);
        _ptr = 0;
        GC.SuppressFinalize(this);
    }

    ~SecretBuffer()
    {
        if (_ptr != 0)
        {
            Sodium.sodium_free(_ptr);
        }
    }
}

/// <summary>Helpers for wiping managed buffers that briefly hold secrets.</summary>
public static class SecureMemory
{
    /// <summary>Allocates a pinned managed array so the GC cannot copy it during compaction.</summary>
    public static byte[] AllocatePinned(int length) => GC.AllocateArray<byte>(length, pinned: true);

    public static void Wipe(Span<byte> buffer) => System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer);

    public static void Wipe(Span<char> buffer) => MemoryMarshal.AsBytes(buffer).Clear();
}
