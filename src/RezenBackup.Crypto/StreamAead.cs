using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace RezenBackup.Crypto;

/// <summary>
/// Segmented authenticated encryption (STREAM construction, Hoang–Reyhanitabar–Rogaway–Vizár 2015) over AES-256-GCM.
/// Each object gets a unique key derived from a random 256-bit salt, so the per-segment nonce can be a counter:
/// <c>nonce_i = BE64(i) ‖ 0x000000 ‖ lastFlag</c>. The object header is the AAD of every segment.
/// </summary>
internal static class StreamNonce
{
    public const int TagSize = 16;

    public static void Build(long segmentIndex, bool last, Span<byte> nonce)
    {
        BinaryPrimitives.WriteInt64BigEndian(nonce, segmentIndex);
        nonce[8] = 0;
        nonce[9] = 0;
        nonce[10] = 0;
        nonce[11] = last ? (byte)1 : (byte)0;
    }
}

/// <summary>
/// Writes an encrypted object to a stream. Plaintext is buffered one segment at a time; the final segment is
/// only emitted from <see cref="Complete"/>, which sets the "last" flag and so protects against truncation.
/// </summary>
public sealed class AeadStreamWriter : IDisposable
{
    private readonly Stream _output;
    private readonly AesGcm _gcm;
    private readonly byte[] _aad;
    private readonly byte[] _plain;
    private readonly byte[] _cipher;
    private readonly int _segmentSize;
    private int _filled;
    private long _segmentIndex;
    private bool _completed;
    private bool _disposed;

    public AeadStreamWriter(Stream output, RepositoryKeys keys, ObjectHeader header)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(header);
        if (header.RepositoryId != keys.RepositoryId)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Header does not match repository keys.");
        }

        _output = output;
        _segmentSize = header.SegmentSize;
        _aad = header.ToBytes();
        Span<byte> key = stackalloc byte[32];
        keys.DeriveObjectKeyForRead(header, key);
        _gcm = new AesGcm(key, StreamNonce.TagSize);
        CryptographicOperations.ZeroMemory(key);

        _plain = ArrayPool<byte>.Shared.Rent(_segmentSize);
        _cipher = ArrayPool<byte>.Shared.Rent(_segmentSize + StreamNonce.TagSize);
        _output.Write(_aad);
        BytesWritten = _aad.Length;
        Header = header;
    }

    public ObjectHeader Header { get; }

    /// <summary>Total ciphertext bytes written including header.</summary>
    public long BytesWritten { get; private set; }

    /// <summary>Total plaintext bytes accepted.</summary>
    public long PlaintextLength { get; private set; }

    public void Write(ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_completed)
        {
            throw new InvalidOperationException("Stream already completed.");
        }

        while (!data.IsEmpty)
        {
            if (_filled == _segmentSize)
            {
                // A full buffer is only known to be non-final once more data arrives.
                EmitSegment(last: false);
            }

            int n = Math.Min(_segmentSize - _filled, data.Length);
            data[..n].CopyTo(_plain.AsSpan(_filled));
            _filled += n;
            PlaintextLength += n;
            data = data[n..];
        }
    }

    /// <summary>Encrypts the final segment (possibly empty) with the last flag set.</summary>
    public void Complete()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_completed)
        {
            return;
        }

        EmitSegment(last: true);
        _completed = true;
    }

    private void EmitSegment(bool last)
    {
        Span<byte> nonce = stackalloc byte[12];
        StreamNonce.Build(_segmentIndex, last, nonce);
        var plain = _plain.AsSpan(0, _filled);
        var cipher = _cipher.AsSpan(0, _filled);
        var tag = _cipher.AsSpan(_filled, StreamNonce.TagSize);
        _gcm.Encrypt(nonce, plain, cipher, tag, _aad);
        _output.Write(_cipher, 0, _filled + StreamNonce.TagSize);
        BytesWritten += _filled + StreamNonce.TagSize;
        CryptographicOperations.ZeroMemory(plain);
        _filled = 0;
        _segmentIndex++;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(_plain);
        ArrayPool<byte>.Shared.Return(_plain);
        ArrayPool<byte>.Shared.Return(_cipher);
        _gcm.Dispose();
    }
}

/// <summary>
/// Random-access reader for an encrypted object. Every segment is authenticated before any of its plaintext
/// is returned; truncation, reordering, and header tampering are all detected.
/// </summary>
public sealed class AeadStreamReader : IDisposable
{
    private readonly Stream _input;
    private readonly AesGcm _gcm;
    private readonly byte[] _aad;
    private readonly long _cipherLength;
    private readonly int _segmentSize;
    private readonly int _stride;
    private readonly byte[] _cipherBuffer;
    private readonly byte[] _segmentBuffer;
    private long _cachedSegment = -1;
    private int _cachedLength;
    private bool _disposed;

    /// <param name="input">Seekable stream positioned anywhere; the reader seeks as needed.</param>
    public AeadStreamReader(Stream input, RepositoryKeys keys, ObjectType? expectedType = null)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(keys);
        if (!input.CanSeek)
        {
            throw new ArgumentException("Stream must be seekable.", nameof(input));
        }

        _input = input;
        Span<byte> headerBytes = stackalloc byte[ObjectHeader.Size];
        input.Seek(0, SeekOrigin.Begin);
        if (ReadFully(input, headerBytes) != ObjectHeader.Size)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Object is truncated.");
        }

        Header = ObjectHeader.Parse(headerBytes, expectedType, keys.RepositoryId);
        _aad = headerBytes.ToArray();
        _segmentSize = Header.SegmentSize;
        _stride = _segmentSize + StreamNonce.TagSize;
        _cipherLength = input.Length - ObjectHeader.Size;
        if (_cipherLength < StreamNonce.TagSize)
        {
            throw new CryptoException(CryptoError.AuthenticationFailed, "Object is truncated.");
        }

        SegmentCount = (_cipherLength + _stride - 1) / _stride;
        long lastSegmentCipher = _cipherLength - ((SegmentCount - 1) * _stride);
        if (lastSegmentCipher < StreamNonce.TagSize)
        {
            throw new CryptoException(CryptoError.AuthenticationFailed, "Object is truncated.");
        }

        PlaintextLength = ((SegmentCount - 1) * _segmentSize) + (lastSegmentCipher - StreamNonce.TagSize);

        Span<byte> key = stackalloc byte[32];
        keys.DeriveObjectKeyForRead(Header, key);
        _gcm = new AesGcm(key, StreamNonce.TagSize);
        CryptographicOperations.ZeroMemory(key);

        _cipherBuffer = ArrayPool<byte>.Shared.Rent(_stride);
        _segmentBuffer = ArrayPool<byte>.Shared.Rent(_segmentSize);
    }

    public ObjectHeader Header { get; }

    public long SegmentCount { get; }

    public long PlaintextLength { get; }

    /// <summary>Decrypts and authenticates one segment into an internal buffer and returns its plaintext.</summary>
    public ReadOnlySpan<byte> ReadSegment(long index)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, SegmentCount);

        if (_cachedSegment == index)
        {
            return _segmentBuffer.AsSpan(0, _cachedLength);
        }

        _cachedSegment = -1;
        bool last = index == SegmentCount - 1;
        long offset = ObjectHeader.Size + (index * _stride);
        int cipherLen = last ? (int)(_cipherLength - (index * _stride)) : _stride;
        _input.Seek(offset, SeekOrigin.Begin);
        if (ReadFully(_input, _cipherBuffer.AsSpan(0, cipherLen)) != cipherLen)
        {
            throw new CryptoException(CryptoError.AuthenticationFailed, "Object is truncated.");
        }

        int plainLen = cipherLen - StreamNonce.TagSize;
        Span<byte> nonce = stackalloc byte[12];
        StreamNonce.Build(index, last, nonce);
        try
        {
            _gcm.Decrypt(
                nonce,
                _cipherBuffer.AsSpan(0, plainLen),
                _cipherBuffer.AsSpan(plainLen, StreamNonce.TagSize),
                _segmentBuffer.AsSpan(0, plainLen),
                _aad);
        }
        catch (AuthenticationTagMismatchException ex)
        {
            CryptographicOperations.ZeroMemory(_segmentBuffer);
            throw new CryptoException(CryptoError.AuthenticationFailed, "Backup integrity verification failed.", ex);
        }

        _cachedSegment = index;
        _cachedLength = plainLen;
        return _segmentBuffer.AsSpan(0, plainLen);
    }

    /// <summary>Reads an arbitrary plaintext range; every touched segment is authenticated first.</summary>
    public void ReadRange(long offset, Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        if (offset + destination.Length > PlaintextLength)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Read beyond end of object.");
        }

        while (!destination.IsEmpty)
        {
            long seg = offset / _segmentSize;
            int within = (int)(offset % _segmentSize);
            var plain = ReadSegment(seg);
            int n = Math.Min(plain.Length - within, destination.Length);
            plain.Slice(within, n).CopyTo(destination);
            destination = destination[n..];
            offset += n;
        }
    }

    /// <summary>Authenticates every segment. Used by verification.</summary>
    public void VerifyAll()
    {
        for (long i = 0; i < SegmentCount; i++)
        {
            ReadSegment(i);
        }
    }

    /// <summary>Decrypts the whole object into memory. Only for small metadata objects.</summary>
    public byte[] ReadAll(long maxLength = 512L * 1024 * 1024)
    {
        if (PlaintextLength > maxLength)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Object is larger than permitted.");
        }

        var result = new byte[PlaintextLength];
        ReadRange(0, result);
        return result;
    }

    /// <summary>Copies all plaintext into <paramref name="destination"/>, authenticating segment by segment.</summary>
    public void CopyTo(Stream destination)
    {
        for (long i = 0; i < SegmentCount; i++)
        {
            destination.Write(ReadSegment(i));
        }
    }

    private static int ReadFully(Stream s, Span<byte> buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int n = s.Read(buffer[total..]);
            if (n == 0)
            {
                break;
            }

            total += n;
        }

        return total;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(_segmentBuffer);
        ArrayPool<byte>.Shared.Return(_segmentBuffer);
        ArrayPool<byte>.Shared.Return(_cipherBuffer);
        _gcm.Dispose();
    }
}
