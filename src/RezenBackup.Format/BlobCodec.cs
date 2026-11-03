using System.Buffers;
using System.IO.Compression;
using RezenBackup.Crypto;

namespace RezenBackup.Format;

public enum BlobCodec : byte
{
    None = 0,
    Brotli = 1,
}

/// <summary>
/// Per-blob compression. Decompression only ever runs on data that has already been authenticated, and output is
/// capped at the recorded raw length to prevent decompression bombs (DESIGN R-S16).
/// </summary>
public static class BlobCompression
{
    private const int Quality = 3;
    private const int Window = 22;

    /// <summary>Compresses if worthwhile; returns the stored bytes and the codec used.</summary>
    public static (byte[] Stored, BlobCodec Codec) Compress(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < 64)
        {
            return (raw.ToArray(), BlobCodec.None);
        }

        int max = BrotliEncoder.GetMaxCompressedLength(raw.Length);
        var rented = ArrayPool<byte>.Shared.Rent(max);
        try
        {
            if (BrotliEncoder.TryCompress(raw, rented, out int written, Quality, Window) && written < raw.Length * 97L / 100)
            {
                return (rented.AsSpan(0, written).ToArray(), BlobCodec.Brotli);
            }

            return (raw.ToArray(), BlobCodec.None);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    public static byte[] Decompress(ReadOnlySpan<byte> stored, BlobCodec codec, int rawLength)
    {
        switch (codec)
        {
            case BlobCodec.None:
                if (stored.Length != rawLength)
                {
                    throw new CryptoException(CryptoError.InvalidFormat, "Stored length mismatch.");
                }

                return stored.ToArray();

            case BlobCodec.Brotli:
                {
                    var output = new byte[rawLength];
                    if (!BrotliDecoder.TryDecompress(stored, output, out int written) || written != rawLength)
                    {
                        throw new CryptoException(CryptoError.InvalidFormat, "Decompression produced an unexpected length.");
                    }

                    return output;
                }

            default:
                throw new CryptoException(CryptoError.UnsupportedVersion, "Unknown compression codec.");
        }
    }
}
