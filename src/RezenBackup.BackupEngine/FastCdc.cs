using System.Buffers;
using System.Buffers.Binary;
using RezenBackup.Crypto;

namespace RezenBackup.BackupEngine;

/// <summary>
/// FastCDC content-defined chunking (Xia et al., USENIX ATC 2016) with normalized chunking level 2 and a
/// <b>keyed</b> gear table derived from the repository key, so boundaries depend on the key (DESIGN §14.2).
/// </summary>
public sealed class FastCdc
{
    private readonly ulong[] _gear = new ulong[256];
    private readonly ulong _maskS;
    private readonly ulong _maskL;

    public FastCdc(RepositoryKeys keys, int min, int avg, int max)
    {
        ArgumentNullException.ThrowIfNull(keys);
        if (min <= 0 || min > avg || avg > max)
        {
            throw new ArgumentOutOfRangeException(nameof(avg), "Chunk sizes must satisfy 0 < min <= avg <= max.");
        }

        Min = min;
        Avg = avg;
        Max = max;
        var table = new byte[256 * 8];
        keys.DeriveCdcGearTable(table);
        for (int i = 0; i < 256; i++)
        {
            _gear[i] = BinaryPrimitives.ReadUInt64LittleEndian(table.AsSpan(i * 8));
        }

        int bits = (int)Math.Round(Math.Log2(avg));
        _maskS = TopBits(bits + 2);
        _maskL = TopBits(Math.Max(1, bits - 2));
    }

    public int Min { get; }

    public int Avg { get; }

    public int Max { get; }

    private static ulong TopBits(int n) => n >= 64 ? ulong.MaxValue : ~0UL << (64 - n);

    /// <summary>Returns the length of the next chunk at the start of <paramref name="data"/>.</summary>
    public int FindCut(ReadOnlySpan<byte> data, bool isFinal)
    {
        int n = data.Length;
        if (n <= Min)
        {
            return n;
        }

        if (n > Max)
        {
            n = Max;
        }
        else if (!isFinal && n < Max)
        {
            // Caller must supply at least Max bytes unless at end of input.
            throw new ArgumentException("Insufficient data for a non-final cut.", nameof(data));
        }

        int normal = Math.Min(Avg, n);
        ulong fp = 0;
        int i = Min;
        for (; i < normal; i++)
        {
            fp = (fp << 1) + _gear[data[i]];
            if ((fp & _maskS) == 0)
            {
                return i + 1;
            }
        }

        for (; i < n; i++)
        {
            fp = (fp << 1) + _gear[data[i]];
            if ((fp & _maskL) == 0)
            {
                return i + 1;
            }
        }

        return n;
    }

    /// <summary>
    /// Splits a stream into chunks, invoking <paramref name="onChunk"/> for each. The span passed to the callback is
    /// only valid during the call. Buffers are wiped after use.
    /// </summary>
    public void Split(Stream input, Action<ReadOnlySpan<byte>> onChunk, CancellationToken ct = default)
    {
        int capacity = Max * 2;
        var buffer = ArrayPool<byte>.Shared.Rent(capacity);
        try
        {
            int start = 0;
            int end = 0;
            bool eof = false;
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                // Refill so at least Max bytes are available (or EOF).
                if (!eof && end - start < Max)
                {
                    if (start > 0)
                    {
                        Buffer.BlockCopy(buffer, start, buffer, 0, end - start);
                        end -= start;
                        start = 0;
                    }

                    while (end < capacity)
                    {
                        int read = input.Read(buffer, end, capacity - end);
                        if (read == 0)
                        {
                            eof = true;
                            break;
                        }

                        end += read;
                    }
                }

                int available = end - start;
                if (available == 0)
                {
                    break;
                }

                int cut = FindCut(buffer.AsSpan(start, available), isFinal: eof);
                onChunk(buffer.AsSpan(start, cut));
                start += cut;
            }
        }
        finally
        {
            Array.Clear(buffer, 0, capacity);
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
