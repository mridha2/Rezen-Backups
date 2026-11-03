using System.Formats.Cbor;
using System.Text;
using RezenBackup.Crypto;

namespace RezenBackup.Format;

/// <summary>Small helpers over System.Formats.Cbor for the positional-array encoding used by Format v1.</summary>
internal static class Cbor
{
    public static CborWriter NewWriter() => new(CborConformanceMode.Canonical, convertIndefiniteLengthEncodings: false);

    public static CborReader NewReader(ReadOnlyMemory<byte> data) => new(data, CborConformanceMode.Lax);

    public static void WriteGuid(this CborWriter w, Guid g) => w.WriteByteString(g.ToByteArray());

    public static Guid ReadGuid(this CborReader r)
    {
        var bytes = r.ReadByteString();
        if (bytes.Length != 16)
        {
            throw new FormatException("Invalid identifier.");
        }

        return new Guid(bytes);
    }

    public static void WriteNullableGuid(this CborWriter w, Guid? g)
    {
        if (g is { } v)
        {
            w.WriteGuid(v);
        }
        else
        {
            w.WriteNull();
        }
    }

    public static Guid? ReadNullableGuid(this CborReader r)
    {
        if (r.PeekState() == CborReaderState.Null)
        {
            r.ReadNull();
            return null;
        }

        return r.ReadGuid();
    }

    public static void WriteChunkId(this CborWriter w, ChunkId id) => w.WriteByteString(id.ToArray());

    public static ChunkId ReadChunkId(this CborReader r) => new(r.ReadByteString());

    public static void WriteNullableBytes(this CborWriter w, byte[]? bytes)
    {
        if (bytes is null)
        {
            w.WriteNull();
        }
        else
        {
            w.WriteByteString(bytes);
        }
    }

    public static byte[]? ReadNullableBytes(this CborReader r)
    {
        if (r.PeekState() == CborReaderState.Null)
        {
            r.ReadNull();
            return null;
        }

        return r.ReadByteString();
    }

    public static void WriteNullableText(this CborWriter w, string? text)
    {
        if (text is null)
        {
            w.WriteNull();
        }
        else
        {
            w.WriteTextStringSafe(text);
        }
    }

    public static string? ReadNullableText(this CborReader r)
    {
        if (r.PeekState() == CborReaderState.Null)
        {
            r.ReadNull();
            return null;
        }

        return r.ReadTextStringSafe();
    }

    public static void WriteNullableLong(this CborWriter w, long? v)
    {
        if (v is { } x)
        {
            w.WriteInt64(x);
        }
        else
        {
            w.WriteNull();
        }
    }

    public static long? ReadNullableLong(this CborReader r)
    {
        if (r.PeekState() == CborReaderState.Null)
        {
            r.ReadNull();
            return null;
        }

        return r.ReadInt64();
    }

    /// <summary>
    /// Writes a name exactly. Windows file names can contain unpaired UTF-16 surrogates that are not valid UTF-8;
    /// those are stored as a tagged byte string of their UTF-16LE code units so they round-trip byte-exact.
    /// </summary>
    public static void WriteTextStringSafe(this CborWriter w, string text)
    {
        if (IsValidUtf16(text))
        {
            w.WriteTextString(text);
        }
        else
        {
            w.WriteTag((CborTag)RawUtf16Tag);
            w.WriteByteString(Encoding.Unicode.GetBytes(text.ToCharArray()));
        }
    }

    public static string ReadTextStringSafe(this CborReader r)
    {
        if (r.PeekState() == CborReaderState.Tag)
        {
            var tag = r.ReadTag();
            if ((ulong)tag != RawUtf16Tag)
            {
                throw new FormatException("Unexpected tag.");
            }

            var bytes = r.ReadByteString();
            var chars = new char[bytes.Length / 2];
            Buffer.BlockCopy(bytes, 0, chars, 0, chars.Length * 2);
            return new string(chars);
        }

        return r.ReadTextString();
    }

    // Private-use CBOR tag number for raw UTF-16LE names.
    private const ulong RawUtf16Tag = 0x525A4E31; // "RZN1"

    private static bool IsValidUtf16(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 >= s.Length || !char.IsLowSurrogate(s[i + 1]))
                {
                    return false;
                }

                i++;
            }
            else if (char.IsLowSurrogate(c))
            {
                return false;
            }
        }

        return true;
    }
}
