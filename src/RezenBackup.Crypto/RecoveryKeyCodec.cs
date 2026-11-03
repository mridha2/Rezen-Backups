using System.Security.Cryptography;
using System.Text;

namespace RezenBackup.Crypto;

/// <summary>
/// Human-readable encoding of the 256-bit Root Secret (DESIGN §7.1):
/// <c>RZN1-XXXX-XXXX-…</c> — 14 groups of 4 Crockford Base32 characters carrying 256 secret bits,
/// a 20-bit typo checksum and 4 zero padding bits.
/// </summary>
public static class RecoveryKeyCodec
{
    public const string Prefix = "RZN1";
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private const int Chars = 56;
    private const int GroupSize = 4;

    public static string Encode(RootSecret secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        Span<byte> payload = stackalloc byte[35]; // 256 + 20 + 4 = 280 bits
        try
        {
            secret.Bytes.CopyTo(payload);
            Span<byte> checksum = stackalloc byte[3];
            ComputeChecksum(secret.Bytes, checksum);
            // 20 checksum bits: checksum[0], checksum[1], high nibble of checksum[2]; low nibble = zero padding.
            payload[32] = checksum[0];
            payload[33] = checksum[1];
            payload[34] = (byte)(checksum[2] & 0xF0);

            var chars = new char[Chars];
            for (int i = 0; i < Chars; i++)
            {
                chars[i] = Alphabet[ReadBits(payload, i * 5, 5)];
            }

            var sb = new StringBuilder(Prefix.Length + Chars + (Chars / GroupSize));
            sb.Append(Prefix);
            for (int i = 0; i < Chars; i += GroupSize)
            {
                sb.Append('-').Append(chars, i, GroupSize);
            }

            SecureMemory.Wipe(chars);
            return sb.ToString();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    /// <summary>
    /// Parses a recovery key. Case-insensitive; hyphens, spaces and the RZN1 prefix are optional; Crockford aliases
    /// (O→0, I/L→1) are accepted.
    /// </summary>
    public static RootSecret Decode(ReadOnlySpan<char> text)
    {
        Span<char> clean = stackalloc char[128];
        int n = 0;
        foreach (char raw in text)
        {
            char c = char.ToUpperInvariant(raw);
            if (c is '-' or ' ' or '\t' or '\r' or '\n')
            {
                continue;
            }

            if (n >= clean.Length)
            {
                throw new CryptoException(CryptoError.RecoveryKeyMalformed, "The recovery key is too long.");
            }

            clean[n++] = c;
        }

        Span<char> body = clean[..n];
        if (body.StartsWith(Prefix.AsSpan()))
        {
            body = body[Prefix.Length..];
        }

        if (body.Length != Chars)
        {
            SecureMemory.Wipe(clean);
            throw new CryptoException(CryptoError.RecoveryKeyMalformed, "The recovery key has the wrong length.");
        }

        Span<byte> payload = stackalloc byte[35];
        try
        {
            payload.Clear();
            for (int i = 0; i < Chars; i++)
            {
                int v = ValueOf(body[i]);
                if (v < 0)
                {
                    throw new CryptoException(CryptoError.RecoveryKeyMalformed, "The recovery key contains invalid characters.");
                }

                WriteBits(payload, i * 5, 5, v);
            }

            if ((payload[34] & 0x0F) != 0)
            {
                throw new CryptoException(CryptoError.RecoveryKeyMalformed, "The recovery key is not valid. Check for typing mistakes.");
            }

            Span<byte> checksum = stackalloc byte[3];
            ComputeChecksum(payload[..32], checksum);
            if (payload[32] != checksum[0] || payload[33] != checksum[1] || payload[34] != (checksum[2] & 0xF0))
            {
                throw new CryptoException(CryptoError.RecoveryKeyMalformed, "The recovery key is not valid. Check for typing mistakes.");
            }

            return RootSecret.FromBytes(payload[..32]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            SecureMemory.Wipe(clean);
        }
    }

    /// <summary>Returns true if the text is syntactically a valid recovery key (checksum passes).</summary>
    public static bool IsWellFormed(ReadOnlySpan<char> text)
    {
        try
        {
            using var _ = Decode(text);
            return true;
        }
        catch (CryptoException)
        {
            return false;
        }
    }

    /// <summary>Returns the groups of a formatted key (without the prefix), used by the "confirm you saved it" step.</summary>
    public static string[] Groups(string formatted) => formatted.Split('-')[1..];

    private static void ComputeChecksum(ReadOnlySpan<byte> secret, Span<byte> destination)
    {
        Span<byte> input = stackalloc byte[6 + 32];
        "RZN-RK"u8.CopyTo(input);
        secret.CopyTo(input[6..]);
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(input, hash);
        hash[..3].CopyTo(destination);
        CryptographicOperations.ZeroMemory(input);
    }

    private static int ValueOf(char c) => c switch
    {
        'O' => 0,
        'I' or 'L' => 1,
        _ => Alphabet.IndexOf(c, StringComparison.Ordinal),
    };

    private static int ReadBits(ReadOnlySpan<byte> data, int bitOffset, int count)
    {
        int value = 0;
        for (int i = 0; i < count; i++)
        {
            int bit = bitOffset + i;
            value = (value << 1) | ((data[bit >> 3] >> (7 - (bit & 7))) & 1);
        }

        return value;
    }

    private static void WriteBits(Span<byte> data, int bitOffset, int count, int value)
    {
        for (int i = 0; i < count; i++)
        {
            int bit = bitOffset + i;
            int v = (value >> (count - 1 - i)) & 1;
            if (v != 0)
            {
                data[bit >> 3] |= (byte)(1 << (7 - (bit & 7)));
            }
        }
    }
}
