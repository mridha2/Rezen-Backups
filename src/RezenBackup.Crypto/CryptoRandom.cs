using System.Security.Cryptography;

namespace RezenBackup.Crypto;

/// <summary>
/// The only source of randomness permitted for security values (spec §18): the operating system CSPRNG
/// (BCryptGenRandom on Windows, the kernel CSPRNG on macOS) via <see cref="RandomNumberGenerator"/>.
/// </summary>
public static class CryptoRandom
{
    public static void Fill(Span<byte> destination) => RandomNumberGenerator.Fill(destination);

    public static byte[] Bytes(int count)
    {
        var bytes = new byte[count];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }

    /// <summary>A random 128-bit identifier (repository, key set, snapshot, pack IDs). Identifiers are not secret.</summary>
    public static Guid NewId()
    {
        Span<byte> bytes = stackalloc byte[16];
        RandomNumberGenerator.Fill(bytes);
        return new Guid(bytes);
    }

    /// <summary>Uniform random integer in [0, maxExclusive).</summary>
    public static int NextInt(int maxExclusive) => RandomNumberGenerator.GetInt32(maxExclusive);
}
