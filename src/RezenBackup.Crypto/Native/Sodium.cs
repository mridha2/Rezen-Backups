using System.Runtime.InteropServices;

namespace RezenBackup.Crypto.Native;

/// <summary>
/// Minimal, audited-surface binding to libsodium. Only the functions Rezen Backup needs are exposed:
/// Argon2id password hashing and guarded memory allocation. All other cryptography uses the .NET BCL
/// (Windows CNG / Apple CommonCrypto / OpenSSL) through System.Security.Cryptography.
/// </summary>
internal static partial class Sodium
{
    private const string Library = "libsodium";

    /// <summary>crypto_pwhash_ALG_ARGON2ID13</summary>
    public const int AlgArgon2Id13 = 2;

    /// <summary>crypto_pwhash_SALTBYTES</summary>
    public const int SaltBytes = 16;

    private static readonly object InitLock = new();
    private static bool _initialized;

    public static void EnsureInitialized()
    {
        if (Volatile.Read(ref _initialized))
        {
            return;
        }

        lock (InitLock)
        {
            if (_initialized)
            {
                return;
            }

            // sodium_init returns 0 on success, 1 if already initialized, -1 on failure.
            if (sodium_init() < 0)
            {
                throw new CryptoException(CryptoError.LibraryUnavailable, "The cryptographic library could not be initialized.");
            }

            Volatile.Write(ref _initialized, true);
        }
    }

    [LibraryImport(Library)]
    private static partial int sodium_init();

    [LibraryImport(Library)]
    internal static unsafe partial int crypto_pwhash(
        byte* output,
        ulong outputLength,
        byte* password,
        ulong passwordLength,
        byte* salt,
        ulong opsLimit,
        nuint memLimit,
        int algorithm);

    /// <summary>X25519: q = n·B (public key from private scalar).</summary>
    [LibraryImport(Library)]
    internal static unsafe partial int crypto_scalarmult_base(byte* q, byte* n);

    /// <summary>X25519: q = n·p. Returns -1 if the result is the all-zero point (low-order input).</summary>
    [LibraryImport(Library)]
    internal static unsafe partial int crypto_scalarmult(byte* q, byte* n, byte* p);

    [LibraryImport(Library)]
    internal static partial nint sodium_malloc(nuint size);

    [LibraryImport(Library)]
    internal static partial void sodium_free(nint ptr);

    [LibraryImport(Library)]
    internal static partial void sodium_memzero(nint ptr, nuint length);
}
