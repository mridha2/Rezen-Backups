namespace RezenBackup.Crypto;

/// <summary>Categories of cryptographic failure. Messages shown to users are chosen by higher layers.</summary>
public enum CryptoError
{
    /// <summary>Authentication tag did not verify: data was modified, corrupted, truncated, or the key is wrong.</summary>
    AuthenticationFailed,

    /// <summary>A structure (header, parameter block) is malformed or out of permitted bounds.</summary>
    InvalidFormat,

    /// <summary>The object was produced by an unknown/newer algorithm or format version.</summary>
    UnsupportedVersion,

    /// <summary>Password or recovery key did not unlock the key material.</summary>
    WrongKey,

    /// <summary>A recovery key was mistyped (checksum mismatch or bad characters).</summary>
    RecoveryKeyMalformed,

    /// <summary>The native cryptographic library is missing or failed to initialize.</summary>
    LibraryUnavailable,

    /// <summary>Key derivation failed (typically insufficient memory for Argon2id).</summary>
    KeyDerivationFailed,
}

/// <summary>
/// Raised for every cryptographic failure. Never contains key material or plaintext.
/// </summary>
public sealed class CryptoException : Exception
{
    public CryptoException(CryptoError error, string message)
        : base(message)
    {
        Error = error;
    }

    public CryptoException(CryptoError error, string message, Exception inner)
        : base(message, inner)
    {
        Error = error;
    }

    public CryptoError Error { get; }
}
