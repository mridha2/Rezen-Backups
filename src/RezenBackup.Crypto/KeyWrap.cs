using System.Security.Cryptography;

namespace RezenBackup.Crypto;

/// <summary>A Root Secret wrapped under a password-derived key (one key slot, DESIGN §6.3).</summary>
public sealed record WrappedSecret(KdfParameters Kdf, byte[] Salt, byte[] Nonce, byte[] Ciphertext, byte[] Tag);

/// <summary>
/// Wraps and unwraps the Root Secret with a key derived from a password by Argon2id. Every wrap uses a fresh salt,
/// hence a fresh key-encryption key, plus a random nonce, so nonce reuse is impossible.
/// </summary>
public static class KeyWrap
{
    public static WrappedSecret WrapWithPassword(RootSecret secret, SecretBuffer passwordBytes, KdfParameters kdf, ReadOnlySpan<byte> associatedData)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentNullException.ThrowIfNull(passwordBytes);
        KdfPolicy.EnsureAcceptableForNewSlot(kdf);

        var salt = CryptoRandom.Bytes(Argon2id.SaltLength);
        var nonce = CryptoRandom.Bytes(12);
        using var kek = new SecretBuffer(32);
        Argon2id.DeriveKey(passwordBytes.ReadOnlySpan, salt, kdf, kek.Span);

        var ciphertext = new byte[RootSecret.Length];
        var tag = new byte[16];
        using var gcm = new AesGcm(kek.ReadOnlySpan, 16);
        gcm.Encrypt(nonce, secret.Bytes, ciphertext, tag, Aad(kdf, salt, associatedData));
        return new WrappedSecret(kdf, salt, nonce, ciphertext, tag);
    }

    /// <summary>Returns the Root Secret, or throws <see cref="CryptoError.WrongKey"/> without revealing why.</summary>
    public static RootSecret UnwrapWithPassword(WrappedSecret wrapped, SecretBuffer passwordBytes, ReadOnlySpan<byte> associatedData)
    {
        ArgumentNullException.ThrowIfNull(wrapped);
        ArgumentNullException.ThrowIfNull(passwordBytes);
        if (!wrapped.Kdf.IsWithinReadBounds || wrapped.Salt.Length != Argon2id.SaltLength || wrapped.Nonce.Length != 12 ||
            wrapped.Ciphertext.Length != RootSecret.Length || wrapped.Tag.Length != 16)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Key slot is malformed.");
        }

        using var kek = new SecretBuffer(32);
        Argon2id.DeriveKey(passwordBytes.ReadOnlySpan, wrapped.Salt, wrapped.Kdf, kek.Span);
        using var plain = new SecretBuffer(RootSecret.Length);
        using var gcm = new AesGcm(kek.ReadOnlySpan, 16);
        try
        {
            gcm.Decrypt(wrapped.Nonce, wrapped.Ciphertext, wrapped.Tag, plain.Span, Aad(wrapped.Kdf, wrapped.Salt, associatedData));
        }
        catch (AuthenticationTagMismatchException ex)
        {
            throw new CryptoException(CryptoError.WrongKey, "Unable to unlock backup. Check your password or recovery key.", ex);
        }

        return RootSecret.FromBytes(plain.ReadOnlySpan);
    }

    private static byte[] Aad(KdfParameters kdf, byte[] salt, ReadOnlySpan<byte> context)
    {
        // AAD = "RZN-SLOT-v1" ‖ kdf params ‖ salt ‖ context (key-set ID): binds the slot descriptor to the ciphertext.
        var aad = new byte[11 + 12 + salt.Length + context.Length];
        "RZN-SLOT-v1"u8.CopyTo(aad);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(11), kdf.MemoryKiB);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(15), kdf.Iterations);
        System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(aad.AsSpan(19), kdf.Parallelism);
        salt.CopyTo(aad, 23);
        context.CopyTo(aad.AsSpan(23 + salt.Length));
        return aad;
    }
}
