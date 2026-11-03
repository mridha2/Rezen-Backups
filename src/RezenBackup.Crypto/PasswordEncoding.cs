using System.Text;

namespace RezenBackup.Crypto;

/// <summary>
/// Converts a user-typed password to the exact bytes fed into Argon2id: Unicode NFC normalization, then UTF-8.
/// NFC guarantees the same passphrase yields the same key on Windows and macOS regardless of keyboard/IME
/// composition (DESIGN §5.3, R-D9).
/// </summary>
public static class PasswordEncoding
{
    /// <summary>
    /// Returns a <see cref="SecretBuffer"/> containing NFC-normalized UTF-8 bytes. The caller should wipe
    /// <paramref name="password"/> after this call.
    /// </summary>
    public static SecretBuffer ToKeyMaterial(ReadOnlySpan<char> password)
    {
        // String.Normalize requires a managed string; this is the one documented short-lived managed copy
        // (DESIGN §22.3). It is released immediately and never stored.
        string? normalized = null;
        char[]? normalizedChars = null;
        try
        {
            string temp = new(password);
            normalized = temp.IsNormalized(NormalizationForm.FormC) ? temp : temp.Normalize(NormalizationForm.FormC);
            normalizedChars = normalized.ToCharArray();

            int byteCount = Encoding.UTF8.GetByteCount(normalizedChars);
            var buffer = new SecretBuffer(Math.Max(byteCount, 1));
            if (byteCount == 0)
            {
                // Represent empty with a 1-byte buffer of length 0 semantics is not possible; callers reject empty passwords.
                buffer.Dispose();
                throw new ArgumentException("Password must not be empty.", nameof(password));
            }

            Encoding.UTF8.GetBytes(normalizedChars, buffer.Span);
            return buffer;
        }
        finally
        {
            if (normalizedChars is not null)
            {
                SecureMemory.Wipe(normalizedChars);
            }
        }
    }
}
