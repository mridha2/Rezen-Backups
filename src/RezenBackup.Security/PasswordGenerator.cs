using System.Security.Cryptography;

namespace RezenBackup.Security;

/// <summary>
/// Generates random backup passwords such as <c>k7Qm-x9Tp-Wd4h-…</c>: six groups of four characters from an alphabet
/// without look-alike characters (no 0/O, 1/l/I), so the password can be read off paper and typed on another computer.
/// 24 characters from 56 symbols is about 139 bits of entropy, drawn from the operating system's CSPRNG.
/// </summary>
public static class PasswordGenerator
{
    public const string Alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    public const int Groups = 6;
    public const int GroupLength = 4;
    public const char Separator = '-';

    public static double EntropyBits => Groups * GroupLength * Math.Log2(Alphabet.Length);

    public static string Generate()
    {
        // Resample in the rare case the strength estimate dislikes the result (e.g. a random "abcd" run), so a
        // generated password is always shown as "Very strong". This discards a negligible share of the space.
        while (true)
        {
            var chars = new char[(Groups * GroupLength) + Groups - 1];
            int pos = 0;
            for (int g = 0; g < Groups; g++)
            {
                if (g > 0)
                {
                    chars[pos++] = Separator;
                }

                for (int i = 0; i < GroupLength; i++)
                {
                    chars[pos++] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
                }
            }

            var password = new string(chars);
            Array.Clear(chars);
            if (PasswordPolicy.Assess(password).Strength == PasswordStrength.VeryStrong)
            {
                return password;
            }
        }
    }
}
