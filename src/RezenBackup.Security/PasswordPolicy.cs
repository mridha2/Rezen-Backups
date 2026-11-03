using System.Globalization;
using System.Reflection;

namespace RezenBackup.Security;

public enum PasswordStrength
{
    VeryWeak = 0,
    Weak = 1,
    Fair = 2,
    Strong = 3,
    VeryStrong = 4,
}

public sealed record PasswordAssessment(
    PasswordStrength Strength,
    double EstimatedBits,
    bool MeetsRequirements,
    IReadOnlyList<string> Feedback,
    string CrackTimeDisplay)
{
    public string StrengthText => Strength switch
    {
        PasswordStrength.VeryWeak => "Very weak",
        PasswordStrength.Weak => "Weak",
        PasswordStrength.Fair => "Fair",
        PasswordStrength.Strong => "Strong",
        _ => "Very strong",
    };
}

/// <summary>
/// Password requirements (spec §7): at least 12 characters, no arbitrary composition rules, passphrases encouraged,
/// any Unicode allowed, no maximum length. Strength is estimated conservatively offline (no network lookups).
/// </summary>
public static class PasswordPolicy
{
    public const int MinimumLength = 12;
    public const int RecommendedLength = 16;

    private static readonly Lazy<string[]> Common = new(LoadCommon);

    private static string[] LoadCommon()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("RezenBackup.Security.common-passwords.txt");
        if (stream is null)
        {
            return [];
        }

        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(w => w.Length >= 4).OrderByDescending(w => w.Length).ToArray();
    }

    private static readonly string[] Sequences =
    [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "qwertyuiopasdfghjklzxcvbnm",
        "qwertzuiopasdfghjklyxcvbnm",
        "azertyuiopqsdfghjklmwxcvbn",
    ];

    public static PasswordAssessment Assess(ReadOnlySpan<char> password)
    {
        var feedback = new List<string>();
        int length = new StringInfo(new string(password)).LengthInTextElements;
        if (length == 0)
        {
            return new PasswordAssessment(PasswordStrength.VeryWeak, 0, false, ["Enter a password."], "instantly");
        }

        bool lower = false, upper = false, digit = false, symbol = false, space = false, other = false;
        foreach (char c in password)
        {
            if (char.IsAsciiLetterLower(c)) lower = true;
            else if (char.IsAsciiLetterUpper(c)) upper = true;
            else if (char.IsAsciiDigit(c)) digit = true;
            else if (c == ' ') space = true;
            else if (c < 128) symbol = true;
            else other = true;
        }

        int charset = (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) + (symbol ? 33 : 0) + (space ? 1 : 0) + (other ? 100 : 0);
        double bitsPerChar = Math.Log2(Math.Max(charset, 2));

        // Conservative: real passwords have structure, so count half of the naive entropy.
        double bits = length * bitsPerChar * 0.5;

        var lowerText = new string(password).ToLowerInvariant();
        var deLeet = lowerText.Replace('0', 'o').Replace('1', 'l').Replace('3', 'e').Replace('4', 'a').Replace('5', 's').Replace('@', 'a').Replace('$', 's').Replace('7', 't');

        // Passphrases: several words separated by spaces or punctuation are strong and memorable.
        var words = lowerText.Split([' ', '-', '_', '.', ','], StringSplitOptions.RemoveEmptyEntries).Where(w => w.Length >= 3).ToArray();
        bool passphrase = words.Length >= 4 && words.Distinct().Count() >= 4;

        // Penalise common passwords contained in the text (individual dictionary words are expected in passphrases).
        int commonCovered = 0;
        foreach (var word in passphrase ? [] : Common.Value)
        {
            if (lowerText.Contains(word, StringComparison.Ordinal) || deLeet.Contains(word, StringComparison.Ordinal))
            {
                commonCovered += word.Length;
                feedback.Add("Avoid common passwords and words like \"" + word + "\".");
                break;
            }
        }

        // Penalise keyboard or alphabet sequences and repeated characters.
        int sequential = LongestSequence(lowerText);
        int repeated = LongestRepeat(lowerText);
        int distinct = lowerText.Distinct().Count();
        if (sequential >= 4)
        {
            feedback.Add("Avoid sequences like \"abcd\" or \"1234\".");
        }

        if (repeated >= 3)
        {
            feedback.Add("Avoid repeated characters.");
        }

        int weakChars = Math.Min(length, commonCovered + Math.Max(0, sequential - 2) + Math.Max(0, repeated - 1));
        bits -= weakChars * bitsPerChar * 0.5;
        if (distinct <= 4)
        {
            bits = Math.Min(bits, distinct * 4);
        }

        if (passphrase)
        {
            bits = Math.Max(bits, words.Distinct().Count() * 11.0);
        }

        bits = Math.Max(0, bits);
        if (length < MinimumLength)
        {
            feedback.Insert(0, $"Use at least {MinimumLength} characters.");
        }
        else if (length < RecommendedLength)
        {
            feedback.Add($"{RecommendedLength} or more characters is recommended — a passphrase of four or more words works well.");
        }

        var strength = bits switch
        {
            < 28 => PasswordStrength.VeryWeak,
            < 36 => PasswordStrength.Weak,
            < 50 => PasswordStrength.Fair,
            < 70 => PasswordStrength.Strong,
            _ => PasswordStrength.VeryStrong,
        };

        bool meets = length >= MinimumLength && strength >= PasswordStrength.Fair;
        if (length >= MinimumLength && !meets)
        {
            feedback.Insert(0, "This password is too easy to guess.");
        }

        return new PasswordAssessment(strength, bits, meets, feedback, CrackTime(bits));
    }

    /// <summary>
    /// Offline attack estimate against Argon2id (256 MiB): assume a well-funded attacker at 100,000 guesses/second.
    /// </summary>
    private static string CrackTime(double bits)
    {
        double seconds = Math.Pow(2, Math.Max(0, bits - 1)) / 100_000;
        return seconds switch
        {
            < 1 => "instantly",
            < 60 => "seconds",
            < 3600 => "minutes",
            < 86_400 => "hours",
            < 2_592_000 => "days",
            < 31_536_000 => "months",
            < 3_153_600_000 => "years",
            _ => "centuries",
        };
    }

    private static int LongestSequence(string s)
    {
        int best = 0;
        foreach (var seq in Sequences)
        {
            foreach (var source in new[] { seq, new string(seq.Reverse().ToArray()) })
            {
                for (int len = Math.Min(s.Length, source.Length); len > best; len--)
                {
                    bool found = false;
                    for (int i = 0; i + len <= source.Length; i++)
                    {
                        if (s.Contains(source.AsSpan(i, len), StringComparison.Ordinal))
                        {
                            found = true;
                            break;
                        }
                    }

                    if (found)
                    {
                        best = len;
                        break;
                    }
                }
            }
        }

        return best;
    }

    private static int LongestRepeat(string s)
    {
        int best = s.Length > 0 ? 1 : 0;
        int run = 1;
        for (int i = 1; i < s.Length; i++)
        {
            run = s[i] == s[i - 1] ? run + 1 : 1;
            best = Math.Max(best, run);
        }

        return best;
    }
}
