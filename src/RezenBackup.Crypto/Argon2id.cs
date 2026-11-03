using System.Diagnostics;
using RezenBackup.Crypto.Native;

namespace RezenBackup.Crypto;

/// <summary>Argon2id cost parameters. Stored alongside each password slot so they can be raised over time (spec §6).</summary>
public readonly record struct KdfParameters(int MemoryKiB, int Iterations, int Parallelism)
{
    /// <summary>v1 default: 256 MiB, 3 passes, 1 lane (libsodium supports a single lane).</summary>
    public static KdfParameters Default => new(256 * 1024, 3, 1);

    /// <summary>Smallest parameters accepted when <em>creating</em> a slot in production.</summary>
    public static KdfParameters MinimumForNewSlots => new(256 * 1024, 3, 1);

    // Bounds accepted when *reading* a slot (protects against DoS from a tampered key file).
    public const int MinReadMemoryKiB = 8 * 1024;
    public const int MaxReadMemoryKiB = 4 * 1024 * 1024;
    public const int MinIterations = 1;
    public const int MaxIterations = 20;

    public bool IsWithinReadBounds =>
        MemoryKiB is >= MinReadMemoryKiB and <= MaxReadMemoryKiB &&
        Iterations is >= MinIterations and <= MaxIterations &&
        Parallelism == 1;

    public bool IsAtLeast(KdfParameters other) => MemoryKiB >= other.MemoryKiB && Iterations >= other.Iterations;

    public override string ToString() => $"argon2id(m={MemoryKiB / 1024}MiB,t={Iterations},p={Parallelism})";
}

/// <summary>Process-wide KDF policy. Weak parameters are only permitted inside the automated test suite.</summary>
public static class KdfPolicy
{
    private static volatile bool _allowWeak;

    /// <summary>For unit tests only: allows small Argon2 parameters so the suite runs quickly.</summary>
    internal static bool AllowWeakParametersForTesting
    {
        get => _allowWeak;
        set => _allowWeak = value;
    }

    /// <summary>True only inside the automated test suite (weak parameters allowed, no calibration).</summary>
    public static bool IsTestMode => _allowWeak;

    /// <summary>Parameters the application should use for new slots. Never weaker than <see cref="KdfParameters.MinimumForNewSlots"/> outside tests.</summary>
    public static KdfParameters Current { get; private set; } = KdfParameters.Default;

    internal static void UseForTesting(KdfParameters parameters)
    {
        AllowWeakParametersForTesting = true;
        Current = parameters;
    }

    public static void EnsureAcceptableForNewSlot(KdfParameters parameters)
    {
        if (!parameters.IsWithinReadBounds)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Key derivation parameters are out of bounds.");
        }

        if (!_allowWeak && !parameters.IsAtLeast(KdfParameters.MinimumForNewSlots))
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Key derivation parameters are weaker than the permitted minimum.");
        }
    }
}

/// <summary>Argon2id (RFC 9106) via libsodium <c>crypto_pwhash</c>.</summary>
public static class Argon2id
{
    public const int SaltLength = Sodium.SaltBytes;

    /// <summary>
    /// Derives <paramref name="output"/>.Length bytes from a password. The password span is not retained or copied
    /// into managed memory by this method.
    /// </summary>
    public static unsafe void DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, KdfParameters parameters, Span<byte> output)
    {
        if (salt.Length != SaltLength)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Invalid salt length.");
        }

        if (!parameters.IsWithinReadBounds)
        {
            throw new CryptoException(CryptoError.InvalidFormat, "Key derivation parameters are out of bounds.");
        }

        if (output.Length < 16)
        {
            throw new ArgumentException("Output too short.", nameof(output));
        }

        Sodium.EnsureInitialized();

        // libsodium requires a non-null password pointer even for empty input.
        Span<byte> empty = stackalloc byte[1];
        fixed (byte* pOut = output)
        fixed (byte* pPw = password.Length == 0 ? empty : password)
        fixed (byte* pSalt = salt)
        {
            int rc = Sodium.crypto_pwhash(
                pOut,
                (ulong)output.Length,
                pPw,
                (ulong)password.Length,
                pSalt,
                (ulong)parameters.Iterations,
                (nuint)((long)parameters.MemoryKiB * 1024),
                Sodium.AlgArgon2Id13);

            if (rc != 0)
            {
                output.Clear();
                throw new CryptoException(CryptoError.KeyDerivationFailed, "Password key derivation failed (insufficient memory?).");
            }
        }
    }

    /// <summary>
    /// Chooses the iteration count so one derivation takes roughly <paramref name="target"/> on this machine,
    /// keeping memory fixed so that weaker computers can still unlock the backup.
    /// </summary>
    public static KdfParameters Calibrate(TimeSpan target, int memoryKiB = 256 * 1024, int maxIterations = 10)
    {
        var baseline = new KdfParameters(memoryKiB, 1, 1);
        Span<byte> salt = stackalloc byte[SaltLength];
        Span<byte> outBuf = stackalloc byte[32];
        CryptoRandom.Fill(salt);
        ReadOnlySpan<byte> probe = "calibration"u8;

        var sw = Stopwatch.StartNew();
        DeriveKey(probe, salt, baseline, outBuf);
        sw.Stop();
        outBuf.Clear();

        double perPass = Math.Max(1, sw.Elapsed.TotalMilliseconds);
        int iterations = (int)Math.Round(target.TotalMilliseconds / perPass);
        iterations = Math.Clamp(iterations, KdfParameters.Default.Iterations, maxIterations);
        return new KdfParameters(memoryKiB, iterations, 1);
    }
}
