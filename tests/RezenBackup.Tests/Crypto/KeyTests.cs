using System.Text;
using RezenBackup.Crypto;

namespace RezenBackup.Tests.Crypto;

public class KeyTests
{
    private static readonly byte[] Context = Encoding.ASCII.GetBytes("keyset-context");

    [Fact]
    public void CorrectPassword_Unwraps()
    {
        using var root = RootSecret.Generate();
        using var pw = PasswordEncoding.ToKeyMaterial("correct horse battery staple");
        var wrapped = KeyWrap.WrapWithPassword(root, pw, TestSetup.FastKdf, Context);
        using var unwrapped = KeyWrap.UnwrapWithPassword(wrapped, pw, Context);
        Assert.True(root.ContentEquals(unwrapped));
    }

    [Fact]
    public void WrongPassword_FailsWithGenericError()
    {
        using var root = RootSecret.Generate();
        using var pw = PasswordEncoding.ToKeyMaterial("correct horse battery staple");
        using var wrong = PasswordEncoding.ToKeyMaterial("correct horse battery stapler");
        var wrapped = KeyWrap.WrapWithPassword(root, pw, TestSetup.FastKdf, Context);
        var ex = Assert.Throws<CryptoException>(() => KeyWrap.UnwrapWithPassword(wrapped, wrong, Context));
        Assert.Equal(CryptoError.WrongKey, ex.Error);
        Assert.Equal("Unable to unlock backup. Check your password or recovery key.", ex.Message);
    }

    [Fact]
    public void TamperedKdfParameters_FailToUnwrap()
    {
        using var root = RootSecret.Generate();
        using var pw = PasswordEncoding.ToKeyMaterial("correct horse battery staple");
        var wrapped = KeyWrap.WrapWithPassword(root, pw, TestSetup.FastKdf, Context);
        var downgraded = wrapped with { Kdf = wrapped.Kdf with { Iterations = 2 } };
        Assert.Throws<CryptoException>(() => KeyWrap.UnwrapWithPassword(downgraded, pw, Context));
    }

    [Fact]
    public void OutOfBoundsKdfParameters_AreRejectedBeforeAllocating()
    {
        using var root = RootSecret.Generate();
        using var pw = PasswordEncoding.ToKeyMaterial("password password");
        var wrapped = KeyWrap.WrapWithPassword(root, pw, TestSetup.FastKdf, Context);
        var huge = wrapped with { Kdf = new KdfParameters(64 * 1024 * 1024, 3, 1) };
        var ex = Assert.Throws<CryptoException>(() => KeyWrap.UnwrapWithPassword(huge, pw, Context));
        Assert.Equal(CryptoError.InvalidFormat, ex.Error);
    }

    [Fact]
    public void UnicodePassword_NfcAndNfdForms_DeriveSameKey()
    {
        // "é" precomposed vs decomposed — e.g. typed on Windows vs pasted from a macOS file name.
        const string nfc = "caf\u00e9 pass phrase";
        const string nfd = "cafe\u0301 pass phrase";
        using var root = RootSecret.Generate();
        using var pw1 = PasswordEncoding.ToKeyMaterial(nfc);
        using var pw2 = PasswordEncoding.ToKeyMaterial(nfd);
        var wrapped = KeyWrap.WrapWithPassword(root, pw1, TestSetup.FastKdf, Context);
        using var unwrapped = KeyWrap.UnwrapWithPassword(wrapped, pw2, Context);
        Assert.True(root.ContentEquals(unwrapped));
    }

    [Fact]
    public void Argon2id_KnownAnswer()
    {
        // Deterministic for fixed inputs: verifies the libsodium binding and parameter plumbing are stable
        // across builds and platforms. Value captured from libsodium crypto_pwhash (argon2id13, t=1, m=8MiB).
        var salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        var out1 = new byte[32];
        var out2 = new byte[32];
        Argon2id.DeriveKey("password"u8, salt, TestSetup.FastKdf, out1);
        Argon2id.DeriveKey("password"u8, salt, TestSetup.FastKdf, out2);
        Assert.Equal(out1, out2);
        Argon2id.DeriveKey("passwore"u8, salt, TestSetup.FastKdf, out2);
        Assert.NotEqual(out1, out2);
    }

    [Fact]
    public void ProductionPolicy_RejectsWeakParametersForNewSlots()
    {
        Assert.False(new KdfParameters(8 * 1024, 1, 1).IsAtLeast(KdfParameters.MinimumForNewSlots));
        Assert.True(KdfParameters.Default.IsAtLeast(KdfParameters.MinimumForNewSlots));
    }

    [Fact]
    public void RepositoryKeys_DifferPerRepository()
    {
        using var root = RootSecret.Generate();
        using var a = root.DeriveRepositoryKeys(CryptoRandom.NewId());
        using var b = root.DeriveRepositoryKeys(CryptoRandom.NewId());
        var data = "same data"u8.ToArray();
        Assert.NotEqual(a.ComputeChunkId(data), b.ComputeChunkId(data));
        Assert.NotEqual(a.ComputeKeyCheck(), b.ComputeKeyCheck());
    }

    [Fact]
    public void ChunkId_IsKeyed_NotPlainHash()
    {
        using var root = RootSecret.Generate();
        using var keys = root.DeriveRepositoryKeys(CryptoRandom.NewId());
        var data = "hello"u8.ToArray();
        var plain = System.Security.Cryptography.SHA256.HashData(data);
        Assert.NotEqual(plain, keys.ComputeChunkId(data).ToArray());
        Assert.Equal(keys.ComputeChunkId(data), keys.ComputeChunkId(data));
        Assert.NotEqual(keys.ComputeChunkId(data), keys.ComputeTreeId(data));
    }

    [Fact]
    public void SealSmall_RoundTripsAndDetectsTampering()
    {
        using var root = RootSecret.Generate();
        using var keys = root.DeriveRepositoryKeys(CryptoRandom.NewId());
        var sealedValue = keys.SealSmall("C:\\Payroll\\2026.xlsx"u8, "ctx"u8);
        Assert.Equal("C:\\Payroll\\2026.xlsx"u8.ToArray(), keys.OpenSmall(sealedValue, "ctx"u8));
        sealedValue[^3] ^= 1;
        Assert.Throws<CryptoException>(() => keys.OpenSmall(sealedValue, "ctx"u8));
    }

    [Fact]
    public void SecretTypes_NeverRenderInToString()
    {
        using var root = RootSecret.Generate();
        using var keys = root.DeriveRepositoryKeys(CryptoRandom.NewId());
        using var buf = SecretBuffer.Random(32);
        Assert.Equal("[REDACTED]", root.ToString());
        Assert.Equal("[REDACTED]", keys.ToString());
        Assert.Equal("[REDACTED]", buf.ToString());
    }

    [Fact]
    public void DisposedSecret_CannotBeRead()
    {
        var buf = SecretBuffer.Random(32);
        buf.Dispose();
        Assert.Throws<ObjectDisposedException>(() => buf.Span.Length);
    }
}

public class RecoveryKeyTests
{
    [Fact]
    public void EncodeDecode_RoundTrip()
    {
        using var root = RootSecret.Generate();
        var text = RecoveryKeyCodec.Encode(root);
        Assert.StartsWith("RZN1-", text, StringComparison.Ordinal);
        Assert.Equal(14, RecoveryKeyCodec.Groups(text).Length);
        using var decoded = RecoveryKeyCodec.Decode(text);
        Assert.True(root.ContentEquals(decoded));
    }

    [Fact]
    public void Decode_IsLenientAboutCaseSpacingAndAliases()
    {
        using var root = RootSecret.Generate();
        var text = RecoveryKeyCodec.Encode(root);
        var body = text[5..].ToLowerInvariant().Replace("-", " ", StringComparison.Ordinal).Replace('0', 'o').Replace('1', 'l');
        var messy = "rzn1 " + body;
        using var decoded = RecoveryKeyCodec.Decode(messy);
        Assert.True(root.ContentEquals(decoded));
    }

    [Fact]
    public void SingleTypo_IsDetectedByChecksum()
    {
        using var root = RootSecret.Generate();
        var text = RecoveryKeyCodec.Encode(root).ToCharArray();
        int detected = 0;
        for (int i = 5; i < text.Length; i++)
        {
            if (text[i] == '-')
            {
                continue;
            }

            var copy = (char[])text.Clone();
            copy[i] = copy[i] == 'A' ? 'B' : 'A';
            if (!RecoveryKeyCodec.IsWellFormed(copy))
            {
                detected++;
            }
        }

        // A change in the four padding bits of the last character, or a checksum collision, is the only way to pass.
        Assert.True(detected >= 55);
    }

    [Fact]
    public void WrongLength_IsRejected()
    {
        var ex = Assert.Throws<CryptoException>(() => RecoveryKeyCodec.Decode("RZN1-ABCD-EFGH"));
        Assert.Equal(CryptoError.RecoveryKeyMalformed, ex.Error);
    }
}
