using RezenBackup.Crypto;

namespace RezenBackup.Tests.Crypto;

public class StreamAeadTests
{
    private static (RootSecret Root, RepositoryKeys Keys) NewKeys()
    {
        var root = RootSecret.Generate();
        return (root, root.DeriveRepositoryKeys(CryptoRandom.NewId()));
    }

    private static byte[] Encrypt(RepositoryKeys keys, byte[] plaintext, ObjectType type = ObjectType.Snapshot, int segmentSize = 4096)
    {
        using var ms = new MemoryStream();
        var header = new ObjectHeader(type, keys.RepositoryId, CryptoRandom.Bytes(32), segmentSize);
        using (var w = new AeadStreamWriter(ms, keys, header))
        {
            // write in odd-sized pieces to exercise buffering
            int pos = 0;
            int step = 1;
            while (pos < plaintext.Length)
            {
                int n = Math.Min(step, plaintext.Length - pos);
                w.Write(plaintext.AsSpan(pos, n));
                pos += n;
                step = (step * 3) + 1;
            }

            w.Complete();
        }

        return ms.ToArray();
    }

    private static byte[] Decrypt(RepositoryKeys keys, byte[] cipher, ObjectType type = ObjectType.Snapshot)
    {
        using var ms = new MemoryStream(cipher);
        using var r = new AeadStreamReader(ms, keys, type);
        return r.ReadAll();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4095)]
    [InlineData(4096)]
    [InlineData(4097)]
    [InlineData(8192)]
    [InlineData(100_000)]
    public void RoundTrip_AllBoundarySizes(int size)
    {
        var (root, keys) = NewKeys();
        using (root)
        using (keys)
        {
            var data = CryptoRandom.Bytes(size);
            var cipher = Encrypt(keys, data);
            Assert.Equal(data, Decrypt(keys, cipher));
        }
    }

    [Fact]
    public void RandomAccess_ReadRange_MatchesPlaintext()
    {
        var (root, keys) = NewKeys();
        using (root)
        using (keys)
        {
            var data = CryptoRandom.Bytes(50_000);
            var cipher = Encrypt(keys, data);
            using var ms = new MemoryStream(cipher);
            using var r = new AeadStreamReader(ms, keys, ObjectType.Snapshot);
            var buf = new byte[10_000];
            r.ReadRange(3_000, buf);
            Assert.Equal(data.AsSpan(3_000, 10_000).ToArray(), buf);
        }
    }

    [Fact]
    public void FlippedBitAnywhere_IsDetected()
    {
        var (root, keys) = NewKeys();
        using (root)
        using (keys)
        {
            var data = CryptoRandom.Bytes(10_000);
            var cipher = Encrypt(keys, data);
            // Every byte position (header, ciphertext, tag) must be protected. Sample positions across the object.
            for (int pos = 0; pos < cipher.Length; pos += 97)
            {
                var tampered = (byte[])cipher.Clone();
                tampered[pos] ^= 0x01;
                Assert.ThrowsAny<CryptoException>(() => Decrypt(keys, tampered));
            }
        }
    }

    [Fact]
    public void ModifiedTag_IsDetected()
    {
        var (root, keys) = NewKeys();
        using (root)
        using (keys)
        {
            var cipher = Encrypt(keys, CryptoRandom.Bytes(100));
            cipher[^1] ^= 0x80;
            var ex = Assert.Throws<CryptoException>(() => Decrypt(keys, cipher));
            Assert.Equal(CryptoError.AuthenticationFailed, ex.Error);
        }
    }

    [Fact]
    public void TruncationAtSegmentBoundary_IsDetected()
    {
        var (root, keys) = NewKeys();
        using (root)
        using (keys)
        {
            var data = CryptoRandom.Bytes(4096 * 3);
            var cipher = Encrypt(keys, data);
            // Drop the final segment entirely: the remaining last segment was encrypted with last=0 and must fail.
            int stride = 4096 + 16;
            var truncated = cipher.AsSpan(0, ObjectHeader.Size + (2 * stride)).ToArray();
            Assert.Throws<CryptoException>(() => Decrypt(keys, truncated));
        }
    }

    [Fact]
    public void ReorderedSegments_AreDetected()
    {
        var (root, keys) = NewKeys();
        using (root)
        using (keys)
        {
            var data = CryptoRandom.Bytes((4096 * 3) + 10);
            var cipher = Encrypt(keys, data);
            int stride = 4096 + 16;
            var swapped = (byte[])cipher.Clone();
            Array.Copy(cipher, ObjectHeader.Size, swapped, ObjectHeader.Size + stride, stride);
            Array.Copy(cipher, ObjectHeader.Size + stride, swapped, ObjectHeader.Size, stride);
            Assert.Throws<CryptoException>(() => Decrypt(keys, swapped));
        }
    }

    [Fact]
    public void WrongRepositoryKeys_FailAuthentication()
    {
        var (root, keys) = NewKeys();
        using (root)
        using (keys)
        {
            var cipher = Encrypt(keys, CryptoRandom.Bytes(100));
            using var otherRoot = RootSecret.Generate();
            using var otherKeys = otherRoot.DeriveRepositoryKeys(keys.RepositoryId);
            Assert.Throws<CryptoException>(() => Decrypt(otherKeys, cipher));
        }
    }

    [Fact]
    public void ObjectTypeConfusion_IsRejected()
    {
        var (root, keys) = NewKeys();
        using (root)
        using (keys)
        {
            var cipher = Encrypt(keys, CryptoRandom.Bytes(100), ObjectType.Snapshot);
            Assert.Throws<CryptoException>(() => Decrypt(keys, cipher, ObjectType.Commit));
        }
    }

    [Fact]
    public void SameplaintextTwice_ProducesDifferentCiphertext()
    {
        var (root, keys) = NewKeys();
        using (root)
        using (keys)
        {
            var data = CryptoRandom.Bytes(1000);
            Assert.NotEqual(Encrypt(keys, data), Encrypt(keys, data));
        }
    }

    [Fact]
    public void ObjectKeys_AreUniquePerSalt_SoCounterNoncesNeverRepeatUnderOneKey()
    {
        var (root, keys) = NewKeys();
        using (root)
        using (keys)
        {
            var seen = new HashSet<string>();
            Span<byte> key = stackalloc byte[32];
            for (int i = 0; i < 2000; i++)
            {
                keys.DeriveObjectKey(KeyClass.Content, 1, CryptoRandom.Bytes(32), key);
                Assert.True(seen.Add(Convert.ToHexString(key)));
            }
        }
    }

    [Fact]
    public void UnsupportedVersion_IsRejected_NotGuessed()
    {
        var (root, keys) = NewKeys();
        using (root)
        using (keys)
        {
            var cipher = Encrypt(keys, CryptoRandom.Bytes(10));
            cipher[8] = 2; // formatVersion = 2
            var ex = Assert.Throws<CryptoException>(() => Decrypt(keys, cipher));
            Assert.Equal(CryptoError.UnsupportedVersion, ex.Error);
        }
    }
}
