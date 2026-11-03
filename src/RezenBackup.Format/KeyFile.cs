using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using RezenBackup.Core;
using RezenBackup.Core.Platform;
using RezenBackup.Crypto;

namespace RezenBackup.Format;

/// <summary>Raised when a key file copy is physically damaged (checksum mismatch), as opposed to a wrong password.</summary>
public sealed class KeyFileDamagedException : Exception
{
    public KeyFileDamagedException(string message)
        : base(message)
    {
    }

    public KeyFileDamagedException(string message, Exception inner)
        : base(message, inner)
    {
    }
}

/// <summary>
/// Key file (DESIGN §6.3): password slots wrapping the Key Set's Root Secret. Contains no plaintext secret,
/// no password and no recovery key.
/// </summary>
public sealed class KeyFile
{
    private static ReadOnlySpan<byte> Magic => "RZNBKKEY"u8;
    private const int HeaderSize = 8 + 2 + 16 + 16 + 8;
    private const int ChecksumSize = 32;

    public KeyFile(Guid keySetId, Guid repositoryId, ulong generation, IReadOnlyList<WrappedSecret> passwordSlots, byte[]? keyCheck)
    {
        KeySetId = keySetId;
        RepositoryId = repositoryId;
        Generation = generation;
        PasswordSlots = passwordSlots;
        KeyCheck = keyCheck;
    }

    public Guid KeySetId { get; }

    /// <summary><see cref="Guid.Empty"/> for the local (per-PC) copy of a Key Set.</summary>
    public Guid RepositoryId { get; }

    public ulong Generation { get; }

    public IReadOnlyList<WrappedSecret> PasswordSlots { get; }

    public byte[]? KeyCheck { get; }

    public KdfParameters WeakestKdf => PasswordSlots.Count == 0 ? default : PasswordSlots.MinBy(s => s.Kdf.MemoryKiB * (long)s.Kdf.Iterations)!.Kdf;

    public static byte[] SlotContext(Guid keySetId)
    {
        var ctx = new byte[7 + 16];
        "keyset:"u8.CopyTo(ctx);
        keySetId.TryWriteBytes(ctx.AsSpan(7));
        return ctx;
    }

    public static KeyFile CreateWithPassword(Guid keySetId, Guid repositoryId, ulong generation, RootSecret secret, SecretBuffer passwordBytes, KdfParameters kdf)
    {
        var slot = KeyWrap.WrapWithPassword(secret, passwordBytes, kdf, SlotContext(keySetId));
        byte[]? check = null;
        if (repositoryId != Guid.Empty)
        {
            using var keys = secret.DeriveRepositoryKeys(repositoryId);
            check = keys.ComputeKeyCheck();
        }

        return new KeyFile(keySetId, repositoryId, generation, [slot], check);
    }

    /// <summary>Returns a copy re-targeted to another repository of the same Key Set (same slots, new key check).</summary>
    public KeyFile ForRepository(Guid repositoryId, RootSecret secret)
    {
        using var keys = secret.DeriveRepositoryKeys(repositoryId);
        return new KeyFile(KeySetId, repositoryId, Generation, PasswordSlots, keys.ComputeKeyCheck());
    }

    /// <summary>Unwraps the Root Secret with a password; throws <see cref="CryptoError.WrongKey"/> if no slot opens.</summary>
    public RootSecret Unlock(SecretBuffer passwordBytes)
    {
        CryptoException? last = null;
        foreach (var slot in PasswordSlots)
        {
            try
            {
                var secret = KeyWrap.UnwrapWithPassword(slot, passwordBytes, SlotContext(KeySetId));
                if (!MatchesKeyCheck(secret))
                {
                    secret.Dispose();
                    throw new CryptoException(CryptoError.WrongKey, UserMessages.UnlockFailed);
                }

                return secret;
            }
            catch (CryptoException ex)
            {
                last = ex;
            }
        }

        throw last ?? new CryptoException(CryptoError.WrongKey, UserMessages.UnlockFailed);
    }

    public bool MatchesKeyCheck(RootSecret secret)
    {
        if (KeyCheck is null || RepositoryId == Guid.Empty)
        {
            return true;
        }

        using var keys = secret.DeriveRepositoryKeys(RepositoryId);
        return CryptographicOperations.FixedTimeEquals(keys.ComputeKeyCheck(), KeyCheck);
    }

    public byte[] Serialize()
    {
        var w = Cbor.NewWriter();
        w.WriteStartArray(2);
        w.WriteStartArray(PasswordSlots.Count);
        foreach (var s in PasswordSlots)
        {
            w.WriteStartArray(9);
            w.WriteTextString("password");
            w.WriteTextString("argon2id");
            w.WriteInt32(s.Kdf.MemoryKiB);
            w.WriteInt32(s.Kdf.Iterations);
            w.WriteInt32(s.Kdf.Parallelism);
            w.WriteByteString(s.Salt);
            w.WriteByteString(s.Nonce);
            w.WriteByteString(s.Ciphertext);
            w.WriteByteString(s.Tag);
            w.WriteEndArray();
        }

        w.WriteEndArray();
        w.WriteNullableBytes(KeyCheck);
        w.WriteEndArray();
        var body = w.Encode();

        var result = new byte[HeaderSize + body.Length + ChecksumSize];
        Magic.CopyTo(result);
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(8), 1);
        KeySetId.TryWriteBytes(result.AsSpan(10, 16));
        RepositoryId.TryWriteBytes(result.AsSpan(26, 16));
        BinaryPrimitives.WriteUInt64LittleEndian(result.AsSpan(42), Generation);
        body.CopyTo(result, HeaderSize);
        SHA256.HashData(result.AsSpan(0, HeaderSize + body.Length), result.AsSpan(HeaderSize + body.Length));
        return result;
    }

    public static KeyFile Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < HeaderSize + ChecksumSize || bytes.Length > 1024 * 1024 || !bytes[..8].SequenceEqual(Magic))
        {
            throw new KeyFileDamagedException("Key file is not recognised.");
        }

        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(bytes[..^ChecksumSize], hash);
        if (!hash.SequenceEqual(bytes[^ChecksumSize..]))
        {
            throw new KeyFileDamagedException("Key file is damaged (checksum mismatch).");
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(bytes[8..]) != 1)
        {
            throw new RezenException(ErrorCode.UnsupportedVersion);
        }

        var keySetId = new Guid(bytes.Slice(10, 16));
        var repositoryId = new Guid(bytes.Slice(26, 16));
        ulong generation = BinaryPrimitives.ReadUInt64LittleEndian(bytes[42..]);

        try
        {
            var r = Cbor.NewReader(bytes[HeaderSize..^ChecksumSize].ToArray());
            r.ReadStartArray();
            int? count = r.ReadStartArray();
            var slots = new List<WrappedSecret>();
            for (int i = 0; i < (count ?? 0); i++)
            {
                r.ReadStartArray();
                var type = r.ReadTextString();
                var kdfName = r.ReadTextString();
                int m = r.ReadInt32();
                int t = r.ReadInt32();
                int p = r.ReadInt32();
                var salt = r.ReadByteString();
                var nonce = r.ReadByteString();
                var ct = r.ReadByteString();
                var tag = r.ReadByteString();
                r.ReadEndArray();
                if (type == "password" && kdfName == "argon2id")
                {
                    slots.Add(new WrappedSecret(new KdfParameters(m, t, p), salt, nonce, ct, tag));
                }
            }

            r.ReadEndArray();
            var check = r.ReadNullableBytes();
            r.ReadEndArray();
            return new KeyFile(keySetId, repositoryId, generation, slots, check);
        }
        catch (Exception ex) when (ex is CborContentException or InvalidOperationException or FormatException)
        {
            throw new KeyFileDamagedException("Key file structure is invalid.", ex);
        }
    }
}

/// <summary>Reads and writes key file copies with write–verify–replace semantics (DESIGN §8.1).</summary>
public static class KeyFileStore
{
    public static KeyFile? TryRead(string path, out bool damaged)
    {
        damaged = false;
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            return KeyFile.Parse(File.ReadAllBytes(path));
        }
        catch (KeyFileDamagedException)
        {
            damaged = true;
            return null;
        }
        catch (IOException)
        {
            damaged = true;
            return null;
        }
    }

    /// <summary>
    /// Writes <paramref name="file"/> to <paramref name="path"/> atomically: write to <c>.new</c>, flush to the
    /// device, read back uncached, confirm it parses and that <paramref name="verify"/> succeeds, then replace.
    /// </summary>
    public static void WriteVerified(string path, KeyFile file, IDurableFileOps ops, Func<KeyFile, bool> verify)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".new";
        var bytes = file.Serialize();
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            fs.Write(bytes);
            ops.FlushToDevice(fs);
        }

        byte[] readBack;
        using (var vs = ops.OpenForVerification(tmp))
        using (var ms = new MemoryStream())
        {
            vs.CopyTo(ms);
            readBack = ms.ToArray();
        }

        var parsed = KeyFile.Parse(readBack);
        if (!readBack.AsSpan().SequenceEqual(bytes) || !verify(parsed))
        {
            File.Delete(tmp);
            throw new RezenException(ErrorCode.CommitFailed, "Key file verification after write failed.");
        }

        ops.AtomicMove(tmp, path, overwrite: true);
        ops.FlushDirectory(Path.GetDirectoryName(path)!);
    }
}
