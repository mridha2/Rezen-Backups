using Microsoft.Extensions.Logging;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Crypto;
using RezenBackup.Format;
using RezenBackup.Logging;
using RezenBackup.Security;

namespace RezenBackup.Application;

public sealed record NewKeySet(KeySetInfo Info, RootSecret Secret, string RecoveryKey);

/// <summary>
/// Password, recovery key and remembered-credential management (DESIGN §6–9). The password is never stored; only
/// wrapped key slots are written (to the drive and a local copy).
/// </summary>
public sealed class KeySetService
{
    private readonly RezenApp _app;
    private int _failedAttempts;
    private DateTimeOffset _lockoutUntil = DateTimeOffset.MinValue;

    internal KeySetService(RezenApp app) => _app = app;

    public IReadOnlyList<KeySetInfo> All => _app.Db.KeySets();

    public KeySetInfo? Default => All.FirstOrDefault();

    /// <summary>Creates a Key Set: random Root Secret, Argon2id password slot, local key file and recovery key.</summary>
    public NewKeySet Create(ReadOnlySpan<char> password, string displayName = "Rezen Backup password")
    {
        var assessment = PasswordPolicy.Assess(password);
        if (!assessment.MeetsRequirements)
        {
            throw new RezenException(ErrorCode.PasswordTooWeak, string.Join(" ", assessment.Feedback));
        }

        var id = CryptoRandom.NewId();
        var secret = RootSecret.Generate();
        try
        {
            var kdf = KdfPolicy.IsTestMode ? KdfPolicy.Current : Argon2id.Calibrate(TimeSpan.FromSeconds(1));
            using var pw = PasswordEncoding.ToKeyMaterial(password);
            var keyFile = KeyFile.CreateWithPassword(id, id, 1, secret, pw, kdf);

            // Verify the slot opens with the password before anything depends on it.
            using (var check = keyFile.Unlock(pw))
            {
                if (!check.ContentEquals(secret))
                {
                    throw new RezenException(ErrorCode.EncryptionFailure, "Key slot verification failed.");
                }
            }

            KeyFileStore.WriteVerified(_app.Paths.LocalKeyFile(id), keyFile, _app.Platform.Durable, f => f.MatchesKeyCheck(secret));
            var info = new KeySetInfo
            {
                Id = id,
                DisplayName = displayName,
                CreatedUtc = DateTimeOffset.UtcNow,
                PasswordGeneration = 1,
                KdfDescription = kdf.ToString(),
            };
            _app.Db.UpsertKeySet(info);
            _app.SecurityLog.Record(SecurityEvents.KeySetCreated, null, kdf.ToString());
            return new NewKeySet(info, secret, RecoveryKeyCodec.Encode(secret));
        }
        catch
        {
            secret.Dispose();
            throw;
        }
    }

    public KeyFile? LocalKeyFile(Guid keySetId) => KeyFileStore.TryRead(_app.Paths.LocalKeyFile(keySetId), out _);

    /// <summary>
    /// Unlocks a Key Set with its password: the local key file first, then the key files on any connected drive.
    /// Failures are reported generically and slowed down after repeated attempts (cosmetic; Argon2id is the defence).
    /// </summary>
    public async Task<RootSecret> UnlockAsync(Guid keySetId, string password, CancellationToken ct = default)
    {
        var wait = _lockoutUntil - DateTimeOffset.UtcNow;
        if (wait > TimeSpan.Zero)
        {
            await Task.Delay(wait, ct).ConfigureAwait(false);
        }

        try
        {
            var secret = await Task.Run(() => UnlockCore(keySetId, password), ct).ConfigureAwait(false);
            _failedAttempts = 0;
            _app.SecurityLog.Record(SecurityEvents.Unlock);
            return secret;
        }
        catch (RezenException ex) when (ex.Code is ErrorCode.WrongPassword)
        {
            _failedAttempts++;
            if (_failedAttempts >= 5)
            {
                _lockoutUntil = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(Math.Min(60, Math.Pow(2, _failedAttempts - 5)));
            }

            _app.SecurityLog.Record(SecurityEvents.FailedUnlock);
            throw;
        }
    }

    private RootSecret UnlockCore(Guid keySetId, string password)
    {
        using var pw = PasswordEncoding.ToKeyMaterial(password);
        var local = LocalKeyFile(keySetId);
        bool wrongLocal = false;
        if (local is not null)
        {
            try
            {
                return local.Unlock(pw);
            }
            catch (CryptoException)
            {
                wrongLocal = true;
            }
        }

        // Local copy missing, damaged, or older than the drive's (password changed elsewhere): try connected drives.
        foreach (var repoPath in ConnectedRepositoryPaths(keySetId))
        {
            // A drive whose key files are older than this computer's (a password change is still pending for it) must
            // not unlock with the previous password, or the change could be undone here.
            if (local is not null && (Repository.ReadBestKeyFile(repoPath)?.Generation ?? 0) < local.Generation)
            {
                continue;
            }

            try
            {
                var secret = Repository.UnlockWithPassword(repoPath, pw, _app.Platform.Durable, out _);
                RestoreLocalKeyFile(keySetId, repoPath, secret);
                return secret;
            }
            catch (RezenException ex) when (ex.Code is ErrorCode.WrongPassword or ErrorCode.RecoveryKeyRequired)
            {
            }
        }

        if (local is null && !wrongLocal && !ConnectedRepositoryPaths(keySetId).Any())
        {
            throw new RezenException(ErrorCode.DriveNotRegistered, "Connect your backup drive to unlock this backup on this computer.", null, null);
        }

        throw new RezenException(ErrorCode.WrongPassword);
    }

    /// <summary>Unlocks with the recovery key and confirms it belongs to this Key Set.</summary>
    public RootSecret UnlockWithRecoveryKey(Guid keySetId, string recoveryKey)
    {
        RootSecret secret;
        try
        {
            secret = RecoveryKeyCodec.Decode(recoveryKey);
        }
        catch (CryptoException ex)
        {
            throw new RezenException(ErrorCode.RecoveryKeyMalformed, null, ex);
        }

        bool verified = false;
        var local = LocalKeyFile(keySetId);
        if (local is { KeyCheck: not null })
        {
            verified = local.MatchesKeyCheck(secret);
        }
        else
        {
            foreach (var path in ConnectedRepositoryPaths(keySetId))
            {
                try
                {
                    using var repo = Repository.Open(path, secret, _app.Platform.Durable);
                    verified = true;
                    break;
                }
                catch (RezenException)
                {
                }
            }
        }

        if (!verified)
        {
            secret.Dispose();
            _app.SecurityLog.Record(SecurityEvents.FailedUnlock, null, "recovery key");
            throw new RezenException(ErrorCode.WrongPassword);
        }

        _app.SecurityLog.Record(SecurityEvents.RecoveryKeyUsed);
        return secret;
    }

    private void RestoreLocalKeyFile(Guid keySetId, string repoPath, RootSecret secret)
    {
        try
        {
            var best = Repository.ReadBestKeyFile(repoPath);
            if (best is null)
            {
                return;
            }

            var existing = LocalKeyFile(keySetId);
            if (existing is not null && existing.Generation > best.Generation)
            {
                return; // never replace a newer local key file with an older one
            }

            var local = best.ForRepository(keySetId, secret);
            KeyFileStore.WriteVerified(_app.Paths.LocalKeyFile(keySetId), local, _app.Platform.Durable, f => f.MatchesKeyCheck(secret));
        }
        catch (Exception ex) when (ex is IOException or RezenException or UnauthorizedAccessException)
        {
            _app.Logger.LogWarning("Could not refresh the local key file copy: {Message}", ex.Message);
        }
    }

    /// <summary>
    /// Changes the password by re-wrapping the Root Secret (spec §11) — no backup data is re-encrypted. Connected
    /// drives are updated now; disconnected ones are updated automatically when next connected (DESIGN §8.2).
    /// </summary>
    public PasswordChangeResult ChangePassword(Guid keySetId, RootSecret secret, ReadOnlySpan<char> newPassword)
    {
        var assessment = PasswordPolicy.Assess(newPassword);
        if (!assessment.MeetsRequirements)
        {
            throw new RezenException(ErrorCode.PasswordTooWeak, string.Join(" ", assessment.Feedback));
        }

        var info = _app.Db.KeySet(keySetId) ?? throw new RezenException(ErrorCode.InvalidConfiguration, "Unknown key set.");
        var current = LocalKeyFile(keySetId);
        ulong generation = (current?.Generation ?? (ulong)info.PasswordGeneration) + 1;
        var kdf = KdfPolicy.IsTestMode ? KdfPolicy.Current : Argon2id.Calibrate(TimeSpan.FromSeconds(1));
        using var pw = PasswordEncoding.ToKeyMaterial(newPassword);
        var newLocal = KeyFile.CreateWithPassword(keySetId, keySetId, generation, secret, pw, kdf);
        using (var check = newLocal.Unlock(pw))
        {
            if (!check.ContentEquals(secret))
            {
                throw new RezenException(ErrorCode.EncryptionFailure, "New key slot verification failed.");
            }
        }

        KeyFileStore.WriteVerified(_app.Paths.LocalKeyFile(keySetId), newLocal, _app.Platform.Durable, f => f.MatchesKeyCheck(secret) && f.Generation == generation);
        var newInfo = info with { PasswordGeneration = info.PasswordGeneration + 1, KdfDescription = kdf.ToString() };
        _app.Db.UpsertKeySet(newInfo);

        int updated = 0;
        int pending = 0;
        foreach (var (record, path) in RepositoriesOfKeySet(keySetId))
        {
            if (path is null)
            {
                pending++;
                continue;
            }

            if (ApplyKeyFileUpdate(record, path, secret, newLocal, newInfo.PasswordGeneration))
            {
                updated++;
            }
            else
            {
                pending++;
            }
        }

        _app.SecurityLog.Record(SecurityEvents.PasswordChanged, null, $"drives updated: {updated}, pending: {pending}");
        if (info.RememberOnThisPc && _app.Platform.Credentials.IsSupported)
        {
            _app.Platform.Credentials.Save(keySetId, secret);
        }

        return new PasswordChangeResult(updated, pending);
    }

    /// <summary>Writes the current password slot to a repository whose key files are out of date.</summary>
    public bool ApplyKeyFileUpdate(RepositoryRecord record, string repoPath, RootSecret secret, KeyFile? localFile = null, int? generation = null)
    {
        localFile ??= LocalKeyFile(_app.Db.Job(record.JobId)?.KeySetId ?? Guid.Empty);
        if (localFile is null)
        {
            return false;
        }

        try
        {
            using var repo = Repository.Open(repoPath, secret, _app.Platform.Durable);
            var repoFile = localFile.ForRepository(repo.RepositoryId, secret);
            repo.ReplaceKeyFiles(repoFile, secret, f => f.Generation == repoFile.Generation);
            var gen = generation ?? _app.Db.KeySet(localFile.KeySetId)?.PasswordGeneration ?? record.PasswordGeneration;
            _app.Db.UpsertRepository(record with { PasswordGeneration = gen });
            return true;
        }
        catch (Exception ex) when (ex is IOException or RezenException or UnauthorizedAccessException)
        {
            _app.Logger.LogWarning("Key files on a backup drive could not be updated yet: {Message}", ex.Message);
            return false;
        }
    }

    public int PendingPasswordUpdates(Guid keySetId)
    {
        var info = _app.Db.KeySet(keySetId);
        if (info is null)
        {
            return 0;
        }

        return RepositoriesOfKeySet(keySetId).Count(r => r.Record.PasswordGeneration < info.PasswordGeneration);
    }

    /// <summary>Enables or disables "Remember password on this PC" (DESIGN §9).</summary>
    public void SetRemember(Guid keySetId, RootSecret? secret, bool remember)
    {
        var info = _app.Db.KeySet(keySetId) ?? throw new RezenException(ErrorCode.InvalidConfiguration, "Unknown key set.");
        if (remember)
        {
            if (secret is null)
            {
                throw new RezenException(ErrorCode.KeyUnavailable);
            }

            if (!_app.Platform.Credentials.IsSupported)
            {
                throw new RezenException(ErrorCode.InvalidConfiguration, "Remembering the password is not supported on this computer.", null, null);
            }

            _app.Platform.Credentials.Save(keySetId, secret);
            _app.SecurityLog.Record(SecurityEvents.RememberEnabled, null, _app.Platform.Credentials.MechanismName);
        }
        else
        {
            _app.Platform.Credentials.Delete(keySetId);
            _app.SecurityLog.Record(SecurityEvents.RememberDisabled);
        }

        _app.Db.UpsertKeySet(info with { RememberOnThisPc = remember });
    }

    /// <summary>Loads the remembered Root Secret for scheduled backups; null if not remembered or unavailable.</summary>
    public RootSecret? TryLoadRemembered(Guid keySetId)
    {
        var info = _app.Db.KeySet(keySetId);
        if (info is not { RememberOnThisPc: true })
        {
            return null;
        }

        var secret = _app.Platform.Credentials.TryLoad(keySetId);
        if (secret is null)
        {
            _app.SecurityLog.Record(SecurityEvents.CredentialUnavailable);
            return null;
        }

        var local = LocalKeyFile(keySetId);
        if (local is not null && !local.MatchesKeyCheck(secret))
        {
            secret.Dispose();
            return null;
        }

        return secret;
    }

    public string RevealRecoveryKey(RootSecret secret)
    {
        _app.SecurityLog.Record(SecurityEvents.RecoveryKeyViewed);
        return RecoveryKeyCodec.Encode(secret);
    }

    public void ConfirmRecoveryKeySaved(Guid keySetId)
    {
        var info = _app.Db.KeySet(keySetId);
        if (info is not null)
        {
            _app.Db.UpsertKeySet(info with { RecoveryKeyConfirmed = true });
        }
    }

    internal IEnumerable<string> ConnectedRepositoryPaths(Guid keySetId) =>
        RepositoriesOfKeySet(keySetId).Select(r => r.Path).OfType<string>();

    internal IReadOnlyList<(RepositoryRecord Record, string? Path)> RepositoriesOfKeySet(Guid keySetId)
    {
        var connected = _app.ConnectedDrives();
        var jobs = _app.Db.Jobs().Where(j => j.KeySetId == keySetId).Select(j => j.Id).ToHashSet();
        return _app.Db.Repositories()
            .Where(r => jobs.Contains(r.JobId))
            .Select(r => (r, connected.TryGetValue(r.DriveId, out var d) ? Path.Combine(d.MountPath, r.RelativePath) : null))
            .Select(x => (x.r, x.Item2 is not null && Repository.Exists(x.Item2) ? x.Item2 : null))
            .ToList();
    }
}

public sealed record PasswordChangeResult(int DrivesUpdated, int DrivesPending);
