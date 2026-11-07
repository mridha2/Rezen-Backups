using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using RezenBackup.Database;

namespace RezenBackup.Logging;

/// <summary>Security events (spec §76). Detail text never contains secrets or file names.</summary>
public static class SecurityEvents
{
    public const string Unlock = "BackupUnlocked";
    public const string FailedUnlock = "UnlockFailed";
    public const string PasswordChanged = "PasswordChanged";
    public const string RecoveryKeyUsed = "RecoveryKeyUsed";
    public const string RecoveryKeyViewed = "RecoveryKeyViewed";
    public const string BackupCreated = "BackupCreated";
    public const string BackupVerified = "BackupVerified";
    public const string Restore = "RestorePerformed";
    public const string IntegrityFailure = "IntegrityFailure";
    public const string Import = "BackupImported";
    public const string CatalogRebuild = "CatalogRebuilt";
    public const string RetentionDeletion = "RetentionDeletion";
    public const string RememberEnabled = "RememberOnPcEnabled";
    public const string RememberDisabled = "RememberOnPcDisabled";
    public const string CredentialUnavailable = "StoredCredentialUnavailable";
    public const string KeySetCreated = "KeySetCreated";
    public const string KeySetDiscarded = "KeySetDiscarded";
    public const string AnomalyDetected = "UnusualChangesDetected";
    public const string SnapshotMissing = "SnapshotMissingFromDrive";
    public const string Locked = "AppLocked";
}

/// <summary>
/// Tamper-evident security log (DESIGN §22.2): each record carries the hash of the previous record and an HMAC under a
/// per-installation key protected by the OS credential store. Editing or deleting records breaks the chain.
/// </summary>
public sealed class SecurityLog
{
    private readonly AppDatabase _db;
    private readonly byte[] _macKey;
    private readonly object _gate = new();

    public SecurityLog(AppDatabase db, byte[] macKey)
    {
        _db = db;
        _macKey = macKey;
    }

    public void Record(string type, Guid? jobId = null, string detail = "")
    {
        lock (_gate)
        {
            var utc = DateTimeOffset.UtcNow;
            var last = _db.LastSecurityEvent();
            var prevHash = last is null ? new byte[32] : SHA256.HashData(last.Mac);
            var mac = Mac(utc, type, jobId, detail, prevHash);
            _db.AddSecurityEvent(utc, type, jobId, detail, prevHash, mac);
        }
    }

    private byte[] Mac(DateTimeOffset utc, string type, Guid? jobId, string detail, byte[] prevHash)
    {
        var text = string.Join('\u001f', utc.ToString("O", CultureInfo.InvariantCulture), type, jobId?.ToString() ?? string.Empty, detail);
        var data = Encoding.UTF8.GetBytes(text).Concat(prevHash).ToArray();
        return HMACSHA256.HashData(_macKey, data);
    }

    /// <summary>Returns the id of the first record that fails verification, or null if the chain is intact.</summary>
    public long? VerifyChain()
    {
        var prev = new byte[32];
        foreach (var e in _db.SecurityEventsAscending())
        {
            if (!e.PrevHash.AsSpan().SequenceEqual(prev))
            {
                return e.Id;
            }

            var expected = Mac(e.Utc, e.Type, e.JobId, e.Detail, e.PrevHash);
            if (!CryptographicOperations.FixedTimeEquals(expected, e.Mac))
            {
                return e.Id;
            }

            prev = SHA256.HashData(e.Mac);
        }

        return null;
    }
}
