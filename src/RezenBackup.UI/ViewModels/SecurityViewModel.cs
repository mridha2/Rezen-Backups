using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RezenBackup.Application;
using RezenBackup.Core;
using RezenBackup.Security;
using RezenBackup.UI.Services;

namespace RezenBackup.UI.ViewModels;

public sealed record SecurityEventItem(string When, string Type, string Detail);

public sealed record IntegrityItem(Guid JobId, string Job, string LastVerified);

/// <summary>Security page (spec §81). Shows state, never secrets.</summary>
public sealed partial class SecurityViewModel : PageViewModel
{
    public SecurityViewModel(UiContext ui)
        : base(ui)
    {
        AutoLockIndex = ui.App.Settings.AutoLock switch
        {
            AutoLockMode.OnMinimize => 0,
            AutoLockMode.After5Minutes => 1,
            AutoLockMode.After15Minutes => 2,
            AutoLockMode.After30Minutes => 3,
            _ => 4,
        };
        LockWithSystem = ui.App.Settings.LockWhenSystemLocks;
    }

    public IReadOnlyList<string> AutoLockOptions { get; } = ["Immediately when minimized", "After 5 minutes", "After 15 minutes", "After 30 minutes", "Never during this session"];

    private static readonly AutoLockMode[] AutoLockModes =
        [AutoLockMode.OnMinimize, AutoLockMode.After5Minutes, AutoLockMode.After15Minutes, AutoLockMode.After30Minutes, AutoLockMode.NeverThisSession];

    [ObservableProperty]
    private string _encryptionText = string.Empty;

    [ObservableProperty]
    private string _passwordText = string.Empty;

    [ObservableProperty]
    private string _recoveryText = string.Empty;

    [ObservableProperty]
    private bool _recoveryConfigured;

    [ObservableProperty]
    private bool _remember;

    [ObservableProperty]
    private string _rememberText = string.Empty;

    [ObservableProperty]
    private bool _backupOnly = true;

    [ObservableProperty]
    private int _autoLockIndex;

    [ObservableProperty]
    private bool _lockWithSystem;

    [ObservableProperty]
    private string _chainStatus = string.Empty;

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string? _busyText;

    public ObservableCollection<SecurityEventItem> Events { get; } = [];

    public ObservableCollection<IntegrityItem> Integrity { get; } = [];

    private bool _loading;

    public override void OnActivated() => Refresh();

    private void Refresh()
    {
        _loading = true;
        var ks = Ui.App.KeySets.Default;
        EncryptionText = $"Enabled — AES-256-GCM authenticated encryption. Key derivation: {ks?.KdfDescription ?? "Argon2id"}.";
        int pending = ks is null ? 0 : Ui.App.KeySets.PendingPasswordUpdates(ks.Id);
        PasswordText = ks is null ? "Not configured" : pending > 0 ? $"Configured — {pending} backup drive(s) still use the previous password. Connect them to finish updating." : "Configured";
        RecoveryConfigured = ks?.RecoveryKeyConfirmed == true;
        RecoveryText = RecoveryConfigured ? "Configured" : "Not configured — you have not confirmed saving a recovery key.";
        Remember = ks?.RememberOnThisPc == true;
        BackupOnly = ks is null || !ks.RememberOnThisPc || ks.RememberBackupOnly;
        RememberText = !Remember
            ? "Disabled — you will be asked for your password before each backup."
            : BackupOnly
                ? $"Enabled with a backup-only key, protected by {Ui.App.Platform.Credentials.MechanismName}. Scheduled backups run automatically, but this key cannot decrypt the contents of your backups — restoring always needs your password or recovery key. It can see file names and backup dates, and could confirm whether a file someone already has or can guess (for example a short PIN file) is in your backups."
                : $"Enabled with the full key, protected by {Ui.App.Platform.Credentials.MechanismName}. Programs running under your account could use it to read your backups. The backup-only key is safer.";

        Integrity.Clear();
        foreach (var j in Ui.App.Jobs.All)
        {
            var last = Ui.App.Db.GetSetting($"job.{j.Id}.lastDeepVerify");
            var when = last is null ? "Never fully verified" : "Last full verification: " + Fmt.When(DateTimeOffset.Parse(last, CultureInfo.InvariantCulture));
            Integrity.Add(new IntegrityItem(j.Id, j.Name, when));
        }

        Events.Clear();
        foreach (var e in Ui.App.Db.SecurityEvents(200))
        {
            Events.Add(new SecurityEventItem(e.Utc.ToLocalTime().ToString("g", CultureInfo.CurrentCulture), e.Type, e.Detail));
        }

        ChainStatus = Ui.App.SecurityLog.VerifyChain() is { } broken
            ? $"Warning: the security log was modified (record {broken})."
            : "Security log integrity verified.";
        _loading = false;
    }

    partial void OnAutoLockIndexChanged(int value)
    {
        if (_loading)
        {
            return;
        }

        var mode = AutoLockModes[Math.Clamp(value, 0, AutoLockModes.Length - 1)];
        Ui.App.SaveSettings(Ui.App.Settings with { AutoLock = mode });
        Ui.Locks.Mode = mode;
    }

    partial void OnLockWithSystemChanged(bool value)
    {
        if (_loading)
        {
            return;
        }

        Ui.App.SaveSettings(Ui.App.Settings with { LockWhenSystemLocks = value });
        Ui.Locks.LockWhenSystemLocks = value;
    }

    partial void OnRememberChanged(bool value)
    {
        if (!_loading)
        {
            _ = ApplyRememberAsync(value);
        }
    }

    partial void OnBackupOnlyChanged(bool value)
    {
        if (!_loading && Remember)
        {
            _ = ApplyRememberAsync(true);
        }
    }

    private async Task ApplyRememberAsync(bool value)
    {
        var ks = Ui.App.KeySets.Default;
        if (ks is null)
        {
            return;
        }

        try
        {
            if (value)
            {
                var session = await Ui.EnsureUnlockedAsync("Enter your password to allow automatic scheduled backups on this computer.");
                if (session is null)
                {
                    Refresh();
                    return;
                }

                session.SetRemember(true, BackupOnly);
            }
            else
            {
                Ui.App.KeySets.SetRemember(ks.Id, null, false);
            }
        }
        catch (RezenException ex)
        {
            await Dialogs.MessageAsync(Ui.MainWindow!, "Remember password", ex.Message, ex.TechnicalDetails, isError: true);
        }

        Refresh();
    }

    [RelayCommand]
    private async Task ChangePassword()
    {
        var session = await Ui.EnsureUnlockedAsync("Enter your current password.");
        if (session is null)
        {
            return;
        }

        var newPassword = await Dialogs.NewPasswordAsync(Ui.MainWindow!, "Change Password",
            "Your backups are not re-encrypted: the encryption key is re-wrapped with the new password on this computer and on every connected backup drive.");
        if (newPassword is null)
        {
            return;
        }

        IsBusy = true;
        BusyText = "Updating key files…";
        using var busy = Ui.Locks.BeginBusy();
        try
        {
            var result = await Task.Run(() => session.ChangePassword(newPassword));
            var msg = result.DrivesPending == 0
                ? $"Password changed. {result.DrivesUpdated} backup drive(s) updated."
                : $"Password changed. {result.DrivesUpdated} drive(s) updated. {result.DrivesPending} drive(s) were not connected and still open with the previous password until they are connected.";
            await Dialogs.MessageAsync(Ui.MainWindow!, "Password changed", msg + " If you changed it because the old password may be known to someone else, note that copies of the drive made earlier can still be opened with the old password.", null);
        }
        catch (RezenException ex)
        {
            await Dialogs.MessageAsync(Ui.MainWindow!, "Password not changed", ex.Message, ex.TechnicalDetails, isError: true);
        }
        finally
        {
            IsBusy = false;
            Refresh();
        }
    }

    [RelayCommand]
    private async Task ViewRecoveryKey()
    {
        var session = await Ui.EnsureUnlockedAsync("Enter your password to view the recovery key.");
        if (session is null)
        {
            return;
        }

        await Dialogs.RecoveryKeyAsync(Ui.MainWindow!, Ui.App, session.RevealRecoveryKey(), session.KeySetId);
        if (!RecoveryConfigured && await Dialogs.ConfirmAsync(Ui.MainWindow!, "Recovery key saved?", "Have you printed or saved the recovery key somewhere safe (not on the backup drive)?", "Yes, it is saved"))
        {
            Ui.App.KeySets.ConfirmRecoveryKeySaved(session.KeySetId);
        }

        Refresh();
    }

    [RelayCommand]
    private async Task Verify(Guid jobId)
    {
        var session = await Ui.EnsureUnlockedAsync("Enter your password to verify the backup.");
        if (session is null)
        {
            return;
        }

        IsBusy = true;
        BusyText = "Reading and authenticating every encrypted pack…";
        try
        {
            using var busy = Ui.Locks.BeginBusy();
            var progress = new Progress<RestoreEngine.DeepVerifyProgress>(p => BusyText = $"Verifying packs {p.PacksDone}/{p.PacksTotal}, snapshots {p.SnapshotsDone}/{p.SnapshotsTotal}…");
            var report = await Task.Run(() => session.DeepVerify(jobId, progress));
            if (report.Healthy)
            {
                await Dialogs.MessageAsync(Ui.MainWindow!, "Encrypted & Verified", $"All {report.PacksChecked} encrypted packs and {report.Snapshots.Count} snapshot(s) were authenticated successfully.", null);
            }
            else
            {
                var details = string.Join(Environment.NewLine,
                    report.DamagedPacks.Select(d => $"Damaged pack {d.PackId} ({d.Kind}): {d.Reason}{(d.RecoveredFromCopy ? " — second copy intact" : string.Empty)}")
                        .Concat(report.Snapshots.Where(s => !s.AllDataPresent).Select(s => $"Snapshot {s.FolderName}: {s.Problem}"))
                        .Concat(report.MissingSnapshotsInChain.Select(m => $"A snapshot before {m} is missing from the drive")));
                await Dialogs.MessageAsync(Ui.MainWindow!, UserMessages.IntegrityFailed, "Some backup data on the drive is damaged or missing. Damaged data is never restored.", details, isError: true);
                if (report.DamagedPacks.Any(d => !d.RecoveredFromCopy) &&
                    await Dialogs.ConfirmAsync(Ui.MainWindow!, "Repair from your files?", "Damaged data will be set aside (not deleted) and the next backup will store it again from your current files where possible.", "Repair"))
                {
                    session.RepairFromSource(jobId, report);
                    if (Ui.App.Jobs.Get(jobId) is { } job)
                    {
                        await Ui.BackUpNowAsync(job);
                    }
                }
            }
        }
        catch (RezenException ex)
        {
            await Dialogs.MessageAsync(Ui.MainWindow!, "Verification stopped", ex.Message, ex.TechnicalDetails, isError: true);
        }
        finally
        {
            IsBusy = false;
            Refresh();
        }
    }

    [RelayCommand]
    private void LockNow() => Ui.Lock("Locked by you.");
}
