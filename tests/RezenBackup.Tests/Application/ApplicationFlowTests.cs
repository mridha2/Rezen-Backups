using RezenBackup.Application;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Policies;
using RezenBackup.Crypto;
using RezenBackup.RestoreEngine;

namespace RezenBackup.Tests.Application;

public class ApplicationFlowTests
{
    private static (JobDefinition Job, NewKeySet KeySet) Setup(AppFixture f)
    {
        File.WriteAllText(Path.Combine(f.Source, "Budget.xlsx"), "budget v1");
        Directory.CreateDirectory(Path.Combine(f.Source, "Invoices"));
        File.WriteAllText(Path.Combine(f.Source, "Invoices", "Invoice-1843.pdf"), "invoice");
        var ks = f.App.KeySets.Create(AppFixture.Password);
        var job = f.App.Jobs.Create(new JobDefinition
        {
            Id = Guid.Empty,
            KeySetId = ks.Info.Id,
            Name = "Company Documents",
            Sources = [f.Source],
            Schedule = Schedule.DailyAt(20),
        }, f.Drive, ks.Secret);
        return (job, ks);
    }

    [Fact]
    public void WeakPassword_IsRejected()
    {
        using var f = new AppFixture();
        var ex = Assert.Throws<RezenException>(() => f.App.KeySets.Create("password1234"));
        Assert.Equal(ErrorCode.PasswordTooWeak, ex.Code);
        Assert.Throws<RezenException>(() => f.App.KeySets.Create("short"));
    }

    [Fact]
    public async Task EndToEnd_Backup_Unlock_Browse_Restore()
    {
        using var f = new AppFixture();
        var (job, ks) = Setup(f);
        Assert.True(Directory.Exists(Path.Combine(f.Drive, "Rezen Backup", Environment.MachineName.Length > 0 ? Core.Policies.PathPolicy.SafeFolderName(Environment.MachineName) : "x", "Company Documents")));

        var run = await f.App.Backups.RunAsync(job.Id, RunTrigger.Manual, ks.Secret.Clone());
        Assert.Equal(RunOutcome.Success, run.Outcome);
        Assert.Equal(SecurityStatus.EncryptedAndVerified, run.Security);
        Assert.Equal(2, run.Files);

        var status = f.App.Status.Dashboard();
        Assert.Equal("Your files are protected.", status.Headline);

        using var session = await UnlockedSession.UnlockAsync(f.App, ks.Info.Id, AppFixture.Password);
        var catalog = session.OpenCatalog(job.Id);
        var snap = Assert.Single(catalog.RestorableSnapshots);
        var target = Path.Combine(f.Root, "restored");
        var report = await session.RestoreAsync(job.Id, catalog.Roots(snap.SnapshotId), new RestoreOptions
        {
            TargetRoot = target,
            ResolveConflict = _ => new ConflictResolution(ConflictChoice.Skip, true),
        });
        Assert.Equal(2, report.FilesRestored);
        Assert.Equal("budget v1", File.ReadAllText(Path.Combine(target, "Documents", "Budget.xlsx")));
        ks.Secret.Dispose();
    }

    [Fact]
    public async Task WrongPassword_GenericMessage_AndSecurityLogged()
    {
        using var f = new AppFixture();
        var (_, ks) = Setup(f);
        var ex = await Assert.ThrowsAsync<RezenException>(() => UnlockedSession.UnlockAsync(f.App, ks.Info.Id, "definitely not it at all"));
        Assert.Equal(UserMessages.UnlockFailed, ex.Message);
        Assert.Contains(f.App.Db.SecurityEvents(), e => e.Type == "UnlockFailed");
        Assert.Null(f.App.SecurityLog.VerifyChain());
        ks.Secret.Dispose();
    }

    [Fact]
    public async Task ScheduledRun_WithoutRememberedPassword_WaitsForPassword()
    {
        using var f = new AppFixture();
        var (job, ks) = Setup(f);
        var run = await f.App.Backups.RunAsync(job.Id, RunTrigger.Scheduled);
        Assert.Equal(RunOutcome.WaitingForPassword, run.Outcome);
        Assert.Equal(SecurityStatus.BackupLocked, run.Security);

        f.App.KeySets.SetRemember(ks.Info.Id, ks.Secret, remember: true);
        var run2 = await f.App.Backups.RunAsync(job.Id, RunTrigger.Scheduled);
        Assert.Equal(RunOutcome.Success, run2.Outcome);

        // Credential becomes unavailable (e.g. Windows password reset): fail safely and ask for the password.
        f.Credentials.Unavailable = true;
        var run3 = await f.App.Backups.RunAsync(job.Id, RunTrigger.Scheduled);
        Assert.Equal(RunOutcome.WaitingForPassword, run3.Outcome);
        Assert.Contains(f.App.Db.SecurityEvents(), e => e.Type == "StoredCredentialUnavailable");
        ks.Secret.Dispose();
    }

    [Fact]
    public async Task DriveDisconnected_RunIsPending_AndDriveLetterChangeIsRecognised()
    {
        using var f = new AppFixture();
        var (job, ks) = Setup(f);
        f.App.KeySets.SetRemember(ks.Info.Id, ks.Secret, true);
        f.Volumes.Connected = false;
        var pendingDrive = new FakeVolumes(f.Drive) { Connected = false };
        _ = pendingDrive;
        // Hide the last mount path too, as if the drive was unplugged.
        var drive = f.App.Db.Drives().Single();
        f.App.Db.UpsertDrive(drive with { LastMountPath = null });
        var run = await f.App.Backups.RunAsync(job.Id, RunTrigger.Scheduled);
        Assert.Equal(RunOutcome.WaitingForDrive, run.Outcome);

        // "Reconnect under a different drive letter": move the drive folder and expose it at the new path.
        var newMount = Path.Combine(f.Root, "drive-F");
        Directory.Move(f.Drive, newMount);
        f.App.Db.UpsertDrive(drive with { LastMountPath = newMount });
        var run2 = await f.App.Backups.RunAsync(job.Id, RunTrigger.DriveConnected);
        Assert.Equal(RunOutcome.Success, run2.Outcome);
        ks.Secret.Dispose();
    }

    [Fact]
    public async Task PasswordChange_UpdatesDrive_OldPasswordStopsWorking()
    {
        using var f = new AppFixture();
        var (job, ks) = Setup(f);
        await f.App.Backups.RunAsync(job.Id, RunTrigger.Manual, ks.Secret.Clone());
        const string newPassword = "silver mountain river lantern 77";
        using (var session = await UnlockedSession.UnlockAsync(f.App, ks.Info.Id, AppFixture.Password))
        {
            var result = session.ChangePassword(newPassword);
            Assert.Equal(1, result.DrivesUpdated);
        }

        await Assert.ThrowsAsync<RezenException>(() => UnlockedSession.UnlockAsync(f.App, ks.Info.Id, AppFixture.Password));
        using var s2 = await UnlockedSession.UnlockAsync(f.App, ks.Info.Id, newPassword);
        Assert.Single(s2.OpenCatalog(job.Id).RestorableSnapshots);
        ks.Secret.Dispose();
    }

    [Fact]
    public async Task ImportOnNewComputer_WithPassword_RestoresEverything()
    {
        using var original = new AppFixture();
        var (job, ks) = Setup(original);
        await original.App.Backups.RunAsync(job.Id, RunTrigger.Manual, ks.Secret.Clone());

        // A brand-new installation sees only the drive.
        using var newPc = new AppFixture(sharedDrive: original.Drive);
        var found = Assert.Single(newPc.App.Import.FindRepositories(original.Drive));
        var imported = newPc.App.Import.ImportWithPassword(found.Path, AppFixture.Password);
        Assert.False(imported.Enabled);
        Assert.Single(newPc.App.Db.Snapshots(imported.Id));

        using var session = await UnlockedSession.UnlockAsync(newPc.App, imported.KeySetId, AppFixture.Password);
        var catalog = session.OpenCatalog(imported.Id);
        var target = Path.Combine(newPc.Root, "restored");
        var report = await session.RestoreAsync(imported.Id, catalog.Roots(catalog.RestorableSnapshots.First().SnapshotId), new RestoreOptions
        {
            TargetRoot = target,
            ResolveConflict = _ => new ConflictResolution(ConflictChoice.Skip, true),
        });
        Assert.Equal(2, report.FilesRestored);
        ks.Secret.Dispose();
    }

    [Fact]
    public async Task ImportWithRecoveryKey_SetsNewPassword()
    {
        using var original = new AppFixture();
        var (job, ks) = Setup(original);
        await original.App.Backups.RunAsync(job.Id, RunTrigger.Manual, ks.Secret.Clone());

        using var newPc = new AppFixture(sharedDrive: original.Drive);
        var found = Assert.Single(newPc.App.Import.FindRepositories(original.Drive));
        const string newPassword = "violet harbour quantum pebble 18";
        var imported = newPc.App.Import.ImportWithRecoveryKey(found.Path, ks.RecoveryKey, newPassword);
        using var session = await UnlockedSession.UnlockAsync(newPc.App, imported.KeySetId, newPassword);
        Assert.Single(session.OpenCatalog(imported.Id).RestorableSnapshots);

        var ex = Assert.Throws<RezenException>(() => newPc.App.Import.ImportWithRecoveryKey(found.Path, "RZN1-0000-0000", newPassword));
        Assert.Equal(ErrorCode.RecoveryKeyMalformed, ex.Code);
        ks.Secret.Dispose();
    }

    [Fact]
    public void RecursiveDestination_IsBlockedAtJobCreation()
    {
        using var f = new AppFixture();
        var ks = f.App.KeySets.Create(AppFixture.Password);
        var inside = Path.Combine(f.Source, "backups");
        Directory.CreateDirectory(inside);
        var ex = Assert.Throws<RezenException>(() => f.App.Jobs.Create(new JobDefinition
        {
            Id = Guid.Empty,
            KeySetId = ks.Info.Id,
            Name = "Loop",
            Sources = [f.Source],
        }, inside, ks.Secret));
        Assert.Equal(ErrorCode.UnsafeConfiguration, ex.Code);
        ks.Secret.Dispose();
    }

    [Fact]
    public async Task FailedFiles_AreReported_WithPathsOnlyAfterUnlock()
    {
        if (OperatingSystem.IsWindows())
        {
            return; // permission simulation below uses POSIX modes
        }

        using var f = new AppFixture();
        var (job, ks) = Setup(f);
        var secretFile = Path.Combine(f.Source, "Payroll-private.xlsx");
        File.WriteAllText(secretFile, "x");
        File.SetUnixFileMode(secretFile, UnixFileMode.None);
        try
        {
            var run = await f.App.Backups.RunAsync(job.Id, RunTrigger.Manual, ks.Secret.Clone());
            Assert.Equal(RunOutcome.CompletedWithWarnings, run.Outcome);
            Assert.Equal(1, run.FilesWarned);
            var issue = Assert.Single(f.App.Db.RunIssues(run.Id));
            Assert.True(issue.PathSealed.AsSpan().IndexOf("Payroll"u8) < 0, "File names must be stored encrypted.");

            using var session = await UnlockedSession.UnlockAsync(f.App, ks.Info.Id, AppFixture.Password);
            var details = session.RunIssues(job.Id, run.Id);
            Assert.Equal(secretFile, details.Single().Path);
            Assert.Equal(IssueKind.PermissionDenied, details.Single().Kind);
        }
        finally
        {
            File.SetUnixFileMode(secretFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            ks.Secret.Dispose();
        }
    }

    [Fact]
    public void ConfigExport_ContainsNoSecrets()
    {
        using var f = new AppFixture();
        var (_, ks) = Setup(f);
        var json = ConfigTransfer.Export(f.App);
        Assert.DoesNotContain(AppFixture.Password, json, StringComparison.Ordinal);
        Assert.DoesNotContain(ks.RecoveryKey, json, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToBase64String(ks.Secret.Bytes), json, StringComparison.Ordinal);
        Assert.Contains("Company Documents", json, StringComparison.Ordinal);
        ks.Secret.Dispose();
    }

    [Fact]
    public void Database_ContainsNoSecrets()
    {
        string dbPath;
        byte[] secretBytes;
        string recovery;
        using (var f = new AppFixture())
        {
            var (_, ks) = Setup(f);
            f.App.KeySets.SetRemember(ks.Info.Id, ks.Secret, true);
            secretBytes = ks.Secret.Bytes.ToArray();
            recovery = ks.RecoveryKey;
            dbPath = f.App.Paths.Database;
            f.App.Db.Dispose();
            var bytes = File.ReadAllBytes(dbPath).Concat(File.Exists(dbPath + "-wal") ? File.ReadAllBytes(dbPath + "-wal") : []).ToArray();
            Assert.True(bytes.AsSpan().IndexOf(secretBytes) < 0);
            Assert.True(bytes.AsSpan().IndexOf(System.Text.Encoding.UTF8.GetBytes(AppFixture.Password)) < 0);
            Assert.True(bytes.AsSpan().IndexOf(System.Text.Encoding.UTF8.GetBytes(recovery)) < 0);
            ks.Secret.Dispose();
        }
    }

    /// <summary>A stale drive must not revert a password change on this computer (review finding 4).</summary>
    [Fact]
    public async Task OldPassword_OnStaleDrive_DoesNotRevertPasswordChange()
    {
        using var f = new AppFixture();
        var (job, ks) = Setup(f);
        const string newPassword = "silver mountain river lantern 77";

        // Change the password while the drive is "disconnected", so the drive keeps the old key slot.
        var drive = f.App.Db.Drives().Single();
        f.Volumes.Connected = false;
        f.App.Db.UpsertDrive(drive with { LastMountPath = null });
        using (var s = await UnlockedSession.UnlockAsync(f.App, ks.Info.Id, AppFixture.Password))
        {
            Assert.Equal(1, s.ChangePassword(newPassword).DrivesPending);
        }

        f.Volumes.Connected = true;
        f.App.Db.UpsertDrive(drive with { LastMountPath = f.Drive });
        await Assert.ThrowsAsync<RezenException>(() => UnlockedSession.UnlockAsync(f.App, ks.Info.Id, AppFixture.Password));
        using var ok = await UnlockedSession.UnlockAsync(f.App, ks.Info.Id, newPassword);
        Assert.NotNull(ok.OpenCatalog(job.Id));
        ks.Secret.Dispose();
    }

    [Fact]
    public async Task PeriodicFullSnapshot_RunsWhenDue_ThenIncremental()
    {
        using var f = new AppFixture();
        var (job, ks) = Setup(f);
        f.App.Db.UpsertJob(job with { FullSnapshotEveryDays = 30 });
        job = f.App.Jobs.Get(job.Id)!;
        var repoId = f.App.Db.RepositoriesForJob(job.Id).Single().Id;
        Assert.Equal(BackupMethod.FullSnapshot, f.App.Backups.ChooseMethod(job, repoId));
        await f.App.Backups.RunAsync(job.Id, RunTrigger.Manual, ks.Secret.Clone());
        Assert.Equal(BackupMethod.Incremental, f.App.Backups.ChooseMethod(job, repoId));

        // A second drive gets its own independent full copy.
        var drive2 = Path.Combine(f.Root, "drive-full2");
        Directory.CreateDirectory(drive2);
        var second = f.App.Jobs.AddDestination(job.Id, drive2, ks.Secret);
        Assert.Equal(BackupMethod.FullSnapshot, f.App.Backups.ChooseMethod(job, second.Id));
        ks.Secret.Dispose();
    }

    /// <summary>Drive rotation: one job, two drives; each drive keeps its own complete, verified history.</summary>
    [Fact]
    public async Task DriveRotation_BacksUpToEveryConnectedDrive()
    {
        using var f = new AppFixture();
        var (job, ks) = Setup(f);
        var drive2 = Path.Combine(f.Root, "offsite-drive");
        Directory.CreateDirectory(drive2);
        var second = f.App.Jobs.AddDestination(job.Id, drive2, ks.Secret);
        Assert.Equal(2, f.App.Db.RepositoriesForJob(job.Id).Count);
        Assert.Throws<RezenException>(() => f.App.Jobs.AddDestination(job.Id, drive2, ks.Secret)); // same drive twice

        var both = await f.App.Backups.RunAsync(job.Id, RunTrigger.Manual, ks.Secret.Clone());
        Assert.Equal(RunOutcome.Success, both.Outcome);
        Assert.Equal(2, f.App.Db.Snapshots(job.Id).Select(s => s.RepositoryId).Distinct().Count());

        // Take the off-site drive away; the next backup only goes to the drive that is present.
        var hidden = drive2 + "-away";
        Directory.Move(drive2, hidden);
        var oneDrive = await f.App.Backups.RunAsync(job.Id, RunTrigger.Manual, ks.Secret.Clone());
        Assert.Equal(RunOutcome.Success, oneDrive.Outcome);
        Assert.Equal(1, f.App.Db.Snapshots(job.Id).Count(s => s.RepositoryId == second.Id));

        // It comes back and is caught up.
        Directory.Move(hidden, drive2);
        await f.App.Backups.RunAsync(job.Id, RunTrigger.DriveConnected, ks.Secret.Clone());
        Assert.Equal(2, f.App.Db.Snapshots(job.Id).Count(s => s.RepositoryId == second.Id));

        using var session = await UnlockedSession.UnlockAsync(f.App, ks.Info.Id, AppFixture.Password);
        Assert.Equal(2, session.OpenCatalog(job.Id, second.Id).RestorableSnapshots.Count());

        f.App.Jobs.RemoveDestination(job.Id, second.Id);
        Assert.True(Directory.Exists(Path.Combine(drive2, "Rezen Backup"))); // nothing deleted on the drive
        Assert.Throws<RezenException>(() => f.App.Jobs.RemoveDestination(job.Id, f.App.Db.RepositoriesForJob(job.Id).Single().Id));
        ks.Secret.Dispose();
    }

    /// <summary>Backup-only remembering stores no Root Secret and still lets scheduled backups run (DESIGN §9.5).</summary>
    [Fact]
    public async Task RememberBackupOnly_RunsScheduledBackups_WithoutStoringTheRootSecret()
    {
        using var f = new AppFixture();
        var (job, ks) = Setup(f);
        f.App.KeySets.SetRemember(ks.Info.Id, ks.Secret, remember: true, backupOnly: true);
        Assert.DoesNotContain(f.Credentials.StoredValues, v => v.AsSpan().IndexOf(ks.Secret.Bytes) >= 0);
        Assert.Null(f.App.KeySets.TryLoadRemembered(ks.Info.Id));

        var run = await f.App.Backups.RunAsync(job.Id, RunTrigger.Scheduled);
        Assert.Equal(RunOutcome.Success, run.Outcome);
        Assert.Equal(SecurityStatus.EncryptedAndVerified, run.Security);

        // A drive added later also gets a backup-only key.
        var drive2 = Path.Combine(f.Root, "drive2");
        Directory.CreateDirectory(drive2);
        var second = f.App.Jobs.AddDestination(job.Id, drive2, ks.Secret);
        using (var k = f.App.KeySets.TryLoadBackupOnly(ks.Info.Id, second.Id))
        {
            Assert.NotNull(k);
            Assert.False(k!.CanReadContent);
        }

        // Switching to the full key stores the Root Secret instead and removes the backup-only keys.
        f.App.KeySets.SetRemember(ks.Info.Id, ks.Secret, remember: true, backupOnly: false);
        using (var full = f.App.KeySets.TryLoadRemembered(ks.Info.Id))
        {
            Assert.NotNull(full);
        }

        Assert.Null(f.App.KeySets.TryLoadBackupOnly(ks.Info.Id, second.Id));
        f.App.KeySets.SetRemember(ks.Info.Id, null, remember: false);
        Assert.DoesNotContain(f.Credentials.StoredValues, v => v.AsSpan().SequenceEqual(ks.Secret.Bytes));
        ks.Secret.Dispose();
    }
}
