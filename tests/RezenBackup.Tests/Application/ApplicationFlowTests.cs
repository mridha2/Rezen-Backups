using RezenBackup.Application;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Policies;
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
}
