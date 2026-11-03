using System.Text;
using RezenBackup.BackupEngine;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Platform;
using RezenBackup.Crypto;
using RezenBackup.Format;
using RezenBackup.RestoreEngine;

namespace RezenBackup.Tests.Engine;

public class BackupRestoreTests
{
    private static byte[] RandomBytes(int n) => CryptoRandom.Bytes(n);

    private static void Populate(TestRepo t)
    {
        t.WriteFile("Payroll.xlsx", "PAYROLL-SECRET-CONTENT salary data");
        t.WriteFile("Customer Contracts/Contract-ÄÖÜ-日本語.pdf", RandomBytes(300_000));
        t.WriteFile("Customer Contracts/empty.txt", Array.Empty<byte>());
        t.WriteFile("Big/large.bin", RandomBytes(5 * 1024 * 1024 + 123));
        t.WriteFile("Deep/a/b/c/d/e/f/note.txt", "deep");
    }

    [Fact]
    public async Task InitialBackup_RestoresIdenticalFiles()
    {
        using var t = new TestRepo();
        Populate(t);
        var result = await t.BackupAsync();
        Assert.Equal(RunOutcome.Success, result.Outcome);
        Assert.Equal(5, result.Stats.Files);
        Assert.DoesNotContain(".incomplete", result.FolderName, StringComparison.Ordinal);

        t.Reopen();
        var report = await t.RestoreAllAsync(result.SnapshotId);
        Assert.Equal(5, report.FilesRestored);
        Assert.False(report.IntegrityFailure);
        TestRepo.AssertTreesEqual(t.Source, Path.Combine(t.RestoreTarget, "Company Documents"));
    }

    [Fact]
    public async Task FullVerification_Passes()
    {
        using var t = new TestRepo();
        Populate(t);
        var result = await t.BackupAsync(t.Options(level: VerificationLevel.Full));
        Assert.Equal(RunOutcome.Success, result.Outcome);
        Assert.Equal(VerificationLevel.Full, result.Verification);
    }

    [Fact]
    public async Task DriveContainsNoPlaintextNamesOrContent()
    {
        using var t = new TestRepo();
        Populate(t);
        await t.BackupAsync();
        var needles = new[] { "Payroll", "Customer Contracts", "PAYROLL-SECRET-CONTENT", "Contract-" }
            .SelectMany(n => new[] { Encoding.UTF8.GetBytes(n), Encoding.Unicode.GetBytes(n) })
            .ToList();
        foreach (var file in Directory.EnumerateFiles(t.RepoPath, "*", SearchOption.AllDirectories))
        {
            Assert.DoesNotContain("Payroll", file, StringComparison.OrdinalIgnoreCase);
            var bytes = File.ReadAllBytes(file);
            foreach (var needle in needles)
            {
                Assert.True(bytes.AsSpan().IndexOf(needle) < 0, $"Plaintext found in {Path.GetFileName(file)}");
            }
        }
    }

    [Fact]
    public async Task Incremental_StoresOnlyChanges_AndRestoresEveryVersion()
    {
        using var t = new TestRepo();
        Populate(t);
        var first = await t.BackupAsync();

        var budget = t.WriteFile("Budget.xlsx", "version 2");
        File.Move(Path.Combine(t.Source, "Big", "large.bin"), Path.Combine(t.Source, "Big", "renamed.bin"));
        File.Delete(Path.Combine(t.Source, "Deep", "a", "b", "c", "d", "e", "f", "note.txt"));
        var second = await t.BackupAsync(t.Options() with { SnapshotLocalTime = DateTime.Now.AddSeconds(1) });

        Assert.Equal(RunOutcome.Success, second.Outcome);
        // Renamed 5 MB file must not be stored again (deduplicated).
        Assert.True(second.Stats.BytesNew < 100_000, $"BytesNew={second.Stats.BytesNew}");
        Assert.Equal(1, second.Stats.FilesNew + second.Stats.FilesChanged - 1); // Budget new, renamed counts as new path

        using (var catalog = t.Catalog())
        {
            Assert.Equal(2, catalog.RestorableSnapshots.Count());
            var hits = catalog.Search(second.SnapshotId, new SearchQuery { NameContains = "budget" });
            Assert.Single(hits);
            var oldHits = catalog.Search(first.SnapshotId, new SearchQuery { Extension = "txt" });
            Assert.Equal(2, oldHits.Count); // empty.txt and note.txt existed in the first snapshot
        }

        var restoreOld = Path.Combine(t.Root, "restore-old");
        await t.RestoreAllAsync(first.SnapshotId, restoreOld);
        Assert.True(File.Exists(Path.Combine(restoreOld, "Company Documents", "Deep", "a", "b", "c", "d", "e", "f", "note.txt")));
        Assert.False(File.Exists(Path.Combine(restoreOld, "Company Documents", "Budget.xlsx")));
        _ = budget;
    }

    [Fact]
    public async Task VersionHistory_ListsDistinctVersions()
    {
        using var t = new TestRepo();
        t.WriteFile("Budget.xlsx", "v1");
        await t.BackupAsync();
        t.WriteFile("Budget.xlsx", "v2 longer");
        File.SetLastWriteTimeUtc(Path.Combine(t.Source, "Budget.xlsx"), DateTime.UtcNow.AddMinutes(1));
        await t.BackupAsync(t.Options() with { SnapshotLocalTime = DateTime.Now.AddSeconds(1) });
        await t.BackupAsync(t.Options() with { SnapshotLocalTime = DateTime.Now.AddSeconds(2) }); // unchanged

        using var catalog = t.Catalog();
        var latest = catalog.RestorableSnapshots.First();
        var item = catalog.Search(latest.SnapshotId, new SearchQuery { NameContains = "Budget" }).Single();
        var versions = catalog.VersionsOf(item);
        Assert.Equal(2, versions.Count);
        Assert.Equal(9, versions[0].Item.Entry.Size);
        Assert.Equal(2, versions[1].Item.Entry.Size);
    }

    [Fact]
    public async Task SourceFiles_AreNeverModified()
    {
        using var t = new TestRepo();
        Populate(t);
        var before = Directory.EnumerateFiles(t.Source, "*", SearchOption.AllDirectories)
            .ToDictionary(p => p, p => (File.ReadAllBytes(p), File.GetLastWriteTimeUtc(p)));
        await t.BackupAsync(t.Options(level: VerificationLevel.Full));
        foreach (var (path, (bytes, mtime)) in before)
        {
            Assert.Equal(bytes, File.ReadAllBytes(path));
            Assert.Equal(mtime, File.GetLastWriteTimeUtc(path));
        }
    }

    [Fact]
    public async Task TamperedPack_IsDetected_AndNoCorruptFileIsLeftBehind()
    {
        using var t = new TestRepo();
        t.WriteFile("doc.bin", RandomBytes(200_000));
        var result = await t.BackupAsync();
        var pack = Directory.EnumerateFiles(Path.Combine(t.RepoPath, "store", "data"), "*.rzp", SearchOption.AllDirectories).Single();
        var bytes = File.ReadAllBytes(pack);
        bytes[ObjectHeader.Size + 1000] ^= 0x55;
        File.WriteAllBytes(pack, bytes);

        t.Reopen();
        var report = await t.RestoreAllAsync(result.SnapshotId);
        Assert.True(report.IntegrityFailure);
        Assert.Equal(1, report.FilesFailed);
        var restoredDir = Path.Combine(t.RestoreTarget, "Company Documents");
        Assert.Empty(Directory.EnumerateFiles(restoredDir, "*", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task TamperedSnapshotRecord_MakesSnapshotInvalid()
    {
        using var t = new TestRepo();
        t.WriteFile("a.txt", "a");
        var result = await t.BackupAsync();
        var rzb = Path.Combine(t.RepoPath, result.FolderName, "snapshot.rzb");
        var bytes = File.ReadAllBytes(rzb);
        bytes[^5] ^= 1;
        File.WriteAllBytes(rzb, bytes);
        t.Reopen();
        var loaded = t.Repo.LoadAllSnapshots().Single();
        Assert.Equal(SnapshotValidity.Invalid, loaded.Validity);
        Assert.False(loaded.IsRestorable);
    }

    [Fact]
    public async Task ManuallyRenamedIncompleteFolder_IsNotTreatedAsComplete()
    {
        using var t = new TestRepo();
        t.WriteFile("a.txt", "a");
        var opts = t.Options() with { FaultInjection = p => { if (p == "after-verify") throw new IOException("simulated crash"); } };
        await Assert.ThrowsAnyAsync<Exception>(() => t.BackupAsync(opts));
        var incomplete = Directory.EnumerateDirectories(t.RepoPath, "*.incomplete").Single();
        Directory.Move(incomplete, incomplete[..^".incomplete".Length]);
        t.Reopen();
        Assert.All(t.Repo.LoadAllSnapshots(), s => Assert.False(s.IsRestorable));
    }

    [Theory]
    [InlineData("after-pack-write")]
    [InlineData("after-data")]
    [InlineData("after-snapshot-record")]
    [InlineData("after-verify")]
    public async Task InterruptedBackup_StaysIncomplete_ThenNextRunSucceeds(string crashPoint)
    {
        using var t = new TestRepo();
        t.WriteFile("big.bin", RandomBytes(3 * 1024 * 1024));
        t.WriteFile("small.txt", "hello");
        var opts = t.Options() with { FaultInjection = p => { if (p == crashPoint) throw new IOException("simulated power loss"); } };
        await Assert.ThrowsAnyAsync<Exception>(() => t.BackupAsync(opts));

        t.Reopen();
        var snaps = t.Repo.LoadAllSnapshots();
        Assert.Single(snaps);
        Assert.Equal(SnapshotValidity.Incomplete, snaps[0].Validity);
        Assert.False(File.Exists(t.Repo.Layout.LockPath));

        var ok = await t.BackupAsync(t.Options() with { SnapshotLocalTime = DateTime.Now.AddSeconds(5) });
        Assert.Equal(RunOutcome.Success, ok.Outcome);
        var report = await t.RestoreAllAsync(ok.SnapshotId);
        Assert.Equal(2, report.FilesRestored);
    }

    [Fact]
    public async Task ResumeIncompleteSnapshot_CompletesSameFolder()
    {
        using var t = new TestRepo();
        t.WriteFile("big.bin", RandomBytes(3 * 1024 * 1024));
        var opts = t.Options() with { FaultInjection = p => { if (p == "after-data") throw new IOException("unplugged"); } };
        await Assert.ThrowsAnyAsync<Exception>(() => t.BackupAsync(opts));
        var folder = Path.GetFileName(Directory.EnumerateDirectories(t.RepoPath, "*.incomplete").Single());

        t.Reopen();
        var resumed = await t.BackupAsync(t.Options() with { ResumeFolderName = folder });
        Assert.Equal(folder[..^".incomplete".Length], resumed.FolderName);
        Assert.True(resumed.Stats.BytesNew < 1024, "Resume must reuse the packs already written.");
    }

    [Fact]
    public async Task CrashBetweenCommitAndRename_IsFinalizedOnNextRun()
    {
        using var t = new TestRepo();
        t.WriteFile("a.txt", "a");
        var opts = t.Options() with { FaultInjection = p => { if (p == "after-commit-record") throw new IOException("crash"); } };
        await Assert.ThrowsAnyAsync<Exception>(() => t.BackupAsync(opts));
        t.Reopen();
        Assert.Equal(SnapshotValidity.CommittedPendingFinalize, t.Repo.LoadAllSnapshots().Single().Validity);

        await t.BackupAsync(t.Options() with { SnapshotLocalTime = DateTime.Now.AddSeconds(3) });
        var all = t.Repo.LoadAllSnapshots();
        Assert.Equal(2, all.Count);
        Assert.All(all, s => Assert.True(s.IsRestorable));
    }

    [Fact]
    public async Task DiskFull_StopsSafely_WithoutCommitting()
    {
        using var t = new TestRepo();
        t.WriteFile("big.bin", RandomBytes(3 * 1024 * 1024));
        var opts = t.Options() with { FreeSpaceProbe = () => 10 * 1024 * 1024, ReserveBytes = 9 * 1024 * 1024 };
        var ex = await Assert.ThrowsAsync<RezenException>(() => t.BackupAsync(opts));
        Assert.Equal(ErrorCode.DestinationFull, ex.Code);
        Assert.Equal("Backup could not continue because the destination drive is full.", ex.Message);
        t.Reopen();
        Assert.All(t.Repo.LoadAllSnapshots(), s => Assert.False(s.IsRestorable));
    }

    [Fact]
    public async Task FullSnapshot_WritesIndependentCopy()
    {
        using var t = new TestRepo();
        t.WriteFile("big.bin", RandomBytes(1024 * 1024));
        var first = await t.BackupAsync();
        var full = await t.BackupAsync(t.Options(BackupMethod.FullSnapshot) with { SnapshotLocalTime = DateTime.Now.AddSeconds(2) });
        Assert.True(full.Stats.BytesNew >= 1024 * 1024);
        t.Reopen();
        var commits = t.Repo.LoadAllSnapshots().Select(s => s.Commit!.Packs.Where(p => p.Kind == PackKind.Data).Select(p => p.PackId).ToHashSet()).ToList();
        Assert.Empty(commits[0].Intersect(commits[1]));
        _ = first;
    }

    [Fact]
    public async Task DestinationInsideSource_IsRejected()
    {
        using var t = new TestRepo();
        var opts = t.Options() with { Sources = [t.Drive] };
        var ex = await Assert.ThrowsAsync<RezenException>(() => t.BackupAsync(opts));
        Assert.Equal(ErrorCode.UnsafeConfiguration, ex.Code);
    }

    [Fact]
    public async Task RestoreConflicts_AreNeverOverwrittenSilently()
    {
        using var t = new TestRepo();
        t.WriteFile("a.txt", "backup version");
        var r = await t.BackupAsync();
        var dest = Path.Combine(t.RestoreTarget, "Company Documents");
        Directory.CreateDirectory(dest);
        File.WriteAllText(Path.Combine(dest, "a.txt"), "newer local version");

        var skip = await t.RestoreAllAsync(r.SnapshotId, onConflict: ConflictChoice.Skip);
        Assert.Equal(1, skip.FilesSkipped);
        Assert.Equal("newer local version", File.ReadAllText(Path.Combine(dest, "a.txt")));

        await t.RestoreAllAsync(r.SnapshotId, onConflict: ConflictChoice.KeepBoth);
        Assert.Equal("newer local version", File.ReadAllText(Path.Combine(dest, "a.txt")));
        Assert.Contains(Directory.EnumerateFiles(dest), f => Path.GetFileName(f).Contains("(Restored", StringComparison.Ordinal));

        await t.RestoreAllAsync(r.SnapshotId, onConflict: ConflictChoice.Replace);
        Assert.Equal("backup version", File.ReadAllText(Path.Combine(dest, "a.txt")));
        Assert.Empty(Directory.EnumerateFiles(dest, "*" + RestoreExecutor.TempSuffix, SearchOption.AllDirectories));
    }

    [Fact]
    public async Task Retention_DeletesOnlyOutsidePolicy_AndRemainingSnapshotsRestore()
    {
        using var t = new TestRepo();
        var baseTime = DateTime.Now;
        for (int i = 0; i < 5; i++)
        {
            t.WriteFile($"file{i}.bin", RandomBytes(100_000));
            await t.BackupAsync(t.Options() with { SnapshotLocalTime = baseTime.AddMinutes(i) });
        }

        var runner = new RetentionRunner(t.Repo);
        var plan = runner.Plan(Core.Policies.RetentionPolicy.LastN(2) with { MinimumKeep = 2 }, new HashSet<Guid>(), DateTimeOffset.Now, t.IndexCache);
        Assert.Equal(3, plan.ToDelete.Count);
        var result = runner.Apply(plan, t.IndexCache);
        Assert.Equal(3, result.DeletedSnapshots.Count);

        t.Reopen();
        var remaining = t.Repo.LoadAllSnapshots();
        Assert.Equal(2, remaining.Count);
        var latest = remaining.Last();
        var report = await t.RestoreAllAsync(latest.Record!.SnapshotId);
        Assert.Equal(5, report.FilesRestored);
        Assert.False(report.IntegrityFailure);
    }

    [Fact]
    public async Task DeepVerify_FindsDamage_AndQuarantinePlusBackupRepairs()
    {
        using var t = new TestRepo();
        t.WriteFile("doc.bin", RandomBytes(200_000));
        await t.BackupAsync();
        var pack = Directory.EnumerateFiles(Path.Combine(t.RepoPath, "store", "data"), "*.rzp", SearchOption.AllDirectories).Single();
        var bytes = File.ReadAllBytes(pack);
        bytes[ObjectHeader.Size + 10] ^= 1;
        File.WriteAllBytes(pack, bytes);

        t.Reopen();
        var verifier = new RepositoryVerifier(t.Repo);
        var report = verifier.Verify();
        Assert.False(report.Healthy);
        var damaged = Assert.Single(report.DamagedPacks);
        verifier.Quarantine(damaged.PackId, damaged.Kind, null);

        // Next backup re-stores the missing chunk from the unchanged source file.
        var repaired = await t.BackupAsync(t.Options() with { IndexCachePath = null, SnapshotLocalTime = DateTime.Now.AddSeconds(4) });
        Assert.True(repaired.Stats.BytesNew >= 200_000);
        t.Reopen();
        Assert.True(new RepositoryVerifier(t.Repo).Verify().Snapshots.Last().AllDataPresent);
    }
}

public class KeyManagementTests
{
    [Fact]
    public void Password_Unlocks_WrongPassword_FailsGenerically()
    {
        using var t = new TestRepo();
        using (var pw = PasswordEncoding.ToKeyMaterial(TestRepo.Password))
        using (var secret = Repository.UnlockWithPassword(t.RepoPath, pw, PortableDurableFileOps.Instance, out _))
        {
            Assert.True(secret.ContentEquals(t.Secret));
        }

        using var wrong = PasswordEncoding.ToKeyMaterial("not the password at all");
        var ex = Assert.Throws<RezenException>(() => Repository.UnlockWithPassword(t.RepoPath, wrong, PortableDurableFileOps.Instance, out _));
        Assert.Equal(ErrorCode.WrongPassword, ex.Code);
        Assert.Equal(UserMessages.UnlockFailed, ex.Message);
    }

    [Fact]
    public async Task RecoveryKey_OpensRepository_OnAnotherMachine()
    {
        using var t = new TestRepo();
        t.WriteFile("a.txt", "recover me");
        var r = await t.BackupAsync();
        var recoveryText = RecoveryKeyCodec.Encode(t.Secret);

        // Simulate a new PC: only the drive and the printed recovery key.
        using var recovered = RecoveryKeyCodec.Decode(recoveryText);
        t.Reopen(recovered);
        var report = await t.RestoreAllAsync(r.SnapshotId);
        Assert.Equal(1, report.FilesRestored);
    }

    [Fact]
    public void WrongRecoveryKey_IsRejected()
    {
        using var t = new TestRepo();
        using var other = RootSecret.Generate();
        var ex = Assert.Throws<RezenException>(() => Repository.Open(t.RepoPath, other, PortableDurableFileOps.Instance));
        Assert.Equal(ErrorCode.WrongPassword, ex.Code);
    }

    [Fact]
    public void DamagedKeyFileCopy_IsRepairedFromTheOther()
    {
        using var t = new TestRepo();
        var keyA = new RepositoryLayout(t.RepoPath).KeyFileA;
        var bytes = File.ReadAllBytes(keyA);
        bytes[60] ^= 0xFF;
        File.WriteAllBytes(keyA, bytes);

        using var pw = PasswordEncoding.ToKeyMaterial(TestRepo.Password);
        using var secret = Repository.UnlockWithPassword(t.RepoPath, pw, PortableDurableFileOps.Instance, out var report);
        Assert.Equal(1, report.DamagedCopies);
        Assert.Equal(1, report.RepairedCopies);
        Assert.NotNull(KeyFileStore.TryRead(keyA, out bool damaged));
        Assert.False(damaged);
    }

    [Fact]
    public void AllKeyFilesDamaged_RequiresRecoveryKey()
    {
        using var t = new TestRepo();
        var layout = new RepositoryLayout(t.RepoPath);
        foreach (var kf in layout.KeyFiles)
        {
            File.WriteAllBytes(kf, new byte[100]);
        }

        using var pw = PasswordEncoding.ToKeyMaterial(TestRepo.Password);
        var ex = Assert.Throws<RezenException>(() => Repository.UnlockWithPassword(t.RepoPath, pw, PortableDurableFileOps.Instance, out _));
        Assert.Equal(ErrorCode.RecoveryKeyRequired, ex.Code);

        // The recovery key still opens everything (no key file needed).
        using var repo = Repository.Open(t.RepoPath, t.Secret, PortableDurableFileOps.Instance);
        Assert.Equal(t.Repo.RepositoryId, repo.RepositoryId);
    }

    [Fact]
    public void PasswordChange_RewrapsWithoutReencrypting()
    {
        using var t = new TestRepo();
        const string newPassword = "an entirely new passphrase 99";
        using var newPw = PasswordEncoding.ToKeyMaterial(newPassword);
        var current = Repository.ReadBestKeyFile(t.RepoPath)!;
        var replacement = KeyFile.CreateWithPassword(t.KeySetId, t.Repo.RepositoryId, current.Generation + 1, t.Secret, newPw, TestSetup.FastKdf);
        t.Repo.ReplaceKeyFiles(replacement, t.Secret, f =>
        {
            using var check = f.Unlock(newPw);
            return check.ContentEquals(t.Secret);
        });

        using var oldPw = PasswordEncoding.ToKeyMaterial(TestRepo.Password);
        Assert.Throws<RezenException>(() => Repository.UnlockWithPassword(t.RepoPath, oldPw, PortableDurableFileOps.Instance, out _));
        using var unlocked = Repository.UnlockWithPassword(t.RepoPath, newPw, PortableDurableFileOps.Instance, out _);
        Assert.True(unlocked.ContentEquals(t.Secret));
    }

    [Fact]
    public void KeyFiles_ContainNoSecretMaterial()
    {
        using var t = new TestRepo();
        foreach (var kf in new RepositoryLayout(t.RepoPath).KeyFiles)
        {
            var bytes = File.ReadAllBytes(kf);
            Assert.True(bytes.AsSpan().IndexOf(t.Secret.Bytes) < 0);
            Assert.True(bytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes(TestRepo.Password)) < 0);
        }
    }
}

public class ReviewRegressionTests
{
    /// <summary>A file whose bytes equal an encoded tree must not collide with that tree (review finding 2).</summary>
    [Fact]
    public async Task FileWithTreeLikeContent_DoesNotCollideWithTrees()
    {
        using var t = new TestRepo();
        var emptyTree = new TreeNode([]).Encode();
        var payload = "tree"u8.ToArray().Concat(emptyTree).ToArray();
        t.WriteFile("evil.bin", payload);
        t.WriteFile("plain.bin", emptyTree);
        Directory.CreateDirectory(Path.Combine(t.Source, "EmptyFolder"));

        var first = await t.BackupAsync();
        Assert.Equal(RunOutcome.Success, first.Outcome);
        var second = await t.BackupAsync(t.Options() with { SnapshotLocalTime = DateTime.Now.AddSeconds(3) });
        Assert.Equal(RunOutcome.Success, second.Outcome);

        t.Reopen();
        var report = await t.RestoreAllAsync(second.SnapshotId);
        Assert.False(report.IntegrityFailure);
        Assert.Equal(payload, File.ReadAllBytes(Path.Combine(t.RestoreTarget, "Company Documents", "evil.bin")));
        Assert.Equal(emptyTree, File.ReadAllBytes(Path.Combine(t.RestoreTarget, "Company Documents", "plain.bin")));
        Assert.True(Directory.Exists(Path.Combine(t.RestoreTarget, "Company Documents", "EmptyFolder")));
    }
}
