using System.Reflection;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Policies;
using RezenBackup.Logging;
using RezenBackup.Scheduler;
using RezenBackup.Security;

namespace RezenBackup.Tests.Policies;

public class ScheduleTests
{
    private static readonly TimeZoneInfo Utc = TimeZoneInfo.Utc;

    [Fact]
    public void Daily_NextRunIsTodayOrTomorrow()
    {
        var s = Schedule.DailyAt(20);
        var morning = new DateTimeOffset(2026, 11, 3, 9, 0, 0, TimeSpan.Zero);
        Assert.Equal(new DateTimeOffset(2026, 11, 3, 20, 0, 0, TimeSpan.Zero), ScheduleCalculator.NextRun(s, morning, Utc));
        var night = new DateTimeOffset(2026, 11, 3, 21, 0, 0, TimeSpan.Zero);
        Assert.Equal(new DateTimeOffset(2026, 11, 4, 20, 0, 0, TimeSpan.Zero), ScheduleCalculator.NextRun(s, night, Utc));
    }

    [Fact]
    public void Weekly_SelectedDays()
    {
        var s = new Schedule { Kind = ScheduleKind.Weekly, TimeOfDay = new TimeOnly(8, 0), Days = [DayOfWeek.Monday, DayOfWeek.Thursday] };
        var tuesday = new DateTimeOffset(2026, 11, 3, 12, 0, 0, TimeSpan.Zero); // Tuesday
        Assert.Equal(DayOfWeek.Thursday, ScheduleCalculator.NextRun(s, tuesday, Utc)!.Value.DayOfWeek);
    }

    [Fact]
    public void Monthly_ClampsToShortMonths()
    {
        var s = new Schedule { Kind = ScheduleKind.Monthly, DayOfMonth = 31, TimeOfDay = new TimeOnly(1, 0) };
        var next = ScheduleCalculator.NextRun(s, new DateTimeOffset(2026, 11, 3, 0, 0, 0, TimeSpan.Zero), Utc)!.Value;
        Assert.Equal(new DateTime(2026, 11, 30, 1, 0, 0), next.DateTime);
    }

    [Fact]
    public void Interval_EverySixHours()
    {
        var s = new Schedule { Kind = ScheduleKind.Interval, IntervalHours = 6 };
        var next = ScheduleCalculator.NextRun(s, new DateTimeOffset(2026, 11, 3, 7, 30, 0, TimeSpan.Zero), Utc)!.Value;
        Assert.Equal(12, next.Hour);
    }

    [Fact]
    public void Manual_NeverRuns() => Assert.Null(ScheduleCalculator.NextRun(Schedule.Manual, DateTimeOffset.Now, Utc));

    [Fact]
    public void DstSpringForwardGap_IsSkippedSafely()
    {
        TimeZoneInfo zone;
        try
        {
            zone = TimeZoneInfo.FindSystemTimeZoneById("America/New_York");
        }
        catch (TimeZoneNotFoundException)
        {
            return;
        }

        var s = Schedule.DailyAt(2, 30); // 2:30 does not exist on 2026-03-08 in New York
        var next = ScheduleCalculator.NextRun(s, new DateTimeOffset(2026, 3, 7, 23, 0, 0, TimeSpan.FromHours(-5)), zone)!.Value;
        Assert.False(zone.IsInvalidTime(next.DateTime));
    }

    [Fact]
    public void MissedRun_IsReportedAsMissed_AndRespectsSetting()
    {
        var job = new JobDefinition { Id = Guid.NewGuid(), KeySetId = Guid.NewGuid(), Name = "J", Schedule = Schedule.DailyAt(20), CreatedUtc = new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero) };
        var last = new Dictionary<Guid, DateTimeOffset> { [job.Id] = new DateTimeOffset(2026, 11, 1, 21, 0, 0, TimeSpan.Zero) };
        var now = new DateTimeOffset(2026, 11, 3, 9, 0, 0, TimeSpan.Zero);
        var due = BackupScheduler.FindDue([job], last, now, agentStarted: now, runMissedGlobally: true, TimeZoneInfo.Utc);
        Assert.Equal(RunTrigger.Missed, Assert.Single(due).Trigger);
        Assert.Empty(BackupScheduler.FindDue([job], last, now, now, runMissedGlobally: false, TimeZoneInfo.Utc));
        Assert.Empty(BackupScheduler.FindDue([job with { Enabled = false }], last, now, now, true, TimeZoneInfo.Utc));
    }

    [Fact]
    public async Task JobQueue_SerialisesJobsOnTheSameDisk()
    {
        var queue = new JobQueue(maxConcurrent: 4);
        int running = 0;
        int maxSeen = 0;
        bool waited = false;
        async Task Work(CancellationToken _)
        {
            int now = Interlocked.Increment(ref running);
            maxSeen = Math.Max(maxSeen, now);
            await Task.Delay(50);
            Interlocked.Decrement(ref running);
        }

        await Task.WhenAll(
            queue.RunAsync(Guid.NewGuid(), "E:\\", Work, () => waited = true, default),
            queue.RunAsync(Guid.NewGuid(), "E:\\", Work, () => waited = true, default));
        Assert.Equal(1, maxSeen);
        Assert.True(waited);
    }
}

public class RetentionTests
{
    private static List<RetentionCandidate> Daily(int count, DateTimeOffset now) =>
        Enumerable.Range(0, count).Select(i => new RetentionCandidate(Guid.NewGuid(), now.AddDays(-i), false, true)).ToList();

    [Fact]
    public void LastN_KeepsNewestN()
    {
        var now = DateTimeOffset.UtcNow;
        var snaps = Daily(10, now);
        var delete = RetentionCalculator.SelectForDeletion(snaps, RetentionPolicy.LastN(5), now);
        Assert.Equal(5, delete.Count);
        Assert.DoesNotContain(snaps[0].SnapshotId, delete);
    }

    [Fact]
    public void Age_NeverDeletesEverything_WhenBackupsStopped()
    {
        var now = DateTimeOffset.UtcNow;
        var old = Daily(10, now.AddDays(-60)); // computer was off for two months
        var delete = RetentionCalculator.SelectForDeletion(old, RetentionPolicy.Days(7), now);
        Assert.Equal(7, delete.Count); // minimum of 3 most recent kept
    }

    [Fact]
    public void PinnedAndUnverified_AreNeverDeleted()
    {
        var now = DateTimeOffset.UtcNow;
        var snaps = Daily(10, now);
        snaps[9] = snaps[9] with { Pinned = true };
        snaps[8] = snaps[8] with { Verified = false };
        var delete = RetentionCalculator.SelectForDeletion(snaps, RetentionPolicy.LastN(3), now);
        Assert.DoesNotContain(snaps[9].SnapshotId, delete);
        Assert.DoesNotContain(snaps[8].SnapshotId, delete);
    }

    [Fact]
    public void Forever_DeletesNothing() =>
        Assert.Empty(RetentionCalculator.SelectForDeletion(Daily(100, DateTimeOffset.UtcNow), RetentionPolicy.Forever, DateTimeOffset.UtcNow));

    [Fact]
    public void Smart_KeepsDailyWeeklyMonthly()
    {
        var now = DateTimeOffset.UtcNow;
        var snaps = Daily(400, now);
        var delete = RetentionCalculator.SelectForDeletion(snaps, RetentionPolicy.Smart, now).ToHashSet();
        var kept = snaps.Where(s => !delete.Contains(s.SnapshotId)).ToList();
        Assert.True(kept.Count(s => now - s.Time <= TimeSpan.FromDays(7)) >= 7);
        Assert.InRange(kept.Count, 7 + 10, 7 + 14 + 13);
        Assert.DoesNotContain(kept, s => now - s.Time > TimeSpan.FromDays(366));
    }
}

public class NamingAndPathTests
{
    [Fact]
    public void SnapshotNames_ParseAllStates()
    {
        Assert.True(SnapshotNaming.TryParse("2026-11-03_20-00-00", out var c));
        Assert.Equal(SnapshotState.Committed, c!.State);
        Assert.True(SnapshotNaming.TryParse("2026-11-03_20-00-00_2.incomplete", out var i));
        Assert.Equal(SnapshotState.Incomplete, i!.State);
        Assert.Equal(2, i.Sequence);
        Assert.True(SnapshotNaming.TryParse("2026-11-03_20-00-00.deleting", out var d));
        Assert.Equal(SnapshotState.Deleting, d!.State);
        Assert.False(SnapshotNaming.TryParse("11-03-26", out _));
    }

    [Fact]
    public void UniqueName_HandlesDstRepeat()
    {
        var t = new DateTime(2026, 11, 1, 1, 30, 0);
        var (name, seq) = SnapshotNaming.ChooseUnique(t, ["2026-11-01_01-30-00", "2026-11-01_01-30-00_2.incomplete"]);
        Assert.Equal("2026-11-01_01-30-00_3", name);
        Assert.Equal(3, seq);
    }

    [Fact]
    public void Overlap_IsDetected()
    {
        var root = Path.Combine(Path.GetTempPath(), "Company");
        var inner = Path.Combine(root, "Invoices");
        Assert.Equal(SourceOverlapKind.NewIsInsideExisting, PathPolicy.CheckNewSource(inner, [root]).Kind);
        Assert.Equal(SourceOverlapKind.NewContainsExisting, PathPolicy.CheckNewSource(root, [inner]).Kind);
        Assert.Equal(SourceOverlapKind.None, PathPolicy.CheckNewSource(root + "2", [root]).Kind);
    }

    [Fact]
    public void WindowsNames_AreMadeValid()
    {
        Assert.Equal("a\uFF1Ab", WindowsNames.MakeValid("a:b"));
        Assert.Equal("_CON.txt", WindowsNames.MakeValid("CON.txt"));
        Assert.Equal("name_", WindowsNames.MakeValid("name."));
        Assert.Same("ok.txt", WindowsNames.MakeValid("ok.txt"));
    }

    [Fact]
    public void Exclusions_MatchDefaultsAndUserRules()
    {
        var m = new ExclusionMatcher([.. ExclusionMatcher.Defaults, new ExclusionRule(ExclusionKind.Folder, "node_modules"), new ExclusionRule(ExclusionKind.Pattern, "*.cache")]);
        Assert.True(m.IsExcludedFile("/x/Thumbs.db", "Thumbs.db"));
        Assert.True(m.IsExcludedFile("/x/~$Budget.xlsx", "~$Budget.xlsx"));
        Assert.True(m.IsExcludedFile("/x/a.TMP", "a.TMP"));
        Assert.True(m.IsExcludedFile("/x/a.cache", "a.cache"));
        Assert.True(m.IsExcludedDirectory("/x/node_modules", "node_modules"));
        Assert.False(m.IsExcludedFile("/x/Budget.xlsx", "Budget.xlsx"));
    }
}

public class PasswordPolicyTests
{
    [Theory]
    [InlineData("password1234")]
    [InlineData("qwertyuiop12")]
    [InlineData("aaaaaaaaaaaaaaaa")]
    [InlineData("short")]
    public void WeakPasswords_AreRejected(string pw) => Assert.False(PasswordPolicy.Assess(pw).MeetsRequirements);

    [Theory]
    [InlineData("correct horse battery staple")]
    [InlineData("orange tractor singing quietly 42")]
    [InlineData("Gx7#pQ2!vL9@mZ4$")]
    [InlineData("смородина зелёная лодка утро")]
    public void StrongPasswordsAndPassphrases_AreAccepted(string pw) => Assert.True(PasswordPolicy.Assess(pw).MeetsRequirements);

    [Fact]
    public void NoArbitraryMaximumLength() => Assert.True(PasswordPolicy.Assess(string.Concat(Enumerable.Repeat("long passphrase word ", 200))).MeetsRequirements);

    [Fact]
    public void AutoLock_FiresAfterIdle_AndIsDeferredWhileBusy()
    {
        var m = new SessionLockManager { Mode = AutoLockMode.After5Minutes };
        string? reason = null;
        m.LockRequested += r => reason = r;
        m.MarkUnlocked();
        using (m.BeginBusy())
        {
            m.Tick(DateTimeOffset.UtcNow.AddMinutes(10));
            Assert.Null(reason);
        }

        m.Tick(DateTimeOffset.UtcNow.AddMinutes(10));
        Assert.NotNull(reason);
        Assert.False(m.IsUnlocked);
    }

    [Fact]
    public void SystemLock_LocksWhenEnabled()
    {
        var m = new SessionLockManager();
        bool locked = false;
        m.LockRequested += _ => locked = true;
        m.MarkUnlocked();
        m.OnSystemSessionLocked();
        Assert.True(locked);
    }
}

public class LoggingTests
{
    [Fact]
    public void Paths_AreRedacted_WhenHidingFileNames()
    {
        LogPrivacy.HideFileNames = true;
        var scrubbed = LogPrivacy.Scrub(@"Could not read C:\Company\Payroll.xlsx and /Users/alice/Secret Plans.docx");
        Assert.DoesNotContain("Payroll", scrubbed, StringComparison.Ordinal);
        Assert.DoesNotContain("alice", scrubbed, StringComparison.Ordinal);
        Assert.Contains("path#", scrubbed, StringComparison.Ordinal);
        Assert.Equal(LogPrivacy.Path("/a/b"), LogPrivacy.Path("/a/b"));
    }

    [Fact]
    public void SecurityLog_DetectsTampering()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rezen-seclog-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            using var db = new Database.AppDatabase(Path.Combine(dir, "t.db"));
            var log = new SecurityLog(db, new byte[32]);
            log.Record(SecurityEvents.Unlock);
            log.Record(SecurityEvents.Restore, null, "files: 3");
            log.Record(SecurityEvents.PasswordChanged);
            Assert.Null(log.VerifyChain());
            db.Exec("UPDATE security_events SET detail='files: 0' WHERE type='RestorePerformed'");
            Assert.NotNull(log.VerifyChain());
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}

/// <summary>Offline gate (DESIGN §1.4): no Rezen assembly may reference networking APIs.</summary>
public class OfflineTests
{
    private static readonly string[] Forbidden =
    [
        "System.Net.Http.HttpClient",
        "System.Net.WebClient",
        "System.Net.Sockets.Socket",
        "System.Net.Sockets.TcpClient",
        "System.Net.Sockets.UdpClient",
        "System.Net.WebRequest",
        "System.Net.Http.HttpMessageHandler",
    ];

    [Fact]
    public void NoAssemblyReferencesNetworkingTypes()
    {
        var dir = AppContext.BaseDirectory;
        var assemblies = Directory.EnumerateFiles(dir, "RezenBackup.*.dll").Where(f => !Path.GetFileName(f).Contains("Tests", StringComparison.Ordinal)).ToList();
        Assert.NotEmpty(assemblies);
        foreach (var file in assemblies)
        {
            using var stream = File.OpenRead(file);
            using var pe = new System.Reflection.PortableExecutable.PEReader(stream);
            var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
            foreach (var handle in md.TypeReferences)
            {
                var tr = md.GetTypeReference(handle);
                var name = md.GetString(tr.Namespace) + "." + md.GetString(tr.Name);
                Assert.DoesNotContain(name, Forbidden);
            }
        }
    }

    [Fact]
    public void ApplicationAssemblyLoads() => Assert.NotNull(Assembly.Load("RezenBackup.Application"));
}
