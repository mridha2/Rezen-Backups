using System.Globalization;
using System.Text;
using RezenBackup.Agent;
using RezenBackup.Application;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Policies;
using RezenBackup.RestoreEngine;
using RezenBackup.Security;

namespace RezenBackup.Cli;

/// <summary>
/// <c>rezen</c> — command-line interface to Rezen Backup for headless use, scripting and support.
/// Passwords are read without echo (or from stdin with --password-stdin) and never accepted as arguments.
/// </summary>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintHelp();
            return 0;
        }

        var opts = Options.Parse(args.Skip(1).ToArray());
        try
        {
            using var app = RezenApp.Create(logPrefix: "cli");
            return args[0] switch
            {
                "status" => Status(app),
                "init" => Init(app, opts),
                "drives" => Drives(app),
                "job-create" => JobCreate(app, opts),
                "jobs" => Jobs(app),
                "backup" => await Backup(app, opts),
                "snapshots" => await Snapshots(app, opts),
                "ls" => await List(app, opts),
                "search" => await Search(app, opts),
                "restore" => await Restore(app, opts),
                "verify" => await Verify(app, opts),
                "import" => Import(app, opts),
                "change-password" => await ChangePassword(app, opts),
                "recovery-key" => await RecoveryKey(app, opts),
                "remember" => await Remember(app, opts),
                "history" => History(app, opts),
                "security-log" => SecurityLog(app),
                "export-config" => ExportConfig(app),
                "agent" => await Agent(app),
                _ => Unknown(args[0]),
            };
        }
        catch (RezenException ex)
        {
            Console.Error.WriteLine(ex.Message);
            if (opts.Has("verbose") && ex.TechnicalDetails is { } t)
            {
                Console.Error.WriteLine("Technical details: " + t);
            }

            return 2;
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine("""
            Rezen Backup — secure offline backup

            Usage: rezen <command> [options]

              status                              Protection status of every job
              init [--name NAME]                  Create the backup password and recovery key
              drives                              List drives that can hold backups
              job-create --name N --source DIR... --dest DRIVE_ROOT [--schedule daily@20:00|manual|hourly:6] [--full-verify] [--hide-names]
              jobs                                List backup jobs
              backup <job>                        Back up now (uses remembered key or asks for the password)
              snapshots <job>                     List dated snapshots (needs password)
              ls <job> [--snapshot FOLDER] [--path a/b]   Browse a snapshot
              search <job> --name TEXT [--ext pdf] [--snapshot FOLDER]
              restore <job> --to DIR [--snapshot FOLDER] [--path a/b] [--on-conflict skip|replace|keep-both]
              verify <job> [--deep]               Verify backup integrity
              import <DRIVE_ROOT> [--recovery-key]  Import existing Rezen Backup from a drive
              change-password                     Change the backup password (re-wraps keys, no re-encryption)
              recovery-key                        Show the recovery key (needs password)
              remember on|off [--full-key]        Remember a backup-only key (default) or the full key for scheduled backups
              history [<job>]                     Backup history
              security-log                        Security events and chain verification
              export-config                       Print configuration JSON (contains no secrets)
              agent                               Run the background agent in this terminal

            Options: --password-stdin  read the password from standard input   --verbose  technical details
            """);
    }

    private static int Unknown(string cmd)
    {
        Console.Error.WriteLine($"Unknown command '{cmd}'. Run 'rezen help'.");
        return 1;
    }

    private static int Status(RezenApp app)
    {
        var d = app.Status.Dashboard();
        Console.WriteLine(d.Headline);
        Console.WriteLine($"Encryption: {d.EncryptionText}");
        foreach (var j in d.Jobs)
        {
            Console.WriteLine();
            Console.WriteLine($"  {j.Job.Name}{(j.Job.Enabled ? string.Empty : " (disabled)")}");
            Console.WriteLine($"    Status:       {j.Security.ToDisplay()}");
            Console.WriteLine($"    Last backup:  {Fmt.When(j.LastSuccess?.StartedUtc)}");
            Console.WriteLine($"    Next backup:  {(j.NextRun is { } n ? Fmt.When(n) : "Manual")}");
            Console.WriteLine($"    Backup drive: {(j.DriveConnected ? "✓ Connected" : "Not connected")} {j.DriveLabel}");
            if (j.Volume is { } v)
            {
                Console.WriteLine($"    Available:    {Fmt.Bytes(v.FreeBytes)} of {Fmt.Bytes(v.TotalBytes)}");
            }

            Console.WriteLine($"    Snapshots:    {j.SnapshotCount}");
            foreach (var w in j.Warnings)
            {
                Console.WriteLine($"    ! {w}");
            }
        }

        foreach (var w in d.Warnings.Where(w => w.StartsWith("No recovery key", StringComparison.Ordinal)))
        {
            Console.WriteLine();
            Console.WriteLine("! " + w);
        }

        return 0;
    }

    private static int Init(RezenApp app, Options opts)
    {
        if (app.KeySets.Default is not null && !opts.Has("force"))
        {
            Console.Error.WriteLine("A backup password already exists. Use 'rezen change-password' to change it.");
            return 1;
        }

        Console.WriteLine("Create your backup password. Your backup drive cannot be opened without it.");
        Console.WriteLine($"Use at least {PasswordPolicy.MinimumLength} characters; a passphrase of four or more words is recommended.");
        string password;
        while (true)
        {
            password = ReadPassword(opts, "Password: ");
            var a = PasswordPolicy.Assess(password);
            Console.WriteLine($"Strength: {a.StrengthText} (estimated offline cracking time: {a.CrackTimeDisplay})");
            foreach (var f in a.Feedback)
            {
                Console.WriteLine("  - " + f);
            }

            if (!a.MeetsRequirements)
            {
                if (opts.Has("password-stdin"))
                {
                    return 1;
                }

                continue;
            }

            if (opts.Has("password-stdin") || ReadPassword(opts, "Confirm password: ") == password)
            {
                break;
            }

            Console.WriteLine("Passwords do not match.");
        }

        var ks = app.KeySets.Create(password, opts.Get("name") ?? "Rezen Backup password");
        ks.Secret.Dispose();
        Console.WriteLine();
        Console.WriteLine("RECOVERY KEY — store it offline (print it, or save it on a different removable device):");
        Console.WriteLine();
        Console.WriteLine("    " + ks.RecoveryKey);
        Console.WriteLine();
        Console.WriteLine("If you lose both your password and your recovery key, your encrypted backups cannot be recovered.");
        Console.WriteLine("Never store the recovery key on the same drive as your backups.");
        if (!opts.Has("password-stdin"))
        {
            var groups = Crypto.RecoveryKeyCodec.Groups(ks.RecoveryKey);
            int i = Crypto.CryptoRandom.NextInt(groups.Length);
            Console.Write($"To confirm you saved it, type group {i + 1}: ");
            if (string.Equals(Console.ReadLine()?.Trim(), groups[i], StringComparison.OrdinalIgnoreCase))
            {
                app.KeySets.ConfirmRecoveryKeySaved(ks.Info.Id);
                Console.WriteLine("Recovery key confirmed.");
            }
            else
            {
                Console.WriteLine("Not confirmed. You can view it again later with 'rezen recovery-key'.");
            }
        }

        return 0;
    }

    private static int Drives(RezenApp app)
    {
        foreach (var c in app.Drives.Candidates())
        {
            Console.WriteLine($"{c.Volume.RootPath,-30} {c.Volume.Label,-20} {c.Volume.FileSystem,-8} {Fmt.Bytes(c.Volume.FreeBytes),10} free  {(c.Volume.IsRemovable ? "removable" : "fixed")}{(c.HasRezenBackups ? "  [Rezen Backup drive]" : string.Empty)}");
        }

        return 0;
    }

    private static int JobCreate(RezenApp app, Options opts)
    {
        var ks = app.KeySets.Default ?? throw new RezenException(ErrorCode.KeyUnavailable, "Run 'rezen init' first.", null, null);
        var name = opts.Get("name") ?? throw new RezenException(ErrorCode.InvalidConfiguration, "--name is required.", null, null);
        var dest = opts.Get("dest") ?? throw new RezenException(ErrorCode.InvalidConfiguration, "--dest is required.", null, null);
        var sources = opts.All("source").Select(Path.GetFullPath).ToList();
        var draft = new JobDefinition
        {
            Id = Guid.Empty,
            KeySetId = ks.Id,
            Name = name,
            Sources = sources,
            Schedule = ParseSchedule(opts.Get("schedule") ?? "daily@20:00"),
            Verification = opts.Has("full-verify") ? VerificationLevel.Full : app.Settings.DefaultVerification,
            HideNamesOnDrive = opts.Has("hide-names"),
        };
        foreach (var m in app.Jobs.Validate(draft, Path.GetFullPath(dest)))
        {
            Console.WriteLine($"{m.Severity}: {m.Message}");
        }

        using var secret = app.KeySets.UnlockAsync(ks.Id, ReadPassword(opts, "Backup password: ")).GetAwaiter().GetResult();
        var job = app.Jobs.Create(draft, Path.GetFullPath(dest), secret);
        Console.WriteLine($"Created job \"{job.Name}\" ({job.Id}). Schedule: {job.Schedule.Describe()}.");
        return 0;
    }

    private static Schedule ParseSchedule(string s)
    {
        if (s == "manual")
        {
            return Schedule.Manual;
        }

        if (s.StartsWith("hourly:", StringComparison.Ordinal))
        {
            return new Schedule { Kind = ScheduleKind.Interval, IntervalHours = int.Parse(s[7..], CultureInfo.InvariantCulture) };
        }

        if (s.StartsWith("daily@", StringComparison.Ordinal))
        {
            return new Schedule { Kind = ScheduleKind.Daily, TimeOfDay = TimeOnly.Parse(s[6..], CultureInfo.InvariantCulture) };
        }

        throw new RezenException(ErrorCode.InvalidConfiguration, "Schedule must be manual, daily@HH:MM or hourly:N.", null, null);
    }

    private static int Jobs(RezenApp app)
    {
        foreach (var j in app.Jobs.All)
        {
            Console.WriteLine($"{j.Id}  {j.Name}  [{j.Schedule.Describe()}]  {(j.Enabled ? "enabled" : "disabled")}");
            foreach (var s in j.Sources)
            {
                Console.WriteLine($"    {s}");
            }
        }

        return 0;
    }

    private static JobDefinition ResolveJob(RezenApp app, Options opts)
    {
        var key = opts.Positional.FirstOrDefault();
        var jobs = app.Jobs.All;
        var job = key is null && jobs.Count == 1 ? jobs[0]
            : jobs.FirstOrDefault(j => j.Id.ToString().StartsWith(key ?? "\0", StringComparison.OrdinalIgnoreCase) || string.Equals(j.Name, key, StringComparison.OrdinalIgnoreCase));
        return job ?? throw new RezenException(ErrorCode.InvalidConfiguration, "Specify a job by name or id ('rezen jobs').", null, null);
    }

    private static async Task<int> Backup(RezenApp app, Options opts)
    {
        var job = ResolveJob(app, opts);
        var secret = app.KeySets.TryLoadRemembered(job.KeySetId) ?? await app.KeySets.UnlockAsync(job.KeySetId, ReadPassword(opts, "Backup password: "));
        Console.WriteLine($"Securing {job.Name}…");
        var runTask = app.Backups.RunAsync(job.Id, RunTrigger.Manual, secret, opts.Get("resume"));
        while (!runTask.IsCompleted)
        {
            await Task.WhenAny(runTask, Task.Delay(500));
            if (app.Backups.Active(job.Id) is { } active && !Console.IsOutputRedirected)
            {
                var p = active.Progress;
                Console.Write($"\r{p.PhaseText,-28} {p.FilesDone:N0}/{p.FilesTotal:N0} files  {Fmt.Bytes(p.BytesDone)}/{Fmt.Bytes(p.BytesTotal)}  {Fmt.Bytes((long)p.BytesPerSecond)}/s   ");
            }
        }

        var run = await runTask;
        Console.WriteLine();
        Console.WriteLine($"{run.Outcome.ToDisplay()} — {run.Security.ToDisplay()}");
        if (run.Message is { } m)
        {
            Console.WriteLine(m);
        }

        if (run.SnapshotFolder is { } f)
        {
            Console.WriteLine($"Snapshot: {f}  ({run.Files:N0} files, {Fmt.Bytes(run.BytesNew)} new)");
        }

        return run.Outcome is RunOutcome.Success or RunOutcome.CompletedWithWarnings ? 0 : 3;
    }

    private static async Task<(UnlockedSession Session, CatalogSession Catalog, JobDefinition Job)> Open(RezenApp app, Options opts)
    {
        var job = ResolveJob(app, opts);
        UnlockedSession session = opts.Has("recovery-key")
            ? UnlockedSession.UnlockWithRecoveryKey(app, job.KeySetId, ReadPassword(opts, "Recovery key: "))
            : await UnlockedSession.UnlockAsync(app, job.KeySetId, ReadPassword(opts, "Backup password: "));
        return (session, session.OpenCatalog(job.Id), job);
    }

    private static SnapshotSummary PickSnapshot(CatalogSession catalog, Options opts)
    {
        var name = opts.Get("snapshot");
        var snap = name is null ? catalog.RestorableSnapshots.FirstOrDefault() : catalog.RestorableSnapshots.FirstOrDefault(s => s.FolderName == name);
        return snap ?? throw new RezenException(ErrorCode.InvalidConfiguration, "No restorable snapshot found.", null, null);
    }

    private static async Task<int> Snapshots(RezenApp app, Options opts)
    {
        var (session, catalog, _) = await Open(app, opts);
        using (session)
        {
            foreach (var s in catalog.Snapshots)
            {
                var stats = s.Record?.Stats;
                Console.WriteLine($"{s.FolderName,-32} {(s.IsRestorable ? "Encrypted & Verified" : s.Validity.ToString()),-22} {stats?.Files ?? 0,8:N0} files  {Fmt.Bytes(stats?.BytesScanned ?? 0),10}  {s.Problem}");
            }
        }

        return 0;
    }

    private static CatalogPath ResolvePath(CatalogSession catalog, SnapshotSummary snap, string? path)
    {
        var root = catalog.Roots(snap.SnapshotId)[0].Path;
        var parts = (path ?? string.Empty).Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries);
        return root with { Components = parts };
    }

    private static async Task<int> List(RezenApp app, Options opts)
    {
        var (session, catalog, _) = await Open(app, opts);
        using (session)
        {
            var snap = PickSnapshot(catalog, opts);
            var items = opts.Get("path") is null ? catalog.Roots(snap.SnapshotId) : catalog.ListChildren(ResolvePath(catalog, snap, opts.Get("path")));
            if (opts.Get("path") is null && items.Count == 1 && items[0].IsDirectory)
            {
                items = catalog.ListChildren(items[0].Path);
            }

            foreach (var i in items)
            {
                Console.WriteLine($"{(i.IsDirectory ? "dir " : "file")}  {Fmt.Bytes(i.Entry.Size),10}  {i.Entry.ModifiedUtc.ToLocalTime():yyyy-MM-dd HH:mm}  {i.Name}{(i.Entry.Status != EntryStatus.Ok ? "  [" + i.Entry.Status + "]" : string.Empty)}");
            }
        }

        return 0;
    }

    private static async Task<int> Search(RezenApp app, Options opts)
    {
        var (session, catalog, _) = await Open(app, opts);
        using (session)
        {
            var snap = PickSnapshot(catalog, opts);
            foreach (var i in catalog.Search(snap.SnapshotId, new SearchQuery { NameContains = opts.Get("name"), Extension = opts.Get("ext"), FolderContains = opts.Get("folder") }))
            {
                Console.WriteLine($"{Fmt.Bytes(i.Entry.Size),10}  {i.Entry.ModifiedUtc.ToLocalTime():yyyy-MM-dd HH:mm}  {i.OriginalFullPath}");
                if (opts.Has("versions"))
                {
                    foreach (var v in catalog.VersionsOf(i))
                    {
                        Console.WriteLine($"            version from {v.Snapshot.FolderName} — {Fmt.Bytes(v.Item.Entry.Size)}");
                    }
                }
            }
        }

        return 0;
    }

    private static async Task<int> Restore(RezenApp app, Options opts)
    {
        var target = opts.Get("to");
        var (session, catalog, job) = await Open(app, opts);
        using (session)
        {
            var snap = PickSnapshot(catalog, opts);
            IReadOnlyList<CatalogItem> items = opts.Get("path") is { } p
                ? [catalog.Find(ResolvePath(catalog, snap, p)) ?? throw new RezenException(ErrorCode.InvalidConfiguration, "Path not found in snapshot.", null, null)]
                : catalog.Roots(snap.SnapshotId);
            var choice = (opts.Get("on-conflict") ?? "ask") switch
            {
                "skip" => ConflictChoice.Skip,
                "replace" => ConflictChoice.Replace,
                "keep-both" => ConflictChoice.KeepBoth,
                _ => (ConflictChoice?)null,
            };
            var report = await session.RestoreAsync(job.Id, items, new RestoreOptions
            {
                TargetRoot = target is null ? null : Path.GetFullPath(target),
                ResolveConflict = c =>
                {
                    if (choice is { } fixedChoice)
                    {
                        return new ConflictResolution(fixedChoice, true);
                    }

                    Console.Write($"\"{c.TargetPath}\" exists. [r]eplace, [k]eep both, [s]kip (add 'a' to apply to all): ");
                    var answer = (Console.ReadLine() ?? "s").Trim().ToLowerInvariant();
                    var pick = answer.StartsWith('r') ? ConflictChoice.Replace : answer.StartsWith('k') ? ConflictChoice.KeepBoth : ConflictChoice.Skip;
                    return new ConflictResolution(pick, answer.EndsWith('a'));
                },
            });
            Console.WriteLine($"Restored {report.FilesRestored:N0} file(s), skipped {report.FilesSkipped:N0}, failed {report.FilesFailed:N0} ({Fmt.Bytes(report.BytesRestored)}).");
            foreach (var issue in report.Issues)
            {
                Console.WriteLine($"  ! {issue.Path}: {issue.Message}");
            }

            foreach (var (o, r) in report.Renamed)
            {
                Console.WriteLine($"  renamed for this system: {o} → {r}");
            }

            return report.IntegrityFailure ? 4 : report.FilesFailed > 0 ? 3 : 0;
        }
    }

    private static async Task<int> Verify(RezenApp app, Options opts)
    {
        var (session, catalog, job) = await Open(app, opts);
        using (session)
        {
            if (!opts.Has("deep"))
            {
                foreach (var s in catalog.Snapshots)
                {
                    Console.WriteLine($"{s.FolderName,-32} {(s.IsRestorable ? "Encrypted & Verified" : s.Validity + " " + s.Problem)}");
                }

                return catalog.Snapshots.Any(s => s.Validity == Format.SnapshotValidity.Invalid) ? 4 : 0;
            }

            var report = session.DeepVerify(job.Id, new Progress<DeepVerifyProgress>(p => Console.Write($"\rPacks {p.PacksDone}/{p.PacksTotal}  snapshots {p.SnapshotsDone}/{p.SnapshotsTotal}   ")));
            Console.WriteLine();
            Console.WriteLine(report.Healthy ? "Encrypted & Verified — every pack and snapshot authenticated." : UserMessages.IntegrityFailed);
            foreach (var d in report.DamagedPacks)
            {
                Console.WriteLine($"  damaged pack {d.PackId} ({d.Kind}): {d.Reason}{(d.RecoveredFromCopy ? " — second copy is intact" : string.Empty)}");
            }

            foreach (var s in report.Snapshots.Where(s => !s.AllDataPresent))
            {
                Console.WriteLine($"  snapshot {s.FolderName}: {s.Problem}");
            }

            foreach (var m in report.MissingSnapshotsInChain)
            {
                Console.WriteLine($"  a snapshot before {m} is missing from the drive");
            }

            if (!report.Healthy && opts.Has("repair"))
            {
                session.RepairFromSource(job.Id, report);
                Console.WriteLine("Damaged packs quarantined. Run 'rezen backup' to re-store affected data from your files.");
            }

            return report.Healthy ? 0 : 4;
        }
    }

    private static int Import(RezenApp app, Options opts)
    {
        var root = opts.Positional.FirstOrDefault() ?? throw new RezenException(ErrorCode.InvalidConfiguration, "Specify the drive root.", null, null);
        var found = app.Import.FindRepositories(Path.GetFullPath(root));
        if (found.Count == 0)
        {
            Console.WriteLine("No Rezen Backup found on this drive.");
            return 1;
        }

        foreach (var f in found)
        {
            Console.WriteLine($"Found: {f.ComputerFolder} / {f.JobFolder}  ({f.SnapshotFolders} snapshots){(f.AlreadyImported ? "  [already imported]" : string.Empty)}");
            if (f.AlreadyImported)
            {
                continue;
            }

            JobDefinition job;
            if (opts.Has("recovery-key"))
            {
                var key = ReadPassword(opts, "Recovery key: ");
                var newPw = ReadPassword(opts, "New backup password: ");
                job = app.Import.ImportWithRecoveryKey(f.Path, key, newPw);
            }
            else
            {
                job = app.Import.ImportWithPassword(f.Path, ReadPassword(opts, "Backup password: "));
            }

            Console.WriteLine($"Imported \"{job.Name}\" with {app.Db.Snapshots(job.Id).Count} snapshot(s). It is restore-only until you enable it.");
        }

        return 0;
    }

    private static async Task<int> ChangePassword(RezenApp app, Options opts)
    {
        var ks = app.KeySets.Default ?? throw new RezenException(ErrorCode.KeyUnavailable);
        using var session = await UnlockedSession.UnlockAsync(app, ks.Id, ReadPassword(opts, "Current password: "));
        var newPw = ReadPassword(opts, "New password: ");
        if (!opts.Has("password-stdin") && ReadPassword(opts, "Confirm new password: ") != newPw)
        {
            Console.Error.WriteLine("Passwords do not match.");
            return 1;
        }

        var r = session.ChangePassword(newPw);
        Console.WriteLine($"Password changed. Backup drives updated: {r.DrivesUpdated}. Pending (disconnected): {r.DrivesPending}.");
        if (r.DrivesPending > 0)
        {
            Console.WriteLine("Disconnected drives still open with the previous password until they are connected and updated.");
        }

        return 0;
    }

    private static async Task<int> RecoveryKey(RezenApp app, Options opts)
    {
        var ks = app.KeySets.Default ?? throw new RezenException(ErrorCode.KeyUnavailable);
        using var session = await UnlockedSession.UnlockAsync(app, ks.Id, ReadPassword(opts, "Backup password: "));
        Console.WriteLine(session.RevealRecoveryKey());
        return 0;
    }

    private static async Task<int> Remember(RezenApp app, Options opts)
    {
        var ks = app.KeySets.Default ?? throw new RezenException(ErrorCode.KeyUnavailable);
        bool on = opts.Positional.FirstOrDefault() == "on";
        if (!on)
        {
            app.KeySets.SetRemember(ks.Id, null, false);
            Console.WriteLine("Turned off. Scheduled backups will ask for your password.");
            return 0;
        }

        using var session = await UnlockedSession.UnlockAsync(app, ks.Id, ReadPassword(opts, "Backup password: "));
        bool fullKey = opts.Has("full-key");
        session.SetRemember(true, backupOnly: !fullKey);
        Console.WriteLine(fullKey
            ? $"Full key remembered using {app.Platform.Credentials.MechanismName}. Scheduled backups can run automatically."
            : $"Backup-only key remembered using {app.Platform.Credentials.MechanismName}. Scheduled backups can run automatically; it cannot decrypt your backups' contents.");
        return 0;
    }

    private static int History(RezenApp app, Options opts)
    {
        Guid? jobId = opts.Positional.Count > 0 ? ResolveJob(app, opts).Id : null;
        var names = app.Jobs.All.ToDictionary(j => j.Id, j => j.Name);
        foreach (var r in app.Db.Runs(jobId, 100))
        {
            Console.WriteLine($"{r.StartedUtc.ToLocalTime():MMM d HH:mm}  {names.GetValueOrDefault(r.JobId, "?"),-22} {r.Outcome.ToDisplay(),-24} {r.Security.ToDisplay(),-24} {Fmt.Bytes(r.BytesNew),10}  {(r.Duration is { } d ? Fmt.Duration(d) : "-"),8}");
        }

        return 0;
    }

    private static int SecurityLog(RezenApp app)
    {
        foreach (var e in app.Db.SecurityEvents(200).Reverse())
        {
            Console.WriteLine($"{e.Utc.ToLocalTime():yyyy-MM-dd HH:mm:ss}  {e.Type,-28} {e.Detail}");
        }

        var broken = app.SecurityLog.VerifyChain();
        Console.WriteLine(broken is null ? "Security log chain intact." : $"WARNING: the security log was modified at record {broken}.");
        return broken is null ? 0 : 4;
    }

    private static int ExportConfig(RezenApp app)
    {
        Console.WriteLine(ConfigTransfer.Export(app));
        return 0;
    }

    private static async Task<int> Agent(RezenApp app)
    {
        await using var host = new AgentHost(app);
        if (!host.TryAcquireSingleInstance())
        {
            Console.Error.WriteLine("The Rezen Backup agent is already running.");
            return 1;
        }

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };
        Console.WriteLine("Rezen Backup agent running. Press Ctrl+C to stop.");
        await host.RunAsync(cts.Token);
        return 0;
    }

    private static string ReadPassword(Options opts, string prompt)
    {
        if (opts.Has("password-stdin") || Console.IsInputRedirected)
        {
            return Console.ReadLine() ?? string.Empty;
        }

        Console.Write(prompt);
        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                break;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0)
                {
                    sb.Length--;
                }

                continue;
            }

            sb.Append(key.KeyChar);
        }

        Console.WriteLine();
        var result = sb.ToString();
        sb.Clear();
        return result;
    }
}

internal sealed class Options
{
    private readonly Dictionary<string, List<string>> _values = new(StringComparer.Ordinal);

    public List<string> Positional { get; } = [];

    public static Options Parse(string[] args)
    {
        var o = new Options();
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            if (a.StartsWith("--", StringComparison.Ordinal))
            {
                var name = a[2..];
                string value = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal) && IsValued(name) ? args[++i] : "true";
                if (!o._values.TryGetValue(name, out var list))
                {
                    list = [];
                    o._values[name] = list;
                }

                list.Add(value);
            }
            else
            {
                o.Positional.Add(a);
            }
        }

        return o;
    }

    private static bool IsValued(string name) => name is "name" or "source" or "dest" or "schedule" or "snapshot" or "path" or "to" or "on-conflict" or "ext" or "folder" or "resume";

    public bool Has(string name) => _values.ContainsKey(name);

    public string? Get(string name) => _values.TryGetValue(name, out var v) ? v[^1] : null;

    public IReadOnlyList<string> All(string name) => _values.TryGetValue(name, out var v) ? v : [];
}
