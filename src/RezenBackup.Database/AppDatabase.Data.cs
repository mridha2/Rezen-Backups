using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using RezenBackup.Core;
using RezenBackup.Core.Domain;

namespace RezenBackup.Database;

public sealed partial class AppDatabase
{
    internal static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = false,
        Converters = { new JsonStringEnumConverter() },
    };

    private static string Ts(DateTimeOffset t) => t.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseTs(string s) => DateTimeOffset.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    private static DateTimeOffset? ParseTsOrNull(SqliteDataReader r, int i) => r.IsDBNull(i) ? null : ParseTs(r.GetString(i));

    private static Guid G(SqliteDataReader r, int i) => Guid.Parse(r.GetString(i));

    private static Guid? GOrNull(SqliteDataReader r, int i) => r.IsDBNull(i) ? null : Guid.Parse(r.GetString(i));

    // ---------------------------------------------------------------- settings

    public string? GetSetting(string key) => Scalar<string>("SELECT value FROM settings WHERE key=$k", ("$k", key));

    public void SetSetting(string key, string value) =>
        Exec("INSERT INTO settings(key,value) VALUES($k,$v) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ("$k", key), ("$v", value));

    public IReadOnlyDictionary<string, string> AllSettings() =>
        Query("SELECT key, value FROM settings", r => (r.GetString(0), r.GetString(1))).ToDictionary(x => x.Item1, x => x.Item2);

    // ---------------------------------------------------------------- key sets

    public void UpsertKeySet(KeySetInfo k) => Exec(
        """
        INSERT INTO key_sets(id, display_name, created_utc, password_generation, recovery_confirmed, remember_on_pc, kdf_description, remember_backup_only)
        VALUES($id,$n,$c,$g,$r,$m,$k,$b)
        ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, password_generation=excluded.password_generation,
            recovery_confirmed=excluded.recovery_confirmed, remember_on_pc=excluded.remember_on_pc, kdf_description=excluded.kdf_description,
            remember_backup_only=excluded.remember_backup_only
        """,
        ("$id", k.Id.ToString()), ("$n", k.DisplayName), ("$c", Ts(k.CreatedUtc)), ("$g", k.PasswordGeneration),
        ("$r", k.RecoveryKeyConfirmed ? 1 : 0), ("$m", k.RememberOnThisPc ? 1 : 0), ("$k", k.KdfDescription), ("$b", k.RememberBackupOnly ? 1 : 0));

    public IReadOnlyList<KeySetInfo> KeySets() => Query(
        "SELECT id, display_name, created_utc, password_generation, recovery_confirmed, remember_on_pc, kdf_description, remember_backup_only FROM key_sets ORDER BY created_utc",
        r => new KeySetInfo
        {
            Id = G(r, 0),
            DisplayName = r.GetString(1),
            CreatedUtc = ParseTs(r.GetString(2)),
            PasswordGeneration = r.GetInt32(3),
            RecoveryKeyConfirmed = r.GetInt32(4) != 0,
            RememberOnThisPc = r.GetInt32(5) != 0,
            KdfDescription = r.IsDBNull(6) ? null : r.GetString(6),
            RememberBackupOnly = r.GetInt32(7) != 0,
        });

    public KeySetInfo? KeySet(Guid id) => KeySets().FirstOrDefault(k => k.Id == id);

    public void DeleteKeySet(Guid id) => Exec("DELETE FROM key_sets WHERE id=$id", ("$id", id.ToString()));

    // ---------------------------------------------------------------- drives

    public void UpsertDrive(DriveRecord d) => Exec(
        """
        INSERT INTO drives(id, label, volume_identifier, file_system, capacity_bytes, last_seen_utc, last_mount_path)
        VALUES($id,$l,$v,$f,$c,$s,$m)
        ON CONFLICT(id) DO UPDATE SET label=excluded.label, volume_identifier=excluded.volume_identifier, file_system=excluded.file_system,
            capacity_bytes=excluded.capacity_bytes, last_seen_utc=excluded.last_seen_utc, last_mount_path=excluded.last_mount_path
        """,
        ("$id", d.Id.ToString()), ("$l", d.Label), ("$v", d.VolumeIdentifier), ("$f", d.FileSystem), ("$c", d.CapacityBytes),
        ("$s", Ts(d.LastSeenUtc)), ("$m", d.LastMountPath));

    public IReadOnlyList<DriveRecord> Drives() => Query(
        "SELECT id, label, volume_identifier, file_system, capacity_bytes, last_seen_utc, last_mount_path FROM drives",
        r => new DriveRecord
        {
            Id = G(r, 0),
            Label = r.GetString(1),
            VolumeIdentifier = r.IsDBNull(2) ? null : r.GetString(2),
            FileSystem = r.GetString(3),
            CapacityBytes = r.GetInt64(4),
            LastSeenUtc = ParseTs(r.GetString(5)),
            LastMountPath = r.IsDBNull(6) ? null : r.GetString(6),
        });

    public DriveRecord? Drive(Guid id) => Drives().FirstOrDefault(d => d.Id == id);

    // ---------------------------------------------------------------- jobs

    public void UpsertJob(JobDefinition job) => Exec(
        """
        INSERT INTO jobs(id, key_set_id, name, enabled, definition_json, created_utc) VALUES($id,$k,$n,$e,$j,$c)
        ON CONFLICT(id) DO UPDATE SET key_set_id=excluded.key_set_id, name=excluded.name, enabled=excluded.enabled, definition_json=excluded.definition_json
        """,
        ("$id", job.Id.ToString()), ("$k", job.KeySetId.ToString()), ("$n", job.Name), ("$e", job.Enabled ? 1 : 0),
        ("$j", JsonSerializer.Serialize(job, Json)), ("$c", Ts(job.CreatedUtc)));

    public IReadOnlyList<JobDefinition> Jobs() => Query(
        "SELECT definition_json FROM jobs ORDER BY created_utc",
        r => JsonSerializer.Deserialize<JobDefinition>(r.GetString(0), Json)!);

    public JobDefinition? Job(Guid id) => Jobs().FirstOrDefault(j => j.Id == id);

    /// <summary>Removes a job from this PC. Never touches the backup drive (backups remain importable).</summary>
    public void DeleteJob(Guid id) => InTransaction(exec =>
    {
        exec("DELETE FROM run_issues WHERE run_id IN (SELECT id FROM runs WHERE job_id=$id)", [("$id", id.ToString())]);
        exec("DELETE FROM runs WHERE job_id=$id", [("$id", id.ToString())]);
        exec("DELETE FROM snapshots WHERE job_id=$id", [("$id", id.ToString())]);
        exec("DELETE FROM repositories WHERE job_id=$id", [("$id", id.ToString())]);
        exec("DELETE FROM jobs WHERE id=$id", [("$id", id.ToString())]);
    });

    // ---------------------------------------------------------------- repositories

    public void UpsertRepository(RepositoryRecord r) => Exec(
        """
        INSERT INTO repositories(id, job_id, drive_id, relative_path, password_generation, created_utc) VALUES($id,$j,$d,$p,$g,$c)
        ON CONFLICT(id) DO UPDATE SET job_id=excluded.job_id, drive_id=excluded.drive_id, relative_path=excluded.relative_path,
            password_generation=excluded.password_generation
        """,
        ("$id", r.Id.ToString()), ("$j", r.JobId.ToString()), ("$d", r.DriveId.ToString()), ("$p", r.RelativePath),
        ("$g", r.PasswordGeneration), ("$c", Ts(r.CreatedUtc)));

    public IReadOnlyList<RepositoryRecord> Repositories() => Query(
        "SELECT id, job_id, drive_id, relative_path, password_generation, created_utc FROM repositories",
        r => new RepositoryRecord
        {
            Id = G(r, 0),
            JobId = G(r, 1),
            DriveId = G(r, 2),
            RelativePath = r.GetString(3),
            PasswordGeneration = r.GetInt32(4),
            CreatedUtc = ParseTs(r.GetString(5)),
        });

    public IReadOnlyList<RepositoryRecord> RepositoriesForJob(Guid jobId) => Repositories().Where(r => r.JobId == jobId).OrderBy(r => r.CreatedUtc).ToList();

    /// <summary>Forgets a repository on this computer. Nothing on the backup drive is touched.</summary>
    public void DeleteRepository(Guid repositoryId) => Exec("DELETE FROM repositories WHERE id=$id", ("$id", repositoryId.ToString()));

    // ---------------------------------------------------------------- snapshots

    public void UpsertSnapshot(SnapshotRow s) => Exec(
        """
        INSERT INTO snapshots(id, repository_id, job_id, folder_name, started_utc, completed_utc, state, security, verification, files,
            bytes_scanned, bytes_new, duration_ms, commit_hash, pinned, anomaly, deleted)
        VALUES($id,$r,$j,$f,$s,$c,$st,$sec,$v,$files,$bs,$bn,$d,$h,$p,$a,$del)
        ON CONFLICT(id) DO UPDATE SET folder_name=excluded.folder_name, completed_utc=excluded.completed_utc, state=excluded.state,
            security=excluded.security, verification=excluded.verification, files=excluded.files, bytes_scanned=excluded.bytes_scanned,
            bytes_new=excluded.bytes_new, duration_ms=excluded.duration_ms, commit_hash=excluded.commit_hash, anomaly=excluded.anomaly,
            deleted=excluded.deleted
        """,
        ("$id", s.Id.ToString()), ("$r", s.RepositoryId.ToString()), ("$j", s.JobId.ToString()), ("$f", s.FolderName), ("$s", Ts(s.StartedUtc)),
        ("$c", s.CompletedUtc is { } c ? Ts(c) : null), ("$st", (int)s.State), ("$sec", (int)s.Security), ("$v", (int)s.Verification),
        ("$files", s.Files), ("$bs", s.BytesScanned), ("$bn", s.BytesNew), ("$d", s.DurationMs), ("$h", s.CommitHash), ("$p", s.Pinned ? 1 : 0),
        ("$a", s.Anomaly ? 1 : 0), ("$del", s.Deleted ? 1 : 0));

    public IReadOnlyList<SnapshotRow> Snapshots(Guid? jobId = null, bool includeDeleted = false) => Query(
        "SELECT id, repository_id, job_id, folder_name, started_utc, completed_utc, state, security, verification, files, bytes_scanned, bytes_new, duration_ms, commit_hash, pinned, anomaly, deleted FROM snapshots"
        + " WHERE ($j IS NULL OR job_id=$j) AND ($all=1 OR deleted=0) ORDER BY started_utc DESC",
        r => new SnapshotRow
        {
            Id = G(r, 0),
            RepositoryId = G(r, 1),
            JobId = G(r, 2),
            FolderName = r.GetString(3),
            StartedUtc = ParseTs(r.GetString(4)),
            CompletedUtc = ParseTsOrNull(r, 5),
            State = (SnapshotState)r.GetInt32(6),
            Security = (SecurityStatus)r.GetInt32(7),
            Verification = (VerificationLevel)r.GetInt32(8),
            Files = r.GetInt64(9),
            BytesScanned = r.GetInt64(10),
            BytesNew = r.GetInt64(11),
            DurationMs = r.GetInt64(12),
            CommitHash = r.IsDBNull(13) ? null : (byte[])r[13],
            Pinned = r.GetInt32(14) != 0,
            Anomaly = r.GetInt32(15) != 0,
            Deleted = r.GetInt32(16) != 0,
        },
        ("$j", jobId?.ToString()), ("$all", includeDeleted ? 1 : 0));

    public void SetSnapshotPinned(Guid id, bool pinned) => Exec("UPDATE snapshots SET pinned=$p WHERE id=$id", ("$p", pinned ? 1 : 0), ("$id", id.ToString()));

    public void MarkSnapshotDeleted(Guid id) => Exec("UPDATE snapshots SET deleted=1 WHERE id=$id", ("$id", id.ToString()));

    // ---------------------------------------------------------------- runs

    public void UpsertRun(RunRow run) => Exec(
        """
        INSERT INTO runs(id, job_id, snapshot_id, trigger, started_utc, ended_utc, outcome, security, error_code, message, technical,
            files, files_warned, bytes_new, bytes_scanned, snapshot_folder)
        VALUES($id,$j,$s,$t,$st,$e,$o,$sec,$err,$m,$tech,$f,$fw,$bn,$bs,$sf)
        ON CONFLICT(id) DO UPDATE SET snapshot_id=excluded.snapshot_id, ended_utc=excluded.ended_utc, outcome=excluded.outcome,
            security=excluded.security, error_code=excluded.error_code, message=excluded.message, technical=excluded.technical,
            files=excluded.files, files_warned=excluded.files_warned, bytes_new=excluded.bytes_new, bytes_scanned=excluded.bytes_scanned,
            snapshot_folder=excluded.snapshot_folder
        """,
        ("$id", run.Id.ToString()), ("$j", run.JobId.ToString()), ("$s", run.SnapshotId?.ToString()), ("$t", (int)run.Trigger),
        ("$st", Ts(run.StartedUtc)), ("$e", run.EndedUtc is { } e ? Ts(e) : null), ("$o", (int)run.Outcome), ("$sec", (int)run.Security),
        ("$err", run.Error is { } err ? (int)err : null), ("$m", run.Message), ("$tech", run.TechnicalDetails), ("$f", run.Files),
        ("$fw", run.FilesWarned), ("$bn", run.BytesNew), ("$bs", run.BytesScanned), ("$sf", run.SnapshotFolder));

    public IReadOnlyList<RunRow> Runs(Guid? jobId = null, int limit = 500) => Query(
        "SELECT id, job_id, snapshot_id, trigger, started_utc, ended_utc, outcome, security, error_code, message, technical, files, files_warned, bytes_new, bytes_scanned, snapshot_folder FROM runs"
        + " WHERE ($j IS NULL OR job_id=$j) ORDER BY started_utc DESC LIMIT $lim",
        r => new RunRow
        {
            Id = G(r, 0),
            JobId = G(r, 1),
            SnapshotId = GOrNull(r, 2),
            Trigger = (RunTrigger)r.GetInt32(3),
            StartedUtc = ParseTs(r.GetString(4)),
            EndedUtc = ParseTsOrNull(r, 5),
            Outcome = (RunOutcome)r.GetInt32(6),
            Security = (SecurityStatus)r.GetInt32(7),
            Error = r.IsDBNull(8) ? null : (ErrorCode)r.GetInt32(8),
            Message = r.IsDBNull(9) ? null : r.GetString(9),
            TechnicalDetails = r.IsDBNull(10) ? null : r.GetString(10),
            Files = r.GetInt64(11),
            FilesWarned = r.GetInt64(12),
            BytesNew = r.GetInt64(13),
            BytesScanned = r.GetInt64(14),
            SnapshotFolder = r.IsDBNull(15) ? null : r.GetString(15),
        },
        ("$j", jobId?.ToString()), ("$lim", limit));

    public void AddRunIssues(Guid runId, IEnumerable<(IssueKind Kind, byte[] SealedPath, string? Detail)> issues) => InTransaction(exec =>
    {
        foreach (var (kind, sealedPath, detail) in issues)
        {
            exec("INSERT INTO run_issues(run_id, kind, path_sealed, detail) VALUES($r,$k,$p,$d)",
                [("$r", runId.ToString()), ("$k", (int)kind), ("$p", sealedPath), ("$d", detail)]);
        }
    });

    public IReadOnlyList<RunIssueRow> RunIssues(Guid runId) => Query(
        "SELECT id, run_id, kind, path_sealed, detail FROM run_issues WHERE run_id=$r ORDER BY id",
        r => new RunIssueRow(r.GetInt64(0), G(r, 1), (IssueKind)r.GetInt32(2), (byte[])r[3], r.IsDBNull(4) ? null : r.GetString(4)),
        ("$r", runId.ToString()));

    /// <summary>Marks runs left "Running" by a crashed process as failed (spec §55).</summary>
    public int FailAbandonedRuns(string message) => Exec(
        "UPDATE runs SET outcome=$f, ended_utc=$now, message=$m WHERE outcome=$running",
        ("$f", (int)RunOutcome.Failed), ("$now", Ts(DateTimeOffset.UtcNow)), ("$m", message), ("$running", (int)RunOutcome.Running));

    // ---------------------------------------------------------------- security events

    public long AddSecurityEvent(DateTimeOffset utc, string type, Guid? jobId, string detail, byte[] prevHash, byte[] mac) => Scalar<long>(
        "INSERT INTO security_events(utc, type, job_id, detail, prev_hash, mac) VALUES($u,$t,$j,$d,$p,$m) RETURNING id",
        ("$u", Ts(utc)), ("$t", type), ("$j", jobId?.ToString()), ("$d", detail), ("$p", prevHash), ("$m", mac));

    public IReadOnlyList<SecurityEventRow> SecurityEvents(int limit = 1000) => Query(
        "SELECT id, utc, type, job_id, detail, prev_hash, mac FROM security_events ORDER BY id DESC LIMIT $lim",
        r => new SecurityEventRow(r.GetInt64(0), ParseTs(r.GetString(1)), r.GetString(2), GOrNull(r, 3), r.GetString(4), (byte[])r[5], (byte[])r[6]),
        ("$lim", limit));

    public SecurityEventRow? LastSecurityEvent() => SecurityEvents(1).FirstOrDefault();

    public IReadOnlyList<SecurityEventRow> SecurityEventsAscending() => Query(
        "SELECT id, utc, type, job_id, detail, prev_hash, mac FROM security_events ORDER BY id ASC",
        r => new SecurityEventRow(r.GetInt64(0), ParseTs(r.GetString(1)), r.GetString(2), GOrNull(r, 3), r.GetString(4), (byte[])r[5], (byte[])r[6]));

    // ---------------------------------------------------------------- pending actions

    public void AddPendingAction(string kind, Guid? repositoryId, Guid? jobId) => Exec(
        "INSERT INTO pending_actions(kind, repository_id, job_id, created_utc) VALUES($k,$r,$j,$c)",
        ("$k", kind), ("$r", repositoryId?.ToString()), ("$j", jobId?.ToString()), ("$c", Ts(DateTimeOffset.UtcNow)));

    public IReadOnlyList<(long Id, string Kind, Guid? RepositoryId, Guid? JobId)> PendingActions() => Query(
        "SELECT id, kind, repository_id, job_id FROM pending_actions ORDER BY id",
        r => (r.GetInt64(0), r.GetString(1), GOrNull(r, 2), GOrNull(r, 3)));

    public void RemovePendingAction(long id) => Exec("DELETE FROM pending_actions WHERE id=$id", ("$id", id));
}
