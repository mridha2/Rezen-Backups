using System.Globalization;
using Microsoft.Data.Sqlite;

namespace RezenBackup.Database;

/// <summary>
/// Local SQLite database (DESIGN §23): configuration plus a cache of what is on the drives. Contains no passwords,
/// keys or recovery keys. Losing it never loses backup data — it can be rebuilt from the drive.
/// </summary>
public sealed partial class AppDatabase : IDisposable
{
    private const int SchemaVersion = 1;
    private readonly string _connectionString;
    private readonly object _gate = new();
    private SqliteConnection? _connection;

    public AppDatabase(string path)
    {
        Path = path;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString();
        Open();
    }

    public string Path { get; }

    private void Open()
    {
        RecoverIfCorrupt();
        _connection = new SqliteConnection(_connectionString);
        _connection.Open();
        Exec("PRAGMA journal_mode=WAL;");
        Exec("PRAGMA synchronous=FULL;");
        Exec("PRAGMA foreign_keys=ON;");
        Exec("PRAGMA busy_timeout=10000;");
        Migrate();
    }

    /// <summary>Checks integrity at start-up; restores the newest healthy backup copy if the database is corrupt.</summary>
    private void RecoverIfCorrupt()
    {
        if (!File.Exists(Path))
        {
            return;
        }

        if (IsHealthy(Path))
        {
            return;
        }

        var corrupt = Path + ".corrupt-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture);
        File.Move(Path, corrupt);
        foreach (var suffix in new[] { "-wal", "-shm" })
        {
            if (File.Exists(Path + suffix))
            {
                File.Move(Path + suffix, corrupt + suffix);
            }
        }

        foreach (var backup in new[] { Path + ".bak1", Path + ".bak2" })
        {
            if (File.Exists(backup) && IsHealthy(backup))
            {
                File.Copy(backup, Path);
                RecoveredFromBackup = true;
                return;
            }
        }

        RecoveredFromBackup = false;
        WasRecreated = true;
    }

    public bool RecoveredFromBackup { get; private set; }

    public bool WasRecreated { get; private set; }

    private static bool IsHealthy(string path)
    {
        try
        {
            using var c = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
            c.Open();
            using var cmd = c.CreateCommand();
            cmd.CommandText = "PRAGMA quick_check;";
            return string.Equals(cmd.ExecuteScalar() as string, "ok", StringComparison.OrdinalIgnoreCase);
        }
        catch (SqliteException)
        {
            return false;
        }
    }

    /// <summary>Daily online backup copy using the SQLite backup API (rotates .bak1 → .bak2).</summary>
    public void BackupCopy()
    {
        lock (_gate)
        {
            var bak1 = Path + ".bak1";
            var bak2 = Path + ".bak2";
            if (File.Exists(bak1))
            {
                File.Copy(bak1, bak2, overwrite: true);
            }

            using var dest = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = bak1, Pooling = false }.ToString());
            dest.Open();
            _connection!.BackupDatabase(dest);
        }
    }

    private void Migrate()
    {
        Exec("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);");
        long current = Scalar<long?>("SELECT MAX(version) FROM schema_version;") ?? 0;
        if (current >= SchemaVersion)
        {
            return;
        }

        using var tx = _connection!.BeginTransaction();
        foreach (var sql in Schema.V1)
        {
            using var cmd = _connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = sql;
            cmd.ExecuteNonQuery();
        }

        using (var cmd = _connection.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "INSERT INTO schema_version(version) VALUES (1);";
            cmd.ExecuteNonQuery();
        }

        tx.Commit();
    }

    internal int Exec(string sql, params (string Name, object? Value)[] args)
    {
        lock (_gate)
        {
            using var cmd = Command(sql, args);
            return cmd.ExecuteNonQuery();
        }
    }

    internal T? Scalar<T>(string sql, params (string Name, object? Value)[] args)
    {
        lock (_gate)
        {
            using var cmd = Command(sql, args);
            var v = cmd.ExecuteScalar();
            if (v is null or DBNull)
            {
                return default;
            }

            var target = Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T);
            return (T)Convert.ChangeType(v, target, CultureInfo.InvariantCulture);
        }
    }

    internal List<T> Query<T>(string sql, Func<SqliteDataReader, T> map, params (string Name, object? Value)[] args)
    {
        lock (_gate)
        {
            using var cmd = Command(sql, args);
            using var reader = cmd.ExecuteReader();
            var list = new List<T>();
            while (reader.Read())
            {
                list.Add(map(reader));
            }

            return list;
        }
    }

    internal void InTransaction(Action<Func<string, (string, object?)[], int>> body)
    {
        lock (_gate)
        {
            using var tx = _connection!.BeginTransaction();
            body((sql, args) =>
            {
                using var cmd = Command(sql, args);
                cmd.Transaction = tx;
                return cmd.ExecuteNonQuery();
            });
            tx.Commit();
        }
    }

    private SqliteCommand Command(string sql, (string Name, object? Value)[] args)
    {
        var cmd = _connection!.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (name, value) in args)
        {
            cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }

        return cmd;
    }

    public void Dispose()
    {
        _connection?.Dispose();
        _connection = null;
    }
}

internal static class Schema
{
    public static readonly string[] V1 =
    [
        """
        CREATE TABLE settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE key_sets (
            id                   TEXT PRIMARY KEY,
            display_name         TEXT NOT NULL,
            created_utc          TEXT NOT NULL,
            password_generation  INTEGER NOT NULL DEFAULT 1,
            recovery_confirmed   INTEGER NOT NULL DEFAULT 0,
            remember_on_pc       INTEGER NOT NULL DEFAULT 0,
            kdf_description      TEXT
        );
        """,
        """
        CREATE TABLE drives (
            id                 TEXT PRIMARY KEY,
            label              TEXT NOT NULL,
            volume_identifier  TEXT,
            file_system        TEXT NOT NULL,
            capacity_bytes     INTEGER NOT NULL,
            last_seen_utc      TEXT NOT NULL,
            last_mount_path    TEXT
        );
        """,
        """
        CREATE TABLE jobs (
            id              TEXT PRIMARY KEY,
            key_set_id      TEXT NOT NULL REFERENCES key_sets(id),
            name            TEXT NOT NULL,
            enabled         INTEGER NOT NULL,
            definition_json TEXT NOT NULL,
            created_utc     TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE repositories (
            id                   TEXT PRIMARY KEY,
            job_id               TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            drive_id             TEXT NOT NULL REFERENCES drives(id),
            relative_path        TEXT NOT NULL,
            password_generation  INTEGER NOT NULL,
            created_utc          TEXT NOT NULL
        );
        """,
        """
        CREATE TABLE snapshots (
            id              TEXT PRIMARY KEY,
            repository_id   TEXT NOT NULL,
            job_id          TEXT NOT NULL,
            folder_name     TEXT NOT NULL,
            started_utc     TEXT NOT NULL,
            completed_utc   TEXT,
            state           INTEGER NOT NULL,
            security        INTEGER NOT NULL,
            verification    INTEGER NOT NULL,
            files           INTEGER NOT NULL,
            bytes_scanned   INTEGER NOT NULL,
            bytes_new       INTEGER NOT NULL,
            duration_ms     INTEGER NOT NULL,
            commit_hash     BLOB,
            pinned          INTEGER NOT NULL DEFAULT 0,
            anomaly         INTEGER NOT NULL DEFAULT 0,
            deleted         INTEGER NOT NULL DEFAULT 0
        );
        """,
        "CREATE INDEX ix_snapshots_job ON snapshots(job_id, started_utc);",
        """
        CREATE TABLE runs (
            id               TEXT PRIMARY KEY,
            job_id           TEXT NOT NULL,
            snapshot_id      TEXT,
            trigger          INTEGER NOT NULL,
            started_utc      TEXT NOT NULL,
            ended_utc        TEXT,
            outcome          INTEGER NOT NULL,
            security         INTEGER NOT NULL,
            error_code       INTEGER,
            message          TEXT,
            technical        TEXT,
            files            INTEGER NOT NULL DEFAULT 0,
            files_warned     INTEGER NOT NULL DEFAULT 0,
            bytes_new        INTEGER NOT NULL DEFAULT 0,
            bytes_scanned    INTEGER NOT NULL DEFAULT 0,
            snapshot_folder  TEXT
        );
        """,
        "CREATE INDEX ix_runs_job ON runs(job_id, started_utc);",
        """
        CREATE TABLE run_issues (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id       TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
            kind         INTEGER NOT NULL,
            path_sealed  BLOB NOT NULL,
            detail       TEXT
        );
        """,
        """
        CREATE TABLE security_events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            utc        TEXT NOT NULL,
            type       TEXT NOT NULL,
            job_id     TEXT,
            detail     TEXT NOT NULL,
            prev_hash  BLOB NOT NULL,
            mac        BLOB NOT NULL
        );
        """,
        """
        CREATE TABLE pending_actions (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            kind           TEXT NOT NULL,
            repository_id  TEXT,
            job_id         TEXT,
            created_utc    TEXT NOT NULL
        );
        """,
    ];
}
