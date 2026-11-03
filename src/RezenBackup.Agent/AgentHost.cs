using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using RezenBackup.Application;
using RezenBackup.Core.Domain;
using RezenBackup.Crypto;
using RezenBackup.DriveMonitor;
using RezenBackup.Scheduler;

namespace RezenBackup.Agent;

/// <summary>
/// The per-user background agent (DESIGN §1.1): runs scheduled backups while the window is closed, runs pending
/// backups when the registered drive is connected, catches up missed schedules, and serves the local IPC channel.
/// </summary>
public sealed class AgentHost : IAsyncDisposable
{
    private readonly RezenApp _app;
    private readonly ILogger _logger;
    private readonly ConcurrentDictionary<Guid, Task> _tasks = new();
    private readonly DateTimeOffset _started = DateTimeOffset.UtcNow;
    private DriveWatcher? _watcher;
    private FileStream? _instanceLock;
    private CancellationTokenSource? _cts;

    public AgentHost(RezenApp app)
    {
        _app = app;
        _logger = app.Loggers.CreateLogger("Agent");
    }

    public bool PausedAll { get; private set; }

    /// <summary>Ensures only one agent per user/data directory.</summary>
    public bool TryAcquireSingleInstance()
    {
        try
        {
            _instanceLock = new FileStream(Path.Combine(_app.Paths.Root, "agent.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
    }

    public async Task RunAsync(CancellationToken ct)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = _cts.Token;
        int abandoned = _app.Db.FailAbandonedRuns("Interrupted: the app or computer stopped during the backup. The backup was not marked complete.");
        if (abandoned > 0)
        {
            _logger.LogWarning("{Count} interrupted run(s) from a previous session were marked as failed.", abandoned);
        }

        _watcher = new DriveWatcher(_app.Platform.Volumes, () => _app.Db.Drives().Select(d => d.LastMountPath).OfType<string>(), _app.Loggers.CreateLogger("Drives"));
        _watcher.Arrived += OnDriveArrived;
        _watcher.Start(TimeSpan.FromSeconds(5));

        var server = Task.Run(() => ServeAsync(token), token);
        _logger.LogInformation("Agent started (version {Version}).", RezenApp.AppVersion);
        var lastDbBackup = DateTimeOffset.MinValue;
        while (!token.IsCancellationRequested)
        {
            try
            {
                _app.ReloadSettings();
                Tick();
                if (DateTimeOffset.UtcNow - lastDbBackup > TimeSpan.FromDays(1))
                {
                    _app.Db.BackupCopy();
                    lastDbBackup = DateTimeOffset.UtcNow;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Scheduler tick failed");
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(30), token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        foreach (var run in _app.Backups.ActiveRuns)
        {
            run.Cancel(); // safe stop: the snapshot stays .incomplete and can be resumed
        }

        await Task.WhenAll(_tasks.Values.Append(server).Select(t => t.ContinueWith(_ => { }, TaskScheduler.Default))).ConfigureAwait(false);
        _logger.LogInformation("Agent stopped.");
    }

    private void Tick()
    {
        if (PausedAll)
        {
            return;
        }

        var jobs = _app.Db.Jobs();
        var lastAttempt = jobs.ToDictionary(j => j.Id, j => _app.Db.Runs(j.Id, 1).FirstOrDefault()?.StartedUtc ?? j.CreatedUtc);
        foreach (var due in BackupScheduler.FindDue(jobs, lastAttempt, DateTimeOffset.Now, _started, _app.Settings.RunMissedBackups))
        {
            Start(due.Job.Id, due.Trigger);
        }
    }

    private void OnDriveArrived(ConnectedDrive drive)
    {
        if (PausedAll || !_app.Settings.AutoBackupOnDriveConnect)
        {
            return;
        }

        foreach (var job in _app.Db.Jobs().Where(j => j.Enabled && j.AutoRunOnConnect && j.DriveId == drive.DriveId))
        {
            var last = _app.Db.Runs(job.Id, 1).FirstOrDefault();
            var next = job.Schedule.Kind == Core.Policies.ScheduleKind.Manual ? null : Core.Policies.ScheduleCalculator.NextRun(job.Schedule, last?.StartedUtc ?? job.CreatedUtc);
            bool pending = last?.Outcome is RunOutcome.WaitingForDrive or RunOutcome.Failed || (next is { } n && n <= DateTimeOffset.Now);
            if (pending)
            {
                _logger.LogInformation("Registered drive connected; running pending backup for job {Job}", job.Id);
                Start(job.Id, RunTrigger.DriveConnected);
            }
        }
    }

    private bool Start(Guid jobId, RunTrigger trigger, RootSecret? secret = null, string? resumeFolder = null)
    {
        if (_tasks.ContainsKey(jobId) || _app.Backups.Active(jobId) is not null)
        {
            secret?.Dispose();
            return false;
        }

        var task = Task.Run(async () =>
        {
            try
            {
                await _app.Backups.RunAsync(jobId, trigger, secret, resumeFolder, _cts?.Token ?? CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Run of job {Job} crashed", jobId);
            }
            finally
            {
                _tasks.TryRemove(jobId, out _);
            }
        });
        _tasks[jobId] = task;
        return true;
    }

    private async Task ServeAsync(CancellationToken ct)
    {
        var name = AgentProtocol.PipeName(_app.Paths);
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                server = new NamedPipeServerStream(name, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await server.WaitForConnectionAsync(ct).ConfigureAwait(false);
                var connection = server;
                server = null;
                _ = Task.Run(() => HandleAsync(connection, ct), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (IOException ex)
            {
                _logger.LogWarning("IPC listener error: {Message}", ex.Message);
                await Task.Delay(1000, ct).ConfigureAwait(false);
            }
            finally
            {
                if (server is not null)
                {
                    await server.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
    }

    private async Task HandleAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using var _ = pipe;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            var line = await ReadLineAsync(pipe, 64 * 1024, timeout.Token).ConfigureAwait(false);
            var request = line is null ? null : JsonSerializer.Deserialize<AgentProtocol.Request>(line, AgentProtocol.Json);
            RootSecret? secret = null;
            if (request is { WithSecret: true })
            {
                using var buffer = new SecretBuffer(RootSecret.Length);
                await ReadExactlyAsync(pipe, buffer, timeout.Token).ConfigureAwait(false);
                secret = RootSecret.FromBytes(buffer.ReadOnlySpan);
            }

            var response = request is null ? new AgentProtocol.Response(false, "Bad request") : Handle(request, secret);
            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(response, AgentProtocol.Json) + "\n");
            await pipe.WriteAsync(bytes, ct).ConfigureAwait(false);
            await pipe.FlushAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or JsonException or OperationCanceledException)
        {
            _logger.LogDebug("IPC request failed: {Message}", ex.Message);
        }
    }

    private AgentProtocol.Response Handle(AgentProtocol.Request request, RootSecret? secret)
    {
        switch (request.Cmd)
        {
            case "ping":
                secret?.Dispose();
                return new AgentProtocol.Response(true, AgentVersion: RezenApp.AppVersion);

            case "status":
                secret?.Dispose();
                return new AgentProtocol.Response(true, AgentVersion: RezenApp.AppVersion, Runs: _app.Backups.ActiveRuns.Select(ToInfo).ToList());

            case "run" when request.JobId is { } jobId:
                bool started = Start(jobId, request.ResumeFolder is null ? RunTrigger.Manual : RunTrigger.Resume, secret, request.ResumeFolder);
                return new AgentProtocol.Response(started, started ? null : "This backup is already running.");

            case "pause" when request.JobId is { } p:
                secret?.Dispose();
                _app.Backups.Active(p)?.Pause.Pause();
                return new AgentProtocol.Response(true);

            case "resume" when request.JobId is { } r:
                secret?.Dispose();
                _app.Backups.Active(r)?.Pause.Resume();
                return new AgentProtocol.Response(true);

            case "cancel" when request.JobId is { } c:
                secret?.Dispose();
                _app.Backups.Active(c)?.Cancel();
                return new AgentProtocol.Response(true);

            case "pause-all":
                secret?.Dispose();
                PausedAll = true;
                foreach (var run in _app.Backups.ActiveRuns)
                {
                    run.Pause.Pause();
                }

                return new AgentProtocol.Response(true);

            case "resume-all":
                secret?.Dispose();
                PausedAll = false;
                foreach (var run in _app.Backups.ActiveRuns)
                {
                    run.Pause.Resume();
                }

                return new AgentProtocol.Response(true);

            case "run-all":
                secret?.Dispose();
                foreach (var job in _app.Db.Jobs().Where(j => j.Enabled))
                {
                    Start(job.Id, RunTrigger.Manual);
                }

                return new AgentProtocol.Response(true);

            case "stop":
                secret?.Dispose();
                _cts?.Cancel();
                return new AgentProtocol.Response(true);

            default:
                secret?.Dispose();
                return new AgentProtocol.Response(false, "Unknown command");
        }
    }

    public IReadOnlyList<AgentProtocol.RunInfo> Runs => _app.Backups.ActiveRuns.Select(ToInfo).ToList();

    public void RunAll()
    {
        foreach (var job in _app.Db.Jobs().Where(j => j.Enabled))
        {
            Start(job.Id, RunTrigger.Manual);
        }
    }

    public void SetPausedAll(bool paused) => Handle(new AgentProtocol.Request(paused ? "pause-all" : "resume-all"), null);

    public void Stop() => _cts?.Cancel();

    private static AgentProtocol.RunInfo ToInfo(ActiveRun r) => new(
        r.Job.Id,
        r.RunId,
        r.Job.Name,
        r.Progress.Phase.ToString(),
        r.Waiting ? "Waiting for another Rezen Backup job." : r.Progress.PhaseText,
        r.Progress.FilesDone,
        r.Progress.FilesTotal,
        r.Progress.BytesDone,
        r.Progress.BytesTotal,
        r.Progress.CurrentFile,
        r.Progress.BytesPerSecond,
        r.Progress.EstimatedRemaining?.TotalSeconds,
        r.Pause.IsPaused,
        r.Waiting);

    private static async Task<string?> ReadLineAsync(Stream s, int max, CancellationToken ct)
    {
        var bytes = new List<byte>(256);
        var one = new byte[1];
        while (bytes.Count < max)
        {
            int n = await s.ReadAsync(one, ct).ConfigureAwait(false);
            if (n == 0)
            {
                return null;
            }

            if (one[0] == (byte)'\n')
            {
                return Encoding.UTF8.GetString([.. bytes]);
            }

            bytes.Add(one[0]);
        }

        return null;
    }

    private static async Task ReadExactlyAsync(Stream s, SecretBuffer buffer, CancellationToken ct)
    {
        var temp = SecureMemory.AllocatePinned(buffer.Length);
        try
        {
            await s.ReadExactlyAsync(temp, ct).ConfigureAwait(false);
            temp.CopyTo(buffer.Span);
        }
        finally
        {
            SecureMemory.Wipe(temp);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        _watcher?.Dispose();
        if (_instanceLock is not null)
        {
            await _instanceLock.DisposeAsync().ConfigureAwait(false);
        }

        _cts?.Dispose();
    }
}
