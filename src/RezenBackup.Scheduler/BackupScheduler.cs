using RezenBackup.Core.Domain;
using RezenBackup.Core.Policies;

namespace RezenBackup.Scheduler;

public sealed record DueJob(JobDefinition Job, RunTrigger Trigger, DateTimeOffset DueAt);

/// <summary>Decides which jobs are due (spec §44) and whether a run is a catch-up of a missed schedule.</summary>
public static class BackupScheduler
{
    /// <param name="lastAttempt">Start time of the most recent run attempt per job (successful or not).</param>
    /// <param name="agentStarted">When the agent started; occurrences before this are "missed".</param>
    public static IReadOnlyList<DueJob> FindDue(
        IEnumerable<JobDefinition> jobs,
        IReadOnlyDictionary<Guid, DateTimeOffset> lastAttempt,
        DateTimeOffset now,
        DateTimeOffset agentStarted,
        bool runMissedGlobally,
        TimeZoneInfo? zone = null)
    {
        var due = new List<DueJob>();
        foreach (var job in jobs)
        {
            if (!job.Enabled || job.Schedule.Kind == ScheduleKind.Manual)
            {
                continue;
            }

            var reference = lastAttempt.TryGetValue(job.Id, out var t) ? t : job.CreatedUtc;
            var next = ScheduleCalculator.NextRun(job.Schedule, reference, zone);
            if (next is not { } n || n > now)
            {
                continue;
            }

            bool missed = n < agentStarted.AddMinutes(-1);
            if (missed && !(runMissedGlobally && job.RunMissed))
            {
                continue;
            }

            due.Add(new DueJob(job, missed ? RunTrigger.Missed : RunTrigger.Scheduled, n));
        }

        return due.OrderBy(d => d.DueAt).ToList();
    }

    public static DateTimeOffset? NextRun(JobDefinition job, DateTimeOffset? lastAttempt, DateTimeOffset now, TimeZoneInfo? zone = null)
    {
        if (!job.Enabled || job.Schedule.Kind == ScheduleKind.Manual)
        {
            return null;
        }

        var reference = lastAttempt ?? job.CreatedUtc;
        var next = ScheduleCalculator.NextRun(job.Schedule, reference, zone);
        if (next is { } n && n <= now)
        {
            return now; // overdue: runs as soon as possible
        }

        return next;
    }
}

/// <summary>
/// Serialises jobs that target the same physical drive (spec §73) and caps total concurrency.
/// </summary>
public sealed class JobQueue
{
    private readonly Dictionary<string, SemaphoreSlim> _perDisk = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _global;
    private readonly object _gate = new();
    private readonly HashSet<Guid> _queuedOrRunning = [];

    public JobQueue(int maxConcurrent = 2)
    {
        _global = new SemaphoreSlim(maxConcurrent, maxConcurrent);
    }

    public bool IsQueuedOrRunning(Guid jobId)
    {
        lock (_gate)
        {
            return _queuedOrRunning.Contains(jobId);
        }
    }

    /// <summary>
    /// Runs <paramref name="work"/> when the disk is free. <paramref name="onWaiting"/> is invoked if the job has to wait
    /// ("Waiting for another Rezen Backup job."). Returns false if the job is already queued.
    /// </summary>
    public async Task<bool> RunAsync(Guid jobId, string diskKey, Func<CancellationToken, Task> work, Action? onWaiting, CancellationToken ct)
    {
        SemaphoreSlim disk;
        lock (_gate)
        {
            if (!_queuedOrRunning.Add(jobId))
            {
                return false;
            }

            if (!_perDisk.TryGetValue(diskKey, out disk!))
            {
                disk = new SemaphoreSlim(1, 1);
                _perDisk[diskKey] = disk;
            }
        }

        try
        {
            if (!disk.Wait(0, CancellationToken.None))
            {
                onWaiting?.Invoke();
                await disk.WaitAsync(ct).ConfigureAwait(false);
            }

            try
            {
                await _global.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    await work(ct).ConfigureAwait(false);
                }
                finally
                {
                    _global.Release();
                }
            }
            finally
            {
                disk.Release();
            }

            return true;
        }
        finally
        {
            lock (_gate)
            {
                _queuedOrRunning.Remove(jobId);
            }
        }
    }
}
