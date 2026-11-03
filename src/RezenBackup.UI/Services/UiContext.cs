using System.Collections.Concurrent;
using Avalonia.Controls;
using Avalonia.Threading;
using RezenBackup.Application;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Crypto;
using RezenBackup.Security;

namespace RezenBackup.UI.Services;

/// <summary>
/// UI-wide state: the unlocked session (if any), auto-lock, and access to the background agent.
/// The remembered credential is never used by the UI to unlock history or restore (DESIGN §9.3).
/// </summary>
public sealed class UiContext : IDisposable
{
    private readonly DispatcherTimer _lockTimer;
    private readonly ConcurrentDictionary<Guid, Task<RunRow>> _inProcess = new();

    public UiContext(RezenApp app)
    {
        App = app;
        Agent = new AgentClient(app.Paths);
        Locks = new SessionLockManager { Mode = app.Settings.AutoLock, LockWhenSystemLocks = app.Settings.LockWhenSystemLocks };
        Locks.LockRequested += reason => Dispatcher.UIThread.Post(() => Lock(reason));
        Locks.BusyEnded += () => Dispatcher.UIThread.Post(() =>
        {
            if (_pendingLockReason is { } pending)
            {
                _pendingLockReason = null;
                Lock(pending);
            }
        });
        _lockTimer = new DispatcherTimer(TimeSpan.FromSeconds(10), DispatcherPriority.Background, (_, _) => CheckLock());
        _lockTimer.Start();
        _lastShow = UiSignals.Read(app.Db, UiSignals.Show);
        _lastLock = UiSignals.Read(app.Db, UiSignals.Lock);
        _signalTimer = new DispatcherTimer(TimeSpan.FromSeconds(2), DispatcherPriority.Background, (_, _) => CheckSignals());
        _signalTimer.Start();
    }

    public RezenApp App { get; }

    public AgentClient Agent { get; }

    public SessionLockManager Locks { get; }

    public Window? MainWindow { get; set; }

    public UnlockedSession? Session { get; private set; }

    public bool IsUnlocked => Session is { IsLocked: false };

    public string? LastLockReason { get; private set; }

    public event Action? SessionChanged;

    private readonly DispatcherTimer _signalTimer;
    private string? _lastShow;
    private string? _lastLock;

    private void CheckSignals()
    {
        var show = UiSignals.Read(App.Db, UiSignals.Show);
        if (show != _lastShow)
        {
            _lastShow = show;
            if (MainWindow is { } w)
            {
                if (w.WindowState == WindowState.Minimized)
                {
                    w.WindowState = WindowState.Normal;
                }

                w.Activate();
            }
        }

        var lockRequest = UiSignals.Read(App.Db, UiSignals.Lock);
        if (lockRequest != _lastLock)
        {
            _lastLock = lockRequest;
            Lock("Locked from the menu bar / tray.");
        }
    }

    private void CheckLock()
    {
        Locks.Tick(DateTimeOffset.UtcNow);
        if (IsUnlocked && Locks.LockWhenSystemLocks)
        {
            Task.Run(() => App.Platform.Session.IsSystemLocked()).ContinueWith(
                t =>
                {
                    if (t.Result)
                    {
                        Locks.OnSystemSessionLocked();
                    }
                },
                TaskScheduler.Default);
        }
    }

    public Guid? DefaultKeySetId => App.KeySets.Default?.Id;

    /// <summary>Returns the unlocked session, asking for the password (or recovery key) if needed.</summary>
    public async Task<UnlockedSession?> EnsureUnlockedAsync(string reason)
    {
        if (IsUnlocked)
        {
            Locks.RegisterActivity();
            return Session;
        }

        if (DefaultKeySetId is not { } keySetId)
        {
            return null;
        }

        while (true)
        {
            var input = await Dialogs.PasswordAsync(MainWindow!, "Unlock Rezen Backup", reason, allowRecoveryKey: true);
            if (input is null)
            {
                return null;
            }

            try
            {
                var session = input.Value.IsRecoveryKey
                    ? UnlockedSession.UnlockWithRecoveryKey(App, keySetId, input.Value.Text)
                    : await UnlockedSession.UnlockAsync(App, keySetId, input.Value.Text);
                Session = session;
                Locks.MarkUnlocked();
                LastLockReason = null;
                SessionChanged?.Invoke();
                return session;
            }
            catch (RezenException ex)
            {
                await Dialogs.MessageAsync(MainWindow!, "Unable to unlock", ex.Message, null, isError: true);
            }
        }
    }

    private string? _pendingLockReason;

    /// <summary>True when a lock was requested while an operation was using the keys; it happens when that operation ends.</summary>
    public bool LockPending => _pendingLockReason is not null;

    public void Lock(string reason)
    {
        if (Session is null)
        {
            return;
        }

        if (Locks.IsBusy)
        {
            // A restore or verification is using the keys on another thread: never free them underneath it.
            _pendingLockReason = reason;
            return;
        }

        Session.Dispose();
        Session = null;
        LastLockReason = reason;
        App.SecurityLog.Record(Logging.SecurityEvents.Locked, null, reason);
        Locks.Lock(reason);
        SessionChanged?.Invoke();
        GC.Collect();
    }

    /// <summary>
    /// "Back Up Now": handed to the background agent so it continues if the window is closed. Uses the remembered key
    /// when enabled; otherwise asks for the password and passes the key to the agent for this run only.
    /// </summary>
    public async Task<bool> BackUpNowAsync(JobDefinition job, string? resumeFolder = null)
    {
        var keySet = App.Db.KeySet(job.KeySetId);
        RootSecret? secret = null;
        if (keySet is not { RememberOnThisPc: true })
        {
            var session = await EnsureUnlockedAsync($"Enter your password to back up \"{job.Name}\".");
            if (session is null)
            {
                return false;
            }

            secret = session.CloneSecret();
        }

        try
        {
            if (!await Agent.IsRunningAsync())
            {
                await AgentLauncher.EnsureRunningAsync(App);
            }

            var response = await Agent.SendAsync(new AgentProtocol.Request("run", job.Id, ResumeFolder: resumeFolder), secret);
            if (response is { Ok: true })
            {
                return true;
            }

            if (response is { Ok: false, Error: { } err })
            {
                await Dialogs.MessageAsync(MainWindow!, job.Name, err, null);
                return false;
            }

            // Agent unavailable: run inside the app (it stops safely if the window is closed).
            RootSecret? owned = secret?.Clone();
            _inProcess[job.Id] = Task.Run(() => App.Backups.RunAsync(job.Id, resumeFolder is null ? RunTrigger.Manual : RunTrigger.Resume, owned, resumeFolder));
            _ = _inProcess[job.Id].ContinueWith(t => _inProcess.TryRemove(job.Id, out _), TaskScheduler.Default);
            return true;
        }
        finally
        {
            secret?.Dispose();
        }
    }

    /// <summary>Active runs from the agent plus any run hosted in this process.</summary>
    public async Task<IReadOnlyList<AgentProtocol.RunInfo>> ActiveRunsAsync()
    {
        var list = new List<AgentProtocol.RunInfo>();
        var response = await Agent.SendAsync(new AgentProtocol.Request("status"), timeoutMs: 400);
        if (response?.Runs is { } runs)
        {
            list.AddRange(runs);
        }

        foreach (var r in App.Backups.ActiveRuns)
        {
            var p = r.Progress;
            list.Add(new AgentProtocol.RunInfo(r.Job.Id, r.RunId, r.Job.Name, p.Phase.ToString(), r.Waiting ? "Waiting for another Rezen Backup job." : p.PhaseText,
                p.FilesDone, p.FilesTotal, p.BytesDone, p.BytesTotal, p.CurrentFile, p.BytesPerSecond, p.EstimatedRemaining?.TotalSeconds, p.Paused, r.Waiting, r.DriveLabel));
        }

        return list;
    }

    public async Task ControlRunAsync(string command, Guid jobId)
    {
        await Agent.SendAsync(new AgentProtocol.Request(command, jobId));
        if (App.Backups.Active(jobId) is { } local)
        {
            switch (command)
            {
                case "pause":
                    local.Pause.Pause();
                    break;
                case "resume":
                    local.Pause.Resume();
                    break;
                case "cancel":
                    local.Cancel();
                    break;
            }
        }
    }

    public void Dispose()
    {
        _lockTimer.Stop();
        _signalTimer.Stop();
        Session?.Dispose();
        Session = null;
        foreach (var r in App.Backups.ActiveRuns)
        {
            r.Cancel();
        }
    }
}
