namespace RezenBackup.Security;

public enum AutoLockMode
{
    OnMinimize = 0,
    After5Minutes = 5,
    After15Minutes = 15,
    After30Minutes = 30,
    NeverThisSession = -1,
}

/// <summary>
/// Auto-lock state machine (spec §46–48). The UI reports activity, minimising and OS session locks; when a lock is due
/// the <see cref="LockRequested"/> event fires and the application clears unlocked key material and decrypted views.
/// </summary>
public sealed class SessionLockManager
{
    private readonly object _gate = new();
    private DateTimeOffset _lastActivity = DateTimeOffset.UtcNow;
    private int _busy;

    public AutoLockMode Mode { get; set; } = AutoLockMode.After15Minutes;

    public bool LockWhenSystemLocks { get; set; } = true;

    public bool IsUnlocked { get; private set; }

    /// <summary>Raised with a reason when the application must lock.</summary>
    public event Action<string>? LockRequested;

    public void MarkUnlocked()
    {
        lock (_gate)
        {
            IsUnlocked = true;
            _lastActivity = DateTimeOffset.UtcNow;
        }
    }

    public void RegisterActivity()
    {
        lock (_gate)
        {
            _lastActivity = DateTimeOffset.UtcNow;
        }
    }

    /// <summary>A long operation (restore) defers auto-lock until it ends (DESIGN §24).</summary>
    public IDisposable BeginBusy()
    {
        Interlocked.Increment(ref _busy);
        return new BusyScope(this);
    }

    public void OnMinimized()
    {
        if (Mode == AutoLockMode.OnMinimize)
        {
            Lock("Locked because the window was minimized.");
        }
    }

    public void OnSystemSessionLocked()
    {
        if (LockWhenSystemLocks)
        {
            Lock("Locked because the computer was locked.");
        }
    }

    /// <summary>Call periodically (e.g. every 15 seconds).</summary>
    public void Tick(DateTimeOffset now)
    {
        if (!IsUnlocked || Volatile.Read(ref _busy) > 0 || Mode is AutoLockMode.NeverThisSession or AutoLockMode.OnMinimize)
        {
            return;
        }

        TimeSpan idle;
        lock (_gate)
        {
            idle = now - _lastActivity;
        }

        if (idle >= TimeSpan.FromMinutes((int)Mode))
        {
            Lock($"Locked after {(int)Mode} minutes of inactivity.");
        }
    }

    public void Lock(string reason)
    {
        lock (_gate)
        {
            if (!IsUnlocked)
            {
                return;
            }

            IsUnlocked = false;
        }

        LockRequested?.Invoke(reason);
    }

    private sealed class BusyScope(SessionLockManager owner) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                Interlocked.Decrement(ref owner._busy);
                owner.RegisterActivity();
            }
        }
    }
}
