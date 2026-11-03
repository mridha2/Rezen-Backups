using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Policies;
using RezenBackup.UI.Services;

namespace RezenBackup.UI.ViewModels;

public sealed record ExclusionRow(ExclusionRule Rule, string Text, string KindText);

/// <summary>Edits an existing job: sources, exclusions, schedule, retention, verification and options.</summary>
public sealed partial class JobEditorViewModel : PageViewModel
{
    private readonly JobDefinition _original;

    private static readonly (string Label, RetentionPolicy Policy)[] RetentionChoices =
    [
        ("Smart: all for 7 days, weekly for 3 months, monthly for 1 year", RetentionPolicy.Smart),
        ("Last 5 snapshots", RetentionPolicy.LastN(5)),
        ("Last 10 snapshots", RetentionPolicy.LastN(10)),
        ("Last 30 snapshots", RetentionPolicy.LastN(30)),
        ("7 days", RetentionPolicy.Days(7)),
        ("30 days", RetentionPolicy.Days(30)),
        ("90 days", RetentionPolicy.Days(90)),
        ("6 months", RetentionPolicy.Days(182)),
        ("1 year", RetentionPolicy.Days(365)),
        ("Forever", RetentionPolicy.Forever),
        ("Latest snapshot only (mirror-like — not recommended)", RetentionPolicy.LastN(1)),
    ];

    private static readonly int[] IntervalHours = [1, 2, 6, 12];

    public JobEditorViewModel(UiContext ui, Guid jobId)
        : base(ui)
    {
        _original = ui.App.Jobs.Get(jobId) ?? throw new RezenException(ErrorCode.InvalidConfiguration, "Unknown job.");
        Name = _original.Name;
        Enabled = _original.Enabled;
        foreach (var s in _original.Sources)
        {
            Sources.Add(s);
        }

        foreach (var r in _original.Exclusions)
        {
            Exclusions.Add(Row(r));
        }

        var sched = _original.Schedule;
        ScheduleKindIndex = sched.Kind switch
        {
            ScheduleKind.Manual => 0,
            ScheduleKind.Daily => 1,
            ScheduleKind.Weekly => 2,
            ScheduleKind.Monthly => 3,
            _ => 4,
        };
        ScheduleTime = sched.TimeOfDay.ToTimeSpan();
        IntervalIndex = Math.Max(0, Array.IndexOf(IntervalHours, sched.IntervalHours));
        DayOfMonth = sched.DayOfMonth;
        Mon = sched.Days.Contains(DayOfWeek.Monday);
        Tue = sched.Days.Contains(DayOfWeek.Tuesday);
        Wed = sched.Days.Contains(DayOfWeek.Wednesday);
        Thu = sched.Days.Contains(DayOfWeek.Thursday);
        Fri = sched.Days.Contains(DayOfWeek.Friday);
        Sat = sched.Days.Contains(DayOfWeek.Saturday);
        Sun = sched.Days.Contains(DayOfWeek.Sunday);
        RetentionIndex = Math.Max(0, Array.FindIndex(RetentionChoices, c => c.Policy.Describe() == _original.Retention.Describe()));
        FullVerification = _original.Verification == VerificationLevel.Full;
        FullSnapshot = _original.Method == BackupMethod.FullSnapshot;
        FullEveryIndex = _original.FullSnapshotEveryDays switch { <= 0 => 0, <= 30 => 1, _ => 2 };
        AutoRunOnConnect = _original.AutoRunOnConnect;
        EjectAfter = _original.EjectAfterBackup;
        SkipOnBattery = _original.SkipOnBattery;
        RunMissed = _original.RunMissed;
        LoadIncomplete();
    }

    public IReadOnlyList<string> RetentionLabels { get; } = RetentionChoices.Select(c => c.Label).ToList();

    public IReadOnlyList<string> ScheduleKinds { get; } = ["Manual only", "Daily", "Weekly / selected days", "Monthly", "Every few hours"];

    public IReadOnlyList<string> Intervals { get; } = ["Every hour", "Every 2 hours", "Every 6 hours", "Every 12 hours"];

    public IReadOnlyList<string> ExclusionKinds { get; } = ["Extension (e.g. .tmp)", "Pattern (e.g. *.cache)", "Folder name (e.g. node_modules)"];

    [ObservableProperty]
    private string _name = string.Empty;

    [ObservableProperty]
    private bool _enabled;

    public ObservableCollection<string> Sources { get; } = [];

    public ObservableCollection<ExclusionRow> Exclusions { get; } = [];

    public ObservableCollection<string> Incomplete { get; } = [];

    [ObservableProperty]
    private bool _hasIncomplete;

    [ObservableProperty]
    private int _newExclusionKind;

    [ObservableProperty]
    private string _newExclusionValue = string.Empty;

    [ObservableProperty]
    private int _scheduleKindIndex;

    [ObservableProperty]
    private TimeSpan? _scheduleTime;

    [ObservableProperty]
    private int _intervalIndex;

    [ObservableProperty]
    private int _dayOfMonth = 1;

    [ObservableProperty]
    private bool _mon;

    [ObservableProperty]
    private bool _tue;

    [ObservableProperty]
    private bool _wed;

    [ObservableProperty]
    private bool _thu;

    [ObservableProperty]
    private bool _fri;

    [ObservableProperty]
    private bool _sat;

    [ObservableProperty]
    private bool _sun;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(RetentionWarning))]
    private int _retentionIndex;

    [ObservableProperty]
    private bool _fullVerification;

    [ObservableProperty]
    private bool _fullSnapshot;

    [ObservableProperty]
    private int _fullEveryIndex;

    public IReadOnlyList<string> FullEveryOptions { get; } = ["Never", "Every 30 days", "Every 90 days"];

    [ObservableProperty]
    private bool _autoRunOnConnect;

    [ObservableProperty]
    private bool _ejectAfter;

    [ObservableProperty]
    private bool _skipOnBattery;

    [ObservableProperty]
    private bool _runMissed;

    [ObservableProperty]
    private string? _error;

    public string? RetentionWarning => RetentionChoices[Math.Clamp(RetentionIndex, 0, RetentionChoices.Length - 1)].Policy.IsMirrorLike
        ? "Files you delete or that get damaged on your computer will disappear from the backup after the next run. Version history protects you; keeping only the latest snapshot does not."
        : null;

    public bool ShowsTime => ScheduleKindIndex is 1 or 2 or 3;

    public bool ShowsDays => ScheduleKindIndex == 2;

    public bool ShowsInterval => ScheduleKindIndex == 4;

    public bool ShowsDayOfMonth => ScheduleKindIndex == 3;

    partial void OnScheduleKindIndexChanged(int value)
    {
        OnPropertyChanged(nameof(ShowsTime));
        OnPropertyChanged(nameof(ShowsDays));
        OnPropertyChanged(nameof(ShowsInterval));
        OnPropertyChanged(nameof(ShowsDayOfMonth));
    }

    private static ExclusionRow Row(ExclusionRule r) => new(r, r.ToString(), r.Kind switch
    {
        ExclusionKind.Extension => "Extension",
        ExclusionKind.Pattern => "Pattern",
        ExclusionKind.Folder => "Folder",
        _ => "File",
    } + (r.IsDefault ? " · default" : string.Empty));

    private void LoadIncomplete()
    {
        Incomplete.Clear();
        foreach (var f in Ui.App.Backups.IncompleteSnapshots(_original.Id))
        {
            Incomplete.Add(f);
        }

        HasIncomplete = Incomplete.Count > 0;
    }

    [RelayCommand]
    private async Task AddFolders()
    {
        foreach (var f in await Dialogs.PickFoldersAsync(Ui.MainWindow!, "Add folders", multiple: true))
        {
            var overlap = PathPolicy.CheckNewSource(f, Sources);
            if (overlap.Kind is SourceOverlapKind.Duplicate or SourceOverlapKind.NewIsInsideExisting)
            {
                await Dialogs.MessageAsync(Ui.MainWindow!, "Already included", $"\"{f}\" is already included in \"{overlap.ExistingSource}\".", null);
                continue;
            }

            if (overlap.Kind == SourceOverlapKind.NewContainsExisting &&
                !await Dialogs.ConfirmAsync(Ui.MainWindow!, "Overlapping folders", $"\"{f}\" contains \"{overlap.ExistingSource}\". The inner folder will be removed from the list so it is not backed up twice.", "Add"))
            {
                continue;
            }

            foreach (var inner in Sources.Where(s => PathPolicy.IsSameOrUnder(s, f)).ToList())
            {
                Sources.Remove(inner);
            }

            Sources.Add(f);
        }
    }

    [RelayCommand]
    private void RemoveSource(string? s)
    {
        if (s is not null)
        {
            Sources.Remove(s);
        }
    }

    [RelayCommand]
    private void AddExclusion()
    {
        var value = NewExclusionValue.Trim();
        if (value.Length == 0)
        {
            return;
        }

        var kind = NewExclusionKind switch
        {
            0 => ExclusionKind.Extension,
            1 => ExclusionKind.Pattern,
            _ => ExclusionKind.Folder,
        };
        Exclusions.Add(Row(new ExclusionRule(kind, value)));
        NewExclusionValue = string.Empty;
    }

    [RelayCommand]
    private async Task AddExcludedFolder()
    {
        foreach (var f in await Dialogs.PickFoldersAsync(Ui.MainWindow!, "Exclude a folder", multiple: true))
        {
            Exclusions.Add(Row(new ExclusionRule(ExclusionKind.Folder, f)));
        }
    }

    [RelayCommand]
    private void RemoveExclusion(ExclusionRow? row)
    {
        if (row is not null)
        {
            Exclusions.Remove(row);
        }
    }

    [RelayCommand]
    private async Task Save()
    {
        Error = null;
        var time = TimeOnly.FromTimeSpan(ScheduleTime ?? new TimeSpan(20, 0, 0));
        var days = new List<DayOfWeek>();
        if (Mon) days.Add(DayOfWeek.Monday);
        if (Tue) days.Add(DayOfWeek.Tuesday);
        if (Wed) days.Add(DayOfWeek.Wednesday);
        if (Thu) days.Add(DayOfWeek.Thursday);
        if (Fri) days.Add(DayOfWeek.Friday);
        if (Sat) days.Add(DayOfWeek.Saturday);
        if (Sun) days.Add(DayOfWeek.Sunday);
        var schedule = ScheduleKindIndex switch
        {
            0 => Schedule.Manual,
            1 => new Schedule { Kind = ScheduleKind.Daily, TimeOfDay = time },
            2 => new Schedule { Kind = ScheduleKind.Weekly, TimeOfDay = time, Days = days.Count == 0 ? [DayOfWeek.Monday] : days },
            3 => new Schedule { Kind = ScheduleKind.Monthly, TimeOfDay = time, DayOfMonth = Math.Clamp(DayOfMonth, 1, 31) },
            _ => new Schedule { Kind = ScheduleKind.Interval, IntervalHours = IntervalHours[Math.Clamp(IntervalIndex, 0, 3)] },
        };
        var retention = RetentionChoices[Math.Clamp(RetentionIndex, 0, RetentionChoices.Length - 1)].Policy;
        if (retention.IsMirrorLike && !_original.Retention.IsMirrorLike &&
            !await Dialogs.ConfirmAsync(Ui.MainWindow!, "Keep only the latest snapshot?", RetentionWarning!, "Use it anyway", danger: true))
        {
            return;
        }

        try
        {
            Ui.App.Jobs.Update(_original with
            {
                Name = Name.Trim(),
                Enabled = Enabled,
                Sources = Sources.ToList(),
                Exclusions = Exclusions.Select(e => e.Rule).ToList(),
                Schedule = schedule,
                Retention = retention,
                Verification = FullVerification ? VerificationLevel.Full : VerificationLevel.Standard,
                Method = FullSnapshot ? BackupMethod.FullSnapshot : BackupMethod.Incremental,
                FullSnapshotEveryDays = FullEveryIndex switch { 1 => 30, 2 => 90, _ => 0 },
                AutoRunOnConnect = AutoRunOnConnect,
                EjectAfterBackup = EjectAfter,
                SkipOnBattery = SkipOnBattery,
                RunMissed = RunMissed,
            });
            Navigation.Go("jobs");
        }
        catch (RezenException ex)
        {
            Error = ex.Message;
        }
    }

    [RelayCommand]
    private static void Cancel() => Navigation.Go("jobs");

    [RelayCommand]
    private async Task ResumeIncomplete(string? folder)
    {
        if (folder is not null && await Ui.BackUpNowAsync(_original, folder))
        {
            Navigation.Go("dashboard");
        }
    }

    [RelayCommand]
    private async Task DiscardIncomplete(string? folder)
    {
        if (folder is null || !await Dialogs.ConfirmAsync(Ui.MainWindow!, "Discard incomplete snapshot?",
                $"\"{folder}\" was interrupted and was never marked complete. Discarding removes it; your completed snapshots are not affected.", "Discard", danger: true))
        {
            return;
        }

        try
        {
            Ui.App.Backups.DiscardIncomplete(_original.Id, folder);
        }
        catch (Exception ex) when (ex is RezenException or IOException)
        {
            await Dialogs.MessageAsync(Ui.MainWindow!, "Could not discard", ex.Message, null, isError: true);
        }

        LoadIncomplete();
    }
}
