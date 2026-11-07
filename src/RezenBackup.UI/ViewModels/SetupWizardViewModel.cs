using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RezenBackup.Application;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Policies;
using RezenBackup.Crypto;
using RezenBackup.Security;
using RezenBackup.UI.Services;

namespace RezenBackup.UI.ViewModels;

public sealed partial class DestinationOption : ObservableObject
{
    public required string Root { get; init; }

    public required string Title { get; init; }

    public required string Detail { get; init; }

    public bool IsRemovable { get; init; }
}

/// <summary>First-time setup and "New backup job" (spec §33).</summary>
public sealed partial class SetupWizardViewModel : PageViewModel
{
    public const int StepFolders = 0;
    public const int StepDrive = 1;
    public const int StepPassword = 2;
    public const int StepRecovery = 3;
    public const int StepSchedule = 4;
    public const int StepVerification = 5;
    public const int StepReview = 6;

    private readonly bool _newJobOnly;
    private NewKeySet? _keySet;

    public SetupWizardViewModel(UiContext ui, bool newJobOnly)
        : base(ui)
    {
        _newJobOnly = newJobOnly && ui.App.KeySets.Default is not null;
        RefreshDestinations();
        PasswordFeedback = "Use at least 12 characters. A passphrase of four or more words is easy to remember and hard to guess.";
    }

    public string PageTitle => _newJobOnly ? "New Backup Job" : "Welcome to Rezen Backup";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StepTitle), nameof(StepNumberText), nameof(CanGoBack), nameof(NextText), nameof(IsFolders), nameof(IsDrive), nameof(IsPassword), nameof(IsRecovery), nameof(IsSchedule), nameof(IsVerification), nameof(IsReview))]
    private int _step;

    public bool IsFolders => Step == StepFolders;

    public bool IsDrive => Step == StepDrive;

    public bool IsPassword => Step == StepPassword;

    public bool IsRecovery => Step == StepRecovery;

    public bool IsSchedule => Step == StepSchedule;

    public bool IsVerification => Step == StepVerification;

    public bool IsReview => Step == StepReview;

    public string StepTitle => Step switch
    {
        StepFolders => "What would you like to protect?",
        StepDrive => "Where should your encrypted backups be stored?",
        StepPassword => "Protect your backups",
        StepRecovery => "Recovery key",
        StepSchedule => "Backup schedule",
        StepVerification => "Security verification",
        _ => "Review",
    };

    public string StepNumberText => $"Step {VisibleIndex(Step) + 1} of {(_newJobOnly ? 5 : 7)}";

    private int VisibleIndex(int step) => _newJobOnly && step > StepDrive ? step - 2 : step;

    public bool CanGoBack => Step > 0;

    public string NextText => Step == StepReview ? "Create Secure Backup" : "Next";

    [ObservableProperty]
    private string? _error;

    // ---- Step 1: folders
    public ObservableCollection<string> Sources { get; } = [];

    public ObservableCollection<string> SourceWarnings { get; } = [];

    [ObservableProperty]
    private string? _selectedSource;

    /// <summary>The name the wizard filled in itself; replaced when a folder is picked, unless the user typed their own.</summary>
    private string _autoJobName = DefaultJobName(null, DateTime.Now);

    [ObservableProperty]
    private string _jobName = DefaultJobName(null, DateTime.Now);

    /// <summary>
    /// Default backup name with today's date, e.g. "Backup 2026-11-04" or "Documents 2026-11-04" once a folder is
    /// picked. ISO dates are safe in folder names on every platform and sort in order.
    /// </summary>
    public static string DefaultJobName(string? folderName, DateTime today) =>
        $"{(string.IsNullOrWhiteSpace(folderName) ? "Backup" : folderName)} {today.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)}";

    [RelayCommand]
    private async Task AddFolders()
    {
        foreach (var f in await Dialogs.PickFoldersAsync(Ui.MainWindow!, "Select folders to protect", multiple: true))
        {
            AddSource(f);
        }
    }

    [RelayCommand]
    private async Task AddFiles()
    {
        foreach (var f in await Dialogs.PickFilesAsync(Ui.MainWindow!, "Select files to protect"))
        {
            AddSource(f);
        }
    }

    internal void AddSource(string path)
    {
        var overlap = PathPolicy.CheckNewSource(path, Sources);
        switch (overlap.Kind)
        {
            case SourceOverlapKind.Duplicate:
                return;
            case SourceOverlapKind.NewIsInsideExisting:
                SourceWarnings.Add($"\"{path}\" is already included in \"{overlap.ExistingSource}\" and was not added again.");
                return;
            case SourceOverlapKind.NewContainsExisting:
                SourceWarnings.Add($"\"{path}\" contains \"{overlap.ExistingSource}\", which was removed to avoid backing it up twice.");
                foreach (var inner in Sources.Where(s => PathPolicy.IsSameOrUnder(s, path)).ToList())
                {
                    Sources.Remove(inner);
                }

                break;
        }

        Sources.Add(path);
        if (Sources.Count == 1 && JobName == _autoJobName)
        {
            _autoJobName = DefaultJobName(Path.GetFileName(path.TrimEnd('/', '\\')), DateTime.Now);
            JobName = _autoJobName;
        }
    }

    [RelayCommand]
    private void RemoveSource(string? path)
    {
        if (path is not null)
        {
            Sources.Remove(path);
        }
    }

    // ---- Step 2: destination
    public ObservableCollection<DestinationOption> Destinations { get; } = [];

    public ObservableCollection<string> DestinationMessages { get; } = [];

    [ObservableProperty]
    private DestinationOption? _selectedDestination;

    [ObservableProperty]
    private bool _hideNamesOnDrive;

    partial void OnSelectedDestinationChanged(DestinationOption? value) => ValidateDestination();

    [RelayCommand]
    private void RefreshDestinations()
    {
        Destinations.Clear();
        foreach (var c in Ui.App.Drives.Candidates())
        {
            Destinations.Add(new DestinationOption
            {
                Root = c.Volume.RootPath,
                Title = string.IsNullOrWhiteSpace(c.Volume.Label) ? c.Volume.RootPath : $"{c.Volume.Label}  ({c.Volume.RootPath})",
                Detail = $"{(c.Volume.IsRemovable ? "External drive" : "Local drive")} · {c.Volume.FileSystem} · {Fmt.Bytes(c.Volume.FreeBytes)} free of {Fmt.Bytes(c.Volume.TotalBytes)}{(c.HasRezenBackups ? " · contains Rezen backups" : string.Empty)}",
                IsRemovable = c.Volume.IsRemovable,
            });
        }
    }

    [RelayCommand]
    private async Task ChooseFolderDestination()
    {
        var picked = await Dialogs.PickFoldersAsync(Ui.MainWindow!, "Choose a backup location", multiple: false);
        if (picked.Count == 1)
        {
            var option = new DestinationOption { Root = picked[0], Title = picked[0], Detail = "Folder on a drive" };
            Destinations.Add(option);
            SelectedDestination = option;
        }
    }

    private void ValidateDestination()
    {
        DestinationMessages.Clear();
        if (SelectedDestination is null)
        {
            return;
        }

        foreach (var m in Ui.App.Drives.Validate(SelectedDestination.Root, Sources))
        {
            DestinationMessages.Add((m.Severity == Application.ValidationSeverity.Blocking ? "✕ " : "! ") + m.Message);
        }
    }

    // ---- Step 3: password
    [ObservableProperty]
    private string _password = string.Empty;

    [ObservableProperty]
    private string _confirmPassword = string.Empty;

    [ObservableProperty]
    private bool _showPassword;

    [ObservableProperty]
    private string _strengthText = string.Empty;

    [ObservableProperty]
    private double _strengthValue;

    [ObservableProperty]
    private string _strengthClass = "muted";

    [ObservableProperty]
    private string _passwordFeedback;

    public char PasswordChar => ShowPassword ? '\0' : '•';

    partial void OnShowPasswordChanged(bool value) => OnPropertyChanged(nameof(PasswordChar));

    /// <summary>Shown under the password boxes while they hold a password generated in the popup.</summary>
    [ObservableProperty]
    private bool _usingGeneratedPassword;

    private bool _fillingGenerated;

    [RelayCommand]
    private async Task GeneratePassword()
    {
        var generated = await Dialogs.GeneratedPasswordAsync(Ui.MainWindow!);
        if (generated is null)
        {
            return;
        }

        _fillingGenerated = true;
        Password = generated;
        ConfirmPassword = generated;
        _fillingGenerated = false;
        UsingGeneratedPassword = true;
        Error = null;
    }

    partial void OnPasswordChanged(string value)
    {
        if (!_fillingGenerated)
        {
            UsingGeneratedPassword = false;
        }

        var a = PasswordPolicy.Assess(value);
        StrengthValue = ((int)a.Strength + 1) * 20;
        StrengthText = value.Length == 0 ? string.Empty : $"{a.StrengthText} · estimated time to crack offline: {a.CrackTimeDisplay}";
        StrengthClass = a.Strength >= PasswordStrength.Strong ? "good" : a.MeetsRequirements ? "warn" : "bad";
        PasswordFeedback = a.Feedback.Count > 0 ? string.Join(" ", a.Feedback) : "Great — this is a strong password.";
    }

    // ---- Step 4: recovery key
    [ObservableProperty]
    private string _recoveryKey = string.Empty;

    /// <summary>Bound to the "I have saved my recovery key" check box.</summary>
    [ObservableProperty]
    private bool _recoveryConfirmed;

    [ObservableProperty]
    private bool _recoverySkipped;

    [ObservableProperty]
    private string? _recoveryMessage;

    [RelayCommand]
    private void PrintRecoveryKey()
    {
        var ok = RecoveryKit.Print(RecoveryKit.Document(RecoveryKey, _keySet!.Info.Id));
        RecoveryMessage = ok ? "Sent to your default printer." : "Printing failed. Check that a printer is set up, or save the key to a removable device.";
    }

    [RelayCommand]
    private async Task SaveRecoveryKey()
    {
        var path = await Dialogs.SaveFileAsync(Ui.MainWindow!, "Save recovery key file", RecoveryKit.FileName, "txt", startInDocuments: true);
        if (path is null)
        {
            return;
        }

        var (allowed, message) = RecoveryKit.CheckLocation(Ui.App, path, SelectedDestination?.Root);
        if (!allowed)
        {
            await Dialogs.MessageAsync(Ui.MainWindow!, "Choose another location", message!, null, isError: true);
            return;
        }

        if (message is not null && !await Dialogs.ConfirmAsync(Ui.MainWindow!, "Cloud folder", message, "Save anyway"))
        {
            return;
        }

        await File.WriteAllTextAsync(path, RecoveryKit.Document(RecoveryKey, _keySet!.Info.Id));
        RecoveryMessage = RecoveryKit.SavedMessage(path);
    }

    [RelayCommand]
    private async Task SkipRecoveryKey()
    {
        if (await Dialogs.ConfirmAsync(Ui.MainWindow!, "Skip the recovery key?",
                "If you lose both your password and your recovery key, your encrypted backups cannot be recovered. You can view the recovery key later from the Security page.",
                "Skip for now", danger: true))
        {
            RecoverySkipped = true;
        }
    }

    // ---- Step 5: schedule
    public IReadOnlyList<string> ScheduleKinds { get; } = ["Manual", "Daily", "Weekly", "Selected days", "Monthly", "Every few hours"];

    [ObservableProperty]
    private int _scheduleKindIndex = 1;

    [ObservableProperty]
    private TimeSpan? _scheduleTime = new TimeSpan(20, 0, 0);

    [ObservableProperty]
    private int _intervalIndex = 2;

    public IReadOnlyList<string> Intervals { get; } = ["Every hour", "Every 2 hours", "Every 6 hours", "Every 12 hours"];

    private static readonly int[] IntervalHours = [1, 2, 6, 12];

    [ObservableProperty]
    private bool _mon = true;

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
    private int _dayOfMonth = 1;

    [ObservableProperty]
    private bool _autoRunOnConnect = true;

    [ObservableProperty]
    private bool _rememberOnPc;

    public bool ShowsTime => ScheduleKindIndex is 1 or 2 or 3 or 4;

    public bool ShowsDays => ScheduleKindIndex is 2 or 3;

    public bool ShowsInterval => ScheduleKindIndex == 5;

    public bool ShowsDayOfMonth => ScheduleKindIndex == 4;

    partial void OnScheduleKindIndexChanged(int value)
    {
        OnPropertyChanged(nameof(ShowsTime));
        OnPropertyChanged(nameof(ShowsDays));
        OnPropertyChanged(nameof(ShowsInterval));
        OnPropertyChanged(nameof(ShowsDayOfMonth));
    }

    public string RememberExplanation => $"Scheduled backups can run automatically. Only a backup-only key is kept, protected by {Ui.App.Platform.Credentials.MechanismName}: it can add new backups but cannot decrypt the contents of your backups, so restoring always needs your password or recovery key (it can still see file names and dates). If this is off, you will be asked for your password before each backup.";

    private Schedule BuildSchedule()
    {
        var time = TimeOnly.FromTimeSpan(ScheduleTime ?? new TimeSpan(20, 0, 0));
        var days = new List<DayOfWeek>();
        if (Mon) days.Add(DayOfWeek.Monday);
        if (Tue) days.Add(DayOfWeek.Tuesday);
        if (Wed) days.Add(DayOfWeek.Wednesday);
        if (Thu) days.Add(DayOfWeek.Thursday);
        if (Fri) days.Add(DayOfWeek.Friday);
        if (Sat) days.Add(DayOfWeek.Saturday);
        if (Sun) days.Add(DayOfWeek.Sunday);
        return ScheduleKindIndex switch
        {
            0 => Schedule.Manual,
            1 => new Schedule { Kind = ScheduleKind.Daily, TimeOfDay = time },
            2 or 3 => new Schedule { Kind = ScheduleKind.Weekly, TimeOfDay = time, Days = days.Count == 0 ? [DayOfWeek.Monday] : days },
            4 => new Schedule { Kind = ScheduleKind.Monthly, TimeOfDay = time, DayOfMonth = Math.Clamp(DayOfMonth, 1, 31) },
            _ => new Schedule { Kind = ScheduleKind.Interval, IntervalHours = IntervalHours[Math.Clamp(IntervalIndex, 0, 3)] },
        };
    }

    // ---- Step 6: verification
    [ObservableProperty]
    private bool _fullVerification;

    // ---- Step 7: review
    public string ReviewSources => string.Join(Environment.NewLine, Sources);

    public string ReviewDestination => SelectedDestination?.Title ?? "—";

    public string ReviewSchedule => BuildSchedule().Describe();

    public string ReviewVerification => FullVerification ? "Full — every new file is re-read from the drive and compared with your original" : "Standard — encrypted data and structure are verified after every backup";

    [ObservableProperty]
    private bool _isBusy;

    [RelayCommand]
    private void Back()
    {
        Error = null;
        int target = Step - 1;
        if (_newJobOnly && target is StepRecovery or StepPassword)
        {
            target = StepDrive;
        }

        Step = Math.Max(0, target);
    }

    [RelayCommand]
    private async Task Next()
    {
        Error = null;
        switch (Step)
        {
            case StepFolders when Sources.Count == 0:
                Error = "Select at least one folder to protect.";
                return;
            case StepFolders when string.IsNullOrWhiteSpace(JobName):
                Error = "Give this backup a name.";
                return;
            case StepDrive:
                if (SelectedDestination is null)
                {
                    Error = "Select where your encrypted backups should be stored.";
                    return;
                }

                ValidateDestination();
                if (DestinationMessages.Any(m => m.StartsWith('✕')))
                {
                    Error = "This destination cannot be used. See the messages above.";
                    return;
                }

                Step = _newJobOnly ? StepSchedule : StepPassword;
                return;
            case StepPassword:
                if (!await CreateKeySetAsync())
                {
                    return;
                }

                break;
            case StepRecovery when !RecoveryConfirmed && !RecoverySkipped:
                Error = "Tick \"I have saved my recovery key\", or choose to skip it.";
                return;
            case StepRecovery when RecoveryConfirmed:
                Ui.App.KeySets.ConfirmRecoveryKeySaved(_keySet!.Info.Id);
                break;
            case StepReview:
                await CreateAsync();
                return;
        }

        Step++;
        if (Step == StepReview)
        {
            OnPropertyChanged(nameof(ReviewSources));
            OnPropertyChanged(nameof(ReviewDestination));
            OnPropertyChanged(nameof(ReviewSchedule));
            OnPropertyChanged(nameof(ReviewVerification));
        }
    }

    private async Task<bool> CreateKeySetAsync()
    {
        if (_keySet is not null)
        {
            return true;
        }

        if (Password != ConfirmPassword)
        {
            Error = "The passwords do not match.";
            return false;
        }

        if (!PasswordPolicy.Assess(Password).MeetsRequirements)
        {
            Error = "Choose a stronger password.";
            return false;
        }

        IsBusy = true;
        try
        {
            var pw = Password;
            _keySet = await Task.Run(() => Ui.App.KeySets.Create(pw));
            Password = string.Empty;
            ConfirmPassword = string.Empty;
            RecoveryKey = _keySet.RecoveryKey;
            return true;
        }
        catch (RezenException ex)
        {
            Error = ex.Message;
            return false;
        }
        finally
        {
            IsBusy = false;
        }
    }


    private async Task CreateAsync()
    {
        IsBusy = true;
        try
        {
            RootSecret secret;
            Guid keySetId;
            if (_keySet is not null)
            {
                secret = _keySet.Secret;
                keySetId = _keySet.Info.Id;
            }
            else
            {
                var session = await Ui.EnsureUnlockedAsync("Enter your backup password to create the new encrypted backup.");
                if (session is null)
                {
                    return;
                }

                secret = session.CloneSecret();
                keySetId = session.KeySetId;
            }

            var draft = new JobDefinition
            {
                Id = Guid.Empty,
                KeySetId = keySetId,
                Name = JobName.Trim(),
                Sources = Sources.ToList(),
                Schedule = BuildSchedule(),
                Verification = FullVerification ? VerificationLevel.Full : VerificationLevel.Standard,
                HideNamesOnDrive = HideNamesOnDrive,
                AutoRunOnConnect = AutoRunOnConnect,
            };
            var dest = SelectedDestination!.Root;
            var job = await Task.Run(() => Ui.App.Jobs.Create(draft, dest, secret));
            if (RememberOnPc)
            {
                Ui.App.KeySets.SetRemember(keySetId, secret, true, backupOnly: true);
            }

            secret.Dispose();
            _keySet = null;
            RecoveryKey = string.Empty; // no longer kept in memory once setup is done
            Ui.App.SaveSettings(Ui.App.Settings with { SetupCompleted = true });
            await AgentLauncher.EnsureRunningAsync(Ui.App);
            Navigation.Go("dashboard");
            if (await Dialogs.ConfirmAsync(Ui.MainWindow!, "Backup job created", $"\"{job.Name}\" is ready. Run the first encrypted backup now?", "Back Up Now"))
            {
                await Ui.BackUpNowAsync(job);
            }
        }
        catch (RezenException ex)
        {
            Error = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void CancelWizard()
    {
        if (_newJobOnly || Ui.App.Jobs.All.Count > 0)
        {
            Navigation.Go("jobs");
        }
    }

    public bool CanCancel => _newJobOnly || Ui.App.Jobs.All.Count > 0;

    public override void OnDeactivated()
    {
        RecoveryKey = string.Empty;
        DiscardUnusedKeySet();
        Password = string.Empty;
        ConfirmPassword = string.Empty;
    }

    /// <summary>
    /// Leaving the wizard after the password step but before the job exists: remove the key set created for it, or it
    /// would linger as the oldest key set with nothing to unlock and a password nobody will be asked for again.
    /// </summary>
    private void DiscardUnusedKeySet()
    {
        if (_keySet is null)
        {
            return;
        }

        var keySet = _keySet;
        _keySet = null;
        keySet.Secret.Dispose();
        try
        {
            Ui.App.KeySets.Discard(keySet.Info.Id);
        }
        catch (RezenException)
        {
            // Used by a job after all: keep it.
        }
    }

    public bool ShowImport => !_newJobOnly;

    [RelayCommand]
    private static void ImportExisting() => Navigation.Go("import");
}
