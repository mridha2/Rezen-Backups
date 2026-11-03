using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RezenBackup.Application;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.Format;
using RezenBackup.RestoreEngine;
using RezenBackup.UI.Services;

namespace RezenBackup.UI.ViewModels;

public sealed record JobChoice(Guid Id, string Name, Guid? RepositoryId = null)
{
    public override string ToString() => Name;
}

public sealed record SnapshotItem(SnapshotSummary Summary, string Title, string Subtitle, bool Restorable);

public sealed partial class BrowserItem : ObservableObject
{
    public BrowserItem(CatalogItem item, bool showPath)
    {
        Item = item;
        Name = item.Name;
        IsDirectory = item.IsDirectory;
        SizeText = item.IsDirectory ? string.Empty : Fmt.Bytes(item.Entry.Size);
        ModifiedText = item.Entry.ModifiedTicksUtc > 0 ? item.Entry.ModifiedUtc.ToLocalTime().ToString("g", CultureInfo.CurrentCulture) : string.Empty;
        Badge = item.Entry.Status switch
        {
            EntryStatus.ChangedDuringBackup => "Changed during backup",
            EntryStatus.CarriedForward => "Previous version kept",
            _ => string.Empty,
        };
        PathText = showPath ? item.OriginalFullPath : string.Empty;
        ShowPath = showPath;
    }

    public bool ShowPath { get; }

    public CatalogItem Item { get; }

    public string Name { get; }

    public bool IsDirectory { get; }

    public string SizeText { get; }

    public string ModifiedText { get; }

    public string Badge { get; }

    public string PathText { get; }

    [ObservableProperty]
    private bool _isChecked;
}

public sealed record VersionItem(FileVersion Version, string Title, string Detail);

/// <summary>Restore (spec §39–43). Nothing protected is shown before unlocking.</summary>
public sealed partial class RestoreViewModel : PageViewModel
{
    private CatalogSession? _catalog;

    public RestoreViewModel(UiContext ui, Guid? jobId)
        : base(ui)
    {
        foreach (var j in ui.App.Jobs.All)
        {
            var repos = ui.App.Jobs.ConnectedRepositories(j.Id);
            if (repos.Count > 1)
            {
                foreach (var (record, _) in repos)
                {
                    Jobs.Add(new JobChoice(j.Id, $"{j.Name} — on {ui.App.Jobs.DriveLabel(record)}", record.Id));
                }
            }
            else
            {
                Jobs.Add(new JobChoice(j.Id, j.Name));
            }
        }

        SelectedJob = Jobs.FirstOrDefault(j => j.Id == jobId) ?? Jobs.FirstOrDefault();
        ui.SessionChanged += OnSessionChanged;
    }

    public ObservableCollection<JobChoice> Jobs { get; } = [];

    public ObservableCollection<SnapshotItem> Snapshots { get; } = [];

    public ObservableCollection<BrowserItem> Items { get; } = [];

    public ObservableCollection<VersionItem> Versions { get; } = [];

    [ObservableProperty]
    private JobChoice? _selectedJob;

    [ObservableProperty]
    private SnapshotItem? _selectedSnapshot;

    [ObservableProperty]
    private BrowserItem? _selectedItem;

    [ObservableProperty]
    private bool _isUnlocked;

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string? _busyText;

    [ObservableProperty]
    private string? _message;

    [ObservableProperty]
    private string _breadcrumb = string.Empty;

    [ObservableProperty]
    private string _searchText = string.Empty;

    [ObservableProperty]
    private string _extensionFilter = string.Empty;

    [ObservableProperty]
    private DateTimeOffset? _modifiedFrom;

    [ObservableProperty]
    private DateTimeOffset? _modifiedTo;

    [ObservableProperty]
    private bool _isSearchResult;

    [ObservableProperty]
    private bool _restoreToOriginal = true;

    [ObservableProperty]
    private string? _targetFolder;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasProgress))]
    private double _progress;

    public bool HasProgress => Progress > 0;

    [ObservableProperty]
    private string? _progressText;

    private CatalogPath? _currentFolder;

    public bool HasVersions => Versions.Count > 0;

    public override void OnActivated()
    {
        IsUnlocked = Ui.IsUnlocked;
        if (IsUnlocked)
        {
            _ = LoadAsync();
        }
    }

    public override void OnDeactivated() => Ui.SessionChanged -= OnSessionChanged;

    private void OnSessionChanged()
    {
        IsUnlocked = Ui.IsUnlocked;
        if (!IsUnlocked)
        {
            OnLocked();
        }
    }

    public override void OnLocked()
    {
        _catalog = null;
        Snapshots.Clear();
        Items.Clear();
        Versions.Clear();
        Breadcrumb = string.Empty;
        IsUnlocked = false;
        Message = Ui.LastLockReason;
    }

    partial void OnSelectedJobChanged(JobChoice? value)
    {
        if (IsUnlocked)
        {
            _ = LoadAsync();
        }
    }

    partial void OnSelectedSnapshotChanged(SnapshotItem? value)
    {
        Versions.Clear();
        OnPropertyChanged(nameof(HasVersions));
        if (value is { Restorable: true } && _catalog is not null)
        {
            ShowRoots();
        }
        else
        {
            Items.Clear();
            Breadcrumb = value?.Summary.Problem ?? string.Empty;
        }
    }

    partial void OnSelectedItemChanged(BrowserItem? value)
    {
        Versions.Clear();
        if (value is { IsDirectory: false } && _catalog is not null)
        {
            foreach (var v in _catalog.VersionsOf(value.Item))
            {
                Versions.Add(new VersionItem(v, Fmt.When(v.Snapshot.StartedUtc), $"{Fmt.Bytes(v.Item.Entry.Size)} · modified {v.Item.Entry.ModifiedUtc.ToLocalTime():g}"));
            }
        }

        OnPropertyChanged(nameof(HasVersions));
    }

    [RelayCommand]
    private async Task Unlock()
    {
        var session = await Ui.EnsureUnlockedAsync("Enter your backup password to browse and restore your files.");
        IsUnlocked = session is not null;
        if (IsUnlocked)
        {
            await LoadAsync();
        }
    }

    private async Task LoadAsync()
    {
        if (SelectedJob is null || Ui.Session is not { } session)
        {
            return;
        }

        Message = null;
        IsBusy = true;
        BusyText = "Reading encrypted backup catalog…";
        using var busy = Ui.Locks.BeginBusy();
        try
        {
            var jobId = SelectedJob.Id;
            var repoId = SelectedJob.RepositoryId;
            _catalog = await Task.Run(() => session.OpenCatalog(jobId, repoId));
            Snapshots.Clear();
            foreach (var s in _catalog.Snapshots)
            {
                var status = s.Validity switch
                {
                    SnapshotValidity.Valid => "Encrypted & Verified",
                    SnapshotValidity.Incomplete => "Incomplete — not restorable",
                    SnapshotValidity.CommittedPendingFinalize => "Verification pending",
                    SnapshotValidity.Deleting => "Being removed",
                    _ => "Integrity Failure",
                };
                var files = s.Record?.Stats.Files is { } f ? $"{f.ToString("N0", CultureInfo.CurrentCulture)} files · " : string.Empty;
                Snapshots.Add(new SnapshotItem(s, s.LocalTime.ToString("dddd, MMMM d, yyyy — h:mm tt", CultureInfo.CurrentCulture), files + status, s.IsRestorable));
            }

            SelectedSnapshot = Snapshots.FirstOrDefault(s => s.Restorable);
            if (Snapshots.Any(s => s.Summary.Validity == SnapshotValidity.Invalid))
            {
                Message = UserMessages.IntegrityFailed + " Damaged snapshots are shown but cannot be restored.";
            }
        }
        catch (RezenException ex)
        {
            Message = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void ShowRoots()
    {
        Items.Clear();
        IsSearchResult = false;
        _currentFolder = null;
        Breadcrumb = SelectedSnapshot?.Title ?? string.Empty;
        foreach (var r in _catalog!.Roots(SelectedSnapshot!.Summary.SnapshotId))
        {
            Items.Add(new BrowserItem(r, showPath: true));
        }
    }

    [RelayCommand]
    private void Open(BrowserItem? item)
    {
        item ??= SelectedItem;
        if (item is not { IsDirectory: true } || _catalog is null)
        {
            return;
        }

        _currentFolder = item.Item.Path;
        Items.Clear();
        IsSearchResult = false;
        Breadcrumb = item.Item.OriginalFullPath;
        foreach (var child in _catalog.ListChildren(item.Item.Path).OrderByDescending(c => c.IsDirectory).ThenBy(c => c.Name, StringComparer.CurrentCultureIgnoreCase))
        {
            Items.Add(new BrowserItem(child, showPath: false));
        }
    }

    [RelayCommand]
    private void Up()
    {
        if (_catalog is null || _currentFolder is null)
        {
            if (IsSearchResult && SelectedSnapshot is not null)
            {
                ShowRoots();
            }

            return;
        }

        var parent = _currentFolder.Parent;
        if (parent is null)
        {
            ShowRoots();
            return;
        }

        var item = _catalog.Find(parent);
        if (item is null)
        {
            ShowRoots();
            return;
        }

        Open(new BrowserItem(item, false));
    }

    [RelayCommand]
    private void Search()
    {
        if (_catalog is null || SelectedSnapshot is not { Restorable: true })
        {
            return;
        }

        var results = _catalog.Search(SelectedSnapshot.Summary.SnapshotId, new SearchQuery
        {
            NameContains = string.IsNullOrWhiteSpace(SearchText) ? null : SearchText.Trim(),
            Extension = string.IsNullOrWhiteSpace(ExtensionFilter) ? null : ExtensionFilter.Trim(),
            ModifiedFromUtc = ModifiedFrom?.UtcDateTime.Date,
            ModifiedToUtc = ModifiedTo?.UtcDateTime.Date.AddDays(1),
            IncludeDirectories = true,
            MaxResults = 2000,
        });
        Items.Clear();
        IsSearchResult = true;
        _currentFolder = null;
        Breadcrumb = $"{results.Count} result(s) in {SelectedSnapshot.Title}";
        foreach (var r in results)
        {
            Items.Add(new BrowserItem(r, showPath: true));
        }
    }

    [RelayCommand]
    private void ClearSearch()
    {
        SearchText = string.Empty;
        ExtensionFilter = string.Empty;
        ModifiedFrom = null;
        ModifiedTo = null;
        if (SelectedSnapshot is { Restorable: true })
        {
            ShowRoots();
        }
    }

    [RelayCommand]
    private async Task ChooseTarget()
    {
        var picked = await Dialogs.PickFoldersAsync(Ui.MainWindow!, "Restore to…", multiple: false);
        if (picked.Count == 1)
        {
            TargetFolder = picked[0];
            RestoreToOriginal = false;
        }
    }

    [RelayCommand]
    private Task RestoreSelected()
    {
        var items = Items.Where(i => i.IsChecked).Select(i => i.Item).ToList();
        if (items.Count == 0 && SelectedItem is not null)
        {
            items.Add(SelectedItem.Item);
        }

        return RestoreAsync(items);
    }

    [RelayCommand]
    private Task RestoreSnapshot()
    {
        if (_catalog is null || SelectedSnapshot is not { Restorable: true })
        {
            return Task.CompletedTask;
        }

        return RestoreAsync(_catalog.Roots(SelectedSnapshot.Summary.SnapshotId).ToList());
    }

    [RelayCommand]
    private Task RestoreVersion(VersionItem? version) =>
        version is null ? Task.CompletedTask : RestoreAsync([version.Version.Item]);

    private async Task RestoreAsync(IReadOnlyList<CatalogItem> items)
    {
        if (items.Count == 0 || _catalog is null || Ui.Session is not { } session || SelectedJob is null)
        {
            Message = "Select the files or folders to restore.";
            return;
        }

        string? target = RestoreToOriginal ? null : TargetFolder;
        if (!RestoreToOriginal && target is null)
        {
            Message = "Choose a folder to restore to.";
            return;
        }

        if (RestoreToOriginal && items.Any(i => !RestoreExecutor.CanRestoreToOriginal(i)))
        {
            Message = "This backup was made on a different operating system. Choose \"Restore to another location\".";
            return;
        }

        long files = 0;
        long bytes = 0;
        foreach (var i in items)
        {
            var (f, b) = _catalog.Measure(i);
            files += f;
            bytes += b;
        }

        var where = target ?? "their original locations";
        if (!await Dialogs.ConfirmAsync(Ui.MainWindow!, "Restore files", $"Restore {files:N0} file(s) ({Fmt.Bytes(bytes)}) to {where}? Existing files are never overwritten without asking.", "Restore"))
        {
            return;
        }

        IsBusy = true;
        BusyText = "Decrypting and verifying…";
        Message = null;
        var owner = Ui.MainWindow!;
        try
        {
            using var busy = Ui.Locks.BeginBusy();
            var progress = new Progress<RestoreProgress>(p =>
            {
                Progress = p.BytesTotal > 0 ? 100.0 * p.BytesDone / p.BytesTotal : 0;
                ProgressText = $"{p.FilesDone:N0} / {p.FilesTotal:N0} files · {Fmt.Bytes(p.BytesDone)} / {Fmt.Bytes(p.BytesTotal)}";
            });
            var report = await session.RestoreAsync(SelectedJob.Id, items, new RestoreOptions
            {
                TargetRoot = target,
                ResolveConflict = c => Dialogs.ConflictFromWorker(owner, c),
            }, progress, default, SelectedJob.RepositoryId);

            var summary = $"Restored {report.FilesRestored:N0} file(s), skipped {report.FilesSkipped:N0}, failed {report.FilesFailed:N0}.";
            var details = string.Join(Environment.NewLine, report.Issues.Select(i => $"{i.Path}: {i.Message}")
                .Concat(report.Renamed.Select(r => $"Renamed for this system: {r.Original} → {r.Restored}")));
            await Dialogs.MessageAsync(owner, report.IntegrityFailure ? UserMessages.IntegrityFailed : "Restore complete",
                report.IntegrityFailure ? summary + " Files that failed verification were not restored." : summary,
                details.Length > 0 ? details : null, isError: report.IntegrityFailure);
        }
        catch (RezenException ex)
        {
            await Dialogs.MessageAsync(owner, "Restore stopped", ex.Message, ex.TechnicalDetails, isError: true);
        }
        finally
        {
            IsBusy = false;
            ProgressText = null;
            Progress = 0;
        }
    }
}
