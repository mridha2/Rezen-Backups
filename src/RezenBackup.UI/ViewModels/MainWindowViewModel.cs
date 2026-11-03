using System.Collections.ObjectModel;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RezenBackup.UI.Services;

namespace RezenBackup.UI.ViewModels;

/// <summary>Base for pages shown in the main content area.</summary>
public abstract partial class PageViewModel : ObservableObject
{
    protected PageViewModel(UiContext ui) => Ui = ui;

    public UiContext Ui { get; }

    public virtual void OnActivated()
    {
    }

    public virtual void OnDeactivated()
    {
    }

    /// <summary>Called when the app locks; pages drop any decrypted data they hold.</summary>
    public virtual void OnLocked()
    {
    }
}

public sealed record NavItem(string Key, string Title, Geometry Icon);

public sealed partial class MainWindowViewModel : ObservableObject
{
    private readonly UiContext _ui;

    public MainWindowViewModel(UiContext ui)
    {
        _ui = ui;
        NavItems =
        [
            new("dashboard", "Dashboard", Icon("IconHome")),
            new("jobs", "Backup Jobs", Icon("IconJobs")),
            new("restore", "Restore", Icon("IconRestore")),
            new("history", "History", Icon("IconHistory")),
            new("security", "Security", Icon("IconShield")),
            new("settings", "Settings", Icon("IconSettings")),
            new("logs", "Logs", Icon("IconLogs")),
            new("about", "About", Icon("IconInfo")),
        ];
        ui.SessionChanged += () =>
        {
            OnPropertyChanged(nameof(IsUnlocked));
            OnPropertyChanged(nameof(LockStatusText));
            if (!ui.IsUnlocked)
            {
                CurrentPage?.OnLocked();
            }
        };
        Navigation.Navigate = Navigate;

        if (ui.App.KeySets.Default is null || !ui.App.Settings.SetupCompleted && ui.App.Jobs.All.Count == 0)
        {
            ShowSetup();
        }
        else
        {
            SelectedNav = NavItems[0];
        }
    }

    public ObservableCollection<NavItem> NavItems { get; }

    [ObservableProperty]
    private NavItem? _selectedNav;

    [ObservableProperty]
    private PageViewModel? _currentPage;

    [ObservableProperty]
    private bool _showNav = true;

    public bool IsUnlocked => _ui.IsUnlocked;

    public string LockStatusText => _ui.IsUnlocked ? "Unlocked — backup history is accessible" : "Locked";

    private static Geometry Icon(string key) =>
        Avalonia.Application.Current!.TryGetResource(key, null, out var g) && g is Geometry geometry ? geometry : new StreamGeometry();

    partial void OnSelectedNavChanged(NavItem? value)
    {
        if (value is not null)
        {
            Show(Create(value.Key, null));
        }
    }

    private void Show(PageViewModel page)
    {
        CurrentPage?.OnDeactivated();
        CurrentPage = page;
        page.OnActivated();
    }

    private PageViewModel Create(string key, object? arg) => key switch
    {
        "dashboard" => new DashboardViewModel(_ui),
        "jobs" => new JobsViewModel(_ui),
        "job-editor" => new JobEditorViewModel(_ui, (Guid)arg!),
        "new-job" => new SetupWizardViewModel(_ui, newJobOnly: true),
        "restore" => new RestoreViewModel(_ui, arg as Guid?),
        "history" => new HistoryViewModel(_ui, arg as Guid?),
        "security" => new SecurityViewModel(_ui),
        "settings" => new SettingsViewModel(_ui),
        "logs" => new LogsViewModel(_ui),
        "about" => new AboutViewModel(_ui),
        "setup" => new SetupWizardViewModel(_ui, newJobOnly: false),
        "import" => new ImportViewModel(_ui),
        _ => new DashboardViewModel(_ui),
    };

    public void Navigate(string key, object? arg = null)
    {
        ShowNav = key != "setup" && !(key == "import" && _ui.App.Jobs.All.Count == 0);
        var nav = NavItems.FirstOrDefault(n => n.Key == key);
        if (nav is not null && arg is null)
        {
            if (SelectedNav == nav)
            {
                Show(Create(key, null));
            }
            else
            {
                SelectedNav = nav;
            }

            return;
        }

        Show(Create(key, arg));
    }

    private void ShowSetup()
    {
        ShowNav = false;
        Show(new SetupWizardViewModel(_ui, newJobOnly: false));
    }

    [RelayCommand]
    private void Lock() => _ui.Lock("Locked by you.");
}

/// <summary>Navigation from any page.</summary>
public static class Navigation
{
    public static Action<string, object?> Navigate { get; set; } = (_, _) => { };

    public static void Go(string key, object? arg = null) => Navigate(key, arg);
}
