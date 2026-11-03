using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RezenBackup.Application;
using RezenBackup.Core;
using RezenBackup.UI.Services;

namespace RezenBackup.UI.ViewModels;

public sealed record FoundItem(FoundRepository Repo, string Title, string Detail);

/// <summary>"Import Existing Rezen Backup" (spec §63): restore on a new computer from the drive alone.</summary>
public sealed partial class ImportViewModel : PageViewModel
{
    public ImportViewModel(UiContext ui)
        : base(ui)
    {
        Scan();
    }

    public ObservableCollection<FoundItem> Found { get; } = [];

    [ObservableProperty]
    private FoundItem? _selected;

    [ObservableProperty]
    private bool _useRecoveryKey;

    [ObservableProperty]
    private string _secret = string.Empty;

    [ObservableProperty]
    private string _newPassword = string.Empty;

    [ObservableProperty]
    private string? _message;

    [ObservableProperty]
    private bool _isBusy;

    public bool HasJobs => Ui.App.Jobs.All.Count > 0;

    [RelayCommand]
    private void Scan()
    {
        Found.Clear();
        var roots = Ui.App.Platform.Volumes.GetVolumes().Select(v => v.RootPath).ToList();
        foreach (var root in roots.Distinct())
        {
            Add(root);
        }

        Message = Found.Count == 0 ? "No Rezen Backup drive was found. Connect your backup drive and select Scan, or choose a folder." : null;
    }

    private void Add(string root)
    {
        foreach (var r in Ui.App.Import.FindRepositories(root))
        {
            Found.Add(new FoundItem(r, $"{r.JobFolder} — from {r.ComputerFolder}", $"{root} · {r.SnapshotFolders} dated snapshot(s){(r.AlreadyImported ? " · already on this computer" : string.Empty)}"));
        }
    }

    [RelayCommand]
    private async Task ChooseFolder()
    {
        var picked = await Dialogs.PickFoldersAsync(Ui.MainWindow!, "Select the backup drive or the folder that contains \"Rezen Backup\"", multiple: false);
        if (picked.Count == 1)
        {
            var root = picked[0];
            if (Path.GetFileName(root.TrimEnd('/', '\\')) == Format.RepositoryLayout.BackupRootFolderName)
            {
                root = Path.GetDirectoryName(root.TrimEnd('/', '\\'))!;
            }

            Add(root);
            Message = Found.Count == 0 ? "No Rezen Backup was found there." : null;
        }
    }

    [RelayCommand]
    private async Task Import()
    {
        if (Selected is null)
        {
            Message = "Select the backup to import.";
            return;
        }

        if (Selected.Repo.AlreadyImported)
        {
            Message = "This backup is already set up on this computer.";
            return;
        }

        IsBusy = true;
        Message = "Unlocking and rebuilding the backup catalog…";
        try
        {
            var repo = Selected.Repo;
            var secret = Secret;
            var newPw = NewPassword;
            var job = UseRecoveryKey
                ? await Task.Run(() => Ui.App.Import.ImportWithRecoveryKey(repo.Path, secret, newPw))
                : await Task.Run(() => Ui.App.Import.ImportWithPassword(repo.Path, secret));
            Secret = string.Empty;
            NewPassword = string.Empty;
            Ui.App.SaveSettings(Ui.App.Settings with { SetupCompleted = true });
            await Dialogs.MessageAsync(Ui.MainWindow!, "Backup imported",
                $"\"{job.Name}\" was imported with {Ui.App.Db.Snapshots(job.Id).Count} snapshot(s). It is restore-only until you enable it in Backup Jobs.", null);
            Navigation.Go("restore", job.Id);
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

    [RelayCommand]
    private void Back() => Navigation.Go(HasJobs ? "settings" : "setup");
}
