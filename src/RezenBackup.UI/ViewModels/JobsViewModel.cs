using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RezenBackup.Application;
using RezenBackup.Core.Domain;
using RezenBackup.UI.Services;

namespace RezenBackup.UI.ViewModels;

public sealed record JobRow(
    Guid Id,
    string Name,
    bool Enabled,
    string Sources,
    string Destination,
    string Schedule,
    string Retention,
    string Verification,
    string Status,
    string ToggleText);

/// <summary>Backup Jobs page (spec §28).</summary>
public sealed partial class JobsViewModel : PageViewModel
{
    public JobsViewModel(UiContext ui)
        : base(ui)
    {
    }

    public ObservableCollection<JobRow> Jobs { get; } = [];

    [ObservableProperty]
    private bool _isEmpty;

    public override void OnActivated() => Refresh();

    private void Refresh()
    {
        Jobs.Clear();
        var connected = Ui.App.ConnectedDrives();
        foreach (var job in Ui.App.Jobs.All)
        {
            var status = Ui.App.Status.ForJob(job, connected);
            Jobs.Add(new JobRow(
                job.Id,
                job.Name,
                job.Enabled,
                string.Join(Environment.NewLine, job.Sources),
                (status.DriveLabel ?? "Backup drive") + (status.DriveConnected ? " — connected" : " — not connected"),
                job.Schedule.Describe(),
                job.Retention.Describe(),
                job.Verification == VerificationLevel.Full ? "Full" : "Standard",
                job.Enabled ? status.Security.ToDisplay() : "Disabled (restore only)",
                job.Enabled ? "Disable" : "Enable"));
        }

        IsEmpty = Jobs.Count == 0;
    }

    [RelayCommand]
    private static void NewJob() => Navigation.Go("new-job");

    [RelayCommand]
    private async Task BackUpNow(Guid id)
    {
        if (Ui.App.Jobs.Get(id) is { } job)
        {
            if (!job.Enabled)
            {
                await Dialogs.MessageAsync(Ui.MainWindow!, job.Name, "This job is disabled. Enable it to back up from this computer.", null);
                return;
            }

            if (await Ui.BackUpNowAsync(job))
            {
                Navigation.Go("dashboard");
            }
        }
    }

    [RelayCommand]
    private static void Edit(Guid id) => Navigation.Go("job-editor", id);

    [RelayCommand]
    private static void Restore(Guid id) => Navigation.Go("restore", id);

    [RelayCommand]
    private static void History(Guid id) => Navigation.Go("history", id);

    [RelayCommand]
    private static void ChangePassword() => Navigation.Go("security");

    [RelayCommand]
    private void Toggle(Guid id)
    {
        if (Ui.App.Jobs.Get(id) is { } job)
        {
            Ui.App.Jobs.SetEnabled(id, !job.Enabled);
            Refresh();
        }
    }

    [RelayCommand]
    private async Task Delete(Guid id)
    {
        if (Ui.App.Jobs.Get(id) is not { } job)
        {
            return;
        }

        if (await Dialogs.ConfirmAsync(Ui.MainWindow!, $"Delete \"{job.Name}\"?",
                "The job is removed from this computer. Your encrypted backups stay on the backup drive and can be imported again at any time. Nothing on the drive is deleted.",
                "Delete Job", danger: true))
        {
            Ui.App.Jobs.Delete(id);
            Refresh();
        }
    }
}
