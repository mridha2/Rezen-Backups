using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RezenBackup.Application;
using RezenBackup.Core;
using RezenBackup.Core.Domain;
using RezenBackup.UI.Services;

namespace RezenBackup.UI.ViewModels;

public sealed record HistoryRow(
    RunRow Run,
    string Date,
    string Job,
    string Status,
    string StatusClass,
    string Security,
    string Data,
    string Duration,
    string Message,
    bool HasIssues,
    string IssuesText);

/// <summary>Backup history (spec §58). Shows statistics only; file-level details require unlocking.</summary>
public sealed partial class HistoryViewModel : PageViewModel
{
    private readonly Guid? _jobId;

    public HistoryViewModel(UiContext ui, Guid? jobId)
        : base(ui)
    {
        _jobId = jobId;
    }

    public ObservableCollection<HistoryRow> Rows { get; } = [];

    [ObservableProperty]
    private HistoryRow? _selected;

    [ObservableProperty]
    private string _title = "History";

    public override void OnActivated() => Refresh();

    [RelayCommand]
    private void Refresh()
    {
        var names = Ui.App.Jobs.All.ToDictionary(j => j.Id, j => j.Name);
        Title = _jobId is { } id && names.TryGetValue(id, out var n) ? $"History — {n}" : "History";
        Rows.Clear();
        foreach (var r in Ui.App.Db.Runs(_jobId, 500))
        {
            Rows.Add(new HistoryRow(
                r,
                r.StartedUtc.ToLocalTime().ToString("MMM d, yyyy  h:mm tt", CultureInfo.CurrentCulture),
                names.GetValueOrDefault(r.JobId, "(deleted job)"),
                r.Outcome == RunOutcome.CompletedWithWarnings ? "Warning" : r.Outcome.ToDisplay(),
                r.Outcome switch
                {
                    RunOutcome.Success => "good",
                    RunOutcome.Failed => "bad",
                    _ => "warn",
                },
                r.Outcome is RunOutcome.Success or RunOutcome.CompletedWithWarnings ? r.Security.ToDisplay() : r.Security == SecurityStatus.EncryptedVerificationPending ? "Not completed" : r.Security.ToDisplay(),
                r.BytesNew > 0 ? Fmt.Bytes(r.BytesNew) : "—",
                r.Duration is { } d ? Fmt.Duration(d) : "—",
                r.Message ?? string.Empty,
                r.FilesWarned > 0,
                r.FilesWarned > 0 ? $"{r.FilesWarned} file(s) could not be backed up" : string.Empty));
        }
    }

    [RelayCommand]
    private async Task ShowDetails(HistoryRow? row)
    {
        row ??= Selected;
        if (row is null)
        {
            return;
        }

        var r = row.Run;
        var text = $"{row.Status} — {row.Security}{Environment.NewLine}{row.Message}" +
                   (r.SnapshotFolder is { } f ? $"{Environment.NewLine}Snapshot: {f}" : string.Empty) +
                   (r.Files > 0 ? $"{Environment.NewLine}{r.Files:N0} files, {Fmt.Bytes(r.BytesScanned)} protected, {Fmt.Bytes(r.BytesNew)} new" : string.Empty);
        await Dialogs.MessageAsync(Ui.MainWindow!, row.Date, text, r.TechnicalDetails, isError: r.Outcome == RunOutcome.Failed);
    }

    /// <summary>"3 files could not be backed up" — paths are encrypted and shown only after unlocking.</summary>
    [RelayCommand]
    private async Task ShowIssues(HistoryRow? row)
    {
        row ??= Selected;
        if (row is not { HasIssues: true })
        {
            return;
        }

        var session = await Ui.EnsureUnlockedAsync("Enter your password to see which files could not be backed up.");
        if (session is null)
        {
            return;
        }

        try
        {
            var issues = await Task.Run(() => session.RunIssues(row.Run.JobId, row.Run.Id));
            var text = string.Join(Environment.NewLine, issues.Select(i => $"{i.Kind.ToDisplay()}: {i.Path}{(i.Detail is { } d ? " (" + d + ")" : string.Empty)}"));
            await Dialogs.MessageAsync(Ui.MainWindow!, row.IssuesText, text.Length == 0 ? "No details available." : text, null);
        }
        catch (RezenException ex)
        {
            await Dialogs.MessageAsync(Ui.MainWindow!, "Details unavailable", ex.Message, ex.TechnicalDetails, isError: true);
        }
    }
}
