using Avalonia.Controls;
using Avalonia.Headless.XUnit;
using Avalonia.Threading;
using Avalonia.VisualTree;
using RezenBackup.Core.Domain;
using RezenBackup.Crypto;
using RezenBackup.UI.ViewModels;
using RezenBackup.UI.Views;

namespace RezenBackup.UI.Tests;

public class UiFlowTests
{
    private static (MainWindow Window, MainWindowViewModel Vm) Open(UiFixture f)
    {
        var vm = new MainWindowViewModel(f.Ui);
        var window = new MainWindow { DataContext = vm };
        f.Ui.MainWindow = window;
        window.Show();
        Dispatcher.UIThread.RunJobs();
        return (window, vm);
    }

    private static void AssertPageRendered(MainWindow window, string expectedView)
    {
        Dispatcher.UIThread.RunJobs();
        var content = window.GetVisualDescendants().OfType<ContentControl>().First(c => c.Content is PageViewModel);
        var view = content.GetVisualDescendants().OfType<UserControl>().FirstOrDefault();
        Assert.NotNull(view);
        Assert.Equal(expectedView, view!.GetType().Name);
    }

    /// <summary>The first-run wizard, driven through the real view models and dialogs, creates an encrypted backup job.</summary>
    [AvaloniaFact]
    public async Task SetupWizard_CreatesJob_AndRunsFirstBackup()
    {
        BindingErrors.Sink.Clear();
        DialogDriver.Reset();
        using var f = new UiFixture();
        var (window, vm) = Open(f);
        var wizard = Assert.IsType<SetupWizardViewModel>(vm.CurrentPage);
        AssertPageRendered(window, nameof(SetupWizardView));

        wizard.Sources.Add(f.Source);
        wizard.JobName = "Company Documents";
        await wizard.NextCommand.ExecuteAsync(null);
        Assert.True(wizard.IsDrive);

        wizard.SelectedDestination = wizard.Destinations.First();
        await wizard.NextCommand.ExecuteAsync(null);
        Assert.True(wizard.IsPassword);

        wizard.Password = "weak";
        wizard.ConfirmPassword = "weak";
        await wizard.NextCommand.ExecuteAsync(null);
        Assert.True(wizard.IsPassword);
        Assert.NotNull(wizard.Error);

        wizard.Password = UiFixture.Password;
        wizard.ConfirmPassword = UiFixture.Password;
        await wizard.NextCommand.ExecuteAsync(null);
        Assert.True(wizard.IsRecovery);
        Assert.StartsWith("RZN1-", wizard.RecoveryKey, StringComparison.Ordinal);
        Assert.Equal(string.Empty, wizard.Password); // cleared from the view model once used

        // Must confirm or skip the recovery key before continuing.
        await wizard.NextCommand.ExecuteAsync(null);
        Assert.True(wizard.IsRecovery);
        var groups = RecoveryKeyCodec.Groups(wizard.RecoveryKey);
        var index = int.Parse(wizard.ConfirmGroupPrompt.Split("group ")[1].Split(' ')[0], System.Globalization.CultureInfo.InvariantCulture) - 1;
        wizard.ConfirmGroupInput = groups[index];
        wizard.ConfirmRecoveryKeyCommand.Execute(null);
        Assert.True(wizard.RecoveryConfirmed);

        await wizard.NextCommand.ExecuteAsync(null); // schedule
        Assert.True(wizard.IsSchedule);
        wizard.RememberOnPc = true;
        await wizard.NextCommand.ExecuteAsync(null); // verification
        wizard.FullVerification = true;
        await wizard.NextCommand.ExecuteAsync(null); // review
        Assert.True(wizard.IsReview);
        Assert.Contains("Daily", wizard.ReviewSchedule, StringComparison.Ordinal);

        DialogDriver.Answer("Back Up Now");
        var create = wizard.NextCommand.ExecuteAsync(null);
        await UiFixture.WaitUntil(() => create.IsCompleted);
        await create;

        var job = Assert.Single(f.App.Jobs.All);
        Assert.Equal("Company Documents", job.Name);
        Assert.Equal(VerificationLevel.Full, job.Verification);
        Assert.True(f.App.Settings.SetupCompleted);
        Assert.True(f.App.KeySets.Default!.RecoveryKeyConfirmed);
        Assert.True(f.App.KeySets.Default!.RememberOnThisPc);
        Assert.True(f.App.KeySets.Default!.RememberBackupOnly);
        Assert.Contains("Backup job created", DialogDriver.Opened);

        await UiFixture.WaitUntil(() => f.App.Db.Runs(job.Id).Any(r => r.Outcome != RunOutcome.Running));
        var run = f.App.Db.Runs(job.Id).First();
        Assert.Equal(RunOutcome.Success, run.Outcome);
        Assert.Equal(SecurityStatus.EncryptedAndVerified, run.Security);

        Assert.IsType<DashboardViewModel>(vm.CurrentPage);
        AssertPageRendered(window, nameof(DashboardView));
        Assert.True(BindingErrors.Sink.Errors.Count == 0, string.Join("\n", BindingErrors.Sink.Errors.Distinct()));
        window.Close();
    }

    /// <summary>Every page renders without binding errors once a job exists.</summary>
    [AvaloniaFact]
    public async Task AllPages_RenderWithoutBindingErrors()
    {
        DialogDriver.Reset();
        using var f = new UiFixture();
        await CreateJobWithBackupAsync(f);
        BindingErrors.Sink.Clear();
        var (window, vm) = Open(f);

        var expected = new Dictionary<string, string>
        {
            ["dashboard"] = nameof(DashboardView),
            ["jobs"] = nameof(JobsView),
            ["restore"] = nameof(RestoreView),
            ["history"] = nameof(HistoryView),
            ["security"] = nameof(SecurityView),
            ["settings"] = nameof(SettingsView),
            ["logs"] = nameof(LogsView),
            ["about"] = nameof(AboutView),
        };
        foreach (var nav in vm.NavItems)
        {
            vm.SelectedNav = nav;
            await Task.Delay(50);
            AssertPageRendered(window, expected[nav.Key]);
        }

        // A command bound through $parent inside an item template really works (Jobs → Edit).
        vm.Navigate("jobs");
        Dispatcher.UIThread.RunJobs();
        var edit = window.GetVisualDescendants().OfType<Button>().First(b => Equals(b.Content, "Edit"));
        Assert.NotNull(edit.Command);
        edit.Command!.Execute(edit.CommandParameter);
        Assert.IsType<JobEditorViewModel>(vm.CurrentPage);

        vm.Navigate("job-editor", f.App.Jobs.All[0].Id);
        AssertPageRendered(window, nameof(JobEditorView));
        vm.Navigate("new-job");
        AssertPageRendered(window, nameof(SetupWizardView));
        vm.Navigate("import");
        AssertPageRendered(window, nameof(ImportView));

        vm.Navigate("dashboard");
        var dash = Assert.IsType<DashboardViewModel>(vm.CurrentPage);
        await UiFixture.WaitUntil(() => dash.HasJobs);
        Assert.Equal("Your files are protected.", dash.Headline);
        Assert.StartsWith("✓", dash.StatusText, StringComparison.Ordinal);

        Assert.True(BindingErrors.Sink.Errors.Count == 0, string.Join("\n", BindingErrors.Sink.Errors.Distinct()));
        window.Close();
    }

    /// <summary>Unlock through the password dialog, browse, search, view versions and restore through the UI.</summary>
    [AvaloniaFact]
    public async Task RestorePage_UnlocksBrowsesAndRestores()
    {
        DialogDriver.Reset();
        using var f = new UiFixture();
        var job = await CreateJobWithBackupAsync(f);
        BindingErrors.Sink.Clear();
        var (window, vm) = Open(f);
        vm.Navigate("restore");
        var restore = Assert.IsType<RestoreViewModel>(vm.CurrentPage);
        Assert.False(restore.IsUnlocked);
        Assert.Empty(restore.Snapshots); // nothing protected is visible before unlocking

        DialogDriver.Enqueue(w =>
        {
            DialogDriver.Type(w, "definitely the wrong password");
            DialogDriver.Click(w, "Unlock");
        });
        DialogDriver.Answer("OK"); // "Unable to unlock" message
        DialogDriver.Unlock(UiFixture.Password);
        var unlock = restore.UnlockCommand.ExecuteAsync(null);
        await UiFixture.WaitUntil(() => unlock.IsCompleted);
        Assert.True(restore.IsUnlocked);
        Assert.Contains("Unable to unlock", DialogDriver.Opened);

        await UiFixture.WaitUntil(() => restore.SelectedSnapshot is not null && restore.Items.Count > 0);
        var root = restore.Items.Single();
        restore.OpenCommand.Execute(root);
        Assert.Contains(restore.Items, i => i.Name == "Budget.xlsx");

        restore.SearchText = "invoice";
        restore.SearchCommand.Execute(null);
        Assert.Single(restore.Items, i => i.Name == "Invoice-1843.pdf");

        restore.ClearSearchCommand.Execute(null);
        restore.OpenCommand.Execute(restore.Items.Single());
        restore.SelectedItem = restore.Items.First(i => i.Name == "Budget.xlsx");
        Assert.True(restore.HasVersions);

        var target = Path.Combine(f.Root, "restored");
        Directory.CreateDirectory(target);
        restore.RestoreToOriginal = false;
        restore.TargetFolder = target;
        restore.SelectedItem.IsChecked = true;
        DialogDriver.Answer("Restore");
        DialogDriver.Answer("OK");
        var run = restore.RestoreSelectedCommand.ExecuteAsync(null);
        await UiFixture.WaitUntil(() => run.IsCompleted);
        Assert.Contains("Restore complete", DialogDriver.Opened);
        Assert.Equal("budget v1", File.ReadAllText(Path.Combine(target, "Documents", "Budget.xlsx")));

        // Locking clears decrypted data from the page.
        f.Ui.Lock("test");
        Dispatcher.UIThread.RunJobs();
        Assert.False(restore.IsUnlocked);
        Assert.Empty(restore.Items);
        Assert.Empty(restore.Snapshots);

        Assert.True(BindingErrors.Sink.Errors.Count == 0, string.Join("\n", BindingErrors.Sink.Errors.Distinct()));
        _ = job;
        window.Close();
    }

    /// <summary>Security page: changing the password through the dialogs re-wraps the key.</summary>
    [AvaloniaFact]
    public async Task SecurityPage_ChangesPassword()
    {
        DialogDriver.Reset();
        using var f = new UiFixture();
        await CreateJobWithBackupAsync(f);
        var (window, vm) = Open(f);
        vm.Navigate("security");
        var security = Assert.IsType<SecurityViewModel>(vm.CurrentPage);
        const string newPassword = "silver mountain river lantern 77";

        DialogDriver.Unlock(UiFixture.Password);
        DialogDriver.Enqueue(w =>
        {
            DialogDriver.Type(w, newPassword, 0);
            DialogDriver.Type(w, newPassword, 1);
            DialogDriver.Click(w, "Change Password");
        });
        DialogDriver.Answer("OK");
        var change = security.ChangePasswordCommand.ExecuteAsync(null);
        await UiFixture.WaitUntil(() => change.IsCompleted);
        Assert.Contains("Password changed", DialogDriver.Opened);

        f.Ui.Lock("test");
        using var s = await Application.UnlockedSession.UnlockAsync(f.App, f.App.KeySets.Default!.Id, newPassword);
        Assert.False(s.IsLocked);
        window.Close();
    }

    private static async Task<JobDefinition> CreateJobWithBackupAsync(UiFixture f)
    {
        var ks = f.App.KeySets.Create(UiFixture.Password);
        f.App.KeySets.ConfirmRecoveryKeySaved(ks.Info.Id);
        var job = f.App.Jobs.Create(new JobDefinition
        {
            Id = Guid.Empty,
            KeySetId = ks.Info.Id,
            Name = "Company Documents",
            Sources = [f.Source],
        }, f.Drive, ks.Secret);
        var run = await f.App.Backups.RunAsync(job.Id, RunTrigger.Manual, ks.Secret);
        Assert.Equal(RunOutcome.Success, run.Outcome);
        f.App.SaveSettings(f.App.Settings with { SetupCompleted = true });
        return job;
    }

    /// <summary>A lock request during a key-using operation waits for it instead of freeing keys underneath it.</summary>
    [AvaloniaFact]
    public async Task Lock_IsDeferredWhileBusy()
    {
        DialogDriver.Reset();
        using var f = new UiFixture();
        await CreateJobWithBackupAsync(f);
        var (window, _) = Open(f);
        DialogDriver.Unlock(UiFixture.Password);
        var unlock = f.Ui.EnsureUnlockedAsync("test");
        await UiFixture.WaitUntil(() => unlock.IsCompleted);
        Assert.True(f.Ui.IsUnlocked);

        var busy = f.Ui.Locks.BeginBusy();
        f.Ui.Lock("system locked");
        Assert.True(f.Ui.IsUnlocked);
        Assert.True(f.Ui.LockPending);
        busy.Dispose();
        await UiFixture.WaitUntil(() => !f.Ui.IsUnlocked);
        window.Close();
    }
}
