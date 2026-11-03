using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RezenBackup.Application;
using RezenBackup.UI.Services;

namespace RezenBackup.UI.ViewModels;

/// <summary>Local technical logs (spec §75). File names are hidden by default.</summary>
public sealed partial class LogsViewModel : PageViewModel
{
    public LogsViewModel(UiContext ui)
        : base(ui)
    {
    }

    public ObservableCollection<string> Files { get; } = [];

    [ObservableProperty]
    private string? _selectedFile;

    [ObservableProperty]
    private string _content = string.Empty;

    public override void OnActivated() => Refresh();

    [RelayCommand]
    private void Refresh()
    {
        Files.Clear();
        foreach (var f in Directory.EnumerateFiles(Ui.App.Paths.LogsDirectory, "*.log").OrderByDescending(f => File.GetLastWriteTimeUtc(f)))
        {
            Files.Add(Path.GetFileName(f));
        }

        SelectedFile = Files.FirstOrDefault();
    }

    partial void OnSelectedFileChanged(string? value)
    {
        if (value is null)
        {
            Content = string.Empty;
            return;
        }

        try
        {
            using var fs = new FileStream(Path.Combine(Ui.App.Paths.LogsDirectory, value), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(fs);
            var text = reader.ReadToEnd();
            Content = text.Length > 400_000 ? "…" + text[^400_000..] : text;
        }
        catch (IOException ex)
        {
            Content = ex.Message;
        }
    }

    [RelayCommand]
    private void OpenFolder() => OsShell.Open(Ui.App.Paths.LogsDirectory);
}

public sealed partial class AboutViewModel : PageViewModel
{
    public AboutViewModel(UiContext ui)
        : base(ui)
    {
    }

    public string Version => "Version " + RezenApp.AppVersion;

    public string Platform => $"{Ui.App.Platform.PlatformName} · {System.Runtime.InteropServices.RuntimeInformation.OSDescription} · .NET {Environment.Version}";

    public string Format => "Backup format: Rezen Backup Format v1";

    public string Credentials => "Remembered key protection: " + Ui.App.Platform.Credentials.MechanismName;
}
