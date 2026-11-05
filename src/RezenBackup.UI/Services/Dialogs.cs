using Avalonia;
using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using RezenBackup.RestoreEngine;

namespace RezenBackup.UI.Services;

/// <summary>Modal dialogs built in code (small, consistent, no raw exceptions by default — spec §85).</summary>
public static class Dialogs
{
    private static Window NewDialog(string title, double width = 460) => new()
    {
        Title = title,
        Width = width,
        SizeToContent = SizeToContent.Height,
        CanResize = false,
        WindowStartupLocation = WindowStartupLocation.CenterOwner,
        ShowInTaskbar = false,
    };

    private static TextBlock Text(string text, string? cls = null, double size = 14)
    {
        var tb = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, FontSize = size };
        if (cls is not null)
        {
            tb.Classes.Add(cls);
        }

        return tb;
    }

    private static Button Btn(string text, bool primary = false, bool danger = false)
    {
        var b = new Button { Content = text, MinWidth = 96, HorizontalContentAlignment = HorizontalAlignment.Center };
        if (primary)
        {
            b.Classes.Add("primary");
        }

        if (danger)
        {
            b.Classes.Add("danger");
        }

        return b;
    }

    private static StackPanel Buttons(params Button[] buttons)
    {
        var p = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 8,
            Margin = new Thickness(0, 16, 0, 0),
        };
        foreach (var b in buttons)
        {
            p.Children.Add(b);
        }

        return p;
    }

    public static async Task MessageAsync(Window owner, string title, string message, string? technical, bool isError = false)
    {
        var dlg = NewDialog(title);
        var panel = new StackPanel { Margin = new Thickness(24), Spacing = 10 };
        panel.Children.Add(Text(title, "h3", 17));
        panel.Children.Add(Text(message, isError ? "bad" : null));
        if (!string.IsNullOrWhiteSpace(technical))
        {
            var details = new SelectableTextBlock { Text = technical, TextWrapping = TextWrapping.Wrap, FontSize = 12 };
            details.Classes.Add("mono");
            panel.Children.Add(new Expander { Header = "View Technical Details", Content = details, HorizontalAlignment = HorizontalAlignment.Stretch });
        }

        var ok = Btn("OK", primary: true);
        ok.Click += (_, _) => dlg.Close();
        panel.Children.Add(Buttons(ok));
        dlg.Content = panel;
        await dlg.ShowDialog(owner);
    }

    public static async Task<bool> ConfirmAsync(Window owner, string title, string message, string confirm = "Continue", bool danger = false, string cancelText = "Cancel")
    {
        var dlg = NewDialog(title);
        bool result = false;
        var panel = new StackPanel { Margin = new Thickness(24), Spacing = 10 };
        panel.Children.Add(Text(title, "h3", 17));
        panel.Children.Add(Text(message));
        var cancel = Btn(cancelText);
        var go = Btn(confirm, primary: !danger, danger: danger);
        cancel.Click += (_, _) => dlg.Close();
        go.Click += (_, _) =>
        {
            result = true;
            dlg.Close();
        };
        panel.Children.Add(Buttons(cancel, go));
        dlg.Content = panel;
        await dlg.ShowDialog(owner);
        return result;
    }

    /// <summary>Asks for the password, or optionally the recovery key. The text box never shows the password by default.</summary>
    public static async Task<(string Text, bool IsRecoveryKey)?> PasswordAsync(Window owner, string title, string prompt, bool allowRecoveryKey)
    {
        var dlg = NewDialog(title);
        (string, bool)? result = null;
        bool recovery = false;
        var panel = new StackPanel { Margin = new Thickness(24), Spacing = 10 };
        panel.Children.Add(Text(title, "h3", 17));
        panel.Children.Add(Text(prompt, "muted"));
        var label = Text("Backup password", "label");
        var box = new TextBox { PasswordChar = '•', Watermark = "Password", RevealPassword = false };
        var show = new CheckBox { Content = "Show password" };
        show.IsCheckedChanged += (_, _) => box.RevealPassword = show.IsChecked == true;
        panel.Children.Add(label);
        panel.Children.Add(box);
        panel.Children.Add(show);
        if (allowRecoveryKey)
        {
            var toggle = new Button { Content = "Use recovery key instead", Classes = { "link" } };
            toggle.Click += (_, _) =>
            {
                recovery = !recovery;
                label.Text = recovery ? "Recovery key (RZN1-…)" : "Backup password";
                box.Watermark = recovery ? "RZN1-XXXX-XXXX-…" : "Password";
                box.PasswordChar = recovery ? '\0' : '•';
                toggle.Content = recovery ? "Use password instead" : "Use recovery key instead";
                box.Text = string.Empty;
            };
            panel.Children.Add(toggle);
        }

        var cancel = Btn("Cancel");
        var ok = Btn("Unlock", primary: true);
        ok.IsDefault = true;
        cancel.IsCancel = true;
        cancel.Click += (_, _) => dlg.Close();
        ok.Click += (_, _) =>
        {
            if (!string.IsNullOrEmpty(box.Text))
            {
                result = (box.Text, recovery);
                box.Text = string.Empty;
                dlg.Close();
            }
        };
        panel.Children.Add(Buttons(cancel, ok));
        dlg.Content = panel;
        dlg.Opened += (_, _) => box.Focus();
        await dlg.ShowDialog(owner);
        return result;
    }

    /// <summary>Asks how to handle an existing file during restore (spec §41). Safe to call from a worker thread.</summary>
    public static ConflictResolution ConflictFromWorker(Window owner, RestoreConflict conflict) =>
        Dispatcher.UIThread.InvokeAsync(() => ConflictAsync(owner, conflict)).GetAwaiter().GetResult();

    public static async Task<ConflictResolution> ConflictAsync(Window owner, RestoreConflict conflict)
    {
        var dlg = NewDialog("File already exists", 520);
        var choice = ConflictChoice.Skip;
        var panel = new StackPanel { Margin = new Thickness(24), Spacing = 10 };
        panel.Children.Add(Text("A file with this name already exists", "h3", 17));
        panel.Children.Add(Text(conflict.TargetPath, "muted", 12));
        panel.Children.Add(Text($"On this computer: {Application.Fmt.Bytes(conflict.ExistingSize)}, modified {conflict.ExistingModifiedUtc.ToLocalTime():g}"));
        panel.Children.Add(Text($"In the backup: {Application.Fmt.Bytes(conflict.BackupSize)}, modified {conflict.BackupModifiedUtc.ToLocalTime():g}"));
        var all = new CheckBox { Content = "Apply to all remaining conflicts" };
        panel.Children.Add(all);
        var skip = Btn("Skip");
        var both = Btn("Keep both");
        var replace = Btn("Replace", danger: true);
        skip.Click += (_, _) => { choice = ConflictChoice.Skip; dlg.Close(); };
        both.Click += (_, _) => { choice = ConflictChoice.KeepBoth; dlg.Close(); };
        replace.Click += (_, _) => { choice = ConflictChoice.Replace; dlg.Close(); };
        panel.Children.Add(Buttons(skip, both, replace));
        dlg.Content = panel;
        await dlg.ShowDialog(owner);
        return new ConflictResolution(choice, all.IsChecked == true);
    }

    public static async Task<IReadOnlyList<string>> PickFoldersAsync(Window owner, string title, bool multiple)
    {
        var result = await owner.StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = title, AllowMultiple = multiple });
        return result.Select(f => f.TryGetLocalPath()).OfType<string>().ToList();
    }

    public static async Task<IReadOnlyList<string>> PickFilesAsync(Window owner, string title)
    {
        var result = await owner.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = title, AllowMultiple = true });
        return result.Select(f => f.TryGetLocalPath()).OfType<string>().ToList();
    }

    public static async Task<string?> SaveFileAsync(Window owner, string title, string suggestedName, string extension, bool startInDocuments = false)
    {
        var start = startInDocuments ? await owner.StorageProvider.TryGetWellKnownFolderAsync(WellKnownFolder.Documents) : null;
        var file = await owner.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = title,
            SuggestedFileName = suggestedName,
            DefaultExtension = extension,
            ShowOverwritePrompt = true,
            SuggestedStartLocation = start,
        });
        return file?.TryGetLocalPath();
    }

    /// <summary>New password + confirmation with a live strength meter. Returns null if cancelled.</summary>
    public static async Task<string?> NewPasswordAsync(Window owner, string title, string explanation)
    {
        var dlg = NewDialog(title, 500);
        string? result = null;
        var panel = new StackPanel { Margin = new Thickness(24), Spacing = 8 };
        panel.Children.Add(Text(title, "h3", 17));
        panel.Children.Add(Text(explanation, "muted"));
        var pw = new TextBox { PasswordChar = '\u2022', Watermark = "New password (at least 12 characters)" };
        var confirm = new TextBox { PasswordChar = '\u2022', Watermark = "Confirm new password" };
        var show = new CheckBox { Content = "Show password" };
        show.IsCheckedChanged += (_, _) => { pw.RevealPassword = show.IsChecked == true; confirm.RevealPassword = show.IsChecked == true; };
        var meter = new ProgressBar { Maximum = 100 };
        var strength = Text(string.Empty, null, 13);
        var feedback = Text(string.Empty, "muted", 12);
        var error = Text(string.Empty, "bad", 13);
        pw.TextChanged += (_, _) =>
        {
            var a = Security.PasswordPolicy.Assess(pw.Text ?? string.Empty);
            meter.Value = ((int)a.Strength + 1) * 20;
            strength.Text = string.IsNullOrEmpty(pw.Text) ? string.Empty : $"{a.StrengthText} · estimated time to crack offline: {a.CrackTimeDisplay}";
            feedback.Text = string.Join(" ", a.Feedback);
        };
        var generate = new Button { Content = "Generate a strong password…", Classes = { "link" } };
        generate.Click += async (_, _) =>
        {
            var generated = await GeneratedPasswordAsync(dlg);
            if (generated is not null)
            {
                pw.Text = generated;
                confirm.Text = generated;
                error.Text = string.Empty;
            }
        };
        panel.Children.Add(generate);
        panel.Children.Add(pw);
        panel.Children.Add(confirm);
        panel.Children.Add(show);
        panel.Children.Add(meter);
        panel.Children.Add(strength);
        panel.Children.Add(feedback);
        panel.Children.Add(error);
        var cancel = Btn("Cancel");
        var ok = Btn("Change Password", primary: true);
        cancel.Click += (_, _) => dlg.Close();
        ok.Click += (_, _) =>
        {
            var a = Security.PasswordPolicy.Assess(pw.Text ?? string.Empty);
            if (!a.MeetsRequirements)
            {
                error.Text = "Choose a stronger password.";
                return;
            }

            if (pw.Text != confirm.Text)
            {
                error.Text = "The passwords do not match.";
                return;
            }

            result = pw.Text;
            pw.Text = string.Empty;
            confirm.Text = string.Empty;
            dlg.Close();
        };
        panel.Children.Add(Buttons(cancel, ok));
        dlg.Content = panel;
        await dlg.ShowDialog(owner);
        return result;
    }

    /// <summary>How long a copied password stays on the clipboard before Rezen Backup clears it.</summary>
    public static readonly TimeSpan ClipboardClearDelay = TimeSpan.FromSeconds(90);

    /// <summary>
    /// Generates a strong random password and shows it with a Copy button and instructions for saving it. The caller
    /// only gets the password once the user confirms they have saved it; returns null if cancelled.
    /// </summary>
    public static async Task<string?> GeneratedPasswordAsync(Window owner)
    {
        var dlg = NewDialog("Generated password", 560);
        string password = Security.PasswordGenerator.Generate();
        string? result = null;
        bool copied = false;

        var panel = new StackPanel { Margin = new Thickness(24), Spacing = 10 };
        panel.Children.Add(Text("Your new backup password", "h3", 17));
        panel.Children.Add(Text($"A random password created on this computer (about {Security.PasswordGenerator.EntropyBits:0} bits of entropy). It has no look-alike characters, so it can be read from paper and typed on another computer.", "muted"));

        var shown = new SelectableTextBlock
        {
            Text = password,
            FontSize = 20,
            TextWrapping = TextWrapping.Wrap,
            HorizontalAlignment = HorizontalAlignment.Center,
            FontFamily = new FontFamily("Menlo, Consolas, Courier New, monospace"),
        };
        panel.Children.Add(new Border { Child = shown, Padding = new Thickness(12), CornerRadius = new CornerRadius(8), BorderThickness = new Thickness(1), BorderBrush = Brushes.Gray });

        var status = Text(string.Empty, "muted", 12);
        var copy = Btn("Copy Password", primary: true);
        var another = Btn("Generate Another");
        panel.Children.Add(new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Children = { copy, another } });
        panel.Children.Add(status);

        var steps = new StackPanel { Spacing = 6 };
        steps.Children.Add(Text("Save this password before you continue", "h3", 15));
        string manager = OperatingSystem.IsMacOS()
            ? "the Passwords app (or Keychain Access) on this Mac, or a password manager such as Bitwarden, 1Password or KeePassXC"
            : "a password manager such as Bitwarden, 1Password or KeePass";
        steps.Children.Add(Text($"1. Click Copy Password, then paste it into {manager} as a new entry named \"Rezen Backup\". Save the entry before closing it."));
        steps.Children.Add(Text("2. Also write it down on paper and keep it with your recovery key, somewhere safe and away from this computer."));
        steps.Children.Add(Text("3. Do not save it on the backup drive, in an unencrypted note or text file, or in an email or chat message to yourself."));
        steps.Children.Add(Text($"You will need this password to restore files, to change backup settings, and to open your backups on another computer. Rezen Backup never stores it, and it clears the clipboard {ClipboardClearDelay.TotalSeconds:0} seconds after you copy it.", "muted", 12));
        panel.Children.Add(new Border { Child = steps, Padding = new Thickness(12), CornerRadius = new CornerRadius(8), Classes = { "card" } });

        var saved = new CheckBox { Content = "I have saved this password somewhere safe" };
        panel.Children.Add(saved);

        var cancel = Btn("Cancel");
        var use = Btn("Use This Password", primary: true);
        use.IsEnabled = false;
        cancel.IsCancel = true;
        saved.IsCheckedChanged += (_, _) => use.IsEnabled = saved.IsChecked == true;

        copy.Click += async (_, _) =>
        {
            if (await CopySecretAsync(owner, password))
            {
                copied = true;
                status.Text = $"Copied. The clipboard will be cleared in {ClipboardClearDelay.TotalSeconds:0} seconds.";
            }
            else
            {
                status.Text = "Could not copy. Select the password above and copy it, or write it down.";
            }
        };
        another.Click += async (_, _) =>
        {
            if (copied)
            {
                await ClearClipboardIfAsync(owner, password);
                copied = false;
            }

            password = Security.PasswordGenerator.Generate();
            shown.Text = password;
            saved.IsChecked = false;
            status.Text = "New password generated. Save this one instead; the previous password will not be used.";
        };
        cancel.Click += (_, _) => dlg.Close();
        use.Click += (_, _) =>
        {
            result = password;
            dlg.Close();
        };

        panel.Children.Add(Buttons(cancel, use));
        dlg.Content = panel;
        await dlg.ShowDialog(owner);

        // Leave the copied password on the clipboard until the timer clears it (the user may still be saving it),
        // but remove it straight away if they backed out.
        if (result is null && copied)
        {
            await ClearClipboardIfAsync(owner, password);
        }

        return result;
    }

    /// <summary>Copies a secret and schedules it to be cleared, unless the user has copied something else since.</summary>
    private static async Task<bool> CopySecretAsync(Window owner, string secret)
    {
        var clipboard = owner.Clipboard;
        if (clipboard is null)
        {
            return false;
        }

        try
        {
            await clipboard.SetTextAsync(secret);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.ExternalException)
        {
            return false;
        }

        DispatcherTimer.RunOnce(() => _ = ClearClipboardIfAsync(owner, secret), ClipboardClearDelay);
        return true;
    }

    private static async Task ClearClipboardIfAsync(Window owner, string secret)
    {
        var clipboard = owner.Clipboard;
        if (clipboard is null)
        {
            return;
        }

        try
        {
            if (await clipboard.TryGetTextAsync() == secret)
            {
                await clipboard.ClearAsync();
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.ExternalException)
        {
            // Clipboard busy or unavailable: nothing more we can safely do.
        }
    }

    /// <summary>Shows the recovery key with Print / Save options.</summary>
    public static async Task RecoveryKeyAsync(Window owner, Application.RezenApp app, string recoveryKey, Guid keySetId)
    {
        var dlg = NewDialog("Recovery key", 560);
        var panel = new StackPanel { Margin = new Thickness(24), Spacing = 10 };
        panel.Children.Add(Text("Your offline recovery key", "h3", 17));
        panel.Children.Add(Text("Print it or save it as a file on this computer or a USB stick. Never store it on the backup drive. Anyone with this key can unlock your backups.", "muted"));
        var key = new SelectableTextBlock { Text = recoveryKey, FontSize = 18, TextWrapping = TextWrapping.Wrap, FontFamily = new FontFamily("Menlo, Consolas, Courier New, monospace") };
        panel.Children.Add(new Border { Child = key, Padding = new Thickness(12), CornerRadius = new CornerRadius(8), BorderThickness = new Thickness(1), BorderBrush = Brushes.Gray });
        panel.Children.Add(Text($"Key set fingerprint: {RecoveryKit.Fingerprint(keySetId)}", "label", 12));
        var status = Text(string.Empty, "muted", 12);
        var print = Btn("Print");
        var save = Btn("Save Recovery Key File\u2026");
        var close = Btn("Close", primary: true);
        print.Click += (_, _) => status.Text = RecoveryKit.Print(RecoveryKit.Document(recoveryKey, keySetId)) ? "Sent to your default printer." : "Printing failed.";
        save.Click += async (_, _) =>
        {
            var path = await SaveFileAsync(dlg, "Save recovery key file", RecoveryKit.FileName, "txt", startInDocuments: true);
            if (path is null)
            {
                return;
            }

            var (allowed, message) = RecoveryKit.CheckLocation(app, path, null);
            if (!allowed)
            {
                status.Text = message;
                return;
            }

            // Ask before writing to a cloud-synced folder (it would upload the key), as the setup wizard does.
            if (message is not null && !await ConfirmAsync(dlg, "Cloud folder", message, "Save anyway"))
            {
                return;
            }

            await File.WriteAllTextAsync(path, RecoveryKit.Document(recoveryKey, keySetId));
            status.Text = RecoveryKit.SavedMessage(path);
        };
        close.Click += (_, _) => dlg.Close();
        panel.Children.Add(status);
        panel.Children.Add(Buttons(print, save, close));
        dlg.Content = panel;
        await dlg.ShowDialog(owner);
    }
}
