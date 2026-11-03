using System.Diagnostics;
using System.Globalization;
using System.Text;
using RezenBackup.Application;
using RezenBackup.Core.Policies;
using RezenBackup.Format;

namespace RezenBackup.UI.Services;

/// <summary>Printing and saving the offline recovery key (spec §12). The key is never written to a temporary file.</summary>
public static class RecoveryKit
{
    public static string Document(string recoveryKey, Guid keySetId) =>
        new StringBuilder()
            .AppendLine("REZEN BACKUP — OFFLINE RECOVERY KEY")
            .AppendLine()
            .AppendLine("Keep this page somewhere safe and offline, away from your backup drive.")
            .AppendLine("It can unlock your encrypted backups if you forget your password.")
            .AppendLine()
            .AppendLine("    " + recoveryKey)
            .AppendLine()
            .AppendLine("Key set fingerprint: " + Fingerprint(keySetId))
            .AppendLine("Created: " + DateTime.Now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture))
            .AppendLine()
            .AppendLine("If you lose both your password and your recovery key, your encrypted backups cannot be recovered.")
            .ToString();

    public static string Fingerprint(Guid keySetId) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(keySetId.ToByteArray()).AsSpan(0, 4));

    /// <summary>Sends the text to the default printer through the local spooler via standard input.</summary>
    public static bool Print(string text)
    {
        try
        {
            ProcessStartInfo psi;
            if (OperatingSystem.IsWindows())
            {
                psi = new ProcessStartInfo("powershell.exe") { RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true };
                psi.ArgumentList.Add("-NoProfile");
                psi.ArgumentList.Add("-NonInteractive");
                psi.ArgumentList.Add("-Command");
                psi.ArgumentList.Add("$input | Out-Printer");
            }
            else
            {
                psi = new ProcessStartInfo("/usr/bin/lp") { RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true };
                psi.ArgumentList.Add("-t");
                psi.ArgumentList.Add("Rezen Backup Recovery Key");
            }

            using var p = Process.Start(psi);
            if (p is null)
            {
                return false;
            }

            p.StandardInput.Write(text);
            p.StandardInput.Close();
            return p.WaitForExit(20_000) && p.ExitCode == 0;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>
    /// Checks a save location. Blocks the backup drive itself (the key must never sit next to the backups) and warns
    /// about cloud-synced folders (spec §3, §12).
    /// </summary>
    public static (bool Allowed, string? Message) CheckLocation(RezenApp app, string path, string? pendingDestination)
    {
        var full = Path.GetFullPath(path);
        var roots = app.ConnectedDrives().Values.Select(d => d.MountPath).ToList();
        if (pendingDestination is not null)
        {
            roots.Add(pendingDestination);
        }

        foreach (var root in roots)
        {
            var volume = app.Platform.Volumes.GetVolumeForPath(root)?.RootPath ?? root;
            if (PathPolicy.IsSameOrUnder(full, volume) || PathPolicy.IsSameOrUnder(full, RepositoryLayout.BackupRootOnVolume(root)))
            {
                return (false, "The recovery key must not be stored on the same drive as your backups. Choose a different removable device or print it.");
            }
        }

        string[] cloud = ["OneDrive", "Dropbox", "Google Drive", "iCloud", "Mobile Documents", "CloudStorage", "Box"];
        if (cloud.Any(c => full.Contains(c, StringComparison.OrdinalIgnoreCase)))
        {
            return (true, "This looks like a cloud-synced folder. Storing the recovery key there uploads it to the internet. A USB stick or a printout is safer.");
        }

        return (true, null);
    }
}
