using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using RezenBackup.Core.Platform;
using RezenBackup.Crypto;

namespace RezenBackup.Platform.MacOS;

/// <summary>Root Secret stored in the user's login Keychain (DESIGN §29). Other macOS users cannot read it.</summary>
[SupportedOSPlatform("macos")]
public sealed class KeychainCredentialStore : ICredentialStore
{
    private const string Service = "com.rezen.backup";

    public bool IsSupported => true;

    public string MechanismName => "macOS Keychain";

    private static string Account(Guid keySetId) => "keyset-" + keySetId.ToString("N");

    public void Save(Guid keySetId, RootSecret secret) => SaveBytes(keySetId, secret.Bytes);

    public void SaveBytes(Guid id, ReadOnlySpan<byte> secret)
    {
        var account = Account(id);
        int length = secret.Length;
        var data = Marshal.AllocHGlobal(length);
        try
        {
            unsafe
            {
                secret.CopyTo(new Span<byte>((void*)data, length));
            }

            int rc = MacNative.SecKeychainFindGenericPassword(0, (uint)Service.Length, Service, (uint)account.Length, account, out _, out nint existing, out nint item);
            if (rc == 0)
            {
                MacNative.SecKeychainItemFreeContent(0, existing);
                rc = MacNative.SecKeychainItemModifyAttributesAndData(item, 0, (uint)length, data);
                MacNative.CFRelease(item);
            }
            else
            {
                rc = MacNative.SecKeychainAddGenericPassword(0, (uint)Service.Length, Service, (uint)account.Length, account, (uint)length, data, out nint newItem);
                if (newItem != 0)
                {
                    MacNative.CFRelease(newItem);
                }
            }

            if (rc != 0)
            {
                throw new SecurityException($"Keychain refused to store the credential (OSStatus {rc}).");
            }
        }
        finally
        {
            unsafe
            {
                new Span<byte>((void*)data, length).Clear();
            }

            Marshal.FreeHGlobal(data);
        }
    }

    public RootSecret? TryLoad(Guid keySetId)
    {
        using var bytes = TryLoadBytes(keySetId);
        return bytes is { Length: RootSecret.Length } ? RootSecret.FromBytes(bytes.ReadOnlySpan) : null;
    }

    public SecretBuffer? TryLoadBytes(Guid id)
    {
        var account = Account(id);
        int rc = MacNative.SecKeychainFindGenericPassword(0, (uint)Service.Length, Service, (uint)account.Length, account, out uint len, out nint data, out nint item);
        if (rc != 0)
        {
            return null;
        }

        try
        {
            if (len == 0 || len > 64 * 1024)
            {
                return null;
            }

            unsafe
            {
                return SecretBuffer.CopyFrom(new ReadOnlySpan<byte>((void*)data, (int)len));
            }
        }
        finally
        {
            unsafe
            {
                new Span<byte>((void*)data, (int)len).Clear();
            }

            MacNative.SecKeychainItemFreeContent(0, data);
            if (item != 0)
            {
                MacNative.CFRelease(item);
            }
        }
    }

    public bool Exists(Guid keySetId)
    {
        var account = Account(keySetId);
        int rc = MacNative.SecKeychainFindGenericPassword(0, (uint)Service.Length, Service, (uint)account.Length, account, out _, out nint data, out nint item);
        if (rc == 0)
        {
            MacNative.SecKeychainItemFreeContent(0, data);
            MacNative.CFRelease(item);
            return true;
        }

        return false;
    }

    public void Delete(Guid keySetId)
    {
        var account = Account(keySetId);
        int rc = MacNative.SecKeychainFindGenericPassword(0, (uint)Service.Length, Service, (uint)account.Length, account, out _, out nint data, out nint item);
        if (rc == 0)
        {
            MacNative.SecKeychainItemFreeContent(0, data);
            MacNative.SecKeychainItemDelete(item);
            MacNative.CFRelease(item);
        }
    }
}

/// <summary>macOS durability: F_FULLFSYNC (plain fsync does not flush the drive cache) and F_NOCACHE read-back.</summary>
[SupportedOSPlatform("macos")]
public sealed class MacDurableFileOps : PortableDurableFileOps
{
    public override void FlushToDevice(FileStream stream)
    {
        stream.Flush(flushToDisk: true);
        int fd = (int)stream.SafeFileHandle.DangerousGetHandle();
        if (MacNative.FcntlNoArg(fd, MacNative.F_FULLFSYNC) != 0)
        {
            // Some filesystems (e.g. network or FAT) do not support F_FULLFSYNC; fsync above already ran.
        }
    }

    public override Stream OpenForVerification(string path)
    {
        var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, FileOptions.SequentialScan);
        MacNative.FcntlWithArg((int)fs.SafeFileHandle.DangerousGetHandle(), MacNative.F_NOCACHE, 1);
        return fs;
    }

    public override void FlushDirectory(string directory)
    {
        int fd = MacNative.Open(directory, 0);
        if (fd < 0)
        {
            return;
        }

        try
        {
            MacNative.FcntlNoArg(fd, MacNative.F_FULLFSYNC);
        }
        finally
        {
            MacNative.Close(fd);
        }
    }
}

/// <summary>Adds inode, ctime and the iCloud "dataless" flag to the portable metadata.</summary>
[SupportedOSPlatform("macos")]
public sealed class MacFileMetadataProvider : PortableFileMetadataProvider
{
    public override SourceFileInfo GetInfo(string path, FileSystemInfo? entry = null)
    {
        var info = base.GetInfo(path, entry);
        var st = MacNative.Lstat(path);
        if (st is not { } s)
        {
            return info;
        }

        var ctime = DateTime.UnixEpoch.AddTicks((s.CtimeSec * TimeSpan.TicksPerSecond) + (s.CtimeNsec / 100));
        bool dataless = (s.Flags & MacNative.SF_DATALESS) != 0;
        return info with
        {
            ChangeTimeUtc = ctime,
            FileId = s.Inode.ToString(System.Globalization.CultureInfo.InvariantCulture),
            IsCloudPlaceholder = info.IsCloudPlaceholder || dataless,
        };
    }
}

[SupportedOSPlatform("macos")]
public sealed class MacPowerManager : IPowerManager
{
    public IDisposable KeepAwake(string reason)
    {
        try
        {
            var psi = new ProcessStartInfo("/usr/bin/caffeinate") { UseShellExecute = false, CreateNoWindow = true };
            psi.ArgumentList.Add("-i");
            psi.ArgumentList.Add("-w");
            psi.ArgumentList.Add(Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
            var p = Process.Start(psi);
            return new Scope(p);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return new Scope(null);
        }
    }

    public bool IsOnBattery
    {
        get
        {
            var output = ProcessRunner.Run("/usr/bin/pmset", ["-g", "batt"]);
            return output?.Contains("'Battery Power'", StringComparison.Ordinal) == true;
        }
    }

    private sealed class Scope(Process? process) : IDisposable
    {
        public void Dispose()
        {
            try
            {
                if (process is { HasExited: false })
                {
                    process.Kill();
                }
            }
            catch (InvalidOperationException)
            {
            }

            process?.Dispose();
        }
    }
}

[SupportedOSPlatform("macos")]
public sealed class MacNotifier(ILogger logger) : INotifier
{
    public void Notify(string title, string message, NotificationKind kind)
    {
        static string Esc(string s) => s.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);
        var script = $"display notification \"{Esc(message)}\" with title \"Rezen Backup\" subtitle \"{Esc(title)}\"";
        if (ProcessRunner.Run("/usr/bin/osascript", ["-e", script]) is null)
        {
            logger.LogWarning("Notification could not be shown.");
        }
    }
}

/// <summary>Per-user LaunchAgent so scheduled backups run while the app window is closed.</summary>
[SupportedOSPlatform("macos")]
public sealed class MacAutostart : IAutostart
{
    public const string Label = "com.rezen.backup.agent";

    private static string PlistPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Library", "LaunchAgents", Label + ".plist");

    public bool IsEnabled => File.Exists(PlistPath);

    public void Enable(string agentExecutablePath)
    {
        var plist = new XDocument(
            new XDocumentType("plist", "-//Apple//DTD PLIST 1.0//EN", "http://www.apple.com/DTDs/PropertyList-1.0.dtd", null),
            new XElement("plist", new XAttribute("version", "1.0"),
                new XElement("dict",
                    new XElement("key", "Label"), new XElement("string", Label),
                    new XElement("key", "ProgramArguments"),
                    new XElement("array", new XElement("string", agentExecutablePath), new XElement("string", "--agent")),
                    new XElement("key", "RunAtLoad"), new XElement("true"),
                    new XElement("key", "KeepAlive"), new XElement("dict", new XElement("key", "SuccessfulExit"), new XElement("false")),
                    new XElement("key", "ProcessType"), new XElement("string", "Background"),
                    new XElement("key", "LimitLoadToSessionType"), new XElement("string", "Aqua"))));
        Directory.CreateDirectory(Path.GetDirectoryName(PlistPath)!);
        plist.Save(PlistPath);
        var domain = "gui/" + MacNative.GetUid().ToString(System.Globalization.CultureInfo.InvariantCulture);
        ProcessRunner.Run("/bin/launchctl", ["bootout", domain, PlistPath]);
        ProcessRunner.Run("/bin/launchctl", ["bootstrap", domain, PlistPath]);
    }

    public void Disable()
    {
        if (!File.Exists(PlistPath))
        {
            return;
        }

        var domain = "gui/" + MacNative.GetUid().ToString(System.Globalization.CultureInfo.InvariantCulture);
        ProcessRunner.Run("/bin/launchctl", ["bootout", domain, PlistPath]);
        File.Delete(PlistPath);
    }
}

[SupportedOSPlatform("macos")]
public sealed class MacVolumeInspector : IVolumeInspector
{
    public IReadOnlyList<VolumeInfo> GetVolumes()
    {
        var result = new List<VolumeInfo>();
        foreach (var d in DriveInfo.GetDrives())
        {
            try
            {
                var root = d.RootDirectory.FullName;
                if (!d.IsReady || !root.StartsWith("/Volumes/", StringComparison.Ordinal))
                {
                    continue;
                }

                var info = DiskInfo(root);
                result.Add(new VolumeInfo(
                    root,
                    // .NET reports the mount path as the "label" on macOS; the volume name is the last path part.
                    d.VolumeLabel.Length > 0 && !d.VolumeLabel.Contains('/', StringComparison.Ordinal) ? d.VolumeLabel : Path.GetFileName(root.TrimEnd('/')),
                    info.FileSystem ?? d.DriveFormat,
                    d.TotalSize,
                    d.AvailableFreeSpace,
                    info.Removable,
                    info.Uuid));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }

        return result;
    }

    public VolumeInfo? GetVolumeForPath(string path)
    {
        var full = Path.GetFullPath(path);
        return GetVolumes().Where(v => full.StartsWith(v.RootPath, StringComparison.Ordinal)).MaxBy(v => v.RootPath.Length);
    }

    public bool TryEject(string rootPath) => ProcessRunner.Run("/usr/sbin/diskutil", ["eject", rootPath]) is not null;

    private static (string? FileSystem, bool Removable, string? Uuid) DiskInfo(string root)
    {
        var xml = ProcessRunner.Run("/usr/sbin/diskutil", ["info", "-plist", root]);
        if (xml is null)
        {
            return (null, true, null);
        }

        try
        {
            var dict = XDocument.Parse(xml).Root?.Element("dict");
            if (dict is null)
            {
                return (null, true, null);
            }

            var elements = dict.Elements().ToList();
            string? Get(string key)
            {
                int i = elements.FindIndex(e => e.Name == "key" && e.Value == key);
                return i >= 0 && i + 1 < elements.Count ? (elements[i + 1].Name == "true" ? "true" : elements[i + 1].Name == "false" ? "false" : elements[i + 1].Value) : null;
            }

            bool internalDisk = Get("Internal") == "true";
            bool removable = Get("RemovableMedia") == "true" || Get("Ejectable") == "true" || !internalDisk;
            return (Get("FilesystemName") ?? Get("FilesystemType"), removable, Get("VolumeUUID"));
        }
        catch (System.Xml.XmlException)
        {
            return (null, true, null);
        }
    }
}

[SupportedOSPlatform("macos")]
public sealed class MacSessionStateMonitor : ISessionStateMonitor
{
    public bool IsSystemLocked()
    {
        var output = ProcessRunner.Run("/usr/sbin/ioreg", ["-n", "Root", "-d1", "-a"]);
        if (output is null)
        {
            return false;
        }

        int i = output.IndexOf("<key>CGSSessionScreenIsLocked</key>", StringComparison.Ordinal);
        return i >= 0 && output.AsSpan(i, Math.Min(80, output.Length - i)).Contains("<true/>", StringComparison.Ordinal);
    }
}
