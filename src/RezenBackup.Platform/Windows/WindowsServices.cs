using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using RezenBackup.Core.Platform;
using RezenBackup.Crypto;

namespace RezenBackup.Platform.Windows;

/// <summary>Root Secret protected with DPAPI (CurrentUser scope, never LocalMachine) — DESIGN §9.1.</summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiCredentialStore(string directory) : ICredentialStore
{
    private static readonly byte[] EntropyPrefix = "RezenBackup/v1/dpapi"u8.ToArray();

    public bool IsSupported => true;

    public string MechanismName => "Windows Data Protection (DPAPI)";

    private string PathFor(Guid id) => Path.Combine(directory, id.ToString("N") + ".dpapi");

    private static byte[] Entropy(Guid id) => [.. EntropyPrefix, .. id.ToByteArray()];

    public void Save(Guid keySetId, RootSecret secret) => SaveBytes(keySetId, secret.Bytes);

    public void SaveBytes(Guid id, ReadOnlySpan<byte> secret)
    {
        Directory.CreateDirectory(directory);
        var plain = secret.ToArray();
        try
        {
            var protectedBytes = ProtectedData.Protect(plain, Entropy(id), DataProtectionScope.CurrentUser);
            var tmp = PathFor(id) + ".tmp";
            File.WriteAllBytes(tmp, protectedBytes);
            File.Move(tmp, PathFor(id), overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public RootSecret? TryLoad(Guid keySetId)
    {
        using var bytes = TryLoadBytes(keySetId);
        return bytes is { Length: RootSecret.Length } ? RootSecret.FromBytes(bytes.ReadOnlySpan) : null;
    }

    public SecretBuffer? TryLoadBytes(Guid id)
    {
        var path = PathFor(id);
        if (!File.Exists(path))
        {
            return null;
        }

        byte[]? plain = null;
        try
        {
            plain = ProtectedData.Unprotect(File.ReadAllBytes(path), Entropy(id), DataProtectionScope.CurrentUser);
            return plain.Length == 0 ? null : SecretBuffer.CopyFrom(plain);
        }
        catch (CryptographicException)
        {
            return null; // e.g. password reset by an administrator invalidates DPAPI keys
        }
        catch (IOException)
        {
            return null;
        }
        finally
        {
            if (plain is not null)
            {
                CryptographicOperations.ZeroMemory(plain);
            }
        }
    }

    public bool Exists(Guid keySetId) => File.Exists(PathFor(keySetId));

    public void Delete(Guid keySetId)
    {
        var path = PathFor(keySetId);
        if (!File.Exists(path))
        {
            return;
        }

        var len = new FileInfo(path).Length;
        File.WriteAllBytes(path, new byte[len]); // best effort overwrite; SSDs may keep old copies (still DPAPI-protected)
        File.Delete(path);
    }
}

/// <summary>Windows durability: MoveFileEx with write-through and uncached (FILE_FLAG_NO_BUFFERING) read-back.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsDurableFileOps(ILogger logger) : PortableDurableFileOps
{
    private const FileOptions NoBuffering = (FileOptions)0x20000000;
    private const int Alignment = 4096;
    private const int BlockSize = 1 << 20;

    public override Stream OpenForVerification(string path)
    {
        try
        {
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read, NoBuffering);
            long length = RandomAccess.GetLength(handle);
            var result = new MemoryStream(checked((int)length));
            unsafe
            {
                void* buffer = NativeMemory.AlignedAlloc(BlockSize, Alignment);
                try
                {
                    var span = new Span<byte>(buffer, BlockSize);
                    long offset = 0;
                    while (offset < length)
                    {
                        int read = RandomAccess.Read(handle, span, offset);
                        if (read <= 0)
                        {
                            break;
                        }

                        int keep = (int)Math.Min(read, length - offset);
                        result.Write(span[..keep]);
                        offset += read;
                    }
                }
                finally
                {
                    NativeMemory.AlignedFree(buffer);
                }
            }

            result.Position = 0;
            return result;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            logger.LogWarning("Uncached read-back unavailable on this volume; using a cached read: {Message}", ex.Message);
            return base.OpenForVerification(path);
        }
    }

    public override void AtomicMove(string source, string destination, bool overwrite)
    {
        uint flags = WinNative.MOVEFILE_WRITE_THROUGH | (overwrite ? WinNative.MOVEFILE_REPLACE_EXISTING : 0);
        if (!WinNative.MoveFileEx(source, destination, flags))
        {
            int err = Marshal.GetLastPInvokeError();
            throw new IOException($"MoveFileEx failed ({err}).", unchecked((int)0x80070000) | err);
        }
    }
}

/// <summary>Adds NTFS change time and file ID (volume serial + file index) without opening file contents.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsFileMetadataProvider : PortableFileMetadataProvider
{
    public override SourceFileInfo GetInfo(string path, FileSystemInfo? entry = null)
    {
        var info = base.GetInfo(path, entry);
        using var handle = WinNative.CreateFile(path, WinNative.FILE_READ_ATTRIBUTES, WinNative.FILE_SHARE_ALL, 0, WinNative.OPEN_EXISTING,
            WinNative.FILE_FLAG_BACKUP_SEMANTICS | WinNative.FILE_FLAG_OPEN_REPARSE_POINT, 0);
        if (handle.IsInvalid)
        {
            return info;
        }

        DateTime? change = null;
        string? fileId = null;
        if (WinNative.GetFileInformationByHandleEx(handle, 0, out var basic, (uint)Marshal.SizeOf<WinNative.FileBasicInfo>()) && basic.ChangeTime > 0)
        {
            change = DateTime.FromFileTimeUtc(basic.ChangeTime);
        }

        if (WinNative.GetFileInformationByHandle(handle, out var byHandle))
        {
            // File index only: a VSS shadow copy has a different volume serial number but keeps file indexes,
            // so the ID stays stable whether a file is read live or from a shadow copy.
            fileId = string.Create(CultureInfo.InvariantCulture, $"{byHandle.FileIndexHigh:x8}{byHandle.FileIndexLow:x8}");
        }

        return info with { ChangeTimeUtc = change, FileId = fileId };
    }
}

[SupportedOSPlatform("windows")]
public sealed class WindowsPowerManager : IPowerManager
{
    public IDisposable KeepAwake(string reason)
    {
        // Execution state is per thread, so a dedicated thread holds it for the duration of the run.
        var release = new ManualResetEventSlim();
        var thread = new Thread(() =>
        {
            WinNative.SetThreadExecutionState(WinNative.ES_CONTINUOUS | WinNative.ES_SYSTEM_REQUIRED);
            release.Wait();
            WinNative.SetThreadExecutionState(WinNative.ES_CONTINUOUS);
        })
        { IsBackground = true, Name = "Rezen keep-awake" };
        thread.Start();
        return new Scope(release);
    }

    public bool IsOnBattery => WinNative.GetSystemPowerStatus(out var s) && s.ACLineStatus == 0;

    private sealed class Scope(ManualResetEventSlim release) : IDisposable
    {
        public void Dispose() => release.Set();
    }
}

/// <summary>Balloon notification via Shell_NotifyIcon, which Windows 10/11 shows as a native toast.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsNotifier(ILogger logger) : INotifier
{
    public void Notify(string title, string message, NotificationKind kind)
    {
        var thread = new Thread(() =>
        {
            nint hwnd = WinNative.CreateWindowEx(0, "STATIC", "RezenBackupNotify", 0, 0, 0, 0, 0, new nint(-3), 0, 0, 0);
            if (hwnd == 0)
            {
                logger.LogWarning("Notification window could not be created.");
                return;
            }

            var data = new WinNative.NotifyIconData
            {
                cbSize = (uint)Marshal.SizeOf<WinNative.NotifyIconData>(),
                hWnd = hwnd,
                uID = 1,
                uFlags = WinNative.NIF_ICON | WinNative.NIF_TIP | WinNative.NIF_INFO,
                hIcon = WinNative.LoadIcon(0, new nint(32516)),
                szTip = "Rezen Backup",
                szInfoTitle = Trim(title, 63),
                szInfo = Trim(message, 255),
                dwInfoFlags = kind switch
                {
                    NotificationKind.Error or NotificationKind.Integrity => WinNative.NIIF_ERROR,
                    NotificationKind.Warning or NotificationKind.LowSpace or NotificationKind.WaitingForDrive => WinNative.NIIF_WARNING,
                    _ => WinNative.NIIF_INFO,
                },
            };
            WinNative.Shell_NotifyIcon(WinNative.NIM_ADD, ref data);
            Thread.Sleep(10_000);
            WinNative.Shell_NotifyIcon(WinNative.NIM_DELETE, ref data);
            WinNative.DestroyWindow(hwnd);
        })
        { IsBackground = true, Name = "Rezen notification" };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
    }

    private static string Trim(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";
}

/// <summary>Starts the agent at sign-in via the per-user Run key (no administrator rights needed).</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsAutostart : IAutostart
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "Rezen Backup Agent";

    public bool IsEnabled
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey);
            return key?.GetValue(ValueName) is string;
        }
    }

    public void Enable(string agentExecutablePath)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKey);
        key.SetValue(ValueName, $"\"{agentExecutablePath}\" --agent");
    }

    public void Disable()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey, writable: true);
        key?.DeleteValue(ValueName, throwOnMissingValue: false);
    }
}

[SupportedOSPlatform("windows")]
public sealed class WindowsVolumeInspector : IVolumeInspector
{
    public IReadOnlyList<VolumeInfo> GetVolumes()
    {
        var result = new List<VolumeInfo>();
        foreach (var d in DriveInfo.GetDrives())
        {
            try
            {
                if (!d.IsReady || d.DriveType is not (DriveType.Removable or DriveType.Fixed))
                {
                    continue;
                }

                var root = d.RootDirectory.FullName;
                var guidBuf = new char[64];
                string? volumeId = WinNative.GetVolumeNameForVolumeMountPoint(root, guidBuf, (uint)guidBuf.Length) ? new string(guidBuf).TrimEnd('\0') : null;
                result.Add(new VolumeInfo(root, d.VolumeLabel, d.DriveFormat, d.TotalSize, d.AvailableFreeSpace, d.DriveType == DriveType.Removable || !IsSystemDrive(root), volumeId));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }

        return result;
    }

    private static bool IsSystemDrive(string root) =>
        string.Equals(Path.GetPathRoot(Environment.SystemDirectory), root, StringComparison.OrdinalIgnoreCase);

    public VolumeInfo? GetVolumeForPath(string path)
    {
        var root = Path.GetPathRoot(Path.GetFullPath(path));
        return GetVolumes().FirstOrDefault(v => string.Equals(v.RootPath, root, StringComparison.OrdinalIgnoreCase));
    }

    public bool TryEject(string rootPath)
    {
        try
        {
            // Shell "Eject" verb — the same action as "Eject" in File Explorer.
            var shellType = Type.GetTypeFromProgID("Shell.Application");
            if (shellType is null)
            {
                return false;
            }

            var shell = Activator.CreateInstance(shellType)!;
            var myComputer = shellType.InvokeMember("NameSpace", System.Reflection.BindingFlags.InvokeMethod, null, shell, [17])!;
            var item = myComputer.GetType().InvokeMember("ParseName", System.Reflection.BindingFlags.InvokeMethod, null, myComputer, [rootPath]);
            if (item is null)
            {
                return false;
            }

            item.GetType().InvokeMember("InvokeVerb", System.Reflection.BindingFlags.InvokeMethod, null, item, ["Eject"]);
            return true;
        }
        catch (Exception ex) when (ex is COMException or System.Reflection.TargetInvocationException or MissingMethodException)
        {
            return false;
        }
    }
}

[SupportedOSPlatform("windows")]
public sealed class WindowsSessionStateMonitor : ISessionStateMonitor
{
    private const int WTSSessionInfoEx = 25;
    private const int WTS_SESSIONSTATE_LOCK = 0;

    public bool IsSystemLocked()
    {
        if (!WinNative.WTSQuerySessionInformation(0, -1, WTSSessionInfoEx, out nint buffer, out uint bytes) || buffer == 0)
        {
            return false;
        }

        try
        {
            if (bytes < 20 || Marshal.ReadInt32(buffer) != 1)
            {
                return false;
            }

            // WTSINFOEXW { DWORD Level; union (8-byte aligned) { WTSINFOEX_LEVEL1_W { ULONG SessionId; INT SessionState; LONG SessionFlags; ... } } }
            int flags = Marshal.ReadInt32(buffer, 16);
            return flags == WTS_SESSIONSTATE_LOCK;
        }
        finally
        {
            WinNative.WTSFreeMemory(buffer);
        }
    }
}
