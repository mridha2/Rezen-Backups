using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace RezenBackup.Platform.MacOS;

[SupportedOSPlatform("macos")]
internal static partial class MacNative
{
    private const string LibSystem = "/usr/lib/libSystem.dylib";
    private const string Security = "/System/Library/Frameworks/Security.framework/Security";
    private const string CoreFoundation = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

    public const int F_NOCACHE = 48;
    public const int F_FULLFSYNC = 51;
    public const uint SF_DATALESS = 0x40000000;
    public const int ErrSecItemNotFound = -25300;
    public const int ErrSecDuplicateItem = -25299;

    // fcntl(fd, cmd) — no variadic argument, safe on every ABI.
    [LibraryImport(LibSystem, EntryPoint = "fcntl", SetLastError = true)]
    public static partial int FcntlNoArg(int fd, int cmd);

    // fcntl(fd, cmd, int) on x86-64: variadic arguments are passed in registers like named ones.
    [LibraryImport(LibSystem, EntryPoint = "fcntl", SetLastError = true)]
    private static partial int FcntlX64(int fd, int cmd, int arg);

    // On Apple arm64, variadic arguments are passed on the stack. Filling x2–x7 with padding places the 9th integer
    // argument in the first stack slot, which is where a variadic callee reads its first variadic argument.
    [LibraryImport(LibSystem, EntryPoint = "fcntl", SetLastError = true)]
    private static partial int FcntlArm64(int fd, int cmd, long p2, long p3, long p4, long p5, long p6, long p7, long arg);

    public static int FcntlWithArg(int fd, int cmd, int arg) =>
        RuntimeInformation.ProcessArchitecture == Architecture.Arm64
            ? FcntlArm64(fd, cmd, 0, 0, 0, 0, 0, 0, arg)
            : FcntlX64(fd, cmd, arg);

    [LibraryImport(LibSystem, EntryPoint = "open", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    public static partial int Open(string path, int flags);

    [LibraryImport(LibSystem, EntryPoint = "close")]
    public static partial int Close(int fd);

    [LibraryImport(LibSystem, EntryPoint = "getuid")]
    public static partial uint GetUid();

    [LibraryImport(LibSystem, EntryPoint = "lstat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static unsafe partial int LstatArm64(string path, byte* buf);

    [LibraryImport(LibSystem, EntryPoint = "lstat$INODE64", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    private static unsafe partial int LstatX64(string path, byte* buf);

    public readonly record struct StatInfo(ulong Inode, long CtimeSec, long CtimeNsec, uint Flags, ushort Mode);

    /// <summary>Darwin 64-bit-inode <c>struct stat</c> (144 bytes) — st_ino @8, st_ctimespec @64, st_flags @116.</summary>
    public static unsafe StatInfo? Lstat(string path)
    {
        byte* buf = stackalloc byte[256];
        int rc = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? LstatArm64(path, buf) : LstatX64(path, buf);
        if (rc != 0)
        {
            return null;
        }

        return new StatInfo(
            *(ulong*)(buf + 8),
            *(long*)(buf + 64),
            *(long*)(buf + 72),
            *(uint*)(buf + 116),
            *(ushort*)(buf + 4));
    }

    [LibraryImport(Security, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SecKeychainAddGenericPassword(
        nint keychain, uint serviceNameLength, string serviceName, uint accountNameLength, string accountName,
        uint passwordLength, nint passwordData, out nint itemRef);

    [LibraryImport(Security, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int SecKeychainFindGenericPassword(
        nint keychainOrArray, uint serviceNameLength, string serviceName, uint accountNameLength, string accountName,
        out uint passwordLength, out nint passwordData, out nint itemRef);

    [LibraryImport(Security)]
    public static partial int SecKeychainItemModifyAttributesAndData(nint itemRef, nint attrList, uint length, nint data);

    [LibraryImport(Security)]
    public static partial int SecKeychainItemFreeContent(nint attrList, nint data);

    [LibraryImport(Security)]
    public static partial int SecKeychainItemDelete(nint itemRef);

    [LibraryImport(CoreFoundation)]
    public static partial void CFRelease(nint cf);
}
