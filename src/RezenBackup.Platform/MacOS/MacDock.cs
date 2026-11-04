using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace RezenBackup.Platform.MacOS;

/// <summary>
/// Controls whether this process has a Dock icon (NSApplication activation policy). The app bundle sets
/// <c>LSUIElement</c>, so every process starts without one: the background agent stays that way, and the main
/// window process promotes itself with <see cref="ShowInDock"/>. Must be called on the main thread after the
/// UI framework has created NSApp.
/// </summary>
[SupportedOSPlatform("macos")]
public static partial class MacDock
{
    private const string LibObjC = "/usr/lib/libobjc.A.dylib";
    private const nint PolicyRegular = 0;
    private const nint PolicyAccessory = 1;

    /// <summary>Normal app: Dock icon, app menu, Cmd-Tab. Also brings the app to the front.</summary>
    public static void ShowInDock()
    {
        var app = SharedApplication();
        if (app == IntPtr.Zero)
        {
            return;
        }

        _ = SendNint(app, Sel("setActivationPolicy:"), PolicyRegular);
        SendBool(app, Sel("activateIgnoringOtherApps:"), true);
    }

    /// <summary>Background helper: no Dock icon or app menu; tray (menu-bar) icons still work.</summary>
    public static void HideFromDock()
    {
        var app = SharedApplication();
        if (app != IntPtr.Zero)
        {
            _ = SendNint(app, Sel("setActivationPolicy:"), PolicyAccessory);
        }
    }

    private static IntPtr SharedApplication()
    {
        var cls = GetClass("NSApplication");
        return cls == IntPtr.Zero ? IntPtr.Zero : Send(cls, Sel("sharedApplication"));
    }

    private static IntPtr Sel(string name) => RegisterName(name);

    [LibraryImport(LibObjC, EntryPoint = "objc_getClass", StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr GetClass(string name);

    [LibraryImport(LibObjC, EntryPoint = "sel_registerName", StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr RegisterName(string name);

    [LibraryImport(LibObjC, EntryPoint = "objc_msgSend")]
    private static partial IntPtr Send(IntPtr receiver, IntPtr selector);

    [LibraryImport(LibObjC, EntryPoint = "objc_msgSend")]
    [return: MarshalAs(UnmanagedType.U1)]
    private static partial bool SendNint(IntPtr receiver, IntPtr selector, nint value);

    [LibraryImport(LibObjC, EntryPoint = "objc_msgSend")]
    private static partial void SendBool(IntPtr receiver, IntPtr selector, [MarshalAs(UnmanagedType.U1)] bool value);
}
