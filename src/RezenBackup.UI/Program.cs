using Avalonia;

namespace RezenBackup.UI;

internal static class Program
{
    public static bool AgentMode { get; private set; }

    [STAThread]
    public static int Main(string[] args)
    {
        AgentMode = args.Contains("--agent");
        return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args, Avalonia.Controls.ShutdownMode.OnExplicitShutdown);
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .With(new MacOSPlatformOptions { ShowInDock = !AgentMode })
            .WithInterFont()
            .LogToTrace();
}
