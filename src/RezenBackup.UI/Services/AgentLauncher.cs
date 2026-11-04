using System.Diagnostics;
using Microsoft.Extensions.Logging;
using RezenBackup.Application;

namespace RezenBackup.UI.Services;

/// <summary>Starts the background agent (same executable with <c>--agent</c>) and registers it to start at sign-in.</summary>
public static class AgentLauncher
{
    /// <summary>The command used to start the app: the native executable, or <c>dotnet RezenBackup.dll</c> in development.</summary>
    public static (string File, string[] Args) SelfCommand(params string[] extra)
    {
        var process = Environment.ProcessPath ?? "RezenBackup";
        var name = Path.GetFileNameWithoutExtension(process);
        if (string.Equals(name, "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            // Development host only (`dotnet RezenBackup.dll`). Assembly.Location is empty in a single-file build.
            return (process, [Path.Combine(AppContext.BaseDirectory, typeof(AgentLauncher).Assembly.GetName().Name + ".dll"), .. extra]);
        }

        return (process, extra);
    }

    public static async Task EnsureRunningAsync(RezenApp app)
    {
        if (!app.Settings.RunBackgroundAgent)
        {
            return;
        }

        var client = new AgentClient(app.Paths);
        if (await client.IsRunningAsync())
        {
            return;
        }

        try
        {
            var (file, args) = SelfCommand("--agent");
            var psi = new ProcessStartInfo(file) { UseShellExecute = false, CreateNoWindow = true };
            foreach (var a in args)
            {
                psi.ArgumentList.Add(a);
            }

            Process.Start(psi);
            for (int i = 0; i < 20 && !await client.IsRunningAsync(); i++)
            {
                await Task.Delay(250);
            }

            // Start with the system only from an installed native executable (never a development `dotnet` host).
            if (app.Settings.StartWithSystem && args.Length == 1 && Environment.GetEnvironmentVariable("REZEN_NO_AUTOSTART") != "1")
            {
                app.Platform.Autostart.Enable(file);
            }
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException or InvalidOperationException)
        {
            app.Logger.LogWarning("Background agent could not be started: {Message}", ex.Message);
        }
    }

    public static void OpenMainWindow()
    {
        var (file, args) = SelfCommand();
        var psi = new ProcessStartInfo(file) { UseShellExecute = false };
        foreach (var a in args)
        {
            psi.ArgumentList.Add(a);
        }

        Process.Start(psi);
    }
}
