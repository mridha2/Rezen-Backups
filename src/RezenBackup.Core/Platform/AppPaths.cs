namespace RezenBackup.Core.Platform;

/// <summary>Per-user application data locations (never on the backup drive).</summary>
public sealed class AppPaths
{
    public AppPaths(string? root = null)
    {
        Root = root ?? Environment.GetEnvironmentVariable("REZEN_DATA_DIR") ?? DefaultRoot();
    }

    public string Root { get; }

    public string Database => Path.Combine(Root, "rezen.db");

    public string LogsDirectory => Path.Combine(Root, "Logs");

    public string KeysDirectory => Path.Combine(Root, "Keys");

    public string CacheDirectory => Path.Combine(Root, "Cache");

    public string CredentialsDirectory => Path.Combine(Root, "Credentials");

    public string IndexCachePath(Guid repositoryId) => Path.Combine(CacheDirectory, repositoryId.ToString("N"), "index.rzc");

    public string LocalKeyFile(Guid keySetId) => Path.Combine(KeysDirectory, keySetId.ToString("N") + ".rzk");

    public string AgentPipeName => "RezenBackup.Agent." + Environment.UserName;

    public static string DefaultRoot()
    {
        if (OperatingSystem.IsWindows())
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Rezen Backup");
        }

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (OperatingSystem.IsMacOS())
        {
            return Path.Combine(home, "Library", "Application Support", "Rezen Backup");
        }

        var xdg = Environment.GetEnvironmentVariable("XDG_DATA_HOME");
        return Path.Combine(string.IsNullOrEmpty(xdg) ? Path.Combine(home, ".local", "share") : xdg, "Rezen Backup");
    }

    /// <summary>Creates the directories and restricts them to the current user where the OS allows.</summary>
    public void EnsureCreated()
    {
        foreach (var dir in new[] { Root, LogsDirectory, KeysDirectory, CacheDirectory, CredentialsDirectory })
        {
            Directory.CreateDirectory(dir);
            if (!OperatingSystem.IsWindows())
            {
                try
                {
                    File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                }
            }
        }
    }
}
