namespace RezenBackup.Format;

public enum PackKind : byte
{
    Data = 1,
    Meta = 2,
}

/// <summary>Paths inside a repository folder (DESIGN §10.1).</summary>
public sealed class RepositoryLayout
{
    public const string BackupRootFolderName = "Rezen Backup";
    public const string FormatName = "Rezen Backup Format v1";
    public const int FormatVersion = 1;

    public RepositoryLayout(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        Root = Path.GetFullPath(root);
    }

    public string Root { get; }

    public string ConfigPath => Path.Combine(Root, "repository.rzc");

    public string LockPath => Path.Combine(Root, "repository.lock");

    public string KeysDirectory => Path.Combine(Root, "keys");

    public string KeyFileA => Path.Combine(KeysDirectory, "key-a.rzk");

    public string KeyFileB => Path.Combine(KeysDirectory, "key-b.rzk");

    public IReadOnlyList<string> KeyFiles => [KeyFileA, KeyFileB];

    public string StoreDirectory => Path.Combine(Root, "store");

    public string DataDirectory => Path.Combine(StoreDirectory, "data");

    public string MetaDirectory => Path.Combine(StoreDirectory, "meta");

    public string MetaCopyDirectory => Path.Combine(StoreDirectory, "meta-copy");

    public string TempDirectory => Path.Combine(StoreDirectory, "tmp");

    public string QuarantineDirectory => Path.Combine(StoreDirectory, "quarantine");

    public string PackPath(PackKind kind, Guid packId, bool copy = false)
    {
        string hex = PackFileName(packId);
        string dir = kind == PackKind.Data ? DataDirectory : (copy ? MetaCopyDirectory : MetaDirectory);
        return Path.Combine(dir, hex[..2], hex + ".rzp");
    }

    public static string PackFileName(Guid packId) => Convert.ToHexStringLower(packId.ToByteArray());

    public static bool TryParsePackFileName(string fileName, out Guid packId)
    {
        packId = Guid.Empty;
        if (!fileName.EndsWith(".rzp", StringComparison.Ordinal) || fileName.Length != 32 + 4)
        {
            return false;
        }

        try
        {
            packId = new Guid(Convert.FromHexString(fileName[..32]));
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public string SnapshotDirectory(string folderName) => Path.Combine(Root, folderName);

    public static string SnapshotMetaPath(string snapshotDir) => Path.Combine(snapshotDir, "snapshot.meta");

    public static string SnapshotRecordPath(string snapshotDir) => Path.Combine(snapshotDir, "snapshot.rzb");

    public static string CommitRecordPath(string snapshotDir) => Path.Combine(snapshotDir, "integrity.dat");

    public static string JournalPath(string snapshotDir) => Path.Combine(snapshotDir, "journal.rzj");

    /// <summary>Path of the repository for a job: <c>&lt;drive&gt;/Rezen Backup/&lt;computer&gt;/&lt;job&gt;</c>.</summary>
    public static string RepositoryPath(string driveBackupRoot, string computerFolder, string jobFolder) =>
        Path.Combine(driveBackupRoot, computerFolder, jobFolder);

    public static string BackupRootOnVolume(string volumeRoot) => Path.Combine(volumeRoot, BackupRootFolderName);

    public void EnsureDirectories()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(KeysDirectory);
        Directory.CreateDirectory(DataDirectory);
        Directory.CreateDirectory(MetaDirectory);
        Directory.CreateDirectory(MetaCopyDirectory);
        Directory.CreateDirectory(TempDirectory);
    }

    public IEnumerable<(Guid PackId, PackKind Kind, string Path)> EnumeratePacks()
    {
        foreach (var (dir, kind) in new[] { (DataDirectory, PackKind.Data), (MetaDirectory, PackKind.Meta) })
        {
            if (!Directory.Exists(dir))
            {
                continue;
            }

            foreach (var file in Directory.EnumerateFiles(dir, "*.rzp", SearchOption.AllDirectories))
            {
                if (TryParsePackFileName(Path.GetFileName(file), out var id))
                {
                    yield return (id, kind, file);
                }
            }
        }
    }
}
