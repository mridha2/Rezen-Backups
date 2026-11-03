using RezenBackup.BackupEngine;
using RezenBackup.Core.Domain;
using RezenBackup.Core.Platform;
using RezenBackup.Crypto;
using RezenBackup.Format;
using RezenBackup.RestoreEngine;

namespace RezenBackup.Tests.Engine;

/// <summary>Temporary source tree + repository for end-to-end engine tests.</summary>
internal sealed class TestRepo : IDisposable
{
    public const string Password = "correct horse battery staple 2026";

    public TestRepo()
    {
        Root = Path.Combine(Path.GetTempPath(), "rezen-test-" + Guid.NewGuid().ToString("N")[..12]);
        Source = Path.Combine(Root, "src", "Company Documents");
        Drive = Path.Combine(Root, "drive");
        RestoreTarget = Path.Combine(Root, "restore");
        Directory.CreateDirectory(Source);
        Directory.CreateDirectory(Drive);
        RepoPath = Path.Combine(Drive, RepositoryLayout.BackupRootFolderName, "TEST-PC", "Company Documents");
        KeySetId = CryptoRandom.NewId();
        Secret = RootSecret.Generate();
        using var pw = PasswordEncoding.ToKeyMaterial(Password);
        KeySetFile = KeyFile.CreateWithPassword(KeySetId, Guid.Empty, 1, Secret, pw, TestSetup.FastKdf);
        Repo = Repository.Create(RepoPath, KeySetId, Secret, KeySetFile, new RepositoryConfig
        {
            JobName = "Company Documents",
            HostName = "TEST-PC",
            CreatedUtc = DateTimeOffset.UtcNow,
            AppVersion = "test",
            ChunkMin = 64 * 1024,
            ChunkAvg = 256 * 1024,
            ChunkMax = 1024 * 1024,
            PackTargetSize = 2 * 1024 * 1024,
        }, PortableDurableFileOps.Instance);
    }

    public string Root { get; }

    public string Source { get; }

    public string Drive { get; }

    public string RepoPath { get; }

    public string RestoreTarget { get; }

    public Guid KeySetId { get; }

    public RootSecret Secret { get; }

    public KeyFile KeySetFile { get; }

    public Repository Repo { get; private set; }

    public string IndexCache => Path.Combine(Root, "cache", "index.rzc");

    public string WriteFile(string relative, byte[] content)
    {
        var path = Path.Combine(Source, relative.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, content);
        return path;
    }

    public string WriteFile(string relative, string content) => WriteFile(relative, System.Text.Encoding.UTF8.GetBytes(content));

    public BackupOptions Options(BackupMethod method = BackupMethod.Incremental, VerificationLevel level = VerificationLevel.Standard) => new()
    {
        Sources = [Source],
        Method = method,
        Verification = level,
        HostName = "TEST-PC",
        AppVersion = "test",
        IndexCachePath = IndexCache,
        ReserveBytes = 0,
        FreeSpaceProbe = () => long.MaxValue,
    };

    public Task<BackupResult> BackupAsync(BackupOptions? options = null) =>
        new BackupRunner(Repo).RunAsync(options ?? Options());

    /// <summary>Re-opens the repository from disk (simulates a fresh process / another PC).</summary>
    public void Reopen(RootSecret? secret = null)
    {
        Repo.Dispose();
        Repo = Repository.Open(RepoPath, secret ?? Secret, PortableDurableFileOps.Instance);
        Repo.LoadIndex(null);
    }

    public CatalogSession Catalog()
    {
        if (Repo.Index.Count == 0)
        {
            Repo.LoadIndex(IndexCache);
        }

        return new CatalogSession(Repo);
    }

    public async Task<RestoreReport> RestoreAllAsync(Guid snapshotId, string? target = null, ConflictChoice onConflict = ConflictChoice.Replace)
    {
        using var catalog = Catalog();
        var roots = catalog.Roots(snapshotId);
        var exec = new RestoreExecutor(catalog);
        return await exec.RestoreAsync(roots, new RestoreOptions
        {
            TargetRoot = target ?? RestoreTarget,
            ResolveConflict = _ => new ConflictResolution(onConflict, true),
        });
    }

    public static void AssertTreesEqual(string expected, string actual)
    {
        var e = Directory.EnumerateFiles(expected, "*", SearchOption.AllDirectories).Select(p => Path.GetRelativePath(expected, p)).OrderBy(p => p, StringComparer.Ordinal).ToList();
        var a = Directory.EnumerateFiles(actual, "*", SearchOption.AllDirectories).Select(p => Path.GetRelativePath(actual, p)).OrderBy(p => p, StringComparer.Ordinal).ToList();
        Assert.Equal(e, a);
        foreach (var rel in e)
        {
            Assert.Equal(File.ReadAllBytes(Path.Combine(expected, rel)), File.ReadAllBytes(Path.Combine(actual, rel)));
        }
    }

    public void Dispose()
    {
        Repo.Dispose();
        Secret.Dispose();
        try
        {
            Directory.Delete(Root, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
