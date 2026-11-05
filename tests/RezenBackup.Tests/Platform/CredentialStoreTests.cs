using Microsoft.Extensions.Logging.Abstractions;
using RezenBackup.Core.Platform;
using RezenBackup.Crypto;
using RezenBackup.Platform;

namespace RezenBackup.Tests.Platform;

/// <summary>
/// Exercises the real OS credential store (Keychain on macOS, DPAPI on Windows). Opt-in with REZEN_KEYCHAIN_TEST=1
/// because it writes (and then deletes) one item in the current user's store.
/// </summary>
public class CredentialStoreTests
{
    [Fact]
    public void RealCredentialStore_RoundTripsAndDeletes()
    {
        if (Environment.GetEnvironmentVariable("REZEN_KEYCHAIN_TEST") != "1" || !(OperatingSystem.IsMacOS() || OperatingSystem.IsWindows()))
        {
            return;
        }

        var paths = new AppPaths(Path.Combine(Path.GetTempPath(), "rezen-cred-" + Guid.NewGuid().ToString("N")[..8]));
        var platform = PlatformFactory.Create(paths, NullLoggerFactory.Instance);
        var store = platform.Credentials;
        Assert.True(store.IsSupported);
        var id = CryptoRandom.NewId();
        using var secret = RootSecret.Generate();
        try
        {
            store.Save(id, secret);
            Assert.True(store.Exists(id));
            using var loaded = store.TryLoad(id);
            Assert.NotNull(loaded);
            Assert.True(loaded!.ContentEquals(secret));

            using var other = RootSecret.Generate();
            store.Save(id, other); // overwrite path
            using var reloaded = store.TryLoad(id);
            Assert.True(reloaded!.ContentEquals(other));
        }
        finally
        {
            store.Delete(id);
        }

        Assert.False(store.Exists(id));
        Assert.Null(store.TryLoad(id));
    }

    [Fact]
    public void MacDurableOps_FullFsyncAndNoCache_Work()
    {
        if (!OperatingSystem.IsMacOS())
        {
            return;
        }

        var ops = new RezenBackup.Platform.MacOS.MacDurableFileOps();
        var file = Path.Combine(Path.GetTempPath(), "rezen-fsync-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (var fs = new FileStream(file, FileMode.Create))
            {
                fs.Write([1, 2, 3, 4]);
                ops.FlushToDevice(fs);
            }

            using var vs = ops.OpenForVerification(file);
            var buf = new byte[4];
            vs.ReadExactly(buf);
            Assert.Equal(new byte[] { 1, 2, 3, 4 }, buf);
            ops.FlushDirectory(Path.GetTempPath());
        }
        finally
        {
            File.Delete(file);
        }
    }

    /// <summary>Drive names shown to the user ("Your backup drive "BACKUP" is connected") are volume names, not paths.</summary>
    [Fact]
    public void MacVolumes_AreNamedByVolumeName_NotMountPath()
    {
        if (!OperatingSystem.IsMacOS())
        {
            return;
        }

        foreach (var v in new RezenBackup.Platform.MacOS.MacVolumeInspector().GetVolumes())
        {
            Assert.DoesNotContain('/', v.Label);
            Assert.Equal(Path.GetFileName(v.RootPath.TrimEnd('/')), v.Label);
        }
    }

    [Fact]
    public void MacMetadata_ReportsInodeAndChangeTime()
    {
        if (!OperatingSystem.IsMacOS())
        {
            return;
        }

        var file = Path.Combine(Path.GetTempPath(), "rezen-stat-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(file, "x");
        try
        {
            var info = new RezenBackup.Platform.MacOS.MacFileMetadataProvider().GetInfo(file);
            Assert.NotNull(info.FileId);
            Assert.NotNull(info.ChangeTimeUtc);
            Assert.InRange(info.ChangeTimeUtc!.Value, DateTime.UtcNow.AddMinutes(-5), DateTime.UtcNow.AddMinutes(5));
            Assert.False(info.IsCloudPlaceholder);
        }
        finally
        {
            File.Delete(file);
        }
    }
}
