using RezenBackup.Core.Domain;
using RezenBackup.Crypto;
using RezenBackup.Format;

namespace RezenBackup.Tests.Engine;

/// <summary>
/// The parallel backup pipeline: compression on the thread pool, packs written by a background thread, pack buffers
/// reused between packs. Results must be identical to a sequential run, and failures must still leave the snapshot
/// incomplete and the repository reusable.
/// </summary>
public class PipelineTests
{
    private static void WriteMixedTree(TestRepo t, int files)
    {
        var words = "invoice budget client project report quarterly meeting notes "u8.ToArray();
        for (int i = 0; i < files; i++)
        {
            int size = 50_000 + CryptoRandom.NextInt(600_000);
            var data = new byte[size];
            if (i % 2 == 0)
            {
                CryptoRandom.Fill(data);
            }
            else
            {
                for (int j = 0; j < size; j++)
                {
                    data[j] = words[(j + (j / 97)) % words.Length];
                }
            }

            t.WriteFile($"folder{i % 7}/file{i:000}.bin", data);
        }
    }

    [Fact]
    public async Task ManyPacks_BackupRestoresByteIdentical_AndVerifiesFully()
    {
        using var t = new TestRepo();
        WriteMixedTree(t, 60); // ~18 MB with 2 MB packs: many data packs and reused pack buffers
        var result = await t.BackupAsync(t.Options(level: VerificationLevel.Full));
        Assert.Equal(RunOutcome.Success, result.Outcome);
        Assert.True(result.PacksWritten >= 6, $"expected several packs, got {result.PacksWritten}");

        t.Reopen();
        var report = await t.RestoreAllAsync(result.SnapshotId);
        Assert.Equal(60, report.FilesRestored);
        TestRepo.AssertTreesEqual(t.Source, Path.Combine(t.RestoreTarget, Path.GetFileName(t.Source)));
    }

    [Fact]
    public async Task DuplicateChunksAcrossFiles_AreStoredOnce()
    {
        using var t = new TestRepo();
        var shared = CryptoRandom.Bytes(1_500_000);
        for (int i = 0; i < 8; i++)
        {
            t.WriteFile($"copy{i}.bin", shared);
        }

        var result = await t.BackupAsync();
        Assert.Equal(RunOutcome.Success, result.Outcome);
        Assert.True(result.Stats.BytesNew < 2 * shared.Length, $"stored {result.Stats.BytesNew} bytes for 8 identical files");
    }

    [Theory]
    [InlineData("before-pack-write", 1)]
    [InlineData("after-pack-write", 1)]
    [InlineData("before-pack-write", 4)]
    [InlineData("after-pack-write", 4)]
    public async Task FailureInBackgroundWriter_LeavesIncompleteSnapshot_ThenNextRunSucceeds(string point, int onPack)
    {
        using var t = new TestRepo();
        WriteMixedTree(t, 40);
        int seen = 0;
        var opts = t.Options() with
        {
            FaultInjection = p =>
            {
                if (p == point && Interlocked.Increment(ref seen) == onPack)
                {
                    throw new IOException("simulated unplug");
                }
            },
        };
        await Assert.ThrowsAnyAsync<Exception>(() => t.BackupAsync(opts));
        Assert.False(File.Exists(t.Repo.Layout.LockPath), "the background writer must have stopped before the lock is released");

        t.Reopen();
        Assert.All(t.Repo.LoadAllSnapshots(), s => Assert.Equal(SnapshotValidity.Incomplete, s.Validity));
        var ok = await t.BackupAsync(t.Options() with { SnapshotLocalTime = DateTime.Now.AddSeconds(5) });
        Assert.Equal(RunOutcome.Success, ok.Outcome);
        var report = await t.RestoreAllAsync(ok.SnapshotId);
        Assert.Equal(40, report.FilesRestored);
    }

    [Fact]
    public async Task CancelDuringBackup_StopsWriterAndReleasesLock()
    {
        using var t = new TestRepo();
        WriteMixedTree(t, 40);
        using var cts = new CancellationTokenSource();
        var progress = new Progress<RezenBackup.BackupEngine.BackupProgress>(p =>
        {
            if (p.BytesDone > 4_000_000)
            {
                cts.Cancel();
            }
        });
        var ex = await Assert.ThrowsAnyAsync<Exception>(() => new RezenBackup.BackupEngine.BackupRunner(t.Repo).RunAsync(t.Options(), progress, null, cts.Token));
        Assert.True(ex is RezenBackup.Core.RezenException or OperationCanceledException, ex.GetType().Name);
        Assert.False(File.Exists(t.Repo.Layout.LockPath));
    }

    /// <summary>Packs are streamed into the encryptor now; sizes around the 1 MiB segment boundary must round-trip.</summary>
    [Theory]
    [InlineData(1)]
    [InlineData(1024 * 1024 - 200)]
    [InlineData(1024 * 1024)]
    [InlineData((2 * 1024 * 1024) + 5)]
    [InlineData(3_300_000)]
    public void PackWrite_RoundTripsBlobsOfAnySize(int blobSize)
    {
        using var t = new TestRepo();
        var builder = new PackBuilder(PackKind.Data, capacity: 64);
        var blobs = new List<(ChunkId Id, byte[] Data)>();
        for (int i = 0; i < 3; i++)
        {
            var data = CryptoRandom.Bytes(Math.Max(1, blobSize - (i * 7)));
            var id = t.Repo.Keys.ComputeChunkId(data);
            builder.Add(id, BlobKind.Data, data, data.Length, BlobCodec.None);
            blobs.Add((id, data));
        }

        var info = PackFormat.Write(t.Repo.Layout, t.Repo.Keys, builder, t.Repo.Ops);
        using var reader = PackReader.Open(t.Repo.Layout.PackPath(PackKind.Data, info.PackId), t.Repo.Keys, PackKind.Data);
        reader.VerifyAllSegments();
        Assert.Equal(3, reader.Entries.Count);
        foreach (var (id, data) in blobs)
        {
            Assert.Equal(data, reader.ReadStored(reader.Entries.Single(e => e.Id == id)));
        }

        // A reset builder gets a new pack id and starts empty.
        var oldId = builder.PackId;
        builder.Reset();
        Assert.NotEqual(oldId, builder.PackId);
        Assert.Equal(0, builder.Count);
        Assert.Equal(0, builder.Size);
    }
}
