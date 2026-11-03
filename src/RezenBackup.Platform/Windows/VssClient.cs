using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using RezenBackup.Core.Platform;

namespace RezenBackup.Platform.Windows;

/// <summary>Wire protocol between the per-user agent and the privileged VSS helper (DESIGN §1.3).</summary>
public static class VssProtocol
{
    public const string PipeName = "RezenBackupService.Vss";

    public sealed record Request(string Op, string? Volume = null, string? ShadowId = null);

    public sealed record Response(bool Ok, string? ShadowId = null, string? Device = null, string? Error = null);

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
}

/// <summary>
/// Creates point-in-time VSS views of the source volumes through the helper service. Files are then read with the
/// user's own token through the shadow device path, so NTFS permissions still apply. Falls back to live reads.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class VssSourceSnapshotProvider(ILogger logger) : ISourceSnapshotProvider
{
    public async Task<ISourceView> CreateViewAsync(IReadOnlyList<string> sourceRoots, CancellationToken cancellationToken)
    {
        var volumes = sourceRoots.Select(s => Path.GetPathRoot(Path.GetFullPath(s)))
            .Where(r => r is { Length: 3 } && r[1] == ':')
            .Select(r => r!.ToUpperInvariant())
            .Distinct()
            .ToList();
        if (volumes.Count == 0)
        {
            return new LiveSourceView();
        }

        var pipe = new NamedPipeClientStream(".", VssProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync(2000, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            logger.LogInformation("VSS helper service not available; reading files directly.");
            return new LiveSourceView();
        }

        var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
        var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
        var mapping = new Dictionary<string, (string Device, string ShadowId)>(StringComparer.OrdinalIgnoreCase);
        foreach (var volume in volumes)
        {
            await writer.WriteLineAsync(JsonSerializer.Serialize(new VssProtocol.Request("create", volume), VssProtocol.Json)).ConfigureAwait(false);
            var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            var response = line is null ? null : JsonSerializer.Deserialize<VssProtocol.Response>(line, VssProtocol.Json);
            if (response is { Ok: true, Device: { } device, ShadowId: { } id })
            {
                mapping[volume] = (device, id);
            }
            else
            {
                logger.LogWarning("VSS snapshot of {Volume} failed: {Error}", volume, response?.Error ?? "no response");
            }
        }

        if (mapping.Count == 0)
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            return new LiveSourceView();
        }

        return new VssView(pipe, reader, writer, mapping, logger);
    }

    private sealed class VssView(NamedPipeClientStream pipe, StreamReader reader, StreamWriter writer, Dictionary<string, (string Device, string ShadowId)> mapping, ILogger logger) : ISourceView
    {
        public bool IsPointInTimeFor(string originalPath) =>
            Path.GetPathRoot(originalPath) is { } root && mapping.ContainsKey(root);

        public string MapForReading(string originalPath)
        {
            var root = Path.GetPathRoot(originalPath);
            if (root is not null && mapping.TryGetValue(root, out var shadow))
            {
                return shadow.Device.TrimEnd('\\') + "\\" + originalPath[root.Length..];
            }

            return originalPath;
        }

        public void Dispose()
        {
            try
            {
                foreach (var (_, (_, id)) in mapping)
                {
                    writer.WriteLine(JsonSerializer.Serialize(new VssProtocol.Request("release", ShadowId: id), VssProtocol.Json));
                    reader.ReadLine();
                }
            }
            catch (IOException ex)
            {
                logger.LogWarning("Releasing VSS snapshots: {Message} (the service removes them when the connection closes).", ex.Message);
            }
            finally
            {
                reader.Dispose();
                writer.Dispose();
                pipe.Dispose();
            }
        }
    }
}
