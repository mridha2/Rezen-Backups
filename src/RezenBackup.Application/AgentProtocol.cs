using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using RezenBackup.Crypto;

namespace RezenBackup.Application;

/// <summary>
/// Local IPC between the desktop app / CLI and the background agent (DESIGN §1.1). The pipe is restricted to the
/// current user (PipeOptions.CurrentUserOnly; a Unix domain socket with peer-credential checks on macOS) and never
/// accepts network clients. A Root Secret, when sent, follows the request line as 32 raw bytes and is never
/// serialised into JSON or a managed string.
/// </summary>
public static class AgentProtocol
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public sealed record Request(string Cmd, Guid? JobId = null, bool WithSecret = false, string? ResumeFolder = null);

    public sealed record RunInfo(
        Guid JobId,
        Guid RunId,
        string JobName,
        string Phase,
        string PhaseText,
        long FilesDone,
        long FilesTotal,
        long BytesDone,
        long BytesTotal,
        string? CurrentFile,
        double BytesPerSecond,
        double? EtaSeconds,
        bool Paused,
        bool Waiting,
        string? DriveLabel = null);

    public sealed record Response(bool Ok, string? Error = null, string? AgentVersion = null, IReadOnlyList<RunInfo>? Runs = null);

    public static string PipeName(Core.Platform.AppPaths paths) =>
        "rezen-agent-" + Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(paths.Root)).AsSpan(0, 6));
}

/// <summary>Client used by the desktop app and CLI. Returns null when the agent is not reachable.</summary>
public sealed class AgentClient(Core.Platform.AppPaths paths)
{
    private readonly string _pipe = AgentProtocol.PipeName(paths);

    public async Task<AgentProtocol.Response?> SendAsync(AgentProtocol.Request request, RootSecret? secret = null, int timeoutMs = 1500, CancellationToken ct = default)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", _pipe, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await pipe.ConnectAsync(timeoutMs, ct).ConfigureAwait(false);
            var line = JsonSerializer.Serialize(request with { WithSecret = secret is not null }, AgentProtocol.Json) + "\n";
            await pipe.WriteAsync(Encoding.UTF8.GetBytes(line), ct).ConfigureAwait(false);
            if (secret is not null)
            {
                var buffer = SecureMemory.AllocatePinned(RootSecret.Length);
                secret.Bytes.CopyTo(buffer);
                try
                {
                    await pipe.WriteAsync(buffer, ct).ConfigureAwait(false);
                }
                finally
                {
                    SecureMemory.Wipe(buffer);
                }
            }

            await pipe.FlushAsync(ct).ConfigureAwait(false);
            using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
            var response = await reader.ReadLineAsync(ct).ConfigureAwait(false);
            return response is null ? null : JsonSerializer.Deserialize<AgentProtocol.Response>(response, AgentProtocol.Json);
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException or JsonException or OperationCanceledException)
        {
            return null;
        }
    }

    public async Task<bool> IsRunningAsync() => (await SendAsync(new AgentProtocol.Request("ping"), timeoutMs: 500).ConfigureAwait(false))?.Ok == true;
}
