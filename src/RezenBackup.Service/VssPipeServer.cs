using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RezenBackup.Platform.Windows;

namespace RezenBackup.Service;

/// <summary>
/// Local named-pipe endpoint for the per-user agent (DESIGN §1.3). Exactly three operations: create, release, list.
/// Interactive users may connect; network access is denied. Shadow copies belong to the connection that created them
/// and are deleted when it disconnects, and in any case after 12 hours.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class VssPipeServer(ShadowCopyManager shadows, ILogger<VssPipeServer> logger) : BackgroundService
{
    private const int MaxShadowsPerConnection = 8;
    private static readonly TimeSpan MaxLifetime = TimeSpan.FromHours(12);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        shadows.CleanupOrphans();
        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = NamedPipeServerStreamAcl.Create(
                    VssProtocol.PipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    4096,
                    4096,
                    Security());
                await pipe.WaitForConnectionAsync(stoppingToken);
                var connection = pipe;
                pipe = null;
                _ = Task.Run(() => HandleAsync(connection, stoppingToken), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (IOException ex)
            {
                logger.LogWarning("Pipe error: {Message}", ex.Message);
                await Task.Delay(1000, stoppingToken);
            }
            finally
            {
                pipe?.Dispose();
            }
        }
    }

    private static PipeSecurity Security()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        return security;
    }

    private async Task HandleAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        var owned = new List<string>();
        string user = "unknown";
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lifetime.CancelAfter(MaxLifetime);
        try
        {
            user = pipe.GetImpersonationUserName();
            using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
            while (!lifetime.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(lifetime.Token);
                if (line is null || line.Length > 4096)
                {
                    break;
                }

                var request = JsonSerializer.Deserialize<VssProtocol.Request>(line, VssProtocol.Json);
                VssProtocol.Response response;
                switch (request?.Op)
                {
                    case "create" when owned.Count >= MaxShadowsPerConnection:
                        response = new VssProtocol.Response(false, Error: "Too many shadow copies.");
                        break;
                    case "create" when ShadowCopyManager.IsValidVolume(request.Volume):
                        try
                        {
                            var (id, device) = shadows.Create(request.Volume!);
                            owned.Add(id);
                            response = new VssProtocol.Response(true, id, device);
                        }
                        catch (Exception ex) when (ex is InvalidOperationException or System.Management.ManagementException or UnauthorizedAccessException)
                        {
                            response = new VssProtocol.Response(false, Error: ex.Message);
                        }

                        break;
                    case "release" when request.ShadowId is { } sid && owned.Contains(sid, StringComparer.OrdinalIgnoreCase):
                        shadows.Delete(sid);
                        owned.RemoveAll(x => string.Equals(x, sid, StringComparison.OrdinalIgnoreCase));
                        response = new VssProtocol.Response(true);
                        break;
                    case "list":
                        response = new VssProtocol.Response(true, string.Join(';', owned));
                        break;
                    default:
                        response = new VssProtocol.Response(false, Error: "Unsupported request.");
                        break;
                }

                await writer.WriteLineAsync(JsonSerializer.Serialize(response, VssProtocol.Json));
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or OperationCanceledException)
        {
            logger.LogDebug("Client {User} disconnected: {Message}", user, ex.Message);
        }
        finally
        {
            foreach (var id in owned)
            {
                shadows.Delete(id);
            }

            await pipe.DisposeAsync();
        }
    }
}
