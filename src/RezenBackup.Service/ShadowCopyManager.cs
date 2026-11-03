using System.Management;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace RezenBackup.Service;

/// <summary>
/// Creates and deletes client-accessible VSS shadow copies through WMI (<c>Win32_ShadowCopy</c>). Every shadow copy it
/// creates is recorded so it can be removed after a crash. It never reads user files.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class ShadowCopyManager
{
    private readonly ILogger<ShadowCopyManager> _logger;
    private readonly string _registry;
    private readonly object _gate = new();

    public ShadowCopyManager(ILogger<ShadowCopyManager> logger)
    {
        _logger = logger;
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Rezen Backup");
        Directory.CreateDirectory(dir);
        _registry = Path.Combine(dir, "vss-shadows.txt");
        Protect(dir);
    }

    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    /// <summary>
    /// Only SYSTEM and Administrators may write the service's data folder, and a registry file created by anyone else
    /// is discarded — so an unprivileged user can never make this service delete shadow copies it did not create.
    /// </summary>
    private void Protect(string dir)
    {
        try
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (var sid in new[] { SystemSid, Admins })
            {
                security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            }

            security.SetOwner(SystemSid);
            new DirectoryInfo(dir).SetAccessControl(security);

            if (File.Exists(_registry))
            {
                var owner = new FileInfo(_registry).GetAccessControl().GetOwner(typeof(SecurityIdentifier));
                if (owner is null || !(owner.Equals(SystemSid) || owner.Equals(Admins)))
                {
                    _logger.LogWarning("Discarding a shadow-copy registry not created by this service.");
                    File.Delete(_registry);
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException)
        {
            _logger.LogWarning("Could not secure the service data folder: {Message}", ex.Message);
        }
    }

    [GeneratedRegex(@"^[A-Za-z]:\\$", RegexOptions.CultureInvariant)]
    private static partial Regex VolumeRoot();

    [GeneratedRegex(@"^\{[0-9A-Fa-f\-]{36}\}$", RegexOptions.CultureInvariant)]
    private static partial Regex ShadowIdPattern();

    public static bool IsValidVolume(string? volume) => volume is not null && VolumeRoot().IsMatch(volume);

    public static bool IsValidShadowId(string? id) => id is not null && ShadowIdPattern().IsMatch(id);

    public (string ShadowId, string Device) Create(string volume)
    {
        if (!IsValidVolume(volume))
        {
            throw new ArgumentException("Invalid volume.", nameof(volume));
        }

        using var shadowClass = new ManagementClass(@"root\cimv2", "Win32_ShadowCopy", null);
        using var input = shadowClass.GetMethodParameters("Create");
        input["Volume"] = volume;
        input["Context"] = "ClientAccessible";
        using var output = shadowClass.InvokeMethod("Create", input, null);
        uint rc = (uint)output["ReturnValue"];
        if (rc != 0)
        {
            throw new InvalidOperationException($"Win32_ShadowCopy.Create returned {rc}.");
        }

        var id = (string)output["ShadowID"];
        Record(id, add: true);
        using var searcher = new ManagementObjectSearcher(@"root\cimv2", $"SELECT DeviceObject FROM Win32_ShadowCopy WHERE ID='{id}'");
        foreach (ManagementObject mo in searcher.Get())
        {
            using (mo)
            {
                var device = (string)mo["DeviceObject"];
                _logger.LogInformation("Created shadow copy {Id} of {Volume}", id, volume);
                return (id, device);
            }
        }

        Delete(id);
        throw new InvalidOperationException("Shadow copy was created but could not be located.");
    }

    public void Delete(string shadowId)
    {
        if (!IsValidShadowId(shadowId))
        {
            return;
        }

        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\cimv2", $"SELECT * FROM Win32_ShadowCopy WHERE ID='{shadowId}'");
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    // This service only ever creates client-accessible shadow copies; never touch any other kind
                    // (System Restore points, backup software).
                    if (mo["ClientAccessible"] is bool clientAccessible && clientAccessible)
                    {
                        mo.Delete();
                    }
                }
            }

            _logger.LogInformation("Deleted shadow copy {Id}", shadowId);
        }
        catch (ManagementException ex)
        {
            _logger.LogWarning("Deleting shadow copy {Id} failed: {Message}", shadowId, ex.Message);
        }
        finally
        {
            Record(shadowId, add: false);
        }
    }

    /// <summary>Removes shadow copies left behind by a previous crash of the service or the computer.</summary>
    public void CleanupOrphans()
    {
        string[] ids;
        lock (_gate)
        {
            ids = File.Exists(_registry) ? File.ReadAllLines(_registry) : [];
        }

        foreach (var id in ids.Where(IsValidShadowId))
        {
            Delete(id);
        }
    }

    private void Record(string id, bool add)
    {
        lock (_gate)
        {
            var set = File.Exists(_registry) ? File.ReadAllLines(_registry).ToHashSet(StringComparer.OrdinalIgnoreCase) : [];
            if (add)
            {
                set.Add(id);
            }
            else
            {
                set.Remove(id);
            }

            File.WriteAllLines(_registry, set);
        }
    }
}
