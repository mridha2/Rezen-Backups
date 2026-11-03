using System.Runtime.CompilerServices;
using RezenBackup.Crypto;

namespace RezenBackup.Tests;

internal static class TestSetup
{
    /// <summary>Fast Argon2 parameters for the test suite only. Production minimum is enforced elsewhere.</summary>
    public static readonly KdfParameters FastKdf = new(8 * 1024, 1, 1);

    [ModuleInitializer]
    internal static void Initialize() => KdfPolicy.UseForTesting(FastKdf);
}
