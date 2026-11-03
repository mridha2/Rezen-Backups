using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using RezenBackup.Service;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("RezenBackupService is a Windows service. On macOS, files are read directly (DESIGN §29).");
    return 1;
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "RezenBackupService");
builder.Services.AddSingleton<ShadowCopyManager>();
builder.Services.AddHostedService<VssPipeServer>();
await builder.Build().RunAsync();
return 0;
