<#
  Builds the Rezen Backup MSI on Windows.

  Requirements: .NET 10 SDK. The WiX SDK is restored automatically by `dotnet build`.

  Optional code signing (credentials stay outside the repository):
    $env:REZEN_SIGN_CERT_THUMBPRINT   SHA-1 thumbprint of a code-signing certificate in the CurrentUser\My store
                                      (e.g. on a hardware token)
    $env:REZEN_SIGN_TIMESTAMP_URL     RFC 3161 timestamp server (build time only; the app itself never uses the network)
#>
param([string]$Runtime = "win-x64")
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
$version = ([xml](Get-Content "$root\Directory.Build.props")).Project.PropertyGroup.Version | Select-Object -First 1
$stage = "$root\artifacts\windows\stage"
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue

dotnet publish "$root\src\RezenBackup.UI" -c Release -r $Runtime --self-contained true -o "$stage\app"
dotnet publish "$root\src\RezenBackup.Cli" -c Release -r $Runtime --self-contained true -o "$stage\cli"
Copy-Item "$stage\cli\rezen*" "$stage\app\" -Force
Remove-Item -Recurse -Force "$stage\cli"
dotnet publish "$root\src\RezenBackup.Service" -c Release -r $Runtime --self-contained true -o "$stage\service"

function Sign([string[]]$files) {
  if (-not $env:REZEN_SIGN_CERT_THUMBPRINT) { return }
  $ts = if ($env:REZEN_SIGN_TIMESTAMP_URL) { @("/tr", $env:REZEN_SIGN_TIMESTAMP_URL, "/td", "sha256") } else { @() }
  & signtool sign /fd sha256 /sha1 $env:REZEN_SIGN_CERT_THUMBPRINT @ts $files
  if ($LASTEXITCODE -ne 0) { throw "signtool failed" }
}

$ours = Get-ChildItem "$stage" -Recurse -Include "RezenBackup*.exe","RezenBackup*.dll","rezen.exe","rezen.dll" | ForEach-Object FullName
Sign $ours

dotnet build "$PSScriptRoot\RezenBackup.Installer.wixproj" -c Release -p:ProductVersion=$version -p:StageDir=$stage -o "$root\artifacts\windows"
$msi = Get-ChildItem "$root\artifacts\windows\*.msi" | Select-Object -First 1
Sign @($msi.FullName)
if (-not $env:REZEN_SIGN_CERT_THUMBPRINT) { Write-Warning "Unsigned build (REZEN_SIGN_CERT_THUMBPRINT not set) — for testing only." }
Write-Host "Built: $($msi.FullName)"
