#!/bin/bash
# Builds a portable, self-contained Windows build: one RezenBackup.exe (no installer, no .NET install needed),
# plus rezen.exe for the command line. Runs on macOS, Linux or Windows (Git Bash).
#
# The portable exe has no shadow-copy (VSS) helper service: that service must run as LocalSystem and is only
# installed by the MSI (installer/windows/build.ps1, Windows only). Without it, files are read directly and
# files locked by other programs may be skipped (they are listed in the backup report).
set -euo pipefail
cd "$(dirname "$0")/../.."
RID="${1:-win-x64}"   # win-x64 | win-arm64
OUT="artifacts/windows/portable-$RID"
rm -rf "$OUT" && mkdir -p "$OUT"
COMMON=(-c Release -r "$RID" --self-contained true -p:PublishSingleFile=true
        -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -p:DebugType=none)
dotnet publish src/RezenBackup.UI "${COMMON[@]}" -o "$OUT"
dotnet publish src/RezenBackup.Cli "${COMMON[@]}" -o "$OUT/cli"
mv "$OUT/cli/rezen.exe" "$OUT/" && rm -rf "$OUT/cli"
VERSION="$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' Directory.Build.props)"
(cd "$OUT" && zip -q -9 "../RezenBackup-$VERSION-$RID-portable.zip" RezenBackup.exe rezen.exe)
echo "Unsigned build (for testing only)."
echo "Built: $OUT/RezenBackup.exe"
echo "Built: artifacts/windows/RezenBackup-$VERSION-$RID-portable.zip"
