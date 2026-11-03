#!/bin/bash
# Builds "Rezen Backup.app" (self-contained, no runtime download) and a .dmg.
#
# Optional signing/notarization — credentials come from the environment, never from this repository:
#   REZEN_MAC_SIGN_IDENTITY   e.g. "Developer ID Application: Rezen (TEAMID)"
#   REZEN_NOTARY_PROFILE      a `xcrun notarytool store-credentials` keychain profile name
set -euo pipefail
cd "$(dirname "$0")/../.."
ARCH="${1:-$(uname -m | sed 's/x86_64/x64/')}"   # arm64 | x64
RID="osx-$ARCH"
VERSION="$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' Directory.Build.props)"
OUT="artifacts/macos/$ARCH"
APP="$OUT/Rezen Backup.app"
rm -rf "$OUT" && mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

dotnet publish src/RezenBackup.UI -c Release -r "$RID" --self-contained true \
  -p:PublishSingleFile=false -p:UseAppHost=true -o "$APP/Contents/MacOS"
dotnet publish src/RezenBackup.Cli -c Release -r "$RID" --self-contained true -o "$OUT/cli"
cp "$OUT/cli/"rezen* "$APP/Contents/MacOS/"

sed "s/__VERSION__/$VERSION/g" installer/macos/Info.plist > "$APP/Contents/Info.plist"

# Icon: render the PNG into an .iconset and convert with iconutil.
ICONSET="$OUT/rezen.iconset"; mkdir -p "$ICONSET"
SRC=src/RezenBackup.UI/Assets/rezen-256.png
for s in 16 32 128 256 512; do
  sips -z $s $s "$SRC" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  d=$((s*2)); sips -z $d $d "$SRC" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/rezen.icns"
rm -rf "$ICONSET"

if [[ -n "${REZEN_MAC_SIGN_IDENTITY:-}" ]]; then
  echo "Signing with: $REZEN_MAC_SIGN_IDENTITY"
  find "$APP/Contents/MacOS" -type f \( -name "*.dylib" -o -perm +111 \) -print0 |
    xargs -0 codesign --force --timestamp --options runtime --entitlements installer/macos/entitlements.plist -s "$REZEN_MAC_SIGN_IDENTITY"
  codesign --force --timestamp --options runtime --entitlements installer/macos/entitlements.plist -s "$REZEN_MAC_SIGN_IDENTITY" "$APP"
  codesign --verify --deep --strict "$APP"
else
  echo "REZEN_MAC_SIGN_IDENTITY not set: building an unsigned app (for local testing only)."
fi

DMG="$OUT/RezenBackup-$VERSION-$ARCH.dmg"
STAGE="$OUT/dmg"; mkdir -p "$STAGE"; cp -R "$APP" "$STAGE/"; ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "Rezen Backup" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGE"

if [[ -n "${REZEN_MAC_SIGN_IDENTITY:-}" ]]; then
  codesign --force --timestamp -s "$REZEN_MAC_SIGN_IDENTITY" "$DMG"
  if [[ -n "${REZEN_NOTARY_PROFILE:-}" ]]; then
    xcrun notarytool submit "$DMG" --keychain-profile "$REZEN_NOTARY_PROFILE" --wait
    xcrun stapler staple "$DMG"
  fi
fi
echo "Built: $APP"
echo "Built: $DMG"
