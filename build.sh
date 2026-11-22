#!/bin/bash
# Build release assets without installing or changing the running firewall.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
VERSION="${1:-2.0.0}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Usage: ./build.sh [2.0.0]' >&2; exit 1; }
[ "$(uname -s)" = Darwin ] || { echo 'Build ClaudeGuard on macOS.' >&2; exit 1; }
for tool in xcrun pkgbuild productbuild codesign iconutil sips; do
    command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done
/usr/bin/python3 -I -c 'import sys; assert sys.version_info >= (3, 9)' || {
    echo 'Install Xcode Command Line Tools first: xcode-select --install' >&2; exit 1;
}
DESKTOP_FILTER="${CLAUDEGUARD_DESKTOP_FILTER:-0}"
LULU_DESKTOP="${CLAUDEGUARD_LULU_DESKTOP:-0}"
if [ "$DESKTOP_FILTER" = 1 ] && [ "$LULU_DESKTOP" = 1 ]; then
    echo 'Choose one Desktop firewall build.' >&2
    exit 1
fi
IDENTITY="${CLAUDEGUARD_APP_SIGN_IDENTITY:--}"
MIN_MACOS=14.0
SWIFT_FLAGS=()
HOST_SOURCES=("$ROOT/src/main.swift" "$ROOT/src/ModeSegmentedControl.swift" "$ROOT/src/DesktopUpdater.swift" "$ROOT/src/LuLuRulesImporter.swift")
if [ "$DESKTOP_FILTER" = 1 ]; then
    if [[ "$IDENTITY" != "Developer ID Application:"* ]] ||
       [ ! -f "${CLAUDEGUARD_APP_PROVISION_PROFILE:-}" ] ||
       [ ! -f "${CLAUDEGUARD_FILTER_PROVISION_PROFILE:-}" ]; then
        echo 'The Desktop filter build requires a Developer ID Application identity and a provisioning profile for each bundle.' >&2
        exit 1
    fi
    MIN_MACOS=15.0
    SWIFT_FLAGS=(-D CLAUDEGUARD_DESKTOP_FILTER)
    HOST_SOURCES+=("$ROOT/src/DesktopFilterController.swift" "$ROOT/src/desktop_filter/DesktopPolicy.swift")
fi
WORK="$(mktemp -d "${TMPDIR:-/tmp}/claudeguard-pkg.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
SDK="$(xcrun --show-sdk-path)"
PAYLOAD="$WORK/root"
APP="$PAYLOAD/Applications/ClaudeGuard.app"
HELPER="$PAYLOAD/Library/Application Support/ClaudeGuard"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$HELPER/Runtime/bin" "$WORK/modules"
if [ "$LULU_DESKTOP" = 1 ]; then
    bash "$ROOT/scripts/fetch-desktop-dependencies.sh" "$WORK/desktop"
    cp "$WORK/desktop/LuLu.dmg" "$ROOT/packaging/lulu-desktop/ClaudeGuard-LuLu-rules.json" "$APP/Contents/Resources/"
    mv "$WORK/desktop/xray" "$WORK/desktop/XRAY_LICENSE" "$WORK/desktop/LULU_LICENSE" "$WORK/desktop/python" "$HELPER/"
    cp "$ROOT/packaging/scripts/runtime-python" "$HELPER/python3"
    chmod 755 "$HELPER/python3" "$HELPER/xray"
    cp "$ROOT/packaging/scripts/configure.py" "$ROOT/packaging/scripts/remove_desktop.py" "$HELPER/"
    UNINSTALLER="$APP/Contents/Helpers/ClaudeGuard Uninstaller.app"
    mkdir -p "$APP/Contents/Helpers"
    /usr/bin/osacompile -o "$UNINSTALLER" "$ROOT/packaging/scripts/Uninstall.applescript"
    /usr/libexec/PlistBuddy -c 'Add :CFBundleIdentifier string com.claudeguard.app.uninstaller' "$UNINSTALLER/Contents/Info.plist"
    codesign --force --sign - "$HELPER/xray"
    codesign --verify --strict "$HELPER/xray"
    "$HELPER/xray" version >/dev/null
fi
for arch in arm64 x86_64; do
    bash "$ROOT/scripts/fetch-proxy-engine.sh" "$WORK/engine-$arch" "$arch"
    echo "Building $arch (macOS $MIN_MACOS+)…"
    xcrun clang -O2 -Wall -Wextra -Werror -isysroot "$SDK" -target "$arch-apple-macos14.0" \
        "$ROOT/src/hosts_helper.c" -o "$WORK/hosts-helper-$arch"
    xcrun clang -O2 -Wall -Wextra -Werror -isysroot "$SDK" -target "$arch-apple-macos14.0" \
        "$ROOT/src/pf_anchor.c" -o "$WORK/pf-anchor-$arch"
    xcrun swiftc -O -sdk "$SDK" -target "$arch-apple-macos$MIN_MACOS" -module-cache-path "$WORK/modules" \
        ${SWIFT_FLAGS[@]+"${SWIFT_FLAGS[@]}"} "${HOST_SOURCES[@]}" -o "$WORK/ClaudeGuardMenuBar-$arch"
    if [ "$DESKTOP_FILTER" = 1 ]; then
        xcrun swiftc -O -sdk "$SDK" -target "$arch-apple-macos$MIN_MACOS" -module-cache-path "$WORK/modules" \
            -module-name ClaudeGuardDesktopFilter "$ROOT"/src/desktop_filter/*.swift -o "$WORK/desktop-filter-$arch"
    fi
done
for name in hosts-helper pf-anchor ClaudeGuardMenuBar; do
    xcrun lipo -create "$WORK/$name-arm64" "$WORK/$name-x86_64" -output "$WORK/$name"
done
cp "$WORK/ClaudeGuardMenuBar" "$APP/Contents/MacOS/"
cp "$WORK/engine-arm64/PROXY-ENGINE-NOTICE.txt" "$HELPER/"
xcrun lipo -create "$WORK/engine-arm64/sing-box" "$WORK/engine-x86_64/sing-box" -output "$HELPER/sing-box"
cp "$ROOT/src/proxy_config.py" "$ROOT/src/proxy_service.py" "$ROOT/src/trace_timing.py" "$ROOT/src/proxy_egress.py" "$HELPER/"
cp "$WORK/hosts-helper" "$WORK/pf-anchor" "$ROOT/src/pf_controller.py" "$HELPER/"
/usr/bin/rsync -a --exclude '__pycache__' --exclude '*.pyc' --exclude '.DS_Store' "$ROOT/src/" "$HELPER/Runtime/src/"
cp "$ROOT/bin/claudeguard" "$HELPER/Runtime/bin/"
cp "$ROOT/uninstall.sh" "$ROOT/packaging/setup_user.py" "$HELPER/Runtime/"
if [ "$LULU_DESKTOP" = 1 ]; then
    touch "$HELPER/Runtime/lulu-desktop"
fi
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$HELPER/"
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$HELPER/Runtime/"
cp "$ROOT/src/vendor/SING_BOX_LICENSE" "$HELPER/SING_BOX_LICENSE"
cp "$ROOT/src/vendor/GPL-3.0.txt" "$HELPER/GPL-3.0.txt"
mkdir -p "$WORK/AppIcon.iconset"
for pair in '16:icon_16x16' '32:icon_16x16@2x' '32:icon_32x32' '64:icon_32x32@2x' \
    '128:icon_128x128' '256:icon_128x128@2x' '256:icon_256x256' '512:icon_256x256@2x' \
    '512:icon_512x512' '1024:icon_512x512@2x'; do
    sips -z "${pair%%:*}" "${pair%%:*}" "$ROOT/assets/AppIcon.png" \
        --out "$WORK/AppIcon.iconset/${pair#*:}.png" >/dev/null
done
iconutil -c icns "$WORK/AppIcon.iconset" -o "$APP/Contents/Resources/AppIcon.icns"
/usr/bin/python3 - "$APP" "$VERSION" "$WORK/components.plist" "$MIN_MACOS" <<'PY'
import plistlib, sys
from pathlib import Path
app, version, components, minimum = sys.argv[1:]
with (Path(app) / 'Contents/Info.plist').open('wb') as f:
    plistlib.dump(dict(CFBundleExecutable='ClaudeGuardMenuBar', CFBundleIconFile='AppIcon',
        CFBundleIdentifier='com.claudeguard.app', CFBundleName='ClaudeGuard',
        CFBundlePackageType='APPL', CFBundleShortVersionString=version,
        CFBundleVersion=version, LSMinimumSystemVersion=minimum, LSUIElement=True), f)
with open(components, 'wb') as f:
    plistlib.dump([dict(RootRelativeBundlePath='Applications/ClaudeGuard.app',
        BundleIsRelocatable=False, BundleIsVersionChecked=True,
        BundleHasStrictIdentifier=True, BundleOverwriteAction='upgrade')], f)
PY
find "$PAYLOAD" -type d -exec chmod 755 {} +
find "$PAYLOAD" -type f -exec chmod 644 {} +
chmod 755 "$HELPER/sing-box" "$APP/Contents/MacOS/ClaudeGuardMenuBar" "$HELPER/hosts-helper" "$HELPER/pf-anchor" \
    "$HELPER/Runtime/bin/claudeguard" "$HELPER/Runtime/uninstall.sh" \
    "$HELPER/Runtime/src/cli_wrapper.py" "$HELPER/Runtime/src/app_launcher.py" "$HELPER/Runtime/src/helper.py"
if [ "$LULU_DESKTOP" = 1 ]; then
    chmod 755 "$HELPER/xray" "$HELPER/python3" "$HELPER"/python/*/bin/python3.13
    chmod 755 "$UNINSTALLER/Contents/MacOS/applet"
    codesign --force --options runtime --sign "$IDENTITY" "$UNINSTALLER"
    "$HELPER/python3" -I -c 'import json, ssl'
fi
for binary in "$HELPER/sing-box" "$HELPER/hosts-helper" "$HELPER/pf-anchor"; do
    codesign --force --options runtime --sign "$IDENTITY" "$binary"
done
if [ "$DESKTOP_FILTER" = 1 ]; then
    FILTER_ID=com.claudeguard.app.desktop-filter
    FILTER="$APP/Contents/Library/SystemExtensions/$FILTER_ID.systemextension"
    FILTER_FILES="$ROOT/packaging/desktop-filter"
    mkdir -p "$FILTER/Contents/MacOS"
    xcrun lipo -create "$WORK/desktop-filter-arm64" "$WORK/desktop-filter-x86_64" \
        -output "$FILTER/Contents/MacOS/$FILTER_ID"
    chmod 755 "$FILTER/Contents/MacOS/$FILTER_ID"
    cp "$CLAUDEGUARD_APP_PROVISION_PROFILE" "$APP/Contents/embedded.provisionprofile"
    cp "$CLAUDEGUARD_FILTER_PROVISION_PROFILE" "$FILTER/Contents/embedded.provisionprofile"
    /usr/bin/security cms -D -i "$CLAUDEGUARD_FILTER_PROVISION_PROFILE" -o "$WORK/filter-profile.plist"
    /usr/bin/security cms -D -i "$CLAUDEGUARD_APP_PROVISION_PROFILE" -o "$WORK/app-profile.plist"
    /usr/bin/python3 - "$FILTER_FILES/Info.plist" "$FILTER/Contents/Info.plist" "$VERSION" \
        "$WORK/filter-profile.plist" "$WORK/app-profile.plist" <<'PYFILTER'
import plistlib, sys
from pathlib import Path

source, destination, version, provider_profile, host_profile = sys.argv[1:]
info = plistlib.loads(Path(source).read_bytes())

def check_profile(path, bundle):
    profile = plistlib.loads(Path(path).read_bytes())
    team, = profile["TeamIdentifier"]
    entitlements = profile["Entitlements"]
    app_id = entitlements.get("com.apple.application-identifier", entitlements.get("application-identifier"))
    if app_id != f"{team}.{bundle}" or "content-filter-provider-systemextension" not in entitlements.get(
            "com.apple.developer.networking.networkextension", []):
        raise SystemExit("Incorrect Network Extension provisioning profile for " + bundle)
    return team, entitlements

team, _ = check_profile(provider_profile, info["CFBundleIdentifier"])
host_team, host = check_profile(host_profile, "com.claudeguard.app")
if team != host_team or host.get("com.apple.developer.system-extension.install") is not True:
    raise SystemExit("The host must use the same team and allow system extension activation")
info["NetworkExtension"]["NEMachServiceName"] = f"{team}.{info['CFBundleIdentifier']}"
info["CFBundleShortVersionString"] = info["CFBundleVersion"] = version
Path(destination).write_bytes(plistlib.dumps(info))
PYFILTER
    codesign --force --options runtime --sign "$IDENTITY" \
        --entitlements "$FILTER_FILES/provider.entitlements" "$FILTER"
    codesign --force --options runtime --sign "$IDENTITY" \
        --entitlements "$FILTER_FILES/app.entitlements" "$APP"
    codesign --verify --deep --strict "$APP"
else
    codesign --force --options runtime --sign "$IDENTITY" "$APP"
fi
mkdir "$WORK/scripts"
for script in preinstall postinstall configure.py; do
    cp "$ROOT/packaging/scripts/$script" "$WORK/scripts/"
done
if [ "$LULU_DESKTOP" = 1 ]; then
    touch "$WORK/scripts/embedded-runtime"
fi
chmod 755 "$WORK/scripts/preinstall" "$WORK/scripts/postinstall"
pkgbuild --root "$PAYLOAD" --component-plist "$WORK/components.plist" \
    --scripts "$WORK/scripts" --identifier com.claudeguard.installer \
    --version "$VERSION" --install-location / --ownership recommended "$WORK/component.pkg"
cat > "$WORK/Distribution.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>ClaudeGuard $VERSION</title>
  <options customize="never" require-scripts="true" hostArchitectures="arm64,x86_64"/>
  <domains enable_localSystem="true" enable_currentUserHome="false" enable_anywhere="false"/>
  <allowed-os-versions><os-version min="$MIN_MACOS"/></allowed-os-versions>
  <welcome file="Welcome.html" mime-type="text/html"/>
  <conclusion file="Conclusion.html" mime-type="text/html"/>
  <choices-outline><line choice="default"/></choices-outline>
  <choice id="default" visible="false"><pkg-ref id="com.claudeguard.installer"/></choice>
  <pkg-ref id="com.claudeguard.installer" version="$VERSION" onConclusion="none">component.pkg</pkg-ref>
</installer-gui-script>
EOF
OUTPUT="$ROOT/ClaudeGuard.pkg"
set -- productbuild --distribution "$WORK/Distribution.xml" --resources "$ROOT/packaging/resources" \
    --package-path "$WORK"
if [ -n "${CLAUDEGUARD_INSTALLER_SIGN_IDENTITY:-}" ]; then
    set -- "$@" --sign "$CLAUDEGUARD_INSTALLER_SIGN_IDENTITY"
fi
"$@" "$WORK/ClaudeGuard.pkg"
# Replace an older build only once the new package has completed successfully.
mv -f "$WORK/ClaudeGuard.pkg" "$OUTPUT"
echo "Built $OUTPUT"
