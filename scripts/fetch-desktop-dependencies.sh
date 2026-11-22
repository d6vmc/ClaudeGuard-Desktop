#!/bin/bash
# Fetch and verify the unchanged third-party desktop dependencies.
set -euo pipefail
destination="${1:?output directory}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$destination"

fetch() {
    local name="$1" url="$2" expected="$3"
    if [ -n "${CLAUDEGUARD_BUILD_ASSET_CACHE:-}" ] && [ -f "$CLAUDEGUARD_BUILD_ASSET_CACHE/$name" ]; then
        cp "$CLAUDEGUARD_BUILD_ASSET_CACHE/$name" "$work/$name"
    else
        curl -fsSL --retry 2 --max-time 240 --proto '=https' "$url" -o "$work/$name"
    fi
    printf '%s  %s\n' "$expected" "$work/$name" | shasum -a 256 -c -
}

xray=https://github.com/XTLS/Xray-core/releases/download/v26.11.9
fetch Xray-macos-arm64-v8a.zip "$xray/Xray-macos-arm64-v8a.zip" 233f0c66681cd0726f81a6b2b6ed6a5710869e312047b522e46ed53035bebd26 &
arm=$!
fetch Xray-macos-64.zip "$xray/Xray-macos-64.zip" 488963e676e06f5e48547f9dd38116aaca8de4234959b4272ae8f284e658dfd0 &
intel=$!
fetch LuLu_4.5.7.dmg https://github.com/objective-see/LuLu/releases/download/v4.5.7/LuLu_4.5.7.dmg 8d60f32b6972648aab9203f2f68bd3a804e2e05c23d60200d5e093d6bdb06e8c &
lulu=$!
fetch LULU_LICENSE https://raw.githubusercontent.com/objective-see/LuLu/v4.5.7/LICENSE.md 3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986 &
lulu_license=$!
python=https://github.com/astral-sh/python-build-standalone/releases/download/20261110
fetch python-arm64.tar.gz "$python/cpython-3.13.18%2B20261110-aarch64-apple-darwin-install_only_stripped.tar.gz" 7a2384641584ab9984221fcb0fc9265df465922af71be71410529e2a9c3f0540 &
python_arm=$!
fetch python-x86_64.tar.gz "$python/cpython-3.13.18%2B20261110-x86_64-apple-darwin-install_only_stripped.tar.gz" d27d59a722db9f69926eb6d9564071247221f45a04da920ea7f3001c97e32f9b &
python_intel=$!
for pid in "$arm" "$intel" "$lulu" "$lulu_license" "$python_arm" "$python_intel"; do
    wait "$pid"
done

unzip -p "$work/Xray-macos-arm64-v8a.zip" xray > "$work/xray-arm64"
unzip -p "$work/Xray-macos-64.zip" xray > "$work/xray-x86_64"
unzip -p "$work/Xray-macos-arm64-v8a.zip" LICENSE > "$destination/XRAY_LICENSE"
xcrun lipo -create "$work/xray-arm64" "$work/xray-x86_64" -output "$destination/xray"
cp "$work/LuLu_4.5.7.dmg" "$destination/LuLu.dmg"
cp "$work/LULU_LICENSE" "$destination/"
for arch in arm64 x86_64; do
    directory="$destination/python/$arch"
    mkdir -p "$directory"
    tar -xzf "$work/python-$arch.tar.gz" -C "$directory" --strip-components 1
done
"$destination/python/$(uname -m)/bin/python3" -I -c 'import json, plistlib, ssl, uuid'
