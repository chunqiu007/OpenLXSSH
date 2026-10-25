#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${1:-release}"
if [[ "$CONFIG" != debug && "$CONFIG" != release ]]; then printf 'usage: %s [debug|release]\n' "$0" >&2; exit 2; fi
swift build --package-path "$ROOT" --configuration "$CONFIG" --disable-automatic-resolution
BIN="$(swift build --package-path "$ROOT" --configuration "$CONFIG" --show-bin-path)"
APP="$ROOT/.build/app-$CONFIG/OpenLXSSHTerminalProbe.app"
if [[ -e "$APP" ]]; then
    python3 - "$APP" <<'PY'
from pathlib import Path
import shutil, sys
path = Path(sys.argv[1])
assert path.name == 'OpenLXSSHTerminalProbe.app' and '.build' in path.parts
shutil.rmtree(path)
PY
fi
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN/OpenLXSSHTerminalProbe" "$BIN/openlxssh-terminal-fixture" "$APP/Contents/MacOS/"
# Preserve upstream resources in the standard App resources directory.
# This tag embeds its Metal shader source in Swift and contains no call to
# Bundle.module; the copied .metal is provenance, not a checkout fallback.
while IFS= read -r bundle; do cp -R "$bundle" "$APP/Contents/Resources/"; done < <(find "$BIN" -maxdepth 1 -name '*.bundle' -type d)
cp "$ROOT"/ThirdParty/* "$APP/Contents/Resources/"
/usr/bin/plutil -create xml1 "$APP/Contents/Info.plist"
/usr/bin/plutil -insert CFBundleIdentifier -string org.openlxssh.experiments.terminalprobe "$APP/Contents/Info.plist"
/usr/bin/plutil -insert CFBundleName -string OpenLXSSHTerminalProbe "$APP/Contents/Info.plist"
/usr/bin/plutil -insert CFBundleDisplayName -string 'OpenLXSSH Local Terminal Probe' "$APP/Contents/Info.plist"
/usr/bin/plutil -insert CFBundleExecutable -string OpenLXSSHTerminalProbe "$APP/Contents/Info.plist"
/usr/bin/plutil -insert CFBundlePackageType -string APPL "$APP/Contents/Info.plist"
/usr/bin/plutil -insert CFBundleShortVersionString -string 0.0.1 "$APP/Contents/Info.plist"
/usr/bin/plutil -insert CFBundleVersion -string 1 "$APP/Contents/Info.plist"
/usr/bin/plutil -insert LSMinimumSystemVersion -string 15.0 "$APP/Contents/Info.plist"
/usr/bin/plutil -insert NSHighResolutionCapable -bool YES "$APP/Contents/Info.plist"
# Local experimental integrity signature only, not Developer ID/notarization.
/usr/bin/codesign --force --sign - "$APP/Contents/MacOS/openlxssh-terminal-fixture"
/usr/bin/codesign --force --sign - "$APP"
/usr/bin/codesign --verify --deep --strict "$APP"
printf '%s\n' "$APP"
