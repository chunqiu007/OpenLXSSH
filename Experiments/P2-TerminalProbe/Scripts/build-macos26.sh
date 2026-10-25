#!/bin/bash
# Compile-only target verification; cannot run the resulting min-26 binary
# on the macOS 15 host. SwiftPM's platform setting overrides --triple alone.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="$ROOT/.build/macos26-package"
mkdir -p "$TARGET"
python3 - "$ROOT" "$TARGET" <<'PY'
from pathlib import Path
import shutil, sys
root, target = map(Path, sys.argv[1:])
(target / 'Package.swift').write_text((root / 'Package.swift').read_text().replace('.macOS(.v15)', '.macOS("26.0")'))
shutil.copyfile(root / 'Package.resolved', target / 'Package.resolved')
for name in ['Sources', 'Tests']:
    destination = target / name
    if not destination.exists(): destination.symlink_to(root / name, target_is_directory=True)
PY
"$ROOT/Scripts/offline-dependencies.sh" swift package --package-path "$TARGET" --disable-dependency-cache resolve --skip-update
swift build --package-path "$TARGET" --configuration release --triple arm64-apple-macosx26.0 --disable-automatic-resolution
BIN="$(swift build --package-path "$TARGET" --configuration release --show-bin-path)"
/usr/bin/vtool -show-build "$BIN/OpenLXSSHTerminalProbe"
