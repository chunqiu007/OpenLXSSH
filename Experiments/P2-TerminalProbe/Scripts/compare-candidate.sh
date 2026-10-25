#!/bin/bash
# One source tree, two exact dependencies. The comparison harness lives under
# ignored .build and symlinks Sources/Tests; no copied or patched upstream code.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CANDIDATE="${P2_CANDIDATE:-1.20.0}"
if [[ "$CANDIDATE" != 1.20.0 && "$CANDIDATE" != 1.99.1 ]]; then printf 'Unsupported comparison candidate\n' >&2; exit 2; fi
PREVIEW="$ROOT/.build/candidate-$CANDIDATE"
mkdir -p "$PREVIEW"
python3 - "$ROOT" "$PREVIEW" "$CANDIDATE" <<'PY'
from pathlib import Path
import sys
root, preview = map(Path, sys.argv[1:3])
version = sys.argv[3]
manifest = (root / 'Package.swift').read_text().replace('exact: "1.99.1"', f'exact: "{version}"')
if version == '1.20.0': manifest = manifest.replace('P2_PREVIEW_API', 'P2_STABLE_API')
(preview / 'Package.swift').write_text(manifest)
for item in ['Sources', 'Tests', 'ThirdParty']:
    destination = preview / item
    if not destination.exists(): destination.symlink_to(root / item, target_is_directory=True)
scripts = preview / 'Scripts'
scripts.mkdir(exist_ok=True)
for name in ['build-app.sh', 'native-smoke.py']:
    destination = scripts / name
    if not destination.exists(): destination.symlink_to(root / 'Scripts' / name)
PY
"$ROOT/Scripts/offline-dependencies.sh" swift package --package-path "$PREVIEW" --disable-dependency-cache resolve --skip-update
if [[ $# -gt 0 ]]; then
    exec swift "$@" --package-path "$PREVIEW" --disable-automatic-resolution
fi
printf '%s\n' "$PREVIEW"
