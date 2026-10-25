#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# P1-04C is the sole recommended fixture path: distinct Development-signed images
# and frozen per-message Mach identity. The old A socket transport was removed.
exec python3 "$ROOT/scripts/package-fixtures.py" "${1:-debug}"
