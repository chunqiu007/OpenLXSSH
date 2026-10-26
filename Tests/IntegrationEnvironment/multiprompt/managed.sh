#!/bin/bash
set -euo pipefail
# Launcher performs no Docker probing, runtime creation or writes.
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
export PYTHONDONTWRITEBYTECODE=1
exec python3 "$SCRIPT_DIR/managed.py" "$@"
