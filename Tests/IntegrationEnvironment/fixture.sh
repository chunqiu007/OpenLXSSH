#!/bin/bash
set -euo pipefail
# No docker probing, environment creation or writes happen in this launcher.
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
exec python3 "$SCRIPT_DIR/fixture.py" "$@"
