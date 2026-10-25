#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$ROOT/.build/verification"
mkdir -p "$LOG"
run() {
    local NAME="$1"; shift
    printf 'COMMAND'; printf ' %q' "$@"; printf '\n'
    set +e
    "$@" >"$LOG/$NAME.log" 2>&1
    local CODE=$?
    set -e
    printf '%s exit=%s log=%s\n' "$NAME" "$CODE" "$LOG/$NAME.log"
    printf '%s\n' "exit=$CODE" >>"$LOG/$NAME.log"
    if [[ "$CODE" -ne 0 ]]; then exit "$CODE"; fi
}
{
    printf 'UTC '; date -u '+%Y-%m-%dT%H:%M:%SZ'
    printf 'Shell working directory %s\n' "$PWD"
    printf 'Swift package directory %s\n' "$ROOT"
    swift --version
    sw_vers
    uname -m
} >"$LOG/environment.log" 2>&1
run package-script-syntax /bin/bash -n "$ROOT/scripts/package-fixtures.sh"
run verify-script-syntax /bin/bash -n "$ROOT/scripts/verify.sh"
run python-script-syntax python3 -c 'import ast,pathlib,sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())' "$ROOT/scripts/package-fixtures.py"
for CONFIG in debug release; do
    run "$CONFIG-build" swift build --package-path "$ROOT" -c "$CONFIG" -Xswiftc -warnings-as-errors -Xcc -Wall -Xcc -Wextra -Xcc -Werror
    run "$CONFIG-test" swift test --package-path "$ROOT" -c "$CONFIG"
    run "$CONFIG-signatures" /bin/bash "$ROOT/scripts/package-fixtures.sh" "$CONFIG"
    FIXTURE="$ROOT/.build/fixtures/$CONFIG"
    run "$CONFIG-self-test" "$FIXTURE/openlxssh-askpass-probe" --self-test "$FIXTURE/openlxssh-askpass-adversary"
    SERVICE="$(python3 -c 'import pathlib,sys; print(next(line.split(" ",1)[1] for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if line.startswith("POSTEXIT_SERVICE ")))' "$LOG/$CONFIG-self-test.log")"
    run "$CONFIG-post-exit" "$FIXTURE/openlxssh-askpass-probe" --lookup "$SERVICE"
done
printf '%s\n' 'PASS Debug/Release build, unit test, distinct Development signatures and frozen-Mach-auth fixture self-test.'
printf '%s\n' 'NOT VERIFIED: SSH server authentication/MFA, macOS26, Sandbox, DeveloperID or release distribution. See verify-app.py for local ssh-keygen readpass/PTY evidence.'
