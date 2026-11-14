#!/usr/bin/env python3
"""Run one explicitly selected, already-built HostProbe phase; never build or automate UI.

terminal-desktop-cua requires official CUA plain/bracketed Cmd+V handshakes.
desktop-cua waits for its exact marked-root finish signal; ready/finish is lifecycle only.
All output stays under DerivedData/UXVerification/NativeProbe-R1. A success report alone
is insufficient: this runner requires natural exit 0 and AppKit willTerminate evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "DerivedData/UXVerification/NativeProbe-R1"
PHASES = ("native-discovery", "native-dismiss", "terminal-desktop-cua", "desktop-cua")
REQUIRED = {
    "native-discovery": {
        "native-main-window", "startup-no-session", "discovery-fresh-isolated-store",
        "discovery-unique-host.address", "discovery-unique-host.name",
        "discovery-unique-host.username", "discovery-unique-save", "discovery-did-not-write",
    },
    "native-dismiss": {
        "fixture-real-editor-persisted", "actual-editor-loads-persisted-record",
        "actual-editor-dirty-not-yet-written", "actual-editor-Cmd-W-only-opens-owned-confirmation",
        "actual-editor-Cancel-preserves-draft-and-owner", "actual-editor-Cancel-does-not-write",
        "actual-editor-Escape-preserves-draft-and-session", "actual-editor-Escape-does-not-write",
        "actual-editor-Discard-does-not-write", "actual-editor-Discard-preserves-session",
        "actual-editor-discarded-draft-not-revived", "actual-editor-dirty-Save-persists-exact-record",
        "actual-editor-dirty-Save-preserves-session", "actual-editor-reopen-reads-saved-value",
        "actual-editor-clean-Escape-keeps-session",
        "native-sheet-Cmd-W-hook-denies-and-keeps-draft",
        "native-sheet-Escape-hook-denies-and-keeps-draft",
        "native-sheet-accept-closes-only-owned-editor", "default-auth-Cmd-W-keeps-tab-without-answer",
        "default-auth-dismiss-never-revives-answer", "unknown-sheet-Cmd-W-is-not-ended",
        "registered-owned-alert-Cmd-W-cancels",
    },
    "terminal-desktop-cua": {
        "fixture-real-editor-persisted", "Cmd-V-exact-UTF8-multiline",
        "Cmd-V-exact-bracketed-UTF8", "CUA-paste-retains-native-owner",
        "CUA-actual-input-activate-terminal-and-press-Cmd-V-plain",
        "CUA-actual-input-press-Cmd-V-bracketed",
    },
    "desktop-cua": {"desktop-cua-ready", "desktop-cua-finish-signal"},
}


SAFE_FAILURE_LABELS = set().union(*REQUIRED.values()) | {
    "initial-load", "discovery-editor-sheet", "discovery-interactive-window",
    "discovery-content-root", "discovery-owned-root", "discovery-owned-window-key",
    "discovery-new-editor-close-confirmation", "discovery-close-confirmation-owner", "discovery-editor-closed",
    "host.name", "host.address", "host.username", "host.password", "host-editor-owner",
    "input-owner", "input-native-focus", "input-native-field-editor", "input-field-editor", "input-native-commit", "input-keeps-committed-field",
    "input-AX-disabled", "input-AX-owner-changed", "input-AX-value-not-settable", "input-AX-commit",
    "button-owner", "button-native-disabled", "button-AX-press-not-supported",
    "visible-button-保存", "visible-button-取消", "visible-button-放弃更改",
    "fixture-fresh-isolated-store", "fixture-editor-owner", "fixture-not-written-before-save", "fixture-persisted-host",
    "dismiss-fixture-host", "dismiss-logic-driver", "dismiss-tab", "dismiss-driver", "dismiss-parent",
    "dismiss-hook-sheet", "dismiss-owned-sheet", "dismiss-hook-accepts", "dismiss-default-auth",
    "dismiss-default-auth-closed", "dismiss-fresh-auth", "dismiss-fresh-auth-closed",
    "unknown-fixture-cleanup", "registered-alert-dismissed", "authentication.answer", "dismiss.fixture.draft",
    "actual-editor-reopened", "actual-editor-owner", "actual-editor-Cmd-W-confirmation",
    "actual-editor-close-confirmation", "actual-editor-cancel-keeps-draft", "actual-editor-Escape-confirmation",
    "actual-editor-Escape-owner", "actual-editor-Escape-cancels-only-confirmation",
    "actual-editor-discard-confirmation", "actual-editor-discard-owner", "actual-editor-discard-closed",
    "actual-editor-reopened-after-discard", "actual-editor-save-owner", "actual-editor-save-confirmation",
    "actual-editor-save-confirmation-owner", "actual-editor-save-closed", "actual-editor-reopened-after-save",
    "actual-editor-clean-owner", "actual-editor-clean-Escape-closes", "menu-select-session", "session-tab",
    "terminal-fixture-host", "terminal-fixture-driver", "terminal-tab", "terminal-logic-driver", "terminal-window",
    "renderer-color-snapshot", "ordinary-text-row", "ANSI-row", "window-capture",
    "hosts.table", "vault-table-window", "hittable-host-table", "vault-context-event", "vault-context-编辑…",
    "menu-newHost", "menu-showVault", "menu-nextWorkspace", "menu-key-event", "menu-key-w",
    "desktop-cua-owned-directory", "desktop-cua-stale-finish-signal", "desktop-cua-window",
    "desktop-cua-ended-before-finish", "desktop-cua-incomplete-no-finish", "desktop-cua-finish-signal-unreadable",
    "desktop-cua-finish-signal-invalid", "desktop-cua-cleanup-incomplete", "desktop-cua-cleanup-not-started",
    "CUA-invalid-paste-bounds", "CUA-window-or-session-closed", "CUA-input-not-exact-payload", "CUA-real-paste",
}
SAFE_FAILURE_LABELS |= {prefix + field for prefix in ("input-committed-", "input-keeps-current-owner-", "input-scroll-reveals-")
                        for field in ("host.name", "host.address", "host.username", "host.password", "host.port", "host.interval", "host.count")}
SAFE_FAILURE_CODES = {"smoke.failed", "incomplete.desktop-cua-cleanup"} | {
    prefix + "." + label for prefix in ("timeout", "check", "missing") for label in SAFE_FAILURE_LABELS
}
SAFE_APPKIT_EVENTS = {"scheduled", "dispatched", "returned-from-terminate", "will-terminate"}


def sanitized_smoke_failure(report: dict[str, object]) -> str | None:
    value = report.get("failureCode")
    if value is None:
        return None
    # Shape checks alone would still allow arbitrary app/user text into logs.
    # Return only exact fixed scenario codes; never stringify unknown values.
    return value if isinstance(value, str) and value in SAFE_FAILURE_CODES else "unrecognized-static-code"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1_048_576), b""):
            value.update(chunk)
    return value.hexdigest()


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def read_json(path: Path) -> object:
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid() or value.st_size > 1_048_576:
        raise ValueError("owned-small-regular-json-required")
    return json.loads(path.read_text(encoding="utf-8"))


def owned_child_stop(process: subprocess.Popen[bytes]) -> tuple[int, str]:
    # Only this live Popen-owned child, never a discovered/stale PID or name-based kill.
    if process.poll() is not None:
        return process.returncode, "already-exited"
    process.terminate()
    try:
        return process.wait(timeout=8), "owned-child-SIGTERM"
    except subprocess.TimeoutExpired:
        process.kill()
        return process.wait(timeout=8), "owned-child-SIGKILL"


def validate_report(directory: Path, phase: str, returncode: int, timed_out: bool) -> dict[str, object]:
    errors: list[str] = []
    if timed_out:
        errors.append("process-timeout-not-natural-exit")
    if returncode != 0:
        errors.append("process-exit-not-zero")
    try:
        report = read_json(directory / f"smoke-{phase}.json")
        if not isinstance(report, dict):
            raise ValueError("report-object-required")
    except (OSError, ValueError, TypeError):
        errors.append("smoke-evidence-missing-or-invalid")
        report = {}
    smoke_failure = sanitized_smoke_failure(report)
    if (report.get("kind") != "HostProbe-native-GUI" or report.get("phase") != phase
            or report.get("passed") is not True or report.get("productRuntimeVerified") is not False):
        errors.append("report-contract-or-phase-failed")
    checks = report.get("checks")
    names: set[str] = set()
    if not isinstance(checks, list) or not checks:
        errors.append("checks-required")
    else:
        for item in checks:
            if not isinstance(item, dict) or item.get("passed") is not True or not isinstance(item.get("name"), str):
                errors.append("check-failed-or-invalid")
                continue
            names.add(item["name"])
    if not REQUIRED[phase].issubset(names):
        errors.append("required-checks-missing")
    try:
        audit = read_json(directory / "termination-audit.json")
        if not isinstance(audit, dict) or not isinstance(audit.get("events"), list):
            raise ValueError("termination-audit-events-required")
    except (OSError, ValueError, TypeError):
        errors.append("termination-evidence-missing-or-invalid")
        audit = {}
    events = audit.get("events", [])
    event_names = [item["event"] for item in events if isinstance(item, dict)
                   and isinstance(item.get("event"), str) and item["event"] in SAFE_APPKIT_EVENTS]
    if not all(name in event_names for name in ("scheduled", "dispatched", "will-terminate")):
        errors.append("AppKit-termination-not-observed")
    if phase == "desktop-cua" and not any(
        isinstance(item, dict) and item.get("desktopCleanupFinished") is True for item in events
    ):
        errors.append("desktop-stores-cleanup-not-observed")
    return {"passed": not errors, "errors": sorted(set(errors)), "checkCount": len(names),
            "smokeFailureCode": smoke_failure,
            "requiredCheckCount": len(REQUIRED[phase]), "AppKitEvents": event_names,
            "scope": ("ready/finish lifecycle only; GUI interactions not asserted" if phase == "desktop-cua"
                      else "in-process controls with substitute network driver; no pixels or SSH/SFTP interoperability"),
            "productRuntimeVerified": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True, help="Absolute path to a built HostProbe .app")
    parser.add_argument("--expected-sha256", required=True, help="Reviewed main binary digest; refuses mismatch")
    parser.add_argument("--phase", choices=PHASES, required=True)
    parser.add_argument("--timeout", type=float, help="10..660 seconds; default 640 desktop-cua, otherwise 120")
    args = parser.parse_args()
    timeout = args.timeout if args.timeout is not None else (640 if args.phase == "desktop-cua" else 120)
    if not 10 <= timeout <= 660:
        parser.error("timeout must be 10..660")
    if not args.app.is_absolute() or args.app.name != "OpenLXSSH.app" or args.app.is_symlink():
        parser.error("app must be an absolute non-symlink OpenLXSSH.app")
    source = args.app.resolve(strict=True)
    binary = source / "Contents/MacOS/OpenLXSSH"
    if binary.is_symlink() or not stat.S_ISREG(binary.stat().st_mode):
        parser.error("main binary must be a regular non-symlink file")
    expected = args.expected_sha256.lower()
    if len(expected) != 64 or any(character not in "0123456789abcdef" for character in expected) or digest(binary) != expected:
        parser.error("main binary sha256 mismatch")
    with (source / "Contents/Info.plist").open("rb") as info:
        plist = plistlib.load(info)
    if plist.get("CFBundleExecutable") != "OpenLXSSH":
        parser.error("unexpected executable identity")
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    evidence = EVIDENCE / f"{args.phase}-{uuid.uuid4()}"
    evidence.mkdir(mode=0o700)
    # Freeze independently; do not codesign, rebuild, alter or remove the source app.
    frozen = evidence / "OpenLXSSH.app"
    shutil.copytree(source, frozen, symlinks=True)
    executable = frozen / "Contents/MacOS/OpenLXSSH"
    if digest(executable) != expected:
        raise ValueError("frozen-binary-sha256-mismatch")
    directory = Path(tempfile.mkdtemp(prefix="OpenLXSSH-AppSmoke-NativeProbe-R1-"))
    os.chmod(directory, 0o700)
    marker = directory / ".openlxssh-app-smoke"
    marker.write_text("OpenLXSSH isolated GUI smoke\n", encoding="utf-8")
    marker.chmod(0o600)
    command = [str(executable), "--self-test-data-dir", str(directory), "--self-test-phase", args.phase]
    metadata = {"phase": args.phase, "command": command, "cwd": str(ROOT), "binarySHA256": expected,
                "sourceApp": str(source), "frozenApp": str(frozen), "isolatedRoot": str(directory),
                "timeoutSeconds": timeout, "uid": os.getuid(), "startedEpoch": time.time()}
    interrupted = False
    timed_out = False
    stopped = "none"
    with (evidence / "app.log").open("xb") as log:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        metadata["pid"] = process.pid
        write_json(evidence / "run.json", metadata)
        print(json.dumps({"evidence": str(evidence), "isolatedRoot": str(directory), "pid": process.pid,
                          "phase": args.phase, "officialCUARequired": args.phase == "terminal-desktop-cua"}), flush=True)
        deadline = time.monotonic() + timeout
        previous_step = None
        try:
            while process.poll() is None:
                ready_file = directory / "Ready.json"
                if ready_file.exists():
                    ready = read_json(ready_file)
                    if isinstance(ready, dict) and ready.get("pid") == process.pid:
                        step = ready.get("expectedStep")
                        # Only fixed known steps, never arbitrary UI text/labels.
                        if step in {"inspect-desktop", "finished-desktop-cua", "incomplete-desktop-cua",
                                    "activate-terminal-and-press-Cmd-V-plain", "press-Cmd-V-bracketed",
                                    "completed-activate-terminal-and-press-Cmd-V-plain", "completed-press-Cmd-V-bracketed",
                                    "finished-or-cancelled"} and step != previous_step:
                            print(json.dumps({"pid": process.pid, "windowNumber": ready.get("windowNumber"), "expectedStep": step}), flush=True)
                            previous_step = step
                if time.monotonic() >= deadline:
                    timed_out = True
                    _, stopped = owned_child_stop(process)
                    break
                time.sleep(0.05)
        except KeyboardInterrupt:
            interrupted = True
            _, stopped = owned_child_stop(process)
        except BaseException:
            _, stopped = owned_child_stop(process)
            raise
        returncode = process.wait()
    write_json(evidence / "exit.json", {"returncode": returncode, "timedOut": timed_out,
               "interrupted": interrupted, "stopAction": stopped, "finishedEpoch": time.time()})
    for pattern in ("smoke-*.json", "control-diagnostics-*.json", "owned-window-key-diagnostics.json", "termination-audit.json", "Ready.json", "paste-routing-diagnostics.json"):
        for artifact in directory.glob(pattern):
            if artifact.is_file() and not artifact.is_symlink():
                shutil.copy2(artifact, evidence / artifact.name)
    try:
        validation = validate_report(directory, args.phase, returncode, timed_out)
    except (OSError, ValueError, TypeError):
        validation = {"passed": False, "errors": ["report-or-termination-evidence-missing-or-invalid"], "productRuntimeVerified": False}
    if interrupted:
        validation["passed"] = False
        validation["errors"] = [*validation.get("errors", []), "runner-interrupted"]
    write_json(evidence / "validation.json", validation)
    print(json.dumps({"evidence": str(evidence), "returncode": returncode, **validation}, sort_keys=True), flush=True)
    return 0 if validation["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
