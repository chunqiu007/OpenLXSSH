#!/usr/bin/env python3
"""Supervise one already-built, explicitly released HostProbe App Native keyonly case.

No build, signing, collect, relay, Docker, GUI automation or secret-file reads. Help and
validate are syntax-only. Live action requires a reviewed binary digest and the existing
local-fixture authorization; flags do not grant authorization. App uses a separately reviewed
current fixed-keyonly binding and the unchanged mature FD reader (not the old pin validator).
The primary separately verifies current fixture/relay policy; this tool never invokes Docker.
Raw App stdout/stderr is bounded and discarded, never logged.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import plistlib
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
INPUTS = ROOT / "DerivedData/AppNativeFinite/Inputs"
MATERIAL_INPUTS = ROOT / "DerivedData/AppRealIntegration/Inputs"
MARKER = ".openlxssh-native-app-finite"
MARKER_TEXT = "OpenLXSSH Native App finite v1\n"
SCENARIO = "keyonly-controller-shell"
CURRENT_IDENTITY = {
    "expectedBase": "docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d",
    "expectedImage": "sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363",
    "expectedProject": "openlxssh-fixture-61ed25328c13",
    "expectedContainer": "ed38148af68e2c6cdb70f18b9a716876754a393df2d530b168ddd2144d99021a",
    "expectedFingerprint": "SHA256:d2G+w7lBrjYDFHHd6c6GxIhk7qzFs6df1i7EVJfeUYs",
}
RECEIPTS = ("native-ready.json", "native-before-stores.json", "native-after-stores.json", "native-will-terminate.json", "native-failure.json", "native-weak-point.json")
FAILURES = frozenset(("arguments", "authorization", "contract", "unsafeInput", "staleMaterial", "preparationDeadline", "activeDeadline", "fullDeadline",
    "importFailed", "hostSaveFailed", "unexpectedSession", "unexpectedAuthentication", "trustMismatch", "typedStages", "terminalBudget", "terminalEvidence",
    "remoteExit", "closeRetired", "closeIncomplete", "drainIncomplete", "resources", "sourceChanged", "cleanup", "beforeStoresClose", "storesClose",
    "afterStoresClose", "quitOrder", "reportWrite", "cancelled", "operation"))
REPORT_KEYS = frozenset(("schema", "kind", "scenario", "runID", "pid", "checkpoint", "passed", "failureCode", "elapsedSeconds", "eofEvidence",
    "guiVerified", "productRuntimeVerified", "authentication", "terminal", "exitStatus", "closeDisposition", "canonicalDrained", "nativeInputBytesAfterExit",
    "nativeInputEvidence", "driverQueueSnapshotEmpty", "sourceKeyUnchanged", "fixtureKnownHostsUnchanged", "trustMatchedOutOfBand", "credentialCalls",
    "connectionAttempts", "productionSessions", "filesVisible", "transferJobs", "filesOperations", "descriptorBaseline", "descriptorAfter", "registryBaselineActive", "registryBaselineRetired",
    "registryAfterActive", "registryAfterRetired", "weakDriverReleased", "weakViewReleased", "localStoreRemoved", "quit", "cleanup", "weakPointWritten", "descriptorSnapshots"))
CLEANUP_STAGES = frozenset(("exerciseRunning", "exerciseReturned", "closingTabs", "weakWait", "descriptorWait", "sourceCheck", "metadataDelete", "ready", "quit"))
CLEANUP_KEYS = frozenset(("cleanupStage", "weakTabAlive", "weakDriverAlive", "weakViewAlive", "terminalHasSuperview", "terminalHasWindow",
                          "currentSessionTabCount", "workspaceIsVault", "descriptorObserved", "knownHostsCheckPerformed", "active"))
ACTIVE_STAGES = frozenset(("preparingHost", "awaitingDriver", "awaitingTrust", "awaitingConnected", "awaitingResize", "awaitingTerminalEvidence", "awaitingExit", "closingTab"))
ACTIVE_OPTIONAL = frozenset(("terminalEvidence", "requestedRows", "requestedColumns", "driverHasLatestResize", "driverResizeInFlight",
                             "terminalRows", "terminalColumns", "inputBeforeAdmission", "inputAfterAdmission"))
# Swift Encodable omits nil optionals. These fields are allowed to be absent, not arbitrary.
OPTIONAL_REPORT = frozenset(("failureCode", "authentication", "terminal", "exitStatus", "nativeInputBytesAfterExit", "descriptorBaseline", "descriptorAfter", "weakPointWritten", "descriptorSnapshots"))
QUIT_KEYS = frozenset(("scheduled", "dispatched", "beforeStores", "afterStores", "willTerminate"))
FD_ROLES = frozenset(("unknown", "systemTZShape", "systemICUShape", "systemLocaleShape", "systemFontShape"))
FD_PHASES = ("baseline", "cleanupFirst", "cleanupLatest")
FD_ENTRY_LIMIT = 32

# A separately approved passwordonly source binding, NOT a change to CURRENT_IDENTITY.
PASSWORD_SCENARIO = "passwordonly-transient-controller-shell"
PASSWORD_WRAPPER = "native-password-fixture.json"
PASSWORD_MATERIAL = "native-password-material.json"
PASSWORD_AUTH_RECEIPT = "native-password-authentication.json"
PASSWORD_IDENTITY = {
    "expectedBase": "docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d",
    "expectedImage": "sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363",
    "expectedProject": "openlxssh-fixture-61ed25328c13",
    "expectedContainer": "ca01afad3e3b02e90369f29d153aceecd07ba6fced28befdf8b4163f7c27172c",
    "expectedFingerprint": "SHA256:YAP/B5jFVHLnyPzRrU3/CJune9REpBSMnm87wcirrJ8",
    "networkID": "b949645e158058f7484e21b758459f8d0e6a284f0d2bb641879faf67f2b50ed1",
    "context": "desktop-linux",
    "endpoint": "unix:///Users/liuwenshuo/.docker/run/docker.sock",
}
PASSWORD_AUTHENTICATION = {"primaryMethod": "password", "primaryStarted": 1, "primaryResults": 1, "primaryCode": 0,
    "primaryAuthenticated": True, "authenticatedEvents": 1, "shellReadyEvents": 1}
PASSWORD_TRANSIENT = {"preparedTabCount": 0, "preparedConnectionAttempts": 0, "preparedIntentConsumed": False,
    "commitCount": 1, "committedTabCount": 1, "intentConsumed": True, "primaryProviderCalls": 1}


MFA_WRAPPER = "native-mfa-fixture.json"
MFA_MATERIAL = "native-mfa-material.json"
MFA_POLICY = "native-mfa-policy.json"
MFA_AUTH_RECEIPT = "native-mfa-authentication.json"
MFA_CLEANUP_RECEIPT = "native-mfa-cleanup.json"
MFA_IDENTITIES = {
    "keyki-controller-shell": {"service": "key-kbd", "port": 22223, "key": "edplain",
        "expectedContainer": "8fe5caf91cd453465d0c90c9c3c6607d7d37252b0a12756048296d26f076dee6",
        "expectedFingerprint": "SHA256:zzZ9B7L8srAQFmIettj3r/r1XwuSSfvZFAs8K2SmWvE"},
    "passwordki-transient-controller-shell": {"service": "password-kbd", "port": 22224, "key": "none",
        "expectedContainer": "5dcc3e0f4cbdae036c7b45113d3b86f06bcf314f20ee6ef03d39a195e009c38c",
        "expectedFingerprint": "SHA256:M89ZPAwqBO3k4+50seWt4j0oCpqAamqWCicE+q1hibc"},
}
MFA_KEYBOARD = {"rounds": 4, "replies": 4, "secretReplies": 3, "zeroReplies": 1, "managementReads": 3,
    "lateReplies": 0, "fieldCounts": [1, 1, 1, 0], "echoFlags": [[False], [False], [False], []]}


class Refusal(Exception):
    """Static labels only; never propagate OS paths, file contents or thrown descriptions."""


def refuse(label: str) -> None:
    raise Refusal(label)


def syntax(path: str) -> None:
    if (not path.startswith("/") or len(path.encode()) >= 4096 or path.endswith("/") or "$" in path
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in path) or any(part in ("", ".", "..") for part in path[1:].split("/"))):
        refuse("path-syntax")


def contract_id(path: str) -> str:
    syntax(path)
    match = re.fullmatch(re.escape(str(INPUTS)) + r"/run-([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})/native-app-fixture\.json", path)
    if not match or str(uuid.UUID(match[1])) != match[1]:
        refuse("contract-path")
    return match[1]


def no_acl(fd: int, path: Path, directory: bool) -> None:
    # Darwin's ACL display is metadata-only and never reads file data. Called solely in
    # explicitly selected preflight/live, never help/validate. App applies its own FD ACL gate.
    probe = subprocess.run(["/bin/ls", "-lde", str(path)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    if probe.returncode or len(probe.stdout) > 4096:
        refuse("acl-metadata")
    lines = probe.stdout.splitlines()
    if len(lines) != 1 or len(lines[0].split(maxsplit=1)[0]) < 10 or b"+" in lines[0].split(maxsplit=1)[0]:
        refuse("acl-refused")
    info = os.fstat(fd)
    if directory and not stat.S_ISDIR(info.st_mode):
        refuse("directory-type")


def opened(path: Path, directory: bool, private: bool = True) -> int:
    syntax(str(path))
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open("/", flags | os.O_DIRECTORY)
    try:
        parts = path.parts[1:]
        for index, component in enumerate(parts):
            child = os.open(component, flags | (os.O_DIRECTORY if directory or index < len(parts) - 1 else 0), dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        expected = 0o700 if directory else 0o600
        if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                or (private and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != expected))
                or (not directory and info.st_nlink != 1)):
            refuse("private-file-policy")
        if private:
            no_acl(fd, path, directory)
        return fd
    except BaseException:
        os.close(fd)
        raise


def stable_read(path: Path, limit: int) -> bytes:
    parent = opened(path.parent, True)
    os.close(parent)
    fd = opened(path, False)
    try:
        before = os.fstat(fd)
        if not 0 <= before.st_size <= limit:
            refuse("public-input-size")
        data = os.read(fd, limit + 1)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if len(data) != before.st_size or len(data) > limit or identity(before) != identity(after) or identity(before) != identity(named):
            refuse("public-input-changed")
        return data
    finally:
        os.close(fd)


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            refuse("duplicate-json-key")
        value[key] = item
    return value


def public_json(path: Path, limit: int) -> object:
    try:
        return json.loads(stable_read(path, limit), object_pairs_hook=unique_object,
                          parse_constant=lambda _: refuse("json-nonfinite"))
    except (UnicodeError, ValueError):
        refuse("public-json")


def digest_binary(path: Path) -> str:
    fd = opened(path, False, private=False)
    try:
        before = os.fstat(fd)
        if before.st_uid != os.getuid() or before.st_mode & 0o022 or before.st_size > 512 * 1024 * 1024:
            refuse("binary-file-policy")
        value = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1_048_576)
            if not chunk:
                break
            value.update(chunk)
        after = os.fstat(fd)
        if (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            refuse("binary-changed")
        return value.hexdigest()
    finally:
        os.close(fd)


def wrapper(path: Path) -> tuple[str, dict[str, object]]:
    run_id = contract_id(str(path))
    for directory in (INPUTS, path.parent):
        fd = opened(directory, True); os.close(fd)
    raw = stable_read(path, 4096)
    # Match the App's intentionally closed ASCII/escaped-slash grammar, not general JSON.
    if any(byte > 126 or (byte < 32 and byte not in (9, 10, 13)) for byte in raw) or re.search(rb"\\(?!/)", raw):
        refuse("closed-json-grammar")
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError):
        refuse("wrapper-json")
    if (not isinstance(value, dict) or set(value) != {"schema", "runID", "scenario", "materialContractPath"}
            or type(value["schema"]) is not int or value["schema"] != 1 or value["runID"] != run_id or value["scenario"] != SCENARIO
            or value["materialContractPath"] != str(MATERIAL_INPUTS / ("run-" + run_id) / "app-real-integration.json")):
        refuse("wrapper-contract")
    if stable_read(path.parent / MARKER, 256) != (MARKER_TEXT + run_id + "\n").encode():
        refuse("wrapper-marker")
    # Public JSON only. No .runtime path is opened by this supervisor.
    material = public_json(Path(value["materialContractPath"]), 8192)
    material_keys = {"schema", "runID", "host", "port", "user", "service", "generation", "expectedBase", "expectedImage", "expectedProject",
                     "expectedContainer", "expectedFingerprint", "collectedAt", "preparedAt", "provenanceSHA256", "knownHostsSHA256", "generationPublicKeySHA256"}
    if (not isinstance(material, dict) or set(material) not in (material_keys, material_keys | {"phase"})
            or type(material.get("schema")) is not int or material["schema"] != 1
            or material.get("runID") != run_id or material.get("phase", "read-only") != "read-only"):
        refuse("material-case")
    if (material.get("host"), material.get("port"), material.get("user"), material.get("service")) != ("127.0.0.1", 22221, "fixture", "keyonly"):
        refuse("material-endpoint")
    if any(material.get(key) != expected for key, expected in CURRENT_IDENTITY.items()):
        refuse("material-current-binding")
    generation = material.get("generation")
    if (not isinstance(generation, str) or not re.fullmatch(re.escape(str(ROOT / "Tests/IntegrationEnvironment/.runtime/keyonly/credentials-")) + r"[0-9a-f]{12}", generation)
            or any(not isinstance(material.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", material[key])
                   for key in ("provenanceSHA256", "knownHostsSHA256", "generationPublicKeySHA256"))):
        refuse("material-public-provenance")
    now = time.time()
    collected, prepared = material.get("collectedAt"), material.get("preparedAt")
    if (any(type(item) not in (int, float) or not math.isfinite(item) for item in (collected, prepared))
            or not 0 < collected <= prepared <= now or now - collected > 120):
        refuse("material-freshness")
    return run_id, material


def exclusive_json(directory: Path, name: str, value: object) -> None:
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":")); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())


def password_contract_id(path: str) -> str:
    syntax(path)
    match = re.fullmatch(re.escape(str(INPUTS)) + r"/run-([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})/native-password-fixture\.json", path)
    if not match or str(uuid.UUID(match[1])) != match[1]:
        refuse("password-contract-path")
    return match[1]


def selected_contract_id(path: str) -> str:
    if path.endswith("/native-concurrent-fixture.json"):
        return concurrent_contract_id(path)
    if path.endswith("/native-trust-fixture.json"):
        return trust_contract_id(path)
    if path.endswith("/native-files-cancel.json"):
        return cancel_contract_id(path)
    if path.endswith("/native-files-conflict.json"):
        return conflict_contract_id(path)
    if path.endswith("/native-files-fixture.json"):
        return files_contract_id(path)
    if path.endswith("/" + MFA_WRAPPER):
        return mfa_contract_id(path)
    return password_contract_id(path) if path.endswith("/" + PASSWORD_WRAPPER) else contract_id(path)


def password_public_object(raw: bytes, keys: set[str]) -> dict[str, object]:
    # Same intentionally flat ASCII grammar as the new App schema; no old decoder/path gate.
    if not raw or any(byte > 126 or (byte < 32 and byte not in (9, 10, 13)) for byte in raw):
        refuse("password-json-grammar")
    string = rb'"(?:[\x20-\x21\x23-\x5b\x5d-\x7e]|\\/)*"'
    number = rb'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?'
    field = string + rb'\s*:\s*(?:' + string + rb'|' + number + rb')'
    if not re.fullmatch(rb'\s*\{\s*' + field + rb'(?:\s*,\s*' + field + rb')*\s*\}\s*', raw):
        refuse("password-json-grammar")
    try:
        value = json.loads(raw, object_pairs_hook=unique_object, parse_constant=lambda _: refuse("password-json-nonfinite"))
    except (UnicodeError, ValueError):
        refuse("password-json")
    if not isinstance(value, dict) or set(value) != keys:
        refuse("password-json-fields")
    return value


def password_wrapper(path: Path) -> tuple[str, dict[str, object]]:
    run_id = password_contract_id(str(path))
    for directory in (INPUTS, path.parent):
        fd = opened(directory, True); os.close(fd)
    value = password_public_object(stable_read(path, 4096), {"schema", "runID", "scenario", "materialContractPath"})
    material_path = path.parent / PASSWORD_MATERIAL
    if (type(value["schema"]) is not int or value["schema"] != 1 or value["runID"] != run_id
            or value["scenario"] != PASSWORD_SCENARIO or value["materialContractPath"] != str(material_path)):
        refuse("password-wrapper-contract")
    if stable_read(path.parent / MARKER, 256) != (MARKER_TEXT + run_id + "\n").encode():
        refuse("password-wrapper-marker")
    keys = {"schema", "runID", "host", "port", "user", "service", "generation", "expectedBase", "expectedImage", "expectedProject",
            "expectedContainer", "expectedFingerprint", "networkID", "context", "endpoint", "collectedAt", "preparedAt", "provenanceSHA256", "knownHostsSHA256"}
    material = password_public_object(stable_read(material_path, 8192), keys)
    numbers = {"schema", "port", "collectedAt", "preparedAt"}
    if (any(type(material[key]) is not str for key in keys - numbers)
            or type(material["schema"]) is not int or material["schema"] != 1 or material["runID"] != run_id
            or type(material["port"]) is not int or material["port"] != 22222
            or (material["host"], material["user"], material["service"]) != ("127.0.0.1", "fixture", "passwordonly")
            or any(material[key] != expected for key, expected in PASSWORD_IDENTITY.items())):
        refuse("password-material-binding")
    if (not re.fullmatch(re.escape(str(ROOT / "Tests/IntegrationEnvironment/.runtime/passwordonly/credentials-")) + r"[0-9a-f]{12}", material["generation"])
            or any(not re.fullmatch(r"[0-9a-f]{64}", material[key]) for key in ("provenanceSHA256", "knownHostsSHA256"))):
        refuse("password-material-provenance")
    collected, prepared, now = material["collectedAt"], material["preparedAt"], time.time()
    if (any(type(item) not in (int, float) or not math.isfinite(item) for item in (collected, prepared))
            or not 0 < collected <= prepared <= now or now - collected > 120):
        refuse("password-material-freshness")
    return run_id, material


def mfa_contract_id(path: str) -> str:
    syntax(path)
    match = re.fullmatch(re.escape(str(INPUTS)) + r"/run-([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})/native-mfa-fixture\.json", path)
    if not match or str(uuid.UUID(match[1])) != match[1]:
        refuse("mfa-contract-path")
    return match[1]


def mfa_wrapper(path: Path) -> tuple[str, dict[str, object]]:
    run_id = mfa_contract_id(str(path))
    for directory in (INPUTS, path.parent):
        fd = opened(directory, True); os.close(fd)
    value = password_public_object(stable_read(path, 4096), {"schema", "runID", "scenario", "materialContractPath"})
    scenario = value.get("scenario")
    if (type(value.get("schema")) is not int or value["schema"] != 1 or value.get("runID") != run_id
            or type(scenario) is not str or scenario not in MFA_IDENTITIES
            or value.get("materialContractPath") != str(path.parent / MFA_MATERIAL)):
        refuse("mfa-wrapper-binding")
    if stable_read(path.parent / MARKER, 256) != (MARKER_TEXT + run_id + "\n").encode():
        refuse("mfa-wrapper-marker")
    identity = MFA_IDENTITIES[scenario]
    keys = {"schema", "runID", "host", "port", "user", "service", "key", "generation", "expectedBase", "expectedImage", "expectedProject",
            "expectedContainer", "expectedFingerprint", "networkID", "context", "endpoint", "collectedAt", "preparedAt", "provenanceSHA256", "knownHostsSHA256", "policyProofSHA256"}
    uses_key = identity["key"] == "edplain"
    if uses_key:
        keys.add("generationPublicKeySHA256")
    material = password_public_object(stable_read(path.parent / MFA_MATERIAL, 8192), keys)
    numeric = {"schema", "port", "collectedAt", "preparedAt"}
    common = {key: PASSWORD_IDENTITY[key] for key in ("expectedBase", "expectedImage", "expectedProject", "networkID", "context", "endpoint")}
    if (any(type(material[key]) is not str for key in keys - numeric)
            or type(material["schema"]) is not int or material["schema"] != 1 or material["runID"] != run_id
            or type(material["port"]) is not int or (material["host"], material["user"]) != ("127.0.0.1", "fixture")
            or any(material[key] != expected for key, expected in {**common, **identity}.items())):
        refuse("mfa-material-binding")
    digests = ["provenanceSHA256", "knownHostsSHA256", "policyProofSHA256"] + (["generationPublicKeySHA256"] if uses_key else [])
    if (not re.fullmatch(re.escape(str(ROOT / ("Tests/IntegrationEnvironment/.runtime/" + identity["service"] + "/credentials-"))) + r"[0-9a-f]{12}", material["generation"])
            or any(not re.fullmatch(r"[0-9a-f]{64}", material[key]) for key in digests)):
        refuse("mfa-material-provenance")
    collected, prepared, now = material["collectedAt"], material["preparedAt"], time.time()
    if (any(type(item) not in (int, float) or not math.isfinite(item) for item in (collected, prepared))
            or not 0 < collected <= prepared <= now or now - collected > 120):
        refuse("mfa-material-freshness")
    raw = stable_read(path.parent / MFA_POLICY, 4096)
    if hashlib.sha256(raw).hexdigest() != material["policyProofSHA256"]:
        refuse("mfa-policy-proof-digest")
    flags = {"runningHealthy", "readonlyRoot", "notPrivileged", "logNone", "loopbackPortExact", "internalBridge", "noBindMounts", "rootPolicyMulti"}
    proof = password_public_object(raw, flags | {"schema", "runID", "service", "containerID", "imageID", "baseImage", "project", "networkID", "context", "endpoint", "port", "verifiedAt"})
    expected = {"schema": 1, "runID": run_id, "service": material["service"], "containerID": material["expectedContainer"], "imageID": material["expectedImage"],
                "baseImage": material["expectedBase"], "project": material["expectedProject"], "networkID": material["networkID"], "context": material["context"],
                "endpoint": material["endpoint"], "port": material["port"], **{key: 1 for key in flags}}
    exact_public_facts({key: proof[key] for key in expected}, expected, "mfa-policy-proof-binding")
    verified = proof["verifiedAt"]
    if type(verified) not in (int, float) or not math.isfinite(verified) or not collected <= verified <= prepared or now - verified > 120:
        refuse("mfa-policy-proof-freshness")
    return run_id, material


def preflight(args: argparse.Namespace) -> tuple[Path, str, Path]:
    started = time.monotonic()
    if args.contract.name == "native-concurrent-fixture.json":
        run_id, material = concurrent_wrapper(args.contract)
    elif args.contract.name == "native-trust-fixture.json":
        run_id, material = trust_wrapper(args.contract)
    elif args.contract.name == "native-files-cancel.json":
        run_id, material = cancel_wrapper(args.contract)
    elif args.contract.name == "native-files-conflict.json":
        run_id, material = conflict_wrapper(args.contract)
    elif args.contract.name == "native-files-fixture.json":
        run_id, material = files_wrapper(args.contract)
    elif args.contract.name == MFA_WRAPPER:
        run_id, material = mfa_wrapper(args.contract)
    else:
        run_id, material = password_wrapper(args.contract) if args.contract.name == PASSWORD_WRAPPER else wrapper(args.contract)
    syntax(str(args.app))
    if args.app.name != "OpenLXSSH.app":
        refuse("app-path")
    for directory in (args.app, args.app / "Contents", args.app / "Contents/MacOS"):
        fd = opened(directory, True, private=False); os.close(fd)
    binary = args.app / "Contents/MacOS/OpenLXSSH"
    if digest_binary(binary) != args.expected_sha256:
        refuse("binary-digest")
    plist_path = args.app / "Contents/Info.plist"
    fd = opened(plist_path, False, private=False)
    try:
        info = os.fstat(fd)
        if info.st_size > 65536:
            refuse("plist-size")
        plist = plistlib.loads(os.read(fd, 65537))
    finally:
        os.close(fd)
    if (plist.get("CFBundleIdentifier") != "org.openlxssh.OpenLXSSH" or plist.get("CFBundleExecutable") != "OpenLXSSH"
            or plist.get("OpenLXSSHRealFixtureHostProbe") is not True or type(plist.get("OpenLXSSHRealFixtureBuildEpoch")) not in (float, int)
            or not math.isfinite(plist["OpenLXSSHRealFixtureBuildEpoch"]) or plist["OpenLXSSHRealFixtureBuildEpoch"] <= 0):
        refuse("hostprobe-plist")
    if material["collectedAt"] < plist["OpenLXSSHRealFixtureBuildEpoch"] or time.time() - material["collectedAt"] > 120:
        refuse("material-build-epoch-or-expiry")
    if args.contract.name == CONCURRENT_WRAPPER:
        raw = stable_read(args.contract.parent / CONCURRENT_POLICY, 4096)
        if hashlib.sha256(raw).hexdigest() != material["policyProofSHA256"]:
            refuse("concurrent-policy-changed")
        policy = password_public_object(raw,
            {"schema", "runID", "service", "containerID", "imageID", "baseImage", "project", "networkID", "context", "endpoint", "port", "verifiedAt",
             "runningHealthy", "readonlyRoot", "notPrivileged", "logNone", "loopbackPortExact", "internalBridge", "noBindMounts", "rootPolicyMulti"})
        if policy["verifiedAt"] < plist["OpenLXSSHRealFixtureBuildEpoch"]:
            refuse("concurrent-policy-build-epoch")
    if args.contract.name == MFA_WRAPPER:
        raw = stable_read(args.contract.parent / MFA_POLICY, 4096)
        if hashlib.sha256(raw).hexdigest() != material["policyProofSHA256"]:
            refuse("mfa-policy-proof-changed")
        proof = json.loads(raw, object_pairs_hook=unique_object)
        if proof["verifiedAt"] < plist["OpenLXSSHRealFixtureBuildEpoch"]:
            refuse("mfa-policy-proof-build-epoch")
    # Verify only, never sign, repair or look up credentials/identities.
    verified = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", "--deep",
        '-R=anchor apple generic and identifier "org.openlxssh.OpenLXSSH"', str(args.app)], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    if verified.returncode:
        refuse("signature-refused")
    selected_receipts = RECEIPTS + ((PASSWORD_AUTH_RECEIPT,) if args.contract.name == PASSWORD_WRAPPER else ())
    if args.contract.name == MFA_WRAPPER:
        selected_receipts += (MFA_AUTH_RECEIPT, MFA_CLEANUP_RECEIPT)
    if args.contract.name == "native-files-fixture.json":
        selected_receipts += ("native-files-transfer.json",)
    if args.contract.name == "native-files-conflict.json":
        selected_receipts += ("native-files-conflict-transfer.json",)
    if args.contract.name == "native-concurrent-fixture.json":
        selected_receipts += ("native-concurrent-authentication.json", "native-concurrent-cleanup.json")
    if args.contract.name == "native-trust-fixture.json":
        selected_receipts += ("native-trust-authentication-1.json", "native-trust-authentication-2.json")
    if args.contract.name == "native-files-cancel.json":
        selected_receipts += ("native-files-cancel-transfer.json",)
    for name in selected_receipts + ("supervisor.json",):
        if os.path.lexists(args.contract.parent / name):
            refuse("receipt-already-exists")
    if time.monotonic() - started > 20:
        refuse("preflight-deadline")
    return binary, run_id, args.contract.parent


def owned_stop(process: subprocess.Popen[bytes]) -> str:
    if process.poll() is not None:
        return "already-exited"
    process.terminate()
    try:
        process.wait(timeout=4)
        return "owned-SIGTERM"
    except subprocess.TimeoutExpired:
        process.kill(); process.wait(timeout=4)
        return "owned-SIGKILL"


def check_active_diagnostic(active: object) -> None:
    if (not isinstance(active, dict) or not {"activeStage"} <= set(active)
            or not set(active) <= ACTIVE_OPTIONAL | {"activeStage"} or active.get("activeStage") not in ACTIVE_STAGES):
        refuse("active-diagnostic-schema")
    for key in ("requestedRows", "requestedColumns", "terminalRows", "terminalColumns"):
        if key in active and (type(active[key]) is not int or not 1 <= active[key] <= 65535):
            refuse("active-diagnostic-cells")
    for key in ("driverHasLatestResize", "driverResizeInFlight"):
        if key in active and type(active[key]) is not bool:
            refuse("active-diagnostic-resize")
    for key in ("inputBeforeAdmission", "inputAfterAdmission"):
        if key not in active:
            continue
        queue = active[key]
        if (not isinstance(queue, dict) or set(queue) != {"pendingBytes", "pendingItems"}
                or any(type(queue[field]) is not int or queue[field] < 0 for field in queue)
                or queue["pendingBytes"] > 256 * 1024 or queue["pendingItems"] > 128):
            refuse("active-diagnostic-input")
    if "terminalEvidence" in active:
        evidence = active["terminalEvidence"]
        required = {"ack", "pty", "resized113x37", "completed"}
        optional = {"observedRows", "observedColumns"}
        if (not isinstance(evidence, dict) or not required <= set(evidence) or not set(evidence) <= required | optional
                or any(type(evidence[key]) is not bool for key in required)
                or any(type(evidence[key]) is not int or not 1 <= evidence[key] <= 65535 for key in optional if key in evidence)
                or ("observedRows" in evidence) != ("observedColumns" in evidence)):
            refuse("active-diagnostic-terminal")


def check_descriptor_snapshots(value: object, report: dict[str, object] | None = None) -> None:
    """Strict scalar schema only. Unknown/truncated observations NEVER exempt a count/weak gate."""
    required = {"schema", "maximumEntries", "atomic", "continuousOpenProven"}
    if (not isinstance(value, dict) or not required <= set(value) or not set(value) <= required | set(FD_PHASES)
            or type(value["schema"]) is not int or value["schema"] != 1
            or type(value["maximumEntries"]) is not int or value["maximumEntries"] != FD_ENTRY_LIMIT
            or value["atomic"] is not False or value["continuousOpenProven"] is not False
            or ("cleanupFirst" in value) != ("cleanupLatest" in value)
            or ("cleanupFirst" in value and "baseline" not in value)):
        refuse("descriptor-diagnostic-schema")
    previous = 0.0
    for phase in FD_PHASES:
        if phase not in value:
            continue
        snapshot = value[phase]
        if not isinstance(snapshot, dict) or set(snapshot) != {"elapsedSeconds", "scanUpperExclusive", "count", "truncated", "complete", "entries"}:
            refuse("descriptor-snapshot-schema")
        elapsed, upper, count, entries = (snapshot[key] for key in ("elapsedSeconds", "scanUpperExclusive", "count", "entries"))
        if (type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < previous
                or type(upper) is not int or not 0 < upper <= 1_048_576 or type(count) is not int or not 0 <= count <= upper
                or not isinstance(entries, list) or len(entries) != min(count, FD_ENTRY_LIMIT)
                or type(snapshot["truncated"]) is not bool or snapshot["truncated"] != (count > FD_ENTRY_LIMIT)
                or type(snapshot["complete"]) is not bool):
            refuse("descriptor-snapshot-values")
        previous, last = elapsed, -1
        for row in entries:
            keys = {"fd", "probeStatus", "role"}
            if (not isinstance(row, dict) or not keys <= set(row) or not set(row) <= keys | {"type", "dev", "ino", "access"}
                    or type(row["fd"]) is not int or not last < row["fd"] < upper
                    or type(row["probeStatus"]) is not str or row["probeStatus"] not in ("stable", "unavailable", "changed")
                    or type(row["role"]) is not str or row["role"] not in FD_ROLES):
                refuse("descriptor-entry-schema")
            last = row["fd"]
            if row["probeStatus"] == "stable":
                if (set(row) != keys | {"type", "dev", "ino", "access"}
                        or type(row["type"]) is not int or not 0 <= row["type"] <= 0o170000 or row["type"] & ~0o170000
                        or type(row["dev"]) is not int or not -(2**31) <= row["dev"] < 2**31
                        or type(row["ino"]) is not int or not 0 <= row["ino"] < 2**64
                        or type(row["access"]) is not int or row["access"] not in (0, 1, 2)
                        or (row["role"] != "unknown" and (row["type"] != stat.S_IFREG or row["access"] != 0))):
                    refuse("descriptor-entry-values")
            elif set(row) != keys or row["role"] != "unknown":
                refuse("descriptor-unknown-values")
        if snapshot["complete"] != (not snapshot["truncated"] and all(row["probeStatus"] == "stable" for row in entries)):
            refuse("descriptor-completeness")
    if report is not None:
        for phase, key in (("baseline", "descriptorBaseline"), ("cleanupLatest", "descriptorAfter")):
            if phase in value and value[phase]["count"] != report.get(key):
                refuse("descriptor-count-binding")
        if ("cleanupLatest" in value) != (report.get("descriptorAfter") is not None):
            refuse("descriptor-phase-binding")


def check_report(report: object, run_id: str, pid: int, checkpoint: str, removed: bool, quit_expected: dict[str, bool]) -> None:
    if not isinstance(report, dict) or not REPORT_KEYS - OPTIONAL_REPORT <= set(report) or not set(report) <= REPORT_KEYS:
        refuse("receipt-schema")
    if "weakPointWritten" in report and type(report["weakPointWritten"]) is not bool:
        refuse("weak-point-diagnostic-type")
    if "descriptorSnapshots" in report:
        check_descriptor_snapshots(report["descriptorSnapshots"], report)
    if (report.get("schema"), report.get("kind"), report.get("scenario"), report.get("runID"), report.get("pid"), report.get("checkpoint")) != (1, "HostProbe-App-Native-finite", SCENARIO, run_id, pid, checkpoint):
        refuse("receipt-identity")
    cleanup = report.get("cleanup")
    if not isinstance(cleanup, dict) or set(cleanup) != CLEANUP_KEYS or cleanup.get("cleanupStage") not in CLEANUP_STAGES:
        refuse("cleanup-diagnostic-schema")
    check_active_diagnostic(cleanup.get("active"))
    for key in CLEANUP_KEYS - {"cleanupStage", "currentSessionTabCount", "active"}:
        if type(cleanup[key]) is not bool:
            refuse("cleanup-diagnostic-type")
    if type(cleanup["currentSessionTabCount"]) is not int or cleanup["currentSessionTabCount"] < 0:
        refuse("cleanup-tab-count")
    if report.get("failureCode") is not None or report.get("passed") is not True:
        refuse("app-case-failed")
    if (cleanup["cleanupStage"] != ("ready" if checkpoint == "ready-for-native-quit" else "quit")
            or any(cleanup[key] for key in ("weakTabAlive", "weakDriverAlive", "weakViewAlive", "terminalHasSuperview", "terminalHasWindow"))
            or cleanup["currentSessionTabCount"] != 0 or not cleanup["workspaceIsVault"]
            or not cleanup["descriptorObserved"] or not cleanup["knownHostsCheckPerformed"]):
        refuse("cleanup-required-facts")
    if report.get("guiVerified") is not False or report.get("productRuntimeVerified") is not False or report.get("eofEvidence") != "notDirectlyObservable":
        refuse("receipt-scope")
    for key in ("canonicalDrained", "driverQueueSnapshotEmpty", "sourceKeyUnchanged", "fixtureKnownHostsUnchanged", "trustMatchedOutOfBand", "weakDriverReleased", "weakViewReleased"):
        if report.get(key) is not True:
            refuse("required-app-fact-missing")
    if report.get("nativeInputEvidence") == "observedWhileSessionAlive":
        if report.get("nativeInputBytesAfterExit") != 0:
            refuse("observed-native-input-not-zero")
    elif report.get("nativeInputEvidence") != "notDirectlyObservableAfterRelease" or report.get("nativeInputBytesAfterExit") is not None:
        refuse("native-input-evidence")
    if (report.get("exitStatus"), report.get("closeDisposition"), report.get("credentialCalls"), report.get("connectionAttempts"), report.get("productionSessions")) != (7, "closed", 0, 1, 1):
        refuse("app-owner-facts")
    if (report.get("filesVisible"), report.get("transferJobs"), report.get("filesOperations")) != (False, 0, 0):
        refuse("unexpected-files-work")
    authentication = report.get("authentication")
    if authentication != {"primaryMethod": "publicKey", "primaryStarted": 1, "primaryResults": 1, "primaryCode": 0,
                          "primaryAuthenticated": True, "authenticatedEvents": 1, "shellReadyEvents": 1}:
        refuse("typed-primary-facts")
    expected_terminal = {"ack": True, "pty": True, "resized113x37": True, "completed": True, "observedRows": 37, "observedColumns": 113}
    if report.get("terminal") != expected_terminal:
        refuse("remote-terminal-facts")
    active = cleanup["active"]
    if (active["activeStage"] != "closingTab" or active.get("terminalEvidence") != expected_terminal
            or (active.get("requestedRows"), active.get("requestedColumns")) != (37, 113)):
        refuse("active-required-facts")
    baseline, after = report.get("descriptorBaseline"), report.get("descriptorAfter")
    if type(baseline) is not int or baseline < 3 or after != baseline:
        refuse("descriptor-baseline")
    for kind in ("Active", "Retired"):
        if type(report.get("registryBaseline" + kind)) is not int or report.get("registryBaseline" + kind) != report.get("registryAfter" + kind):
            refuse("registry-baseline")
    elapsed = report.get("elapsedSeconds")
    if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or not 0 <= elapsed <= 90:
        refuse("app-deadline")
    if report.get("localStoreRemoved") is not removed or report.get("quit") != quit_expected:
        refuse("quit-point-facts")


def exact_public_facts(value: object, expected: dict[str, object], label: str) -> None:
    if (not isinstance(value, dict) or set(value) != set(expected)
            or any(type(value[key]) is not type(wanted) or value[key] != wanted for key, wanted in expected.items())):
        refuse(label)


def check_password_authentication(report: object, run_id: str, pid: int) -> None:
    expected_keys = {"schema", "kind", "scenario", "sourceKeyScope", "acceptanceScope", "guiVerified", "productRuntimeVerified",
                     "runID", "pid", "authentication", "transient", "credentialCalls"}
    if not isinstance(report, dict) or set(report) != expected_keys:
        refuse("password-authentication-schema")
    expected = {"schema": 1, "kind": "HostProbe-App-Native-password-authentication", "scenario": PASSWORD_SCENARIO,
                "sourceKeyScope": "notApplicablePassword", "acceptanceScope": "authentication-only-resources-unverified",
                "guiVerified": False, "productRuntimeVerified": False, "runID": run_id, "pid": pid, "credentialCalls": 0}
    exact_public_facts({key: report[key] for key in expected}, expected, "password-authentication-identity")
    exact_public_facts(report["authentication"], PASSWORD_AUTHENTICATION, "password-authentication-stages")
    exact_public_facts(report["transient"], PASSWORD_TRANSIENT, "password-authentication-transient")


def check_password_report(report: object, run_id: str, pid: int, checkpoint: str, removed: bool, quit_expected: dict[str, bool]) -> None:
    # Password has its OWN closed schema. No fake keyonly/sourceKeyUnchanged fact is constructed.
    keys = (REPORT_KEYS - {"sourceKeyUnchanged"}) | {"sourceKeyScope", "transient"}
    optional = OPTIONAL_REPORT - {"authentication", "terminal", "descriptorBaseline", "descriptorAfter"}
    if not isinstance(report, dict) or not keys - optional <= set(report) or not set(report) <= keys:
        refuse("password-receipt-schema")
    expected = {"schema": 1, "kind": "HostProbe-App-Native-finite", "scenario": PASSWORD_SCENARIO, "runID": run_id,
                "pid": pid, "checkpoint": checkpoint, "passed": True, "sourceKeyScope": "notApplicablePassword",
                "guiVerified": False, "productRuntimeVerified": False, "eofEvidence": "notDirectlyObservable",
                "exitStatus": 7, "closeDisposition": "closed", "credentialCalls": 0, "connectionAttempts": 1, "productionSessions": 1,
                "filesVisible": False, "transferJobs": 0, "filesOperations": 0, "localStoreRemoved": removed}
    exact_public_facts({key: report[key] for key in expected}, expected, "password-receipt-identity")
    if report.get("failureCode") is not None:
        refuse("password-app-case-failed")
    for key in ("canonicalDrained", "driverQueueSnapshotEmpty", "fixtureKnownHostsUnchanged", "trustMatchedOutOfBand", "weakDriverReleased", "weakViewReleased"):
        if report[key] is not True:
            refuse("password-required-app-fact")
    if "weakPointWritten" in report and type(report["weakPointWritten"]) is not bool:
        refuse("weak-point-diagnostic-type")
    if "descriptorSnapshots" in report:
        check_descriptor_snapshots(report["descriptorSnapshots"], report)
    cleanup = report["cleanup"]
    if not isinstance(cleanup, dict) or set(cleanup) != CLEANUP_KEYS:
        refuse("password-cleanup-schema")
    expected_cleanup = {"cleanupStage": "ready" if checkpoint == "ready-for-native-quit" else "quit", "weakTabAlive": False,
                        "weakDriverAlive": False, "weakViewAlive": False, "terminalHasSuperview": False, "terminalHasWindow": False,
                        "currentSessionTabCount": 0, "workspaceIsVault": True, "descriptorObserved": True, "knownHostsCheckPerformed": True}
    exact_public_facts({key: cleanup[key] for key in expected_cleanup}, expected_cleanup, "password-cleanup-required-facts")
    check_active_diagnostic(cleanup["active"])
    exact_public_facts(report["authentication"], PASSWORD_AUTHENTICATION, "password-typed-primary-facts")
    exact_public_facts(report["transient"], PASSWORD_TRANSIENT, "password-transient-facts")
    terminal = {"ack": True, "pty": True, "resized113x37": True, "completed": True, "observedRows": 37, "observedColumns": 113}
    exact_public_facts(report["terminal"], terminal, "password-terminal-facts")
    active = cleanup["active"]
    if (active["activeStage"] != "closingTab" or active.get("terminalEvidence") != terminal
            or (active.get("requestedRows"), active.get("requestedColumns")) != (37, 113)):
        refuse("password-active-required-facts")
    if report["nativeInputEvidence"] == "observedWhileSessionAlive":
        if type(report.get("nativeInputBytesAfterExit")) is not int or report["nativeInputBytesAfterExit"] != 0:
            refuse("password-observed-native-input-not-zero")
    elif report["nativeInputEvidence"] != "notDirectlyObservableAfterRelease" or report.get("nativeInputBytesAfterExit") is not None:
        refuse("password-native-input-evidence")
    baseline, after = report.get("descriptorBaseline"), report.get("descriptorAfter")
    if type(baseline) is not int or baseline < 3 or type(after) is not int or after != baseline:
        refuse("password-descriptor-baseline")
    for kind in ("Active", "Retired"):
        before, final = report["registryBaseline" + kind], report["registryAfter" + kind]
        if type(before) is not int or type(final) is not int or before != final:
            refuse("password-registry-baseline")
    elapsed = report["elapsedSeconds"]
    if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or not 0 <= elapsed <= 90:
        refuse("password-app-deadline")
    exact_public_facts(report["quit"], quit_expected, "password-quit-point-facts")


def mfa_authentication_facts(scenario: str) -> dict[str, object]:
    uses_key = MFA_IDENTITIES[scenario]["key"] == "edplain"
    return {"primaryMethod": "publicKey" if uses_key else "password", "primaryStarted": 1, "primaryResults": 1,
            "primaryCode": -19 if uses_key else -18, "primaryAuthenticated": False, "keyboardStarted": 1, "keyboardResults": 1,
            "keyboardCode": 0, "keyboardAuthenticated": True, "authenticatedEvents": 1, "shellReadyEvents": 1}


def check_mfa_keyboard(value: object) -> None:
    exact_public_facts(value, MFA_KEYBOARD, "mfa-four-round-facts")
    if (any(type(item) is not int for item in value["fieldCounts"])
            or any(type(row) is not list or any(type(flag) is not bool for flag in row) for row in value["echoFlags"])):
        refuse("mfa-four-round-types")


def check_mfa_authentication(report: object, run_id: str, pid: int, scenario: str) -> None:
    uses_key = MFA_IDENTITIES[scenario]["key"] == "edplain"
    required = {"schema", "kind", "acceptanceScope", "guiVerified", "productRuntimeVerified", "runID", "pid", "scenario", "authentication", "keyboard",
                "primaryProviderCalls", "credentialCalls", "externalPolicyProofValidated"}
    keys = required if uses_key else required | {"transient"}
    if not isinstance(report, dict) or set(report) != keys:
        refuse("mfa-authentication-schema")
    expected = {"schema": 1, "kind": "HostProbe-App-Native-MFA-authentication", "acceptanceScope": "authentication-only-resources-unverified",
                "guiVerified": False, "productRuntimeVerified": False, "runID": run_id, "pid": pid, "scenario": scenario,
                "primaryProviderCalls": 1, "credentialCalls": 0, "externalPolicyProofValidated": True}
    exact_public_facts({key: report[key] for key in expected}, expected, "mfa-authentication-binding")
    exact_public_facts(report["authentication"], mfa_authentication_facts(scenario), "mfa-authentication-stages")
    check_mfa_keyboard(report["keyboard"])
    if not uses_key:
        exact_public_facts(report["transient"], PASSWORD_TRANSIENT, "mfa-transient-facts")


def check_mfa_cleanup(report: object, run_id: str, pid: int, scenario: str, require_removed: bool) -> None:
    keys = {"schema", "kind", "acceptanceScope", "runID", "pid", "scenario", "statusReads", "serverSessionStatus", "management"}
    if not isinstance(report, dict) or set(report) != keys:
        refuse("mfa-cleanup-schema")
    expected = {"schema": 1, "kind": "HostProbe-App-Native-MFA-cleanup", "acceptanceScope": "authentication-cleanup-only-resources-unverified",
                "runID": run_id, "pid": pid, "scenario": scenario}
    exact_public_facts({key: report[key] for key in expected}, expected, "mfa-cleanup-binding")
    if type(report["statusReads"]) is not int or report["statusReads"] not in (0, 1) or report["serverSessionStatus"] not in ("removed", "present", "unknown"):
        refuse("mfa-cleanup-outcome")
    facts = report["management"]
    fact_keys = {"calls", "returnedCalls", "successfulReapedCalls", "pendingCalls", "cancellationRequested", "reapEvidenceComplete"}
    if (not isinstance(facts, dict) or set(facts) != fact_keys
            or any(type(facts[key]) is not int or facts[key] < 0 for key in ("calls", "returnedCalls", "successfulReapedCalls", "pendingCalls"))
            or type(facts["cancellationRequested"]) is not bool or type(facts["reapEvidenceComplete"]) is not bool
            or facts["returnedCalls"] + facts["pendingCalls"] != facts["calls"] or facts["successfulReapedCalls"] > facts["returnedCalls"]):
        refuse("mfa-management-facts")
    complete = facts["pendingCalls"] == 0 and facts["returnedCalls"] == facts["calls"] == facts["successfulReapedCalls"]
    if facts["reapEvidenceComplete"] != complete:
        refuse("mfa-management-reap-evidence")
    if require_removed and (report["statusReads"] != 1 or report["serverSessionStatus"] != "removed" or facts["calls"] != 4
                            or not complete or facts["cancellationRequested"] is not True):
        refuse("mfa-cleanup-required")


def check_mfa_report(report: object, run_id: str, pid: int, scenario: str, checkpoint: str, removed: bool, quit_expected: dict[str, bool]) -> None:
    uses_key = MFA_IDENTITIES[scenario]["key"] == "edplain"
    keys = (REPORT_KEYS - {"authentication", "sourceKeyUnchanged"}) | {"mfaAuthentication", "mfaKeyboard"}
    keys |= {"sourceKeyUnchanged"} if uses_key else {"sourceKeyScope", "transient"}
    optional = OPTIONAL_REPORT - {"authentication", "terminal", "descriptorBaseline", "descriptorAfter"}
    if not isinstance(report, dict) or not keys - optional <= set(report) or not set(report) <= keys:
        refuse("mfa-report-schema")
    expected = {"schema": 1, "kind": "HostProbe-App-Native-finite", "runID": run_id, "pid": pid, "scenario": scenario, "checkpoint": checkpoint,
                "passed": True, "guiVerified": False, "productRuntimeVerified": False, "eofEvidence": "notDirectlyObservable", "exitStatus": 7,
                "closeDisposition": "closed", "credentialCalls": 0, "connectionAttempts": 1, "productionSessions": 1, "filesVisible": False,
                "transferJobs": 0, "filesOperations": 0, "localStoreRemoved": removed}
    exact_public_facts({key: report[key] for key in expected}, expected, "mfa-report-identity")
    if report.get("failureCode") is not None:
        refuse("mfa-app-case-failed")
    required_facts = ["canonicalDrained", "driverQueueSnapshotEmpty", "fixtureKnownHostsUnchanged", "trustMatchedOutOfBand", "weakDriverReleased", "weakViewReleased"]
    if uses_key:
        required_facts.append("sourceKeyUnchanged")
    elif report["sourceKeyScope"] != "notApplicablePassword":
        refuse("mfa-source-key-scope")
    for key in required_facts:
        if report[key] is not True:
            refuse("mfa-required-app-fact")
    exact_public_facts(report["mfaAuthentication"], mfa_authentication_facts(scenario), "mfa-report-stages")
    check_mfa_keyboard(report["mfaKeyboard"])
    if not uses_key:
        exact_public_facts(report["transient"], PASSWORD_TRANSIENT, "mfa-report-transient")
    cleanup = report["cleanup"]
    if not isinstance(cleanup, dict) or set(cleanup) != CLEANUP_KEYS:
        refuse("mfa-shared-cleanup-schema")
    expected_cleanup = {"cleanupStage": "ready" if checkpoint == "ready-for-native-quit" else "quit", "weakTabAlive": False, "weakDriverAlive": False,
                        "weakViewAlive": False, "terminalHasSuperview": False, "terminalHasWindow": False, "currentSessionTabCount": 0,
                        "workspaceIsVault": True, "descriptorObserved": True, "knownHostsCheckPerformed": True}
    exact_public_facts({key: cleanup[key] for key in expected_cleanup}, expected_cleanup, "mfa-shared-cleanup-facts")
    check_active_diagnostic(cleanup["active"])
    terminal = {"ack": True, "pty": True, "resized113x37": True, "completed": True, "observedRows": 37, "observedColumns": 113}
    exact_public_facts(report["terminal"], terminal, "mfa-terminal-facts")
    active = cleanup["active"]
    if active["activeStage"] != "closingTab" or active.get("terminalEvidence") != terminal or (active.get("requestedRows"), active.get("requestedColumns")) != (37, 113):
        refuse("mfa-active-required-facts")
    if report["nativeInputEvidence"] == "observedWhileSessionAlive":
        if type(report.get("nativeInputBytesAfterExit")) is not int or report["nativeInputBytesAfterExit"] != 0:
            refuse("mfa-native-input-not-zero")
    elif report["nativeInputEvidence"] != "notDirectlyObservableAfterRelease" or report.get("nativeInputBytesAfterExit") is not None:
        refuse("mfa-native-input-evidence")
    before, after = report.get("descriptorBaseline"), report.get("descriptorAfter")
    if type(before) is not int or before < 3 or type(after) is not int or after != before:
        refuse("mfa-descriptor-baseline")
    for kind in ("Active", "Retired"):
        if type(report["registryBaseline" + kind]) is not int or type(report["registryAfter" + kind]) is not int or report["registryBaseline" + kind] != report["registryAfter" + kind]:
            refuse("mfa-registry-baseline")
    if "weakPointWritten" in report and type(report["weakPointWritten"]) is not bool:
        refuse("weak-point-diagnostic-type")
    if "descriptorSnapshots" in report:
        check_descriptor_snapshots(report["descriptorSnapshots"], report)
    elapsed = report["elapsedSeconds"]
    if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or not 0 <= elapsed <= 90:
        refuse("mfa-app-deadline")
    exact_public_facts(report["quit"], quit_expected, "mfa-quit-facts")


def supervise(args: argparse.Namespace, binary: Path, run_id: str, directory: Path) -> int:
    concurrent = args.contract.name == "native-concurrent-fixture.json"
    trust = args.contract.name == "native-trust-fixture.json"
    cancel = args.contract.name == "native-files-cancel.json"
    conflict = args.contract.name == "native-files-conflict.json"
    files = args.contract.name == "native-files-fixture.json"
    password = args.contract.name == PASSWORD_WRAPPER
    mfa = args.contract.name == MFA_WRAPPER
    scenario = None
    if concurrent:
        scenario = CONCURRENT_SCENARIO
        command = [str(binary), "--native-concurrent-fixture-test", "--native-concurrent-fixture-contract", str(args.contract), "--authorized-local-fixture", "--primary-released"]
    elif trust:
        selected = password_public_object(stable_read(args.contract, 4096), {"schema", "runID", "scenario", "materialContractPath"})
        scenario = selected["scenario"]
        if scenario not in TRUST_SCENARIOS:
            refuse("trust-scenario")
        command = [str(binary), "--native-trust-fixture-test", "--native-trust-fixture-contract", str(args.contract), "--authorized-local-fixture", "--primary-released"]
    elif cancel:
        command = [str(binary), "--native-files-cancel-test", "--native-files-cancel-contract", str(args.contract), "--authorized-local-fixture", "--primary-released"]
    elif conflict:
        command = [str(binary), "--native-files-conflict-test", "--native-files-conflict-contract", str(args.contract), "--authorized-local-fixture", "--primary-released"]
    elif files:
        command = [str(binary), "--native-files-fixture-test", "--native-files-fixture-contract", str(args.contract), "--authorized-local-fixture", "--primary-released"]
    elif mfa:
        wrapper_value = password_public_object(stable_read(args.contract, 4096), {"schema", "runID", "scenario", "materialContractPath"})
        scenario = wrapper_value["scenario"]
        if scenario not in MFA_IDENTITIES:
            refuse("mfa-scenario")
        command = [str(binary), "--native-mfa-fixture-test", "--native-mfa-fixture-contract", str(args.contract), "--authorized-local-fixture", "--primary-released"]
    elif password:
        command = [str(binary), "--native-password-fixture-test", "--native-password-fixture-contract", str(args.contract), "--authorized-local-fixture", "--primary-released"]
    else:
        command = [str(binary), "--native-app-fixture-test", "--native-app-fixture-contract", str(args.contract), "--authorized-local-fixture", "--primary-released"]
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/var/empty", "LANG": "C", "LC_ALL": "C"}
    start = time.monotonic()
    process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert process.stdout is not None
    output = 0; stop = "none"; failure: str | None = None; interrupted = False
    failure_cleanup_deadline: float | None = None
    def interrupt(_number: int, _frame: object) -> None:
        nonlocal interrupted
        interrupted = True
    previous = {number: signal.signal(number, interrupt) for number in (signal.SIGINT, signal.SIGTERM)}
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    os.set_blocking(process.stdout.fileno(), False)
    try:
        while process.poll() is None:
            if interrupted:
                failure = "supervisor-interrupted"; break
            if time.monotonic() - start >= 95:
                failure = "process-deadline-not-natural-exit"; break
            for key, _ in selector.select(0.05):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                output += len(chunk) # Content is deliberately discarded, never copied into logs.
            if output > 16384:
                failure = "app-output-budget"; break
            if failure_cleanup_deadline is not None and time.monotonic() >= failure_cleanup_deadline:
                break
            if os.path.lexists(directory / "native-failure.json") and failure_cleanup_deadline is None:
                failure = "app-failure-receipt"
                # Failure stays failure, but let the App's own bounded cleanup/termination finish.
                failure_cleanup_deadline = min(time.monotonic() + 12, start + 95)
        if failure is not None and process.poll() is None:
            stop = owned_stop(process)
        code = process.wait(timeout=2)
        if code != 0 and failure is None:
            failure = "process-exit-not-zero"
        if failure is None:
            # Byte budget includes output already buffered when poll() first saw process exit.
            while True:
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                output += len(chunk)
                if output > 16384:
                    refuse("app-output-budget")
            checks = (
                ("native-ready.json", "ready-for-native-quit", False, dict(scheduled=False, dispatched=False, beforeStores=False, afterStores=False, willTerminate=False)),
                ("native-before-stores.json", "before-stores-close", False, dict(scheduled=True, dispatched=True, beforeStores=True, afterStores=False, willTerminate=False)),
                ("native-after-stores.json", "after-stores-close", True, dict(scheduled=True, dispatched=True, beforeStores=True, afterStores=True, willTerminate=False)),
            )
            for name, checkpoint, removed, expected in checks:
                if concurrent:
                    check_concurrent_report(public_json(directory / name, 16384), run_id, process.pid, checkpoint, removed, expected)
                elif trust:
                    check_trust_report(public_json(directory / name, 16384), run_id, process.pid, scenario, checkpoint, removed, expected)
                elif cancel:
                    check_cancel_report(public_json(directory / name, 16384), run_id, process.pid, checkpoint, removed, expected)
                elif conflict:
                    check_conflict_report(public_json(directory / name, 16384), run_id, process.pid, checkpoint, removed, expected)
                elif files:
                    check_files_report(public_json(directory / name, 16384), run_id, process.pid, checkpoint, removed, expected)
                elif mfa:
                    check_mfa_report(public_json(directory / name, 16384), run_id, process.pid, scenario, checkpoint, removed, expected)
                elif password:
                    check_password_report(public_json(directory / name, 16384), run_id, process.pid, checkpoint, removed, expected)
                else:
                    check_report(public_json(directory / name, 16384), run_id, process.pid, checkpoint, removed, expected)
            if cancel:
                check_cancel_report(public_json(directory / "native-files-cancel-transfer.json", 16384), run_id, process.pid,
                    "transfer-only-resources-unverified", False, dict(scheduled=False, dispatched=False, beforeStores=False, afterStores=False, willTerminate=False), transfer_only=True)
            if conflict:
                check_conflict_report(public_json(directory / "native-files-conflict-transfer.json", 16384), run_id, process.pid,
                    "transfer-only-resources-unverified", False, dict(scheduled=False, dispatched=False, beforeStores=False, afterStores=False, willTerminate=False), transfer_only=True)
            if files:
                check_files_report(public_json(directory / "native-files-transfer.json", 16384), run_id, process.pid,
                    "transfer-only-resources-unverified", False, dict(scheduled=False, dispatched=False, beforeStores=False, afterStores=False, willTerminate=False), transfer_only=True)
            if mfa:
                check_mfa_authentication(public_json(directory / MFA_AUTH_RECEIPT, 4096), run_id, process.pid, scenario)
                check_mfa_cleanup(public_json(directory / MFA_CLEANUP_RECEIPT, 4096), run_id, process.pid, scenario, True)
            if concurrent:
                check_concurrent_authentication(public_json(directory / "native-concurrent-authentication.json", 16384), run_id, process.pid)
                check_concurrent_cleanup(public_json(directory / "native-concurrent-cleanup.json", 16384), run_id, process.pid, True)
            if trust:
                for ordinal in range(1, TRUST_SCENARIOS[scenario] + 1):
                    check_trust_authentication(public_json(directory / ("native-trust-authentication-" + str(ordinal) + ".json"), 16384), run_id, process.pid, scenario, ordinal)
            if password:
                check_password_authentication(public_json(directory / PASSWORD_AUTH_RECEIPT, 4096), run_id, process.pid)
            terminal = public_json(directory / "native-will-terminate.json", 4096)
            expected = dict(scheduled=True, dispatched=True, beforeStores=True, afterStores=True, willTerminate=True)
            if (not isinstance(terminal, dict) or set(terminal) != {"schema", "runID", "pid", "passed", "quit"}
                    or terminal != {"schema": 1, "runID": run_id, "pid": process.pid, "passed": True, "quit": expected}):
                refuse("will-terminate-required")
    except Refusal as error:
        failure = error.args[0]
        stop = owned_stop(process)
        code = process.wait()
    except BaseException:
        failure = "supervisor-operation-failed"
        stop = owned_stop(process)
        code = process.wait()
    finally:
        selector.close(); process.stdout.close()
        for number, handler in previous.items():
            signal.signal(number, handler)
    # This optional receipt may prove authentication even if the unchanged resource gate failed.
    # It never clears failure, changes the process return, or asserts product/resource acceptance.
    password_authentication = "not-observed"
    if password:
        try:
            check_password_authentication(public_json(directory / PASSWORD_AUTH_RECEIPT, 4096), run_id, process.pid)
            password_authentication = "observed-authentication-only-resources-unverified"
        except Exception:
            password_authentication = "missing-or-refused"
    result = {"schema": 1, "runID": run_id, "scenario": "keyonly-direct-sftp-manifest-cancel-retry" if cancel else ("keyonly-direct-sftp-manifest-conflict" if conflict else ("keyonly-direct-sftp-manifest" if files else (scenario if mfa else (PASSWORD_SCENARIO if password else SCENARIO)))), "pid": process.pid, "passed": failure is None,
              "failureCode": failure, "returncode": code, "stopAction": stop, "naturalExit": stop == "none" and code == 0,
              "elapsedSeconds": time.monotonic() - start, "discardedOutputBytes": output, "guiVerified": False,
              "binarySHA256": args.expected_sha256, "scope": "real App Controller/NativeBuilder short shell only; no GUI/EOF/default-switch acceptance"}
    if concurrent:
        result["scenario"] = CONCURRENT_SCENARIO
        result["scope"] = "two exact App keyKI owners; cancel A and continue B; authentication/management/resources separate; no GUI/TUI"
        result["authenticationObservation"] = "missing-or-refused"
        result["cleanupObservation"] = "missing-or-refused"
        try:
            check_concurrent_authentication(public_json(directory / "native-concurrent-authentication.json", 16384), run_id, process.pid)
            result["authenticationObservation"] = "observed-two-owner-isolation-only-resources-unverified"
        except Exception:
            pass
        try:
            cleanup = public_json(directory / "native-concurrent-cleanup.json", 16384)
            check_concurrent_cleanup(cleanup, run_id, process.pid, False)
            result["cleanupObservation"] = "per-owner-removed" if cleanup["passed"] else "per-owner-not-complete"
        except Exception:
            pass
    if trust:
        result["scenario"] = scenario
        result["scope"] = "logical App exact trust/authentication; short shell only; strict resources and natural quit separate; no GUI/EOF"
        result["authenticationObservation"] = "missing-or-refused"
        try:
            for ordinal in range(1, TRUST_SCENARIOS[scenario] + 1):
                check_trust_authentication(public_json(directory / ("native-trust-authentication-" + str(ordinal) + ".json"), 16384), run_id, process.pid, scenario, ordinal)
            result["authenticationObservation"] = "observed-trust-authentication-only-resources-unverified"
        except Exception:
            pass
    if cancel:
        result["scope"] = "controlled local read gate with actual bytes; explicit manifest retry, not natural catch/native blocked I/O"
        result["transferObservation"] = "missing-or-refused"
        try:
            check_cancel_report(public_json(directory / "native-files-cancel-transfer.json", 16384), run_id, process.pid,
                "transfer-only-resources-unverified", False, dict(scheduled=False, dispatched=False, beforeStores=False, afterStores=False, willTerminate=False), transfer_only=True)
            result["transferObservation"] = "observed-controlled-cancel-and-explicit-retry-only"
        except Exception:
            pass
    if conflict:
        result["scope"] = "logical App SFTP two-upload rename+skip only; no GUI/batch propagation"
        result["transferObservation"] = "missing-or-refused"
        try:
            check_conflict_report(public_json(directory / "native-files-conflict-transfer.json", 16384), run_id, process.pid,
                "transfer-only-resources-unverified", False, dict(scheduled=False, dispatched=False, beforeStores=False, afterStores=False, willTerminate=False), transfer_only=True)
            result["transferObservation"] = "observed-mixed-outcome-and-original-preservation-only"
        except Exception:
            pass
    if files:
        result["scope"] = "logical App Files real SFTP only; no dualPane pixels/Finder/shell/default/resource shortcut"
        result["transferObservation"] = "missing-or-refused"
        try:
            check_files_report(public_json(directory / "native-files-transfer.json", 16384), run_id, process.pid,
                "transfer-only-resources-unverified", False, dict(scheduled=False, dispatched=False, beforeStores=False, afterStores=False, willTerminate=False), transfer_only=True)
            result["transferObservation"] = "observed-roundtrip-only-close-resources-separate"
        except Exception:
            pass
    if password:
        result["authenticationObservation"] = password_authentication
    if mfa:
        result["authenticationObservation"] = "missing-or-refused"
        result["authenticationCleanupObservation"] = "missing-or-refused"
        try:
            check_mfa_authentication(public_json(directory / MFA_AUTH_RECEIPT, 4096), run_id, process.pid, scenario)
            result["authenticationObservation"] = "observed-authentication-only-resources-unverified"
        except Exception:
            pass
        try:
            cleanup = public_json(directory / MFA_CLEANUP_RECEIPT, 4096)
            check_mfa_cleanup(cleanup, run_id, process.pid, scenario, False)
            result["authenticationCleanupObservation"] = cleanup["serverSessionStatus"]
        except Exception:
            pass
    exclusive_json(directory, "supervisor.json", result)
    print(json.dumps(result, sort_keys=True))
    return 0 if failure is None else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    once = ("--app", "--expected-sha256", "--contract", "--authorized-local-fixture", "--primary-released")
    for flag in once:
        if sum(argument == flag or argument.startswith(flag + "=") for argument in sys.argv[1:]) > 1:
            refuse("duplicate-argument")
    parser.add_argument("action", choices=("help", "validate", "preflight", "live"), nargs="?", default="help")
    parser.add_argument("--app", type=Path)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--contract", type=Path)
    parser.add_argument("--authorized-local-fixture", action="store_true")
    parser.add_argument("--primary-released", action="store_true")
    args = parser.parse_args()
    if args.action == "help":
        parser.print_help(); return 0
    if args.contract is None:
        refuse("contract-required")
    selected_contract_id(str(args.contract))
    if args.action == "validate":
        if args.app is not None or args.expected_sha256 is not None or args.authorized_local_fixture or args.primary_released:
            refuse("syntax-only-arguments")
        print("Native App fixture syntax only; no file/process/network I/O."); return 0
    if not args.authorized_local_fixture or not args.primary_released:
        refuse("release-gates-required")
    if args.app is None or args.expected_sha256 is None or not re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256):
        refuse("reviewed-app-digest-required")
    binary, run_id, directory = preflight(args)
    if args.action == "preflight":
        print(json.dumps({"schema": 1, "runID": run_id, "preflightOnly": True, "liveExecuted": False, "secretRead": False})); return 0
    return supervise(args, binary, run_id, directory)



# Independent Files schema; original keyonly/password/MFA validator paths stay closed.
def files_contract_id(path: str) -> str:
    syntax(path)
    match = re.fullmatch(re.escape(str(INPUTS)) + r"/run-([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})/native-files-fixture\.json", path)
    if not match or str(uuid.UUID(match[1])) != match[1]:
        refuse("files-contract-path")
    return match[1]


def files_wrapper(path: Path) -> tuple[str, dict[str, object]]:
    run_id = files_contract_id(str(path))
    for directory in (INPUTS, path.parent):
        fd = opened(directory, True); os.close(fd)
    value = password_public_object(stable_read(path, 4096), {"schema", "runID", "scenario", "materialContractPath"})
    material_path = path.parent / "native-files-material.json"
    if (type(value["schema"]) is not int or value["schema"] != 1 or value["runID"] != run_id
            or value["scenario"] != "keyonly-direct-sftp-manifest" or value["materialContractPath"] != str(material_path)):
        refuse("files-wrapper-binding")
    if stable_read(path.parent / MARKER, 256) != (MARKER_TEXT + run_id + "\n").encode():
        refuse("files-wrapper-marker")
    keys = {"schema", "runID", "host", "port", "user", "service", "generation", "expectedBase", "expectedImage", "expectedProject", "expectedContainer",
            "expectedFingerprint", "collectedAt", "preparedAt", "provenanceSHA256", "knownHostsSHA256", "generationPublicKeySHA256"}
    material = password_public_object(stable_read(material_path, 8192), keys)
    numeric = {"schema", "port", "collectedAt", "preparedAt"}
    if (any(type(material[key]) is not str for key in keys - numeric) or type(material["schema"]) is not int or material["schema"] != 1
            or material["runID"] != run_id or type(material["port"]) is not int or material["port"] != 22221
            or (material["host"], material["user"], material["service"]) != ("127.0.0.1", "fixture", "keyonly")
            or any(material[key] != expected for key, expected in CURRENT_IDENTITY.items())):
        refuse("files-material-binding")
    if (not re.fullmatch(re.escape(str(ROOT / "Tests/IntegrationEnvironment/.runtime/keyonly/credentials-")) + r"[0-9a-f]{12}", material["generation"])
            or any(not re.fullmatch(r"[0-9a-f]{64}", material[key]) for key in ("provenanceSHA256", "knownHostsSHA256", "generationPublicKeySHA256"))):
        refuse("files-material-provenance")
    collected, prepared, now = material["collectedAt"], material["preparedAt"], time.time()
    if (any(type(item) not in (int, float) or not math.isfinite(item) for item in (collected, prepared)) or not 0 < collected <= prepared <= now or now - collected > 120):
        refuse("files-material-freshness")
    return run_id, material


def files_io(value: object, zero: bool = False) -> dict[str, int]:
    keys = {"readOpen", "read", "writeOpen", "write", "mutations", "readBytes", "writeBytes"}
    if not isinstance(value, dict) or set(value) != keys or any(type(item) is not int or item < 0 for item in value.values()):
        refuse("files-io-schema")
    if zero and any(value.values()):
        refuse("files-prepare-content-io")
    return value


def files_descriptor_snapshots(value: object) -> dict[str, object]:
    # Files wire v1: lossless fixed scalar columns, not a reduced observation or pass exemption.
    keys = {"schema", "wireVersion", "maximumEntries", "atomic", "continuousOpenProven"}
    if (not isinstance(value, dict) or not keys <= set(value) or not set(value) <= keys | set(FD_PHASES)
            or type(value["wireVersion"]) is not int or value["wireVersion"] != 1):
        refuse("files-descriptor-schema")
    result = {key: value[key] for key in keys - {"wireVersion"}}
    for phase in FD_PHASES:
        if phase not in value:
            continue
        row = value[phase]
        if not isinstance(row, list) or len(row) != 6 or not isinstance(row[5], list) or len(row[5]) > FD_ENTRY_LIMIT:
            refuse("files-descriptor-snapshot-row")
        entries = []
        for entry in row[5]:
            if not isinstance(entry, list) or len(entry) != 7:
                refuse("files-descriptor-entry-row")
            statuses = ("stable", "unavailable", "changed")
            roles = ("unknown", "systemTZShape", "systemICUShape", "systemLocaleShape", "systemFontShape")
            if type(entry[5]) is not int or not 0 <= entry[5] < len(statuses) or type(entry[6]) is not int or not 0 <= entry[6] < len(roles):
                refuse("files-descriptor-enum-columns")
            item = dict(zip(("fd", "type", "dev", "ino", "access", "probeStatus", "role"), entry[:5] + [statuses[entry[5]], roles[entry[6]]]))
            if entry[5] != 0:
                if any(entry[index] is not None for index in (1, 2, 3, 4)):
                    refuse("files-descriptor-unknown-columns")
                item = {key: item[key] for key in ("fd", "probeStatus", "role")}
            entries.append(item)
        result[phase] = dict(zip(("elapsedSeconds", "scanUpperExclusive", "count", "truncated", "complete"), row[:5]), entries=entries)
    check_descriptor_snapshots(result)
    return result


def check_files_report(report: object, run_id: str, pid: int, checkpoint: str, removed: bool, quit_expected: dict[str, bool], transfer_only: bool = False) -> None:
    import base64
    keys = {"schema", "kind", "scenario", "acceptanceScope", "guiVerified", "productRuntimeVerified", "shellSessions", "rescueAttempts",
        "runID", "pid", "checkpoint", "elapsedSeconds", "passed", "transferOnly", "closedAndClean", "localStoreRemoved", "nonce", "sourceKeyUnchanged",
        "fixtureKnownHostsUnchanged", "trustMatchedOutOfBand", "credentialCalls", "capabilityPassed", "serverBinding", "capability", "plans", "jobs", "source", "remote", "download",
        "services", "managerClosed", "managerDrained", "managerJobs", "managerOperations", "managerPreparing", "managerReady", "managerConfirming", "managerReservedEntries", "managerReservedMetadataBytes", "remoteRootRemoved", "localPayloadRemoved", "deletePlanIDs", "descriptors", "descriptorIdentityMatched", "quit"}
    if not isinstance(report, dict) or set(report) != keys:
        refuse("files-report-schema")
    expected = {"schema": 1, "kind": "HostProbe-App-Files-manifest", "scenario": "keyonly-direct-sftp-manifest",
        "acceptanceScope": "logical-App-real-SFTP-not-dualPane-pixels-or-Finder", "guiVerified": False, "productRuntimeVerified": False,
        "shellSessions": 0, "rescueAttempts": 0, "runID": run_id, "pid": pid, "checkpoint": checkpoint, "transferOnly": True,
        "sourceKeyUnchanged": True, "trustMatchedOutOfBand": True, "credentialCalls": 0, "capabilityPassed": True, "localStoreRemoved": removed}
    exact_public_facts({key: report[key] for key in expected}, expected, "files-required-facts")
    nonce = report["nonce"]
    if type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        refuse("files-nonce")
    def canonical(value: object) -> bool:
        try:
            return type(value) is str and str(uuid.UUID(value)) == value.lower()
        except (ValueError, AttributeError):
            return False
    if not canonical(report["serverBinding"]):
        refuse("files-server-binding")
    root = ("/fixture/home/openlxssh-app-manifest-" + nonce + "/树 folder").encode()
    relative = [b"", "子 e\u0301 [#; $]".encode(), b".hidden [#; $].bin", "子 e\u0301 [#; $]/内容 空格.bin".encode()]
    expected_payload = []
    for name, size in ((relative[2], 4096), (relative[3], 8192)):
        seed = hashlib.sha256(b"OpenLXSSH non-secret Files R2 " + name).digest()
        payload = (seed * ((size + len(seed) - 1) // len(seed)))[:size]
        expected_payload.append({"relativePathBase64": base64.b64encode(name).decode(), "bytes": size, "sha256": hashlib.sha256(payload).hexdigest()})
    if any(report[name] != expected_payload for name in ("source", "remote", "download")):
        refuse("files-real-payload-digests")
    capability = report["capability"]
    cap_keys = {"planID", "serverBinding", "parentBase64", "directoryBase64", "acknowledgedRiskCount", "passed", "retainedPathCount", "remoteDelta"}
    if not isinstance(capability, dict) or set(capability) != cap_keys or not canonical(capability["planID"]) or capability["serverBinding"] != report["serverBinding"]:
        refuse("files-capability-binding")
    exact_public_facts({key: capability[key] for key in ("acknowledgedRiskCount", "passed", "retainedPathCount")},
        {"acknowledgedRiskCount": 1, "passed": True, "retainedPathCount": 0}, "files-capability-result")
    parent = root.rsplit(b"/", 1)[0]
    if capability["parentBase64"] != base64.b64encode(parent).decode(): refuse("files-capability-parent")
    directory = base64.b64decode(capability["directoryBase64"], validate=True)
    if not directory.startswith(parent + b"/.openlxssh-capability.") or b"/" in directory[len(parent) + 1:]: refuse("files-capability-directory")
    cap_io = files_io(capability["remoteDelta"])
    if min(cap_io["readOpen"], cap_io["writeOpen"], cap_io["readBytes"], cap_io["writeBytes"]) <= 0: refuse("files-capability-actual-io")
    plans, jobs = report["plans"], report["jobs"]
    if not isinstance(plans, list) or not isinstance(jobs, list) or len(plans) != 2 or len(jobs) != 2:
        refuse("files-roundtrip-count")
    for index, (plan, job) in enumerate(zip(plans, jobs)):
        plan_keys = {"planID", "reviewID", "serviceID", "hostID", "lifetime", "revision", "direction", "sourceBase64", "destinationBase64", "itemCount", "fileCount", "directoryCount", "totalBytes", "namesBase64", "remoteDelta", "localDelta", "jobsBefore", "jobsAfter", "confirmCalls"}
        job_keys = {"id", "generation", "planID", "batchID", "transferredBytes", "succeededFiles", "succeededDirectories", "items", "remoteDelta", "localDelta", "streams"}
        if not isinstance(plan, dict) or set(plan) != plan_keys or not isinstance(job, dict) or set(job) != job_keys:
            refuse("files-plan-job-schema")
        for name in ("planID", "reviewID", "serviceID", "hostID", "lifetime", "revision"):
            if not canonical(plan[name]): refuse("files-plan-identity")
        exact_public_facts({key: plan[key] for key in ("direction", "itemCount", "fileCount", "directoryCount", "totalBytes", "jobsBefore", "jobsAfter", "confirmCalls")},
            {"direction": "upload" if index == 0 else "download", "itemCount": 4, "fileCount": 2, "directoryCount": 2, "totalBytes": 12288, "jobsBefore": 0, "jobsAfter": 0, "confirmCalls": 1}, "files-frozen-review")
        local_root = "/树 folder".encode()
        source, destination = (local_root, root) if index == 0 else (root, local_root)
        if (plan["sourceBase64"], plan["destinationBase64"]) != (base64.b64encode(source).decode(), base64.b64encode(destination).decode()):
            refuse("files-raw-roots")
        expected_names = {base64.b64encode(source + (b"/" + name if name else b"")).decode() for name in relative}
        if not isinstance(plan["namesBase64"], list) or len(plan["namesBase64"]) != 4 or set(plan["namesBase64"]) != expected_names:
            refuse("files-frozen-names")
        files_io(plan["remoteDelta"], True); files_io(plan["localDelta"], True)
        if any(not canonical(job[name]) for name in ("id", "generation", "planID", "batchID")) or job["planID"] != plan["planID"]:
            refuse("files-actual-job-identity")
        exact_public_facts({key: job[key] for key in ("transferredBytes", "succeededFiles", "succeededDirectories")}, {"transferredBytes": 12288, "succeededFiles": 2, "succeededDirectories": 2}, "files-actual-progress")
        if not isinstance(job["items"], list) or len(job["items"]) != 4:
            refuse("files-item-results")
        observed_items = set()
        for item_row in job["items"]:
            if not isinstance(item_row, list) or len(item_row) != 4:
                refuse("files-item-result-columns")
            item = dict(zip(("sourceBase64", "destinationBase64", "bytes", "acknowledgedRiskCount"), item_row))
            if type(item["sourceBase64"]) is not str or type(item["destinationBase64"]) is not str or type(item["bytes"]) is not int or type(item["acknowledgedRiskCount"]) is not int or not 1 <= item["acknowledgedRiskCount"] <= 3:
                refuse("files-item-result-schema")
            observed_items.add((item["sourceBase64"], item["destinationBase64"], item["bytes"]))
        expected_items = set()
        for name, size in zip(relative, (0, 0, 4096, 8192)):
            suffix = b"/" + name if name else b""
            expected_items.add((base64.b64encode(source + suffix).decode(), base64.b64encode(destination + suffix).decode(), size))
        if observed_items != expected_items:
            refuse("files-actual-item-results")
        remote, local = files_io(job["remoteDelta"]), files_io(job["localDelta"])
        if remote["writeBytes" if index == 0 else "readBytes"] < 12288 or local["readBytes" if index == 0 else "writeBytes"] < 12288:
            refuse("files-actual-service-io")
        if not isinstance(job["streams"], list) or not 4 <= len(job["streams"]) <= 8:
            refuse("files-streams")
        wanted = set()
        for payload in expected_payload:
            name = base64.b64decode(payload["relativePathBase64"])
            pairs = (("source", local_root + b"/" + name, False), ("remote", root + b"/" + name, True)) if index == 0 else (("remote", root + b"/" + name, False), ("download", local_root + b"/" + name, True))
            for side, path, writing in pairs:
                wanted.add((side, base64.b64encode(path).decode(), writing, payload["bytes"], payload["sha256"]))
        observed = set()
        for stream_row in job["streams"]:
            if not isinstance(stream_row, list) or len(stream_row) != 5:
                refuse("files-stream-columns")
            stream = dict(zip(("side", "pathBase64", "writing", "bytes", "sha256"), stream_row))
            if type(stream["side"]) is not str or type(stream["pathBase64"]) is not str or type(stream["sha256"]) is not str or type(stream["writing"]) is not bool or type(stream["bytes"]) is not int:
                refuse("files-stream-schema")
            observed.add(tuple(stream[key] for key in ("side", "pathBase64", "writing", "bytes", "sha256")))
        if observed != wanted:
            refuse("files-stream-digests")
    if jobs[0]["id"] == jobs[1]["id"] or plans[0]["planID"] == plans[1]["planID"] or any(plans[0][key] != plans[1][key] for key in ("serviceID", "hostID", "lifetime")):
        refuse("files-shared-owner")
    services = report["services"]
    service_keys = {"remote", "local", "attempts", "remoteServices", "localServices", "closedRemote", "closedLocal", "liveHandles", "rescuedHandles", "handleCloseFailures", "observationFailed", "bindings"}
    if not isinstance(services, dict) or set(services) != service_keys:
        refuse("files-services-schema")
    files_io(services["remote"]); files_io(services["local"])
    exact_public_facts({key: services[key] for key in ("attempts", "remoteServices", "localServices", "liveHandles", "rescuedHandles", "handleCloseFailures", "observationFailed")},
        {"attempts": 1, "remoteServices": 1, "localServices": 2, "liveHandles": 0, "rescuedHandles": 0, "handleCloseFailures": 0, "observationFailed": False}, "files-service-observations")
    if services["bindings"] != [report["serverBinding"]]: refuse("files-binding-continuity")
    if not transfer_only:
        exact_public_facts({key: report[key] for key in ("passed", "closedAndClean", "fixtureKnownHostsUnchanged", "managerClosed", "managerDrained", "managerJobs", "managerOperations", "remoteRootRemoved", "localPayloadRemoved", "descriptorIdentityMatched")},
            {"passed": True, "closedAndClean": True, "fixtureKnownHostsUnchanged": True, "managerClosed": True, "managerDrained": True, "managerJobs": 1, "managerOperations": 0, "remoteRootRemoved": True, "localPayloadRemoved": True, "descriptorIdentityMatched": True}, "files-clean-close")
        if services["closedRemote"] != 1 or services["closedLocal"] != 2 or len(report["deletePlanIDs"]) != 2 or any(not canonical(value) for value in report["deletePlanIDs"]):
            refuse("files-real-close-delete")
        exact_public_facts({key: report[key] for key in ("managerPreparing", "managerReady", "managerConfirming", "managerReservedEntries")},
            {"managerPreparing": 0, "managerReady": 0, "managerConfirming": 0, "managerReservedEntries": 4}, "files-manager-final-plans")
        if type(report["managerReservedMetadataBytes"]) is not int or not 0 < report["managerReservedMetadataBytes"] <= 8 * 1024 * 1024:
            refuse("files-manager-history-reservation")
        phases = files_descriptor_snapshots(report["descriptors"])
        check_descriptor_snapshots(phases)
        if any(phases.get(phase, {}).get("complete") is not True for phase in FD_PHASES):
            refuse("files-descriptor-unknown")
        if phases.get("baseline", {}).get("entries") != phases.get("cleanupLatest", {}).get("entries") or phases.get("baseline", {}).get("count") != phases.get("cleanupLatest", {}).get("count"):
            refuse("files-descriptor-identity")
    else:
        exact_public_facts({key: report[key] for key in ("passed", "closedAndClean", "localStoreRemoved", "managerClosed", "remoteRootRemoved", "localPayloadRemoved", "descriptorIdentityMatched")},
            {"passed": False, "closedAndClean": False, "localStoreRemoved": False, "managerClosed": False, "remoteRootRemoved": False, "localPayloadRemoved": False, "descriptorIdentityMatched": False}, "files-transfer-only-scope")
    exact_public_facts(report["quit"], quit_expected, "files-quit-order")
    if type(report["elapsedSeconds"]) not in (int, float) or not 0 <= report["elapsedSeconds"] <= 90:
        refuse("files-deadline")


# Closed two-upload case. The old passed files wrapper/report validator above is unchanged.
def conflict_contract_id(path: str) -> str:
    syntax(path)
    match = re.fullmatch(re.escape(str(INPUTS)) + r"/run-([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})/native-files-conflict\.json", path)
    if not match or str(uuid.UUID(match[1])) != match[1]: refuse("conflict-contract-path")
    return match[1]


def conflict_wrapper(path: Path) -> tuple[str, dict[str, object]]:
    run_id = conflict_contract_id(str(path))
    for directory in (INPUTS, path.parent):
        fd = opened(directory, True); os.close(fd)
    value = password_public_object(stable_read(path, 4096), {"schema", "runID", "scenario", "materialContractPath"})
    if (type(value["schema"]) is not int or value["schema"] != 1 or value["runID"] != run_id
            or value["scenario"] != "keyonly-direct-sftp-manifest-conflict" or value["materialContractPath"] != str(path.parent / "native-files-material.json")):
        refuse("conflict-wrapper")
    if stable_read(path.parent / MARKER, 256) != (MARKER_TEXT + run_id + "\n").encode(): refuse("conflict-marker")
    material = password_public_object(stable_read(path.parent / "native-files-material.json", 8192),
        {"schema", "runID", "host", "port", "user", "service", "generation", "expectedBase", "expectedImage", "expectedProject", "expectedContainer", "expectedFingerprint",
         "collectedAt", "preparedAt", "provenanceSHA256", "knownHostsSHA256", "generationPublicKeySHA256"})
    if (type(material["schema"]) is not int or material["schema"] != 1 or material["runID"] != run_id or type(material["port"]) is not int
            or (material["host"], material["port"], material["user"], material["service"]) != ("127.0.0.1", 22221, "fixture", "keyonly")
            or any(material[key] != expected for key, expected in CURRENT_IDENTITY.items())): refuse("conflict-material-binding")
    if (type(material["generation"]) is not str or not re.fullmatch(re.escape(str(ROOT / "Tests/IntegrationEnvironment/.runtime/keyonly/credentials-")) + r"[0-9a-f]{12}", material["generation"])
            or any(type(material[key]) is not str or not re.fullmatch(r"[0-9a-f]{64}", material[key]) for key in ("provenanceSHA256", "knownHostsSHA256", "generationPublicKeySHA256"))): refuse("conflict-material-provenance")
    collected, prepared = material["collectedAt"], material["preparedAt"]
    if any(type(x) not in (int, float) or not math.isfinite(x) for x in (collected, prepared)) or not 0 < collected <= prepared <= time.time() or time.time() - collected > 120: refuse("conflict-material-freshness")
    return run_id, material


def check_conflict_report(value: object, run_id: str, pid: int, checkpoint: str, removed: bool, quit_expected: dict[str, bool], transfer_only: bool = False) -> None:
    import base64
    keys = {"schema", "wireVersion", "kind", "scenario", "acceptanceScope", "guiVerified", "batchPropagationVerified", "shellSessions", "rescueAttempts", "runID", "pid", "checkpoint", "elapsedSeconds",
        "passed", "transferOnly", "closedAndClean", "localStoreRemoved", "nonce", "sourceKeyUnchanged", "fixtureKnownHostsUnchanged", "trustMatchedOutOfBand", "credentialCalls", "capability", "plans", "jobs", "decisions",
        "seed", "fresh", "remoteVerified", "verificationPhaseID", "verificationStreams", "services", "managerClosed", "managerDrained", "managerJobs", "managerOperations", "remoteRootRemoved", "localPayloadRemoved", "deletePlanIDs", "descriptors", "descriptorIdentityMatched", "quit"}
    if not isinstance(value, dict) or set(value) != keys: refuse("conflict-report-schema")
    expected = dict(schema=1, wireVersion=1, kind="HostProbe-App-Files-manifest-conflict", scenario="keyonly-direct-sftp-manifest-conflict", acceptanceScope="logical-App-real-SFTP-conflict-not-GUI-or-batch-propagation",
        guiVerified=False, batchPropagationVerified=False, shellSessions=0, rescueAttempts=0, runID=run_id, pid=pid, checkpoint=checkpoint, transferOnly=True,
        localStoreRemoved=removed, sourceKeyUnchanged=True, trustMatchedOutOfBand=True, credentialCalls=0)
    exact_public_facts({key: value[key] for key in expected}, expected, "conflict-identity")
    def uid(item):
        try: return type(item) is str and str(uuid.UUID(item)) == item.lower()
        except (ValueError, AttributeError): return False
    if type(value["nonce"]) is not str or not re.fullmatch(r"[0-9a-f]{32}", value["nonce"]): refuse("conflict-nonce")
    root = ("/fixture/home/openlxssh-app-manifest-" + value["nonce"] + "/树 folder").encode(); local = "/树 folder".encode()
    relative = [b"", "子 e\u0301 [#; $]".encode(), b".hidden [#; $].bin", "子 e\u0301 [#; $]/内容 空格.bin".encode()]
    alternate = "保留副本 [#; $].bin".encode()
    b64 = lambda x: base64.b64encode(x).decode()
    def digest(name, size, fresh):
        seed = hashlib.sha256((b"OpenLXSSH non-secret Files conflict Fresh " if fresh else b"OpenLXSSH non-secret Files R2 ") + name).digest()
        return dict(relativePathBase64=b64(name), bytes=size, sha256=hashlib.sha256((seed * ((size + 31) // 32))[:size]).hexdigest())
    seed = [digest(name, size, False) for name, size in zip(relative[2:], (4096,8192))]
    fresh = [digest(name, size, True) for name, size in zip(relative[2:], (4096,8192))]
    final = seed + [{**fresh[0], "relativePathBase64": b64(alternate)}]
    if value["seed"] != seed or value["fresh"] != fresh or value["remoteVerified"] != final: refuse("conflict-final-real-digests")
    plan_rows, job_rows, decision_rows = value["plans"], value["jobs"], value["decisions"]
    if any(not isinstance(x,list) or len(x)!=2 for x in (plan_rows,job_rows,decision_rows)): refuse("conflict-two-plans-jobs-decisions")
    plans = []
    for row in plan_rows:
        if not isinstance(row,list) or len(row)!=19: refuse("conflict-plan-columns")
        plans.append(dict(zip(("planID","reviewID","serviceID","hostID","lifetime","revision","direction","sourceBase64","destinationBase64","itemCount","fileCount","directoryCount","totalBytes","namesBase64","remoteDelta","localDelta","jobsBefore","jobsAfter","confirmCalls"),row)))
    jobs = []
    for row in job_rows:
        if not isinstance(row,list) or len(row)!=11: refuse("conflict-job-columns")
        jobs.append(dict(zip(("phaseID","id","generation","planID","batchID","state","transferredBytes","items","remoteDelta","localDelta","streams"),row)))
    decisions = []
    for row in decision_rows:
        if not isinstance(row,list) or len(row)!=9: refuse("conflict-decision-columns")
        decisions.append(dict(zip(("id","jobID","generation","batchID","phaseID","source","destination","strategy","applyToBatch"),row)))
    phases=[]
    for index,(plan,job) in enumerate(zip(plans,jobs)):
        if not isinstance(plan,dict) or set(plan)!={"planID","reviewID","serviceID","hostID","lifetime","revision","direction","sourceBase64","destinationBase64","itemCount","fileCount","directoryCount","totalBytes","namesBase64","remoteDelta","localDelta","jobsBefore","jobsAfter","confirmCalls"}: refuse("conflict-plan-schema")
        for key in ("planID","reviewID","serviceID","hostID","lifetime","revision"):
            if not uid(plan[key]):refuse("conflict-plan-owner")
        exact_public_facts({key:plan[key] for key in ("direction","itemCount","fileCount","directoryCount","totalBytes","jobsBefore","jobsAfter","confirmCalls")},dict(direction="upload",itemCount=4,fileCount=2,directoryCount=2,totalBytes=12288,jobsBefore=0,jobsAfter=0,confirmCalls=1),"conflict-review")
        if plan["sourceBase64"]!=b64(local) or plan["destinationBase64"]!=b64(root) or not isinstance(plan["namesBase64"],list) or len(plan["namesBase64"])!=4 or set(plan["namesBase64"])!={b64(local+(b"/"+x if x else b"")) for x in relative}:refuse("conflict-raw-plan")
        files_io(plan["remoteDelta"],True);files_io(plan["localDelta"],True)
        if not isinstance(job,dict) or set(job)!={"phaseID","id","generation","planID","batchID","state","transferredBytes","items","remoteDelta","localDelta","streams"}:refuse("conflict-job-schema")
        for key in ("phaseID","id","generation","planID","batchID"):
            if not uid(job[key]):refuse("conflict-job-owner")
        phases.append(job["phaseID"])
        if job["planID"]!=plan["planID"]:refuse("conflict-job-plan")
        exact_public_facts({key:job[key] for key in ("state","transferredBytes")},dict(state="succeeded" if index==0 else "completedWithSkips",transferredBytes=12288 if index==0 else 4096),"conflict-true-state")
        if not isinstance(job["items"],list) or len(job["items"])!=4:refuse("conflict-items")
        wanted=set()
        for name,size in zip(relative,(0,0,4096,8192)):
            dest=alternate if index==1 and name==relative[2] else name
            wanted.add((b64(local+(b"/"+name if name else b"")),b64(root+(b"/"+dest if dest else b"")),"skipped" if index==1 and name==relative[3] else "succeeded",0 if index==1 and name==relative[3] else size))
        observed=set()
        for item in job["items"]:
            if not isinstance(item,list) or len(item)!=5 or any(type(item[i]) is not str for i in (0,1,2)) or type(item[3]) is not int or type(item[4]) is not int or not 1<=item[4]<=4:refuse("conflict-item-columns")
            observed.add(tuple(item[:4]))
        if observed!=wanted:refuse("conflict-item-results")
        io=files_io(job["remoteDelta"]);localio=files_io(job["localDelta"])
        if io["writeBytes"]!=(12288 if index==0 else 4096) or localio["readBytes"]<(12288 if index==0 else 4096):refuse("conflict-real-io")
        expected_streams=set()
        for item,payload in enumerate(seed if index==0 else fresh[:1]):
            name=relative[2+item];dest=alternate if index==1 else name
            for side,path,writing in (("source" if index==0 else "fresh",local+b"/"+name,False),("remote",root+b"/"+dest,True)):
                expected_streams.add((job["phaseID"],side,b64(path),writing,payload["bytes"],payload["sha256"]))
        actual=set()
        if not isinstance(job["streams"],list) or not 2<=len(job["streams"])<=8:refuse("conflict-stream-count")
        for stream in job["streams"]:
            if not isinstance(stream,list) or len(stream)!=5:refuse("conflict-stream-wire")
            if type(stream[2]) is not bool or type(stream[3]) is not int or any(type(stream[i]) is not str for i in (0,1,4)):refuse("conflict-stream-types")
            actual.add((job["phaseID"],*stream))
        if actual!=expected_streams:refuse("conflict-stream-phase-digest")
    if len(set(phases))!=2 or jobs[0]["id"]==jobs[1]["id"] or jobs[0]["generation"]==jobs[1]["generation"] or jobs[0]["batchID"]==jobs[1]["batchID"] or plans[0]["planID"]==plans[1]["planID"] or any(plans[0][key]!=plans[1][key] for key in ("serviceID","hostID","lifetime")):refuse("conflict-owner-separation")
    if decisions[0]["id"]==decisions[1]["id"]:refuse("conflict-decision-reuse")
    for index,decision in enumerate(decisions):
        if not isinstance(decision,dict) or set(decision)!={"id","jobID","generation","batchID","phaseID","source","destination","strategy","applyToBatch"} or not uid(decision["id"]):refuse("conflict-decision-schema")
        exact_public_facts({key:decision[key] for key in ("jobID","generation","batchID","phaseID","source","destination","strategy","applyToBatch")},dict(jobID=jobs[1]["id"],generation=jobs[1]["generation"],batchID=jobs[1]["batchID"],phaseID=phases[1],source=b64(local+b"/"+relative[2+index]),destination=b64(root+b"/"+relative[2+index]),strategy="rename" if index==0 else "skip",applyToBatch=index==1),"conflict-current-decisions")
    verify=value["verificationPhaseID"]
    if not uid(verify) or verify in phases or not isinstance(value["verificationStreams"],list) or len(value["verificationStreams"])!=3:refuse("conflict-independent-verification")
    actual=[]
    for record in value["verificationStreams"]:
        if not isinstance(record,list) or len(record)!=2 or record[0]!=verify or not isinstance(record[1],list) or len(record[1])!=5:refuse("conflict-verification-stream")
        stream=record[1]
        if type(stream[2]) is not bool or stream[2] or type(stream[3]) is not int:refuse("conflict-verification-types")
        actual.append((stream[0],stream[1],stream[3],stream[4]))
    wanted=[("remote",b64(root+b"/"+base64.b64decode(x["relativePathBase64"])),x["bytes"],x["sha256"]) for x in final]
    if actual!=wanted:refuse("conflict-original-preservation-read")
    services=value["services"]
    if not isinstance(services,dict) or set(services)!={"remote","local","attempts","remoteServices","localServices","closedRemote","closedLocal","liveHandles","rescuedHandles","handleCloseFailures","observationFailed","bindings"}:refuse("conflict-services")
    exact_public_facts({key:services[key] for key in ("attempts","remoteServices","localServices","liveHandles","rescuedHandles","handleCloseFailures","observationFailed")},dict(attempts=1,remoteServices=1,localServices=2,liveHandles=0,rescuedHandles=0,handleCloseFailures=0,observationFailed=False),"conflict-real-services")
    files_io(services["remote"]);files_io(services["local"])
    if not isinstance(services["bindings"],list) or len(services["bindings"])!=1 or not uid(services["bindings"][0]):refuse("conflict-binding")
    cap=value["capability"]
    if not isinstance(cap,dict) or set(cap)!={"planID","serverBinding","parentBase64","directoryBase64","acknowledgedRiskCount","passed","retainedPathCount","remoteDelta"}:refuse("conflict-capability-schema")
    if not uid(cap["planID"]) or cap["serverBinding"]!=services["bindings"][0] or cap["parentBase64"]!=b64(root.rsplit(b"/",1)[0]):refuse("conflict-capability-binding")
    exact_public_facts({k:cap[k] for k in ("acknowledgedRiskCount","passed","retainedPathCount")},dict(acknowledgedRiskCount=1,passed=True,retainedPathCount=0),"conflict-capability")
    capio=files_io(cap["remoteDelta"])
    if min(capio["readOpen"],capio["writeOpen"],capio["readBytes"],capio["writeBytes"])<=0:refuse("conflict-capability-actual-io")
    if type(cap["directoryBase64"]) is not str:refuse("conflict-capability-directory")
    directory=base64.b64decode(cap["directoryBase64"],validate=True);parent=root.rsplit(b"/",1)[0]
    if not directory.startswith(parent+b"/.openlxssh-capability.") or b"/" in directory[len(parent)+1:]:refuse("conflict-capability-directory")
    if not transfer_only:
        exact_public_facts({k:value[k] for k in ("passed","closedAndClean","fixtureKnownHostsUnchanged","managerClosed","managerDrained","managerJobs","managerOperations","remoteRootRemoved","localPayloadRemoved","descriptorIdentityMatched")},dict(passed=True,closedAndClean=True,fixtureKnownHostsUnchanged=True,managerClosed=True,managerDrained=True,managerJobs=1,managerOperations=0,remoteRootRemoved=True,localPayloadRemoved=True,descriptorIdentityMatched=True),"conflict-close")
        if type(services["closedRemote"]) is not int or services["closedRemote"]!=1 or type(services["closedLocal"]) is not int or services["closedLocal"]!=2 or not isinstance(value["deletePlanIDs"],list) or len(value["deletePlanIDs"])!=2 or any(not uid(x) for x in value["deletePlanIDs"]):refuse("conflict-delete-close")
        phasesFD=files_descriptor_snapshots(value["descriptors"])
        if any(phasesFD.get(k,{}).get("complete") is not True for k in FD_PHASES) or phasesFD["baseline"]["entries"]!=phasesFD["cleanupLatest"]["entries"] or phasesFD["baseline"]["count"]!=phasesFD["cleanupLatest"]["count"]:refuse("conflict-strict-FD")
    else:
        exact_public_facts({k:value[k] for k in ("passed","closedAndClean","managerClosed","remoteRootRemoved","localPayloadRemoved","descriptorIdentityMatched")},dict(passed=False,closedAndClean=False,managerClosed=False,remoteRootRemoved=False,localPayloadRemoved=False,descriptorIdentityMatched=False),"conflict-transfer-only")
    exact_public_facts(value["quit"],quit_expected,"conflict-quit")
    if type(value["elapsedSeconds"]) not in (int,float) or not math.isfinite(value["elapsedSeconds"]) or not 0<=value["elapsedSeconds"]<=90:refuse("conflict-deadline")


# R6 is a separately closed consumer; prior roundtrip/conflict validators are unchanged.
def cancel_contract_id(path: str) -> str:
    syntax(path)
    match = re.fullmatch(re.escape(str(INPUTS)) + r"/run-([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})/native-files-cancel\.json", path)
    if not match or str(uuid.UUID(match[1])) != match[1]: refuse("cancel-contract-path")
    return match[1]


def cancel_wrapper(path: Path) -> tuple[str, dict[str, object]]:
    run_id = cancel_contract_id(str(path))
    for directory in (INPUTS, path.parent):
        fd = opened(directory, True); os.close(fd)
    value = password_public_object(stable_read(path,4096), {"schema","runID","scenario","materialContractPath"})
    if (type(value["schema"]) is not int or value["schema"]!=1 or value["runID"]!=run_id or value["scenario"]!="keyonly-direct-sftp-manifest-cancel-retry"
            or value["materialContractPath"]!=str(path.parent/"native-files-material.json")):refuse("cancel-wrapper")
    if stable_read(path.parent/MARKER,256)!=(MARKER_TEXT+run_id+"\n").encode():refuse("cancel-marker")
    material=password_public_object(stable_read(path.parent/"native-files-material.json",8192),{"schema","runID","host","port","user","service","generation","expectedBase","expectedImage","expectedProject","expectedContainer","expectedFingerprint","collectedAt","preparedAt","provenanceSHA256","knownHostsSHA256","generationPublicKeySHA256"})
    if (type(material["schema"]) is not int or material["schema"]!=1 or material["runID"]!=run_id or type(material["port"]) is not int
            or (material["host"],material["port"],material["user"],material["service"])!=("127.0.0.1",22221,"fixture","keyonly") or any(material[k]!=v for k,v in CURRENT_IDENTITY.items())):refuse("cancel-material-binding")
    if (type(material["generation"]) is not str or not re.fullmatch(re.escape(str(ROOT/"Tests/IntegrationEnvironment/.runtime/keyonly/credentials-"))+r"[0-9a-f]{12}",material["generation"])
            or any(type(material[k]) is not str or not re.fullmatch(r"[0-9a-f]{64}",material[k]) for k in ("provenanceSHA256","knownHostsSHA256","generationPublicKeySHA256"))):refuse("cancel-material-provenance")
    collected,prepared=material["collectedAt"],material["preparedAt"]
    if any(type(x) not in (int,float) or not math.isfinite(x) for x in (collected,prepared)) or not 0<collected<=prepared<=time.time() or time.time()-collected>120:refuse("cancel-material-freshness")
    return run_id,material


def check_cancel_report(value: object, run_id: str, pid: int, checkpoint: str, removed: bool, quit_expected: dict[str,bool], transfer_only: bool=False) -> None:
    import base64
    keys={"schema","wireVersion","kind","scenario","acceptanceScope","guiVerified","nativeBlockedIOVerified","naturalCatchVerified","shellSessions","rescueAttempts","runID","pid","checkpoint","elapsedSeconds","passed","transferOnly","closedAndClean","localStoreRemoved","nonce","sourceKeyUnchanged","fixtureKnownHostsUnchanged","trustMatchedOutOfBand","credentialCalls","capability","plans","jobs","gate","cancelPoint","partialVerified","secondAbsentAfterCancel","source","remoteVerified","verificationPhaseID","verificationStreams","services","managerClosed","managerDrained","managerJobs","managerOperations","remoteRootRemoved","localPayloadRemoved","deletePlanIDs","descriptors","descriptorIdentityMatched","quit"}
    if not isinstance(value,dict) or set(value)!=keys:refuse("cancel-report-schema")
    expected=dict(schema=1,wireVersion=1,kind="HostProbe-App-Files-manifest-cancel-retry",scenario="keyonly-direct-sftp-manifest-cancel-retry",acceptanceScope="controlled-local-read-scheduling-real-bytes-not-natural-catch-or-native-blocked-I/O",guiVerified=False,nativeBlockedIOVerified=False,naturalCatchVerified=False,shellSessions=0,rescueAttempts=0,runID=run_id,pid=pid,checkpoint=checkpoint,transferOnly=True,localStoreRemoved=removed,sourceKeyUnchanged=True,trustMatchedOutOfBand=True,credentialCalls=0,secondAbsentAfterCancel=True)
    exact_public_facts({k:value[k] for k in expected},expected,"cancel-identity")
    def uid(x):
        try:return type(x) is str and str(uuid.UUID(x))==x.lower()
        except (ValueError,AttributeError):return False
    if type(value["nonce"]) is not str or not re.fullmatch(r"[0-9a-f]{32}",value["nonce"]):refuse("cancel-nonce")
    root=("/fixture/home/openlxssh-app-manifest-"+value["nonce"]+"/树 folder").encode();local="/树 folder".encode()
    relative=[b"","子 e\u0301 [#; $]".encode(),b".hidden [#; $].bin","子 e\u0301 [#; $]/内容 空格.bin".encode()]
    b64=lambda x:base64.b64encode(x).decode()
    def digest(name,size):
        seed=hashlib.sha256(b"OpenLXSSH non-secret Files R2 "+name).digest();return hashlib.sha256((seed*((size+31)//32))[:size]).hexdigest()
    payload=[dict(relativePathBase64=b64(n),bytes=s,sha256=digest(n,s)) for n,s in zip(relative[2:],(4096,262144))]
    if value["source"]!=payload or value["remoteVerified"]!=payload or value["partialVerified"]!=payload[0]:refuse("cancel-real-payload-digests")
    if any(not isinstance(value[k],list) or len(value[k])!=2 for k in ("plans","jobs")):refuse("cancel-two-plans-jobs")
    plans=[];jobs=[]
    for row in value["plans"]:
        if not isinstance(row,list) or len(row)!=19:refuse("cancel-plan-columns")
        plans.append(dict(zip(("planID","reviewID","serviceID","hostID","lifetime","revision","direction","sourceBase64","destinationBase64","itemCount","fileCount","directoryCount","totalBytes","namesBase64","remoteDelta","localDelta","jobsBefore","jobsAfter","confirmCalls"),row)))
    for row in value["jobs"]:
        if not isinstance(row,list) or len(row)!=14:refuse("cancel-job-columns")
        jobs.append(dict(zip(("phaseID","id","generation","planID","batchID","retryOf","state","bytes","error","items","retained","remoteDelta","localDelta","streams"),row)))
    for index,(plan,job) in enumerate(zip(plans,jobs)):
        if any(not uid(plan[k]) for k in ("planID","reviewID","serviceID","hostID","lifetime","revision")) or any(not uid(job[k]) for k in ("phaseID","id","generation","planID","batchID")):refuse("cancel-owner")
        exact_public_facts({k:plan[k] for k in ("direction","itemCount","fileCount","directoryCount","totalBytes","jobsBefore","jobsAfter","confirmCalls")},dict(direction="upload",itemCount=4,fileCount=2,directoryCount=2,totalBytes=266240,jobsBefore=index,jobsAfter=index,confirmCalls=1),"cancel-new-review")
        if plan["sourceBase64"]!=b64(local) or plan["destinationBase64"]!=b64(root) or not isinstance(plan["namesBase64"],list) or len(plan["namesBase64"])!=4 or set(plan["namesBase64"])!={b64(local+(b"/"+n if n else b"")) for n in relative}:refuse("cancel-plan-raw-scope")
        files_io(plan["remoteDelta"],True);files_io(plan["localDelta"],True)
        if job["planID"]!=plan["planID"] or job["retryOf"]!=(None if index==0 else jobs[0]["id"]) or job["retained"]!=[]:refuse("cancel-retry-owner")
        exact_public_facts({k:job[k] for k in ("state","bytes","error")},dict(state="cancelled" if index==0 else "completedWithSkips",bytes=69632 if index==0 else 262144,error="cancelled" if index==0 else None),"cancel-actual-state")
        if not isinstance(job["items"],list) or len(job["items"])!=4:refuse("cancel-real-partial-items")
        wanted=set()
        for n,size in zip(relative,(0,0,4096,262144)):
            state="failed" if index==0 and n==relative[3] else ("skipped" if index==1 and n==relative[2] else "succeeded")
            wanted.add((b64(local+(b"/"+n if n else b"")),b64(root+(b"/"+n if n else b"")),state,0 if state!="succeeded" else size,"cancelled" if state=="failed" else None,None))
        actual=set()
        for item in job["items"]:
            if not isinstance(item,list) or len(item)!=7 or any(type(item[i]) is not str for i in (0,1,2)) or type(item[3]) is not int or type(item[5]) is not int or not 1<=item[5]<=4 or item[4] not in (None,"cancelled") or item[6] is not None:refuse("cancel-item-types")
            actual.add((item[0],item[1],item[2],item[3],item[4],item[6]))
        if actual!=wanted:refuse("cancel-preserved-partial")
        remoteio,localio=files_io(job["remoteDelta"]),files_io(job["localDelta"])
        if remoteio["writeBytes"]!=(69632 if index==0 else 262144) or localio["readBytes"]!=(69632 if index==0 else 262144):refuse("cancel-actual-stream-bytes")
        if not isinstance(job["streams"],list) or len(job["streams"])!=(4 if index==0 else 2):refuse("cancel-stream-count")
        expected_streams={("source",b64(local+b"/"+relative[2]),False,4096,digest(relative[2],4096)),("remote",b64(root+b"/"+relative[2]),True,4096,digest(relative[2],4096))} if index==0 else set()
        expected_streams.add(("source",b64(local+b"/"+relative[3]),False,65536 if index==0 else 262144,digest(relative[3],65536 if index==0 else 262144)))
        if index==1:expected_streams.add(("remote",b64(root+b"/"+relative[3]),True,262144,digest(relative[3],262144)))
        observed=set();temps=0
        for stream in job["streams"]:
            if not isinstance(stream,list) or len(stream)!=5 or any(type(stream[i]) is not str for i in (0,1,4)) or type(stream[2]) is not bool or type(stream[3]) is not int:refuse("cancel-stream-wire")
            raw=base64.b64decode(stream[1],validate=True)
            if index==0 and stream[0]=="remote" and stream[2] and raw.startswith(root+b"/"+relative[1]+b"/.openlxssh-transfer.") and raw.endswith(b".part"):
                if b"/" in raw[len(root+b"/"+relative[1])+1:] or stream[3]!=65536 or stream[4]!=digest(relative[3],65536):refuse("cancel-owned-temp-prefix")
                temps+=1
            else:observed.add(tuple(stream))
        if observed!=expected_streams or temps!=(1 if index==0 else 0):refuse("cancel-phase-stream-integrity")
    if any(jobs[0][k]==jobs[1][k] for k in ("id","generation","phaseID","batchID","planID")) or any(plans[0][k]!=plans[1][k] for k in ("serviceID","hostID","lifetime")):refuse("cancel-fresh-generation")
    gate=value["gate"]
    if not isinstance(gate,dict) or set(gate)!={"phaseID","readCalls","forwardedReads","arrived","waiting","localCancellationObserved","aborted"}:refuse("cancel-gate-schema")
    exact_public_facts(gate,dict(phaseID=jobs[0]["phaseID"],readCalls=2,forwardedReads=1,arrived=True,waiting=False,localCancellationObserved=True,aborted=False),"cancel-controlled-gate")
    point=value["cancelPoint"]
    exact_public_facts(point,dict(phaseID=jobs[0]["phaseID"],jobID=jobs[0]["id"],generation=jobs[0]["generation"],transferredBytes=69632,remoteWrittenBytes=65536,firstCommitted=True),"cancel-positive-current-point")
    phase=value["verificationPhaseID"]
    if not uid(phase) or phase in [x["phaseID"] for x in jobs] or not isinstance(value["verificationStreams"],list) or len(value["verificationStreams"])!=2:refuse("cancel-independent-verification")
    for record,p in zip(value["verificationStreams"],payload):
        expected=[phase,["remote",b64(root+b"/"+base64.b64decode(p["relativePathBase64"])),False,p["bytes"],p["sha256"]]]
        if record!=expected or type(record[1][2]) is not bool or type(record[1][3]) is not int:refuse("cancel-verification-actual-read")
    services=value["services"]
    if not isinstance(services,dict) or set(services)!={"remote","local","attempts","remoteServices","localServices","closedRemote","closedLocal","liveHandles","rescuedHandles","handleCloseFailures","observationFailed","bindings"}:refuse("cancel-services-schema")
    exact_public_facts({k:services[k] for k in ("attempts","remoteServices","localServices","liveHandles","rescuedHandles","handleCloseFailures","observationFailed")},dict(attempts=1,remoteServices=1,localServices=1,liveHandles=0,rescuedHandles=0,handleCloseFailures=0,observationFailed=False),"cancel-shared-service-no-rescue")
    files_io(services["remote"]);files_io(services["local"])
    if not isinstance(services["bindings"],list) or len(services["bindings"])!=1 or not uid(services["bindings"][0]):refuse("cancel-binding")
    cap=value["capability"]
    if not isinstance(cap,dict) or set(cap)!={"planID","serverBinding","parentBase64","directoryBase64","acknowledgedRiskCount","passed","retainedPathCount","remoteDelta"}:refuse("cancel-capability-schema")
    exact_public_facts({k:cap[k] for k in ("serverBinding","parentBase64","acknowledgedRiskCount","passed","retainedPathCount")},dict(serverBinding=services["bindings"][0],parentBase64=b64(root.rsplit(b"/",1)[0]),acknowledgedRiskCount=1,passed=True,retainedPathCount=0),"cancel-capability-binding")
    if not uid(cap["planID"]):refuse("cancel-capability-plan")
    capio=files_io(cap["remoteDelta"])
    if min(capio["readOpen"],capio["writeOpen"],capio["readBytes"],capio["writeBytes"])<=0:refuse("cancel-capability-real-io")
    raw=base64.b64decode(cap["directoryBase64"],validate=True);parent=root.rsplit(b"/",1)[0]
    if not raw.startswith(parent+b"/.openlxssh-capability.") or b"/" in raw[len(parent)+1:]:refuse("cancel-probe-scope")
    if not transfer_only:
        exact_public_facts({k:value[k] for k in ("passed","closedAndClean","fixtureKnownHostsUnchanged","managerClosed","managerDrained","managerJobs","managerOperations","remoteRootRemoved","localPayloadRemoved","descriptorIdentityMatched")},dict(passed=True,closedAndClean=True,fixtureKnownHostsUnchanged=True,managerClosed=True,managerDrained=True,managerJobs=2,managerOperations=0,remoteRootRemoved=True,localPayloadRemoved=True,descriptorIdentityMatched=True),"cancel-final-drain")
        exact_public_facts({k:services[k] for k in ("closedRemote","closedLocal")},dict(closedRemote=1,closedLocal=1),"cancel-real-closes")
        if not isinstance(value["deletePlanIDs"],list) or len(value["deletePlanIDs"])!=2 or any(not uid(x) for x in value["deletePlanIDs"]):refuse("cancel-delete-plans")
        fd=files_descriptor_snapshots(value["descriptors"])
        if any(fd.get(k,{}).get("complete") is not True for k in FD_PHASES) or fd["baseline"]["entries"]!=fd["cleanupLatest"]["entries"] or fd["baseline"]["count"]!=fd["cleanupLatest"]["count"]:refuse("cancel-strict-FD")
    else:
        exact_public_facts({k:value[k] for k in ("passed","closedAndClean","managerClosed","remoteRootRemoved","localPayloadRemoved","descriptorIdentityMatched")},dict(passed=False,closedAndClean=False,managerClosed=False,remoteRootRemoved=False,localPayloadRemoved=False,descriptorIdentityMatched=False),"cancel-transfer-only")
    exact_public_facts(value["quit"],quit_expected,"cancel-native-quit")
    if type(value["elapsedSeconds"]) not in (int,float) or not math.isfinite(value["elapsedSeconds"]) or not 0<=value["elapsedSeconds"]<=90:refuse("cancel-deadline")

# Independent Trust M3 gates. No existing case validator is called or widened.
TRUST_SCENARIOS = {"keyonly-trust-once2": 2, "keyonly-trust-persist2": 2, "keyonly-trust-changed1": 1}
TRUST_WRONG_PUBLIC_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAICVjCQeOke+c616gj3L7T3Xi0vvxcnF4wNs5FYMv6g3C"


def trust_contract_id(path: str) -> str:
    syntax(path)
    match = re.fullmatch(re.escape(str(INPUTS)) + r"/run-([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})/native-trust-fixture\.json", path)
    if not match or str(uuid.UUID(match[1])) != match[1]:
        refuse("trust-contract-path")
    return match[1]


def trust_wrapper(path: Path) -> tuple[str, dict[str, object]]:
    run_id = trust_contract_id(str(path))
    for directory in (INPUTS, path.parent):
        fd = opened(directory, True); os.close(fd)
    value = password_public_object(stable_read(path, 4096), {"schema", "runID", "scenario", "materialContractPath"})
    material_path = path.parent / "native-trust-material.json"
    if (type(value["schema"]) is not int or value["schema"] != 1 or value["runID"] != run_id
            or type(value["scenario"]) is not str or value["scenario"] not in TRUST_SCENARIOS or value["materialContractPath"] != str(material_path)):
        refuse("trust-wrapper")
    if stable_read(path.parent / MARKER, 256) != (MARKER_TEXT + run_id + "\n").encode():
        refuse("trust-marker")
    keys = {"schema", "runID", "host", "port", "user", "service", "generation", "expectedBase", "expectedImage", "expectedProject",
            "expectedContainer", "expectedFingerprint", "collectedAt", "preparedAt", "provenanceSHA256", "knownHostsSHA256", "generationPublicKeySHA256"}
    material = password_public_object(stable_read(material_path, 8192), keys)
    numbers = {"schema", "port", "collectedAt", "preparedAt"}
    if (any(type(material[key]) is not str for key in keys - numbers)
            or type(material["schema"]) is not int or material["schema"] != 1 or material["runID"] != run_id or type(material["port"]) is not int
            or (material["host"], material["port"], material["user"], material["service"]) != ("127.0.0.1", 22221, "fixture", "keyonly")
            or any(material[key] != expected for key, expected in CURRENT_IDENTITY.items())):
        refuse("trust-material-binding")
    if (not re.fullmatch(re.escape(str(ROOT / "Tests/IntegrationEnvironment/.runtime/keyonly/credentials-")) + r"[0-9a-f]{12}", material["generation"])
            or any(not re.fullmatch(r"[0-9a-f]{64}", material[key]) for key in ("provenanceSHA256", "knownHostsSHA256", "generationPublicKeySHA256"))):
        refuse("trust-material-provenance")
    collected, prepared, now = material["collectedAt"], material["preparedAt"], time.time()
    if (any(type(value) not in (int, float) or not math.isfinite(value) for value in (collected, prepared))
            or not 0 < collected <= prepared <= now or now - collected > 120):
        refuse("trust-material-freshness")
    return run_id, material


def trust_uuid(value: object) -> bool:
    try:
        return type(value) is str and str(uuid.UUID(value)) == value.lower()
    except (ValueError, AttributeError):
        return False


def check_trust_bytes(value: object, missing: bool = False) -> None:
    if missing:
        exact_public_facts(value, {"presence": "missing"}, "trust-initial-missing")
        return
    if (not isinstance(value, dict) or set(value) != {"presence", "bytes", "sha256"} or value["presence"] != "present"
            or type(value["bytes"]) is not int or not 0 < value["bytes"] <= 16384
            or type(value["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"])):
        refuse("trust-public-bytes")


def check_trust_prefix(scenario: str, facts: object, owners: object, before: object, points: object) -> None:
    import base64
    if (scenario not in TRUST_SCENARIOS or not isinstance(facts, list) or not 1 <= len(facts) <= TRUST_SCENARIOS[scenario]
            or not isinstance(owners, list) or len(owners) != len(facts) or not isinstance(points, list)):
        refuse("trust-prefix-count")
    check_trust_bytes(before, True)
    changed = scenario == "keyonly-trust-changed1"
    offset = 2 if changed else 1
    if len(points) != len(facts) + offset:
        refuse("trust-point-count")
    for point in points:
        if (not isinstance(point, dict) or set(point) != {"label", "records", "publicBytes"}
                or type(point["label"]) is not str or type(point["records"]) is not int or not 0 <= point["records"] <= 1):
            refuse("trust-point-schema")
        check_trust_bytes(point["publicBytes"])
    if points[0]["label"] != "initialized" or points[0]["records"] != 0:
        refuse("trust-initialized")
    if changed and (points[1]["label"] != "seeded-wrong-public-pin" or points[1]["records"] != 1 or points[1]["publicBytes"] == points[0]["publicBytes"]):
        refuse("trust-seeded-pin")
    for owner in owners:
        if (not isinstance(owner, dict) or set(owner) != {"tabID", "sessionID", "generation"} or any(not trust_uuid(owner[key]) for key in ("tabID", "sessionID"))
                or type(owner["generation"]) is not int or owner["generation"] != 1):
            refuse("trust-owner")
    for key in ("tabID", "sessionID"):
        if len({owner[key].lower() for owner in owners}) != len(owners):
            refuse("trust-fresh-owner")
    required = {"attemptID", "ordinal", "connectionCalls", "primaryCalls", "keyboardCalls", "pendingCalls", "changedCallbacks", "shellSessions", "stages", "requests", "observationFailed"}
    optional = {"primarySessionID", "primaryRequestID", "pendingRequestID", "authentication", "changed", "callbackChanged", "preAcceptanceProviderZero", "errorKind", "errorOperation"}
    for index, value in enumerate(facts):
        if (not isinstance(value, dict) or not required <= set(value) or not set(value) <= required | optional
                or not trust_uuid(value["attemptID"]) or any(type(value[key]) is not int for key in required - {"attemptID", "stages", "requests", "observationFailed"})
                or value["ordinal"] != index + 1 or value["connectionCalls"] != 1 or value["keyboardCalls"] != 0 or value["observationFailed"] is not False):
            refuse("trust-actual-call-schema")
        point = points[index + offset]
        if point["label"] != "attempt-" + str(index + 1):
            refuse("trust-point-owner")
        if changed:
            wrong = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(TRUST_WRONG_PUBLIC_BLOB, validate=True)).digest()).decode().rstrip("=")
            exact_public_facts({key: value[key] for key in ("primaryCalls", "pendingCalls", "shellSessions", "stages")},
                               {"primaryCalls": 0, "pendingCalls": 0, "shellSessions": 0, "stages": []}, "trust-changed-before-auth")
            if (value.get("errorKind"), value.get("errorOperation")) != ("untrusted", "host-key") or value["changedCallbacks"] not in (0, 1):
                refuse("trust-changed-typed-error")
            expected_keys = required | {"changed", "errorKind", "errorOperation"} | ({"callbackChanged"} if value["changedCallbacks"] == 1 else set())
            if set(value) != expected_keys:
                refuse("trust-changed-no-material-owner")
            exact_changed = {"expectedFingerprint": wrong, "presentedFingerprint": CURRENT_IDENTITY["expectedFingerprint"], "exactEndpoint": True, "exactAlgorithm": True}
            exact_public_facts(value["changed"], exact_changed, "trust-changed-exact-typed-fact")
            if value["changedCallbacks"] == 1:
                exact_public_facts(value["callbackChanged"], exact_changed, "trust-changed-callback-consistent")
            if value["requests"] != [{"stage": "changed"}] * value["changedCallbacks"]:
                refuse("trust-changed-request-stages")
            if point["records"] != 1 or point["publicBytes"] != points[1]["publicBytes"]:
                refuse("trust-wrong-pin-unchanged")
        else:
            pending = 1 if scenario == "keyonly-trust-once2" or index == 0 else 0
            expected_keys = required | {"primarySessionID", "primaryRequestID", "authentication"} | ({"pendingRequestID", "preAcceptanceProviderZero"} if pending else set())
            if (set(value) != expected_keys or any(not trust_uuid(value[key]) for key in ("primarySessionID", "primaryRequestID"))
                    or (pending and not trust_uuid(value["pendingRequestID"])) or value["primaryCalls"] != 1 or value["pendingCalls"] != pending
                    or value["changedCallbacks"] != 0 or value["shellSessions"] != 1
                    or value["stages"] != ["advertised", "primaryStarted.publicKey", "primaryResult.publicKey", "authenticated", "shellReady"]):
                refuse("trust-success-exact-calls")
            if pending:
                exact_public_facts(value["preAcceptanceProviderZero"], {"primaryCalls": 0, "keyboardCalls": 0, "shellSessions": 0,
                    "pendingCalls": 1, "pendingRequestID": value["pendingRequestID"]}, "trust-pre-acceptance-real-zero-sample")
            expected_requests = ([{"stage": "pending", "requestID": value["pendingRequestID"]}] if pending else []) + [{"stage": "primary", "requestID": value["primaryRequestID"]}]
            if value["requests"] != expected_requests:
                refuse("trust-exact-request-stage-order")
            exact_public_facts(value["authentication"], {"primaryMethod": "publicKey", "primaryStarted": 1, "primaryResults": 1, "primaryCode": 0,
                              "primaryAuthenticated": True, "authenticatedEvents": 1, "shellReadyEvents": 1}, "trust-keyonly-authentication")
            if scenario == "keyonly-trust-once2":
                if point["records"] != 0 or point["publicBytes"] != points[0]["publicBytes"]:
                    refuse("trust-once-no-persistence")
            elif point["records"] != 1 or point["publicBytes"] == points[0]["publicBytes"] or point["publicBytes"] != points[offset]["publicBytes"]:
                refuse("trust-persistent-single-write")
    for key in ("attemptID", "primarySessionID", "primaryRequestID", "pendingRequestID"):
        ids = [value[key].lower() for value in facts if key in value]
        if len(set(ids)) != len(ids):
            refuse("trust-distinct-actual-requests")


def check_trust_authentication(value: object, run_id: str, pid: int, scenario: str, ordinal: int) -> None:
    keys = {"schema", "kind", "acceptanceScope", "guiVerified", "productRuntimeVerified", "runID", "pid", "scenario", "ordinal", "beforeInitialization", "points", "facts", "owners", "credentialCalls"}
    if not isinstance(value, dict) or set(value) != keys:
        refuse("trust-authentication-schema")
    expected = dict(schema=1, kind="HostProbe-App-trust-authentication", acceptanceScope="trust-authentication-only-resources-unverified",
                    guiVerified=False, productRuntimeVerified=False, runID=run_id, pid=pid, scenario=scenario, ordinal=ordinal, credentialCalls=0)
    exact_public_facts({key: value[key] for key in expected}, expected, "trust-authentication-identity")
    check_trust_prefix(scenario, value["facts"], value["owners"], value["beforeInitialization"], value["points"])
    if len(value["facts"]) != ordinal:
        refuse("trust-authentication-prefix")


def check_trust_report(value: object, run_id: str, pid: int, scenario: str, checkpoint: str, removed: bool, quit_expected: dict[str, bool]) -> None:
    keys = {"schema", "kind", "acceptanceScope", "guiVerified", "productRuntimeVerified", "eofEvidence", "exitStatusEvidence", "runID", "pid", "scenario", "checkpoint", "elapsedSeconds",
            "passed", "closedAndClean", "localStoreRemoved", "authenticationComplete", "beforeInitialization", "points", "attempts", "sourceKeyScope", "fixtureKnownHostsUnchanged", "credentialCalls",
            "descriptorBaseline", "descriptorAfter", "descriptorIdentityMatched", "descriptors", "registryBaselineActive", "registryBaselineRetired", "registryAfterActive", "registryAfterRetired", "quit"}
    changed = scenario == "keyonly-trust-changed1"
    if not isinstance(value, dict) or set(value) != keys | (set() if changed else {"sourceKeyUnchanged"}):
        refuse("trust-report-schema")
    expected = dict(schema=1, kind="HostProbe-App-trust", acceptanceScope="logical-App-trust-short-shell-not-GUI-EOF-or-default-backend", guiVerified=False, productRuntimeVerified=False,
                    eofEvidence="notObserved", exitStatusEvidence="notRequested", runID=run_id, pid=pid, scenario=scenario, checkpoint=checkpoint,
                    passed=True, closedAndClean=True, localStoreRemoved=removed, authenticationComplete=True, fixtureKnownHostsUnchanged=True, credentialCalls=0, descriptorIdentityMatched=True,
                    sourceKeyScope="notRead-password-manual-trust-rejection" if changed else "fixture-client-key-memory-comparison-only")
    if not changed:
        expected["sourceKeyUnchanged"] = True
    exact_public_facts({key: value[key] for key in expected}, expected, "trust-report-identity")
    if not isinstance(value["attempts"], list) or len(value["attempts"]) != TRUST_SCENARIOS[scenario]:
        refuse("trust-report-attempt-count")
    for attempt in value["attempts"]:
        required = {"facts", "owner", "closeDisposition", "canonicalDrained", "queueEmpty", "weakAfterClose", "weakNow"}
        if not isinstance(attempt, dict) or set(attempt) != required | (set() if changed else {"terminal"}):
            refuse("trust-attempt-report-schema")
        exact_public_facts({key: attempt[key] for key in ("closeDisposition", "canonicalDrained", "queueEmpty")},
                           dict(closeDisposition="closed", canonicalDrained=True, queueEmpty=True), "trust-attempt-real-close")
        for key in ("weakAfterClose", "weakNow"):
            weak = attempt[key]
            if not isinstance(weak, dict) or set(weak) != {"tabAlive", "driverAlive", "viewAlive"} or any(type(flag) is not bool for flag in weak.values()):
                refuse("trust-weak-schema")
        if any(attempt["weakNow"].values()):
            refuse("trust-all-weak-released")
        if not changed:
            exact_public_facts(attempt["terminal"], dict(ack=True, pty=True, resized113x37=True, completed=True, observedRows=37, observedColumns=113), "trust-real-terminal")
    check_trust_prefix(scenario, [attempt["facts"] for attempt in value["attempts"]], [attempt["owner"] for attempt in value["attempts"]], value["beforeInitialization"], value["points"])
    fd = files_descriptor_snapshots(value["descriptors"])
    if (any(fd.get(phase, {}).get("complete") is not True for phase in FD_PHASES)
            or fd["baseline"]["entries"] != fd["cleanupLatest"]["entries"] or fd["baseline"]["count"] != fd["cleanupLatest"]["count"]
            or type(value["descriptorBaseline"]) is not int or type(value["descriptorAfter"]) is not int
            or value["descriptorBaseline"] < 3 or value["descriptorBaseline"] != fd["baseline"]["count"] or value["descriptorAfter"] != value["descriptorBaseline"]):
        refuse("trust-strict-FD")
    for name in ("Active", "Retired"):
        before, after = value["registryBaseline" + name], value["registryAfter" + name]
        if type(before) is not int or type(after) is not int or before < 0 or before != after:
            refuse("trust-registry-drained")
    exact_public_facts(value["quit"], quit_expected, "trust-native-quit")
    if type(value["elapsedSeconds"]) not in (int, float) or not math.isfinite(value["elapsedSeconds"]) or not 0 <= value["elapsedSeconds"] <= 90:
        refuse("trust-app-deadline")


# Concurrent keyKI is a new fixed consumer; no old decoder/pin validator is widened.
CONCURRENT_SCENARIO = "keyki-concurrent-cancel-a"
CONCURRENT_WRAPPER = "native-concurrent-fixture.json"
CONCURRENT_MATERIAL = "native-concurrent-material.json"
CONCURRENT_POLICY = "native-concurrent-policy.json"


def concurrent_contract_id(path: str) -> str:
    syntax(path)
    match = re.fullmatch(re.escape(str(INPUTS)) + r"/run-([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})/native-concurrent-fixture\.json", path)
    if not match or str(uuid.UUID(match[1])) != match[1]:
        refuse("concurrent-contract-path")
    return match[1]


def concurrent_wrapper(path: Path) -> tuple[str, dict[str, object]]:
    run_id = concurrent_contract_id(str(path))
    for directory in (INPUTS, path.parent):
        fd = opened(directory, True); os.close(fd)
    value = password_public_object(stable_read(path, 4096), {"schema", "runID", "scenario", "materialContractPath"})
    if (type(value["schema"]) is not int or value["schema"] != 1 or value["runID"] != run_id or value["scenario"] != CONCURRENT_SCENARIO
            or value["materialContractPath"] != str(path.parent / CONCURRENT_MATERIAL)):
        refuse("concurrent-wrapper")
    if stable_read(path.parent / MARKER, 256) != (MARKER_TEXT + run_id + "\n").encode():
        refuse("concurrent-marker")
    identity = MFA_IDENTITIES["keyki-controller-shell"]
    keys = {"schema", "runID", "host", "port", "user", "service", "key", "generation", "expectedBase", "expectedImage", "expectedProject", "expectedContainer",
            "expectedFingerprint", "networkID", "context", "endpoint", "collectedAt", "preparedAt", "provenanceSHA256", "knownHostsSHA256", "policyProofSHA256", "generationPublicKeySHA256"}
    material = password_public_object(stable_read(path.parent / CONCURRENT_MATERIAL, 8192), keys)
    if (any(type(material[key]) is not str for key in keys - {"schema", "port", "collectedAt", "preparedAt"})
            or type(material["schema"]) is not int or material["schema"] != 1 or material["runID"] != run_id
            or type(material["port"]) is not int or (material["host"], material["port"], material["user"], material["service"], material["key"]) != ("127.0.0.1", 22223, "fixture", "key-kbd", "edplain")
            or any(material[key] != identity[key] for key in ("expectedContainer", "expectedFingerprint"))
            or any(material[key] != PASSWORD_IDENTITY[key] for key in ("expectedBase", "expectedImage", "expectedProject", "networkID", "context", "endpoint"))):
        refuse("concurrent-material-binding")
    if (not re.fullmatch(re.escape(str(ROOT / "Tests/IntegrationEnvironment/.runtime/key-kbd/credentials-")) + r"[0-9a-f]{12}", material["generation"])
            or any(not re.fullmatch(r"[0-9a-f]{64}", material[key]) for key in ("provenanceSHA256", "knownHostsSHA256", "policyProofSHA256", "generationPublicKeySHA256"))):
        refuse("concurrent-material-provenance")
    collected, prepared, now = material["collectedAt"], material["preparedAt"], time.time()
    if any(type(v) not in (int, float) or not math.isfinite(v) for v in (collected, prepared)) or not 0 < collected <= prepared <= now or now - collected > 120:
        refuse("concurrent-material-freshness")
    raw = stable_read(path.parent / CONCURRENT_POLICY, 4096)
    if hashlib.sha256(raw).hexdigest() != material["policyProofSHA256"]:
        refuse("concurrent-policy-digest")
    flags = {"runningHealthy", "readonlyRoot", "notPrivileged", "logNone", "loopbackPortExact", "internalBridge", "noBindMounts", "rootPolicyMulti"}
    proof = password_public_object(raw, flags | {"schema", "runID", "service", "containerID", "imageID", "baseImage", "project", "networkID", "context", "endpoint", "port", "verifiedAt"})
    expected = dict(schema=1, runID=run_id, service="key-kbd", containerID=material["expectedContainer"], imageID=material["expectedImage"], baseImage=material["expectedBase"],
                    project=material["expectedProject"], networkID=material["networkID"], context=material["context"], endpoint=material["endpoint"], port=22223, **{key: 1 for key in flags})
    exact_public_facts({key: proof[key] for key in expected}, expected, "concurrent-policy-binding")
    verified = proof["verifiedAt"]
    if type(verified) not in (int, float) or not math.isfinite(verified) or not collected <= verified <= prepared or now - verified > 120:
        refuse("concurrent-policy-freshness")
    return run_id, material


def concurrent_owner(value: object, role: str) -> None:
    keys = {"role", "ticketID", "hostID", "tabID", "appSessionID", "requestID", "generation"}
    if (not isinstance(value, dict) or set(value) != keys or value["role"] != role
            or any(not trust_uuid(value[key]) for key in keys - {"role", "generation"})
            or type(value["generation"]) is not int or value["generation"] != 1 or value["tabID"] != value["appSessionID"]):
        refuse("concurrent-exact-App-owner")


def concurrent_isolation(value: object) -> None:
    booleans = {"twoFirstPending", "distinctDrivers", "distinctPackageSessions", "distinctFixtureSessions", "tokensUncancelledAtFirstPair",
                "crossReplyRejected", "bPromptUnchangedAfterCross", "lateReplyRejected", "bOwnerUnchangedAfterACancel"}
    counts = {"aManagementReadsBeforeCancel", "bManagementReadsBeforeCancel"}
    if not isinstance(value, dict) or set(value) != booleans | counts | {"a", "b"}:
        refuse("concurrent-isolation-schema")
    exact_public_facts({key: value[key] for key in booleans | counts}, {**{key: True for key in booleans}, **{key: 0 for key in counts}}, "concurrent-isolation-actual-facts")
    concurrent_owner(value["a"], "A"); concurrent_owner(value["b"], "B")
    if value["a"]["hostID"] != value["b"]["hostID"] or any(value["a"][key] == value["b"][key] for key in ("ticketID", "tabID", "appSessionID", "requestID")):
        refuse("concurrent-two-distinct-owners")


def concurrent_native(value: object, owner: dict[str, object], role: str) -> None:
    required = {"ticket", "connectCalls", "primaryCalls", "keyboardCalls", "trustCallbacks", "shellSessions", "packageSessionID", "primaryRequestID", "stages", "observationFailed"}
    keys = required | ({"aCancellation", "errorKind", "errorOperation"} if role == "A" else {"bAuthentication"})
    if not isinstance(value, dict) or set(value) != keys:
        refuse("concurrent-native-schema")
    exact_public_facts(value["ticket"], dict(id=owner["ticketID"], hostID=owner["hostID"], appSessionID=owner["appSessionID"]), "concurrent-ticket-not-package-id")
    exact_public_facts({key: value[key] for key in ("connectCalls", "primaryCalls", "keyboardCalls", "trustCallbacks", "shellSessions", "observationFailed")},
                       dict(connectCalls=1, primaryCalls=1, keyboardCalls=1 if role == "A" else 4, trustCallbacks=0, shellSessions=0 if role == "A" else 1, observationFailed=False), "concurrent-native-actual-counts")
    if not trust_uuid(value["packageSessionID"]) or not trust_uuid(value["primaryRequestID"]):
        refuse("concurrent-native-primary-request")
    stages = ["advertised", "primaryStarted.publicKey", "primaryResult.publicKey", "keyboardStarted", "keyboardResult"]
    if value["stages"] != stages + ([] if role == "A" else ["authenticated", "shellReady"]):
        refuse("concurrent-native-stages")
    if role == "A":
        if value["errorKind"] != "cancelled" or value["errorOperation"] not in ("cancel", "keyboard-interaction", "keyboard-authentication", "connect", "establish", "host-key", "primary-authentication", "authentication", "other"):
            refuse("concurrent-A-actual-cancellation")
        facts = value["aCancellation"]
        expected = dict(primaryMethod="publicKey", primaryCode=-19, primaryAuthenticated=False, keyboardAuthenticated=False, authenticatedEvents=0, shellReadyEvents=0)
        if not isinstance(facts, dict) or set(facts) != set(expected) | {"keyboardResultCode"}:
            refuse("concurrent-A-cancellation-schema")
        exact_public_facts({key: facts[key] for key in expected}, expected, "concurrent-A-primary-partial")
        if type(facts["keyboardResultCode"]) is not int or not -(2**31) <= facts["keyboardResultCode"] < 2**31 or facts["keyboardResultCode"] == 0:
            refuse("concurrent-A-keyboard-cancel-code")
    else:
        exact_public_facts(value["bAuthentication"], mfa_authentication_facts("keyki-controller-shell"), "concurrent-B-real-authentication")


def concurrent_keyboard(value: object, role: str) -> None:
    if role == "B":
        check_mfa_keyboard(value)
    else:
        exact_public_facts(value, dict(rounds=1, replies=0, secretReplies=0, zeroReplies=0, managementReads=0, lateReplies=0, fieldCounts=[1], echoFlags=[[False]]), "concurrent-A-never-read-or-replied")
        if any(type(item) is not int for item in value["fieldCounts"]) or any(type(row) is not list or any(type(flag) is not bool for flag in row) for row in value["echoFlags"]):
            refuse("concurrent-A-keyboard-types")


def check_concurrent_authentication(value: object, run_id: str, pid: int) -> None:
    keys = {"schema", "kind", "scenario", "acceptanceScope", "guiVerified", "productRuntimeVerified", "runID", "pid", "isolation", "a", "b", "aKeyboard", "bKeyboard", "aBudgetClosed", "credentialCalls"}
    if not isinstance(value, dict) or set(value) != keys:
        refuse("concurrent-auth-schema")
    expected = dict(schema=1, kind="HostProbe-App-keyKI-concurrent-authentication", scenario=CONCURRENT_SCENARIO,
                    acceptanceScope="two-App-owners-authentication-only-resources-unverified", guiVerified=False, productRuntimeVerified=False,
                    runID=run_id, pid=pid, aBudgetClosed=True, credentialCalls=0)
    exact_public_facts({key: value[key] for key in expected}, expected, "concurrent-auth-identity")
    concurrent_isolation(value["isolation"])
    concurrent_native(value["a"], value["isolation"]["a"], "A"); concurrent_native(value["b"], value["isolation"]["b"], "B")
    if any(value["a"][key] == value["b"][key] for key in ("packageSessionID", "primaryRequestID")):
        refuse("concurrent-distinct-package-primary")
    concurrent_keyboard(value["aKeyboard"], "A"); concurrent_keyboard(value["bKeyboard"], "B")


def concurrent_status(value: object, role: str, require_removed: bool) -> bool:
    if not isinstance(value, dict) or set(value) != {"role", "statusReads", "serverSessionStatus", "management"} or value["role"] != role:
        refuse("concurrent-status-owner-schema")
    if (type(value["statusReads"]) is not int or value["statusReads"] not in (0, 1)
            or type(value["serverSessionStatus"]) is not str or value["serverSessionStatus"] not in ("removed", "present", "unknown")
            or (value["statusReads"] == 0 and value["serverSessionStatus"] != "unknown")):
        refuse("concurrent-status-observation")
    facts = value["management"]
    keys = {"calls", "returnedCalls", "successfulReapedCalls", "pendingCalls", "cancellationRequested", "reapEvidenceComplete"}
    if (not isinstance(facts, dict) or set(facts) != keys or any(type(facts[key]) is not int or facts[key] < 0 for key in keys - {"cancellationRequested", "reapEvidenceComplete"})
            or any(type(facts[key]) is not bool for key in ("cancellationRequested", "reapEvidenceComplete"))
            or facts["calls"] > (1 if role == "A" else 4) or not facts["successfulReapedCalls"] <= facts["returnedCalls"] <= facts["calls"]
            or facts["pendingCalls"] != facts["calls"] - facts["returnedCalls"]
            or facts["reapEvidenceComplete"] != (facts["pendingCalls"] == 0 and facts["returnedCalls"] == facts["calls"] and facts["successfulReapedCalls"] == facts["calls"])):
        refuse("concurrent-management-real-reap")
    count = 1 if role == "A" else 4
    complete = value["statusReads"] == 1 and value["serverSessionStatus"] == "removed" and facts == dict(calls=count, returnedCalls=count, successfulReapedCalls=count, pendingCalls=0, cancellationRequested=True, reapEvidenceComplete=True)
    if require_removed and not complete:
        refuse("concurrent-per-owner-cleanup-required")
    return complete


def check_concurrent_cleanup(value: object, run_id: str, pid: int, require_removed: bool) -> None:
    keys = {"schema", "kind", "scenario", "acceptanceScope", "runID", "pid", "a", "b", "passed"}
    if not isinstance(value, dict) or set(value) != keys or type(value["passed"]) is not bool:
        refuse("concurrent-cleanup-schema")
    expected = dict(schema=1, kind="HostProbe-App-keyKI-concurrent-cleanup", scenario=CONCURRENT_SCENARIO, acceptanceScope="per-owner-management-status-only-resources-unverified", runID=run_id, pid=pid)
    exact_public_facts({key: value[key] for key in expected}, expected, "concurrent-cleanup-identity")
    a = concurrent_status(value["a"], "A", require_removed); b = concurrent_status(value["b"], "B", require_removed)
    if value["passed"] != (a and b):
        refuse("concurrent-cleanup-no-aggregate-substitution")


def check_concurrent_report(value: object, run_id: str, pid: int, checkpoint: str, removed: bool, quit_expected: dict[str, bool]) -> None:
    keys = {"schema", "kind", "scenario", "acceptanceScope", "guiVerified", "productRuntimeVerified", "terminalEvidence", "eofEvidence", "runID", "pid", "checkpoint", "elapsedSeconds",
            "passed", "authenticationComplete", "cleanupComplete", "closedAndClean", "localStoreRemoved", "a", "b", "isolation", "aKeyboard", "bKeyboard", "managementA", "managementB",
            "sourceKeyUnchanged", "fixtureKnownHostsUnchanged", "approvedPinUnchanged", "credentialCalls", "descriptors", "descriptorIdentityMatched",
            "registryBaselineActive", "registryBaselineRetired", "registryAfterActive", "registryAfterRetired", "quit"}
    if not isinstance(value, dict) or set(value) != keys:
        refuse("concurrent-report-schema")
    expected = dict(schema=1, kind="HostProbe-App-keyKI-concurrent", scenario=CONCURRENT_SCENARIO,
                    acceptanceScope="logical-App-two-owner-isolation-not-GUI-terminal-or-resource-shortcut", guiVerified=False, productRuntimeVerified=False,
                    terminalEvidence="notExercised", eofEvidence="notObserved", runID=run_id, pid=pid, checkpoint=checkpoint, passed=True,
                    authenticationComplete=True, cleanupComplete=True, closedAndClean=True, localStoreRemoved=removed,
                    sourceKeyUnchanged=True, fixtureKnownHostsUnchanged=True, approvedPinUnchanged=True, credentialCalls=0, descriptorIdentityMatched=True)
    exact_public_facts({key: value[key] for key in expected}, expected, "concurrent-report-identity")
    concurrent_isolation(value["isolation"])
    for key, role in (("a", "A"), ("b", "B")):
        life = value[key]
        if not isinstance(life, dict) or set(life) != {"role", "owner", "native", "closeDisposition", "canonicalDrained", "queueEmpty", "nativeClosed", "weak"}:
            refuse("concurrent-lifecycle-schema")
        exact_public_facts({field: life[field] for field in ("role", "closeDisposition", "canonicalDrained", "queueEmpty", "nativeClosed")},
                           dict(role=role, closeDisposition="closed", canonicalDrained=True, queueEmpty=True, nativeClosed=True), "concurrent-lifecycle-real-close")
        concurrent_owner(life["owner"], role)
        if life["owner"] != value["isolation"][key]:
            refuse("concurrent-lifecycle-owner-binding")
        concurrent_native(life["native"], life["owner"], role)
        exact_public_facts(life["weak"], dict(tabAlive=False, driverAlive=False, viewAlive=False), "concurrent-all-weak-required")
    if any(value["a"]["native"][key] == value["b"]["native"][key] for key in ("packageSessionID", "primaryRequestID")):
        refuse("concurrent-report-distinct-package")
    concurrent_keyboard(value["aKeyboard"], "A"); concurrent_keyboard(value["bKeyboard"], "B")
    concurrent_status(value["managementA"], "A", True); concurrent_status(value["managementB"], "B", True)
    fd = files_descriptor_snapshots(value["descriptors"])
    if any(fd.get(phase, {}).get("complete") is not True for phase in FD_PHASES) or fd["baseline"]["entries"] != fd["cleanupLatest"]["entries"] or fd["baseline"]["count"] != fd["cleanupLatest"]["count"]:
        refuse("concurrent-strict-shared-FD")
    for name in ("Active", "Retired"):
        before, after = value["registryBaseline" + name], value["registryAfter" + name]
        if type(before) is not int or type(after) is not int or before < 0 or before != after:
            refuse("concurrent-registry-baseline")
    exact_public_facts(value["quit"], quit_expected, "concurrent-real-Delegate-quit")
    if type(value["elapsedSeconds"]) not in (int, float) or not math.isfinite(value["elapsedSeconds"]) or not 0 <= value["elapsedSeconds"] <= 90:
        refuse("concurrent-full-deadline")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refusal as error:
        sys.stderr.write("Native App finite supervisor refused: " + error.args[0] + ".\n"); sys.exit(2)
    except Exception:
        sys.stderr.write("Native App finite supervisor refused: operation-failed.\n"); sys.exit(2)
