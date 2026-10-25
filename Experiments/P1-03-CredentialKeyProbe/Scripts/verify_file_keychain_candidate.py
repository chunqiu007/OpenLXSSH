#!/usr/bin/env python3
"""Explicit file-based Keychain candidate. No DP fallback, profile, ACL edit, lock or unlock.

Only the existing Apple Development identity is used. All bundles/tickets live in
ignored .build/. The legacy no-UI flag is set/read/restored in each single-threaded
fixture process, never as a user/global setting. A timeout terminates only the owned
child; no authorization dialog is answered. No user credentials are read.

References: Apple TN3137, TN2206; SDK SecItem.h (legacy UI caveat), SecKeychain.h
(process optional-interaction flag), SecAccess.h/SecACL.h (default creator ACL).
Run: /usr/bin/python3 Scripts/verify_file_keychain_candidate.py
Exact recovery: --cleanup-run <run UUID>
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hmac
import os
from pathlib import Path
import plistlib
import re
import shutil
import sys
import uuid

sys.dont_write_bytecode = True
from verify_signed_keychain import Harness, ProbeFailure, ROOT, FLAGS

STORE = ROOT / ".build" / "file-keychain-candidate"
CREATOR_ID = "org.openlxssh.p103.FileKeychainCandidate"
OTHER_ID = CREATOR_ID + ".DifferentIdentifier"
EXECUTABLE = "FileKeychainCandidate"


class FileHarness(Harness):
    def __init__(self, run_id):
        super().__init__(run_id)
        self.log.close()
        self.work = STORE / str(run_id)
        self.active = self.work / "FileKeychainCandidate.app"
        self.backup = self.work / "original" / "FileKeychainCandidate.app"
        self.log = (ROOT / ".build" / "verification" / ("file-candidate-" + str(run_id) + ".log")).open("a", encoding="utf-8")

    def bundle(self, destination, binary, version, identifier):
        if destination.exists():
            raise ProbeFailure("Refuse to overwrite fixture")
        (destination / "Contents" / "MacOS").mkdir(parents=True, mode=0o700)
        info = {"CFBundleExecutable": EXECUTABLE, "CFBundleIdentifier": identifier,
                "CFBundleName": "OpenLXSSH File Keychain Candidate Fixture", "CFBundlePackageType": "APPL",
                "CFBundleVersion": str(version), "CFBundleShortVersionString": "0.0." + str(version),
                "LSMinimumSystemVersion": "15.0", "LSUIElement": True}
        with (destination / "Contents" / "Info.plist").open("wb") as output:
            plistlib.dump(info, output)
        shutil.copy2(binary, destination / "Contents" / "MacOS" / EXECUTABLE)
        os.chmod(destination / "Contents" / "MacOS" / EXECUTABLE, 0o700)

    def sign_file(self, bundle, identity, identifier):
        args = ["/usr/bin/codesign", "--force", "--sign", identity, "--options", "runtime", "--timestamp=none",
                "--identifier", identifier, str(bundle)]
        shown = list(args)
        shown[shown.index(identity)] = "<existing-Apple-Development-identity>"
        code, _, _ = self.command(args, shown=shown, timeout=15)
        if code:
            raise ProbeFailure("Existing identity signing failed; no ACL modification or retry")

    def verify_file(self, bundle, identifier, adhoc=False):
        code, _, _ = self.command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(bundle)])
        if code:
            raise ProbeFailure("Strict signature check failed")
        code, out, error = self.command(["/usr/bin/codesign", "--display", "--verbose=4", str(bundle)])
        text = (out + error).decode(errors="replace")
        team = re.findall(r"^TeamIdentifier=(.+)$", text, re.M)
        actual_id = re.findall(r"^Identifier=(.+)$", text, re.M)
        hashes = re.findall(r"^CDHash=(.+)$", text, re.M)
        runtime = bool(re.search(r"^CodeDirectory.*\bruntime\b", text, re.M))
        team_ok = team == (["not set"] if adhoc else [self.team])
        self.emit("signature_team_expected: " + str(team_ok))
        self.emit("signature_identifier_expected: " + str(actual_id == [identifier]))
        self.emit("hardened_runtime_enabled: " + str(runtime))
        self.emit("signature_is_adhoc: " + str("Signature=adhoc" in text))
        adhoc_ok = ("Signature=adhoc" in text) == adhoc
        if code or not team_ok or not adhoc_ok or actual_id != [identifier] or not runtime or len(hashes) != 1:
            raise ProbeFailure("Unexpected fixture signature")
        code, out, _ = self.command(["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", str(bundle)])
        claimed = plistlib.loads(out) if out.strip() else {}
        self.emit("candidate_entitlement_count: " + str(len(claimed)))
        if code or claimed:
            raise ProbeFailure("File candidate must not claim DP access-group or runtime exception entitlements")
        code, out, error = self.command(["/usr/bin/codesign", "--display", "-r-", str(bundle)])
        if code:
            raise ProbeFailure("Cannot inspect designated requirement")
        # Requirement is stdout; stderr contains Executable=<bundle-specific-path>.
        # Compare the actual designated expression, never the display path prefix/suffix.
        if b"designated => " not in out:
            raise ProbeFailure("Missing designated requirement expression")
        requirement = out.split(b"designated => ", 1)[-1].strip().splitlines()[0]
        if bundle == self.active:
            self.signature_verified = True
        return hashes[0], requirement

    def step(self, mode, ticket, bundle=None, proof=False):
        binary = (bundle or self.active) / "Contents" / "MacOS" / EXECUTABLE
        read_fd = write_fd = None
        try:
            args = [str(binary), mode, str(ticket)]
            if proof:
                read_fd, write_fd = os.pipe()
                args.append(str(write_fd))
            code, out, _ = self.command(args, pass_fds=(write_fd,) if proof else (), timeout=15)
            lines = out.decode(errors="replace").splitlines()
            for line in lines:
                if line.startswith("FILE CANDIDATE "):
                    self.emit(line)
            if code:
                raise ProbeFailure("Explicit file candidate step failed; retain exact ticket, do not change ACL")
            if "FILE CANDIDATE process_interaction_flag_restored: true" not in lines:
                raise ProbeFailure("Process interaction flag restoration not verified")
            if proof:
                os.close(write_fd)
                write_fd = None
                result = os.read(read_fd, 33)
                if len(result) != 32:
                    raise ProbeFailure("Invalid memory proof framing")
                return result
        finally:
            if read_fd is not None:
                os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)

    def cleanup_pending(self):
        state = self.work / "state"
        if not state.exists():
            return
        tickets = sorted(state.glob("*.json"))
        self.emit("pending_exact_ticket_count: " + str(len(tickets)))
        if tickets and not self.signature_verified:
            raise ProbeFailure("Cleanup creator code is not verified; retain ticket")
        for ticket in tickets:
            self.step("cleanup", ticket)
        self.emit("all_own_keychain_items_cleanup_verified: " + str(not list(state.glob("*.json"))))

    def execute_file(self, cleanup_only=False):
        self.emit("Task P1-03-R2; explicit file-based candidate; no DP fallback")
        self.emit("fixture_run_uuid: " + str(self.run_id))
        identity = self.discover_identity()
        if cleanup_only:
            self.verify_file(self.active, CREATOR_ID)
            self.cleanup_pending()
            return
        pending = list(STORE.glob("*/state/*.json"))
        if pending:
            raise ProbeFailure("Prior exact cleanup tickets remain; use --cleanup-run before new writes")
        self.work.mkdir(mode=0o700, parents=True)
        state = self.work / "state"
        state.mkdir(mode=0o700)
        code, _, _ = self.command(["/usr/bin/swift", "build", "--package-path", str(ROOT), "-c", "release"] + FLAGS, timeout=120)
        if code:
            raise ProbeFailure("Release build failed")
        code, out, _ = self.command(["/usr/bin/swift", "build", "--package-path", str(ROOT), "-c", "release", "--show-bin-path"])
        binary = Path(out.decode().strip()) / "openlxssh-file-keychain-candidate"
        if code or not binary.is_file() or ROOT / ".build" not in binary.parents:
            raise ProbeFailure("Unexpected candidate executable")
        replacement = self.work / "replacement" / "FileKeychainCandidate.app"
        other = self.work / "different-identifier" / "FileKeychainCandidate.app"
        adhoc = self.work / "different-signature" / "FileKeychainCandidate.app"
        for destination, version, identifier in [(self.active, 1, CREATOR_ID), (replacement, 2, CREATOR_ID), (other, 1, OTHER_ID)]:
            self.bundle(destination, binary, version, identifier)
            self.sign_file(destination, identity, identifier)
        self.bundle(adhoc, binary, 1, CREATOR_ID)
        code, _, _ = self.command(["/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime", "--timestamp=none",
                                   "--identifier", CREATOR_ID, str(adhoc)])
        if code:
            raise ProbeFailure("Cannot create isolated ad hoc negative fixture")
        first_hash, first_requirement = self.verify_file(self.active, CREATOR_ID)
        second_hash, second_requirement = self.verify_file(replacement, CREATOR_ID)
        _, other_requirement = self.verify_file(other, OTHER_ID)
        _, adhoc_requirement = self.verify_file(adhoc, CREATOR_ID, adhoc=True)
        self.emit("same_identity_replacement_DR_equal: " + str(first_requirement == second_requirement))
        self.emit("same_identity_replacement_code_hash_changed: " + str(first_hash != second_hash))
        self.emit("different_identifier_DR_different: " + str(first_requirement != other_requirement))
        self.emit("different_signature_DR_different: " + str(first_requirement != adhoc_requirement))
        if first_requirement != second_requirement or first_hash == second_hash or first_requirement == other_requirement or first_requirement == adhoc_requirement:
            raise ProbeFailure("Code identity comparison failed")
        ticket = state / "own-item.json"
        expected = self.step("create", ticket, proof=True)
        observed = self.step("read", ticket, proof=True)
        self.emit("same_creator_relaunch_memory_digest_matches: " + str(hmac.compare_digest(expected, observed)))
        if not hmac.compare_digest(expected, observed):
            raise ProbeFailure("Relaunch proof mismatch")
        # Separate fixture processes: no shared interaction flag or concurrent legacy API
        # calls within one process. Wrong namespace/reference queries run alongside a valid
        # creator read, and may never be accepted as a code-denial substitute.
        with ThreadPoolExecutor(max_workers=3) as pool:
            valid = pool.submit(self.step, "read", ticket, proof=True)
            wrong1 = pool.submit(self.step, "wrong-reference", ticket)
            wrong2 = pool.submit(self.step, "wrong-reference", ticket)
            concurrent_proof = valid.result()
            wrong1.result()
            wrong2.result()
        self.emit("concurrent_valid_read_memory_digest_matches: " + str(hmac.compare_digest(expected, concurrent_proof)))
        if not hmac.compare_digest(expected, concurrent_proof):
            raise ProbeFailure("Concurrent creator read proof mismatch")
        self.step("deny", ticket, bundle=other)
        self.step("deny", ticket, bundle=adhoc)
        self.backup.parent.mkdir(mode=0o700)
        self.signature_verified = False
        self.active.rename(self.backup)
        replacement.rename(self.active)
        self.verify_file(self.active, CREATOR_ID)
        observed = self.step("read", ticket, proof=True)
        self.emit("same_DR_version_replacement_memory_digest_matches: " + str(hmac.compare_digest(expected, observed)))
        if not hmac.compare_digest(expected, observed):
            raise ProbeFailure("Same-DR replacement proof mismatch")
        self.cleanup_pending()
        self.emit("FILE CANDIDATE local_signed_CRUD_ACL_relaunch_replacement_denial: PASS")
        self.emit("locked_keychain_runtime_test_executed: False (no user Keychain lock/unlock)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cleanup-run", type=uuid.UUID)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("Do not run as root")
    STORE.mkdir(mode=0o700, parents=True, exist_ok=True)
    harness = FileHarness(args.cleanup_run or uuid.uuid4())
    result = 0
    try:
        harness.execute_file(cleanup_only=args.cleanup_run is not None)
    except (ProbeFailure, OSError, ValueError, KeyboardInterrupt) as error:
        harness.emit("INCOMPLETE: " + (str(error) if isinstance(error, ProbeFailure) else type(error).__name__))
        result = 1
    finally:
        try:
            harness.cleanup_pending()
        except (ProbeFailure, OSError, ValueError):
            harness.emit("CLEANUP INCOMPLETE; exact nonsecret ticket retained")
            harness.emit("recovery: /usr/bin/python3 " + str(Path(__file__).resolve()) + " --cleanup-run " + str(harness.run_id))
            result = 3
        harness.emit("script_exit: " + str(result))
        harness.log.close()
    return result


if __name__ == "__main__":
    sys.exit(main())
