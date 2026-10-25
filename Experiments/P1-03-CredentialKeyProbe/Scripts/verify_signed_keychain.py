#!/usr/bin/env python3
"""Offline, existing-identity-only macOS Keychain experiment. Never run with sudo.

Run: /usr/bin/python3 Scripts/verify_signed_keychain.py
Recovery: same command with --cleanup-run <printed run UUID>.

Evidence used for the single entitlement hypothesis:
- SDK Entitlements.plist: com.apple.application-identifier template.
- SDK Security.framework/Headers/SecItem.h: application identifier is the private
  default group when keychain-access-groups is absent.
- https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps
- https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles
- https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains
  Data Protection access-group entitlements, including the private default group,
  require provisioning authorization. This deliberately profile-free experiment
  tests the existing-identity/minimal-appID hypothesis once, not a supported
  substitute for provisioning. Explicit shared groups are never claimed.

No Apple login, profile/certificate creation, timestamp server, ACL changes,
security weakening, private key export, or authorization-dialog automation.
Identity hash/certificate subject/Team/entitlement values never enter logs.
The signing command is bounded: a dialog or denied private-key access must be
resolved by the user outside this script, not by changing ACLs or retrying here.
"""
import argparse
import hashlib
import hmac
import os
from pathlib import Path
import plistlib
import re
import shlex
import shutil
import signal
import ssl
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_ID = "org.openlxssh.p103.KeychainProbe"  # Fixture only, not the product identifier.
EXECUTABLE = "KeychainProbe"
STORE = ROOT / ".build" / "signed-keychain"
VERIFY = ROOT / ".build" / "verification"
FLAGS = ["-Xswiftc", "-warnings-as-errors", "-Xcc", "-Wall", "-Xcc", "-Wextra", "-Xcc", "-Werror"]


class ProbeFailure(Exception):
    pass


class Harness:
    def __init__(self, run_id):
        self.run_id = run_id
        self.work = STORE / str(run_id)
        self.active = self.work / "KeychainProbe.app"
        self.backup = self.work / "version1" / "KeychainProbe.app"
        VERIFY.mkdir(parents=True, exist_ok=True)
        self.log = (VERIFY / ("signed-keychain-" + str(run_id) + ".log")).open("a", encoding="utf-8")
        self.redactions = []
        self.expected_entitlements = None
        self.team = None
        self.signature_verified = False

    def emit(self, line):
        # No unrestricted child output may be emitted: callers choose summaries only.
        for value in self.redactions:
            line = line.replace(value, "<identity-metadata>")
        print(line, flush=True)
        self.log.write(line + "\n")
        self.log.flush()

    def command(self, arguments, *, shown=None, timeout=20, input_bytes=None, pass_fds=()):
        self.emit("cwd: " + str(ROOT))
        self.emit("command: " + shlex.join(shown or arguments))
        process = subprocess.Popen(arguments, cwd=ROOT, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=pass_fds,
                                   start_new_session=True,
                                   env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(Path.home())})
        try:
            stdout, stderr = process.communicate(input=input_bytes, timeout=timeout)
        except subprocess.TimeoutExpired:
            # No dialog is answered. Only this owned process group is terminated/reaped.
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            self.emit("exit: timeout; owned process reaped; possible authorization interaction, no response supplied")
            raise ProbeFailure("Bounded command timed out; stop, do not approve prompts or retry signing")
        self.emit("exit: " + str(process.returncode))
        return process.returncode, stdout, stderr

    def discover_identity(self):
        args = ["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"]
        code, out, _ = self.command(args)
        if code:
            raise ProbeFailure("Unable to inspect existing identities")
        identities = re.findall(rb'\b([A-Fa-f0-9]{40})\s+"([^\"]+)"', out)
        selected = [(value.decode(), name.decode()) for value, name in identities if name.startswith(b"Apple Development:")]
        self.emit("valid_identity_count: " + str(len(identities)))
        self.emit("apple_development_identity_count: " + str(len(selected)))
        if len(selected) != 1:
            raise ProbeFailure("Need exactly one existing Apple Development identity; no automatic selection or creation")
        identity, subject = selected[0]
        self.redactions += [identity, subject]
        args = ["/usr/bin/security", "find-certificate", "-a", "-c", subject, "-p"]
        shown = ["/usr/bin/security", "find-certificate", "-a", "-c", "<selected-public-certificate-subject>", "-p"]
        code, out, _ = self.command(args, shown=shown)
        certificates = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S)
        matching = [cert for cert in certificates if hashlib.sha1(ssl.PEM_cert_to_DER_cert(cert.decode())).hexdigest().upper() == identity.upper()]
        self.emit("matching_public_certificate_count: " + str(len(matching)))
        if code or len(matching) != 1:
            raise ProbeFailure("Selected identity does not uniquely match its existing public certificate")
        args = ["/usr/bin/openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253"]
        code, out, _ = self.command(args, input_bytes=matching[0])
        teams = re.findall(rb"(?:^|,)OU=([A-Z0-9]{10})(?:,|$)", out.replace(b"subject=", b"").strip())
        self.emit("certificate_team_count: " + str(len(teams)))
        if code or len(teams) != 1:
            raise ProbeFailure("No unique Team identifier in the matching Apple Development certificate")
        self.team = teams[0].decode()
        self.redactions += [self.team]
        self.expected_entitlements = {"com.apple.application-identifier": self.team + "." + BUNDLE_ID}
        self.emit("team_source_is_matching_existing_certificate: True")
        self.emit("explicit_shared_access_group_count: 0")
        return identity

    def build_bundle(self, destination, binary, version):
        if destination.exists():
            raise ProbeFailure("Refuse to overwrite an existing fixture bundle")
        (destination / "Contents" / "MacOS").mkdir(parents=True, mode=0o700)
        info = {"CFBundleExecutable": EXECUTABLE, "CFBundleIdentifier": BUNDLE_ID,
                "CFBundleName": "OpenLXSSH P1-03 Keychain Fixture", "CFBundlePackageType": "APPL",
                "CFBundleVersion": str(version), "CFBundleShortVersionString": "0.0." + str(version),
                "LSMinimumSystemVersion": "15.0", "LSUIElement": True,
                "NSHighResolutionCapable": True}
        with (destination / "Contents" / "Info.plist").open("wb") as output:
            plistlib.dump(info, output)
        shutil.copy2(binary, destination / "Contents" / "MacOS" / EXECUTABLE)
        os.chmod(destination / "Contents" / "MacOS" / EXECUTABLE, 0o700)

    def sign(self, bundle, identity):
        entitlements = self.work / "private-default-group.entitlements"
        with entitlements.open("wb") as output:
            plistlib.dump(self.expected_entitlements, output)
        os.chmod(entitlements, 0o600)
        args = ["/usr/bin/codesign", "--force", "--sign", identity, "--options", "runtime", "--timestamp=none",
                "--entitlements", str(entitlements), "--identifier", BUNDLE_ID, str(bundle)]
        shown = list(args)
        shown[shown.index(identity)] = "<existing-Apple-Development-identity>"
        code, _, error = self.command(args, shown=shown, timeout=15)
        if code:
            # codesign may print certificate names/hash; never echo its raw diagnostics.
            known = re.findall(rb"(?:errSec[A-Za-z]+|CSSMERR_[A-Z_]+|0x[0-9a-fA-F]{8})", error)
            self.emit("sign_error_symbol_count: " + str(len(known)))
            raise ProbeFailure("Existing identity signing failed; raw identity-bearing diagnostic withheld; no ACL change/retry")

    def verify_bundle(self, bundle):
        args = ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(bundle)]
        code, _, _ = self.command(args)
        if code:
            raise ProbeFailure("Strict bundle verification failed")
        code, out, error = self.command(["/usr/bin/codesign", "--display", "--verbose=4", str(bundle)])
        text = (out + error).decode(errors="replace")
        observed_team = re.findall(r"^TeamIdentifier=(.+)$", text, re.M)
        identifier = re.findall(r"^Identifier=(.+)$", text, re.M)
        cdhash = re.findall(r"^CDHash=(.+)$", text, re.M)
        runtime = bool(re.search(r"^CodeDirectory.*\bruntime\b", text, re.M))
        self.emit("signature_team_matches_certificate: " + str(observed_team == [self.team]))
        self.emit("signature_identifier_matches_fixture: " + str(identifier == [BUNDLE_ID]))
        self.emit("hardened_runtime_enabled: " + str(runtime))
        self.emit("ad_hoc_signature: " + str("Signature=adhoc" in text))
        if code or observed_team != [self.team] or identifier != [BUNDLE_ID] or not runtime or "Signature=adhoc" in text or len(cdhash) != 1:
            raise ProbeFailure("Signature identity/runtime check failed")
        code, out, _ = self.command(["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", str(bundle)])
        try:
            claimed = plistlib.loads(out)
        except plistlib.InvalidFileException:
            raise ProbeFailure("Unable to parse signed entitlements") from None
        self.emit("signed_entitlement_count: " + str(len(claimed)))
        self.emit("signed_entitlements_match_exact_minimum: " + str(claimed == self.expected_entitlements))
        if code or claimed != self.expected_entitlements:
            raise ProbeFailure("Unexpected entitlement; no execution")
        code, out, error = self.command(["/usr/bin/codesign", "--display", "-r-", str(bundle)])
        if code:
            raise ProbeFailure("Unable to read designated requirement")
        if bundle == self.active:
            self.signature_verified = True
        return cdhash[0], out + error

    def run_probe(self, options, proof=False):
        binary = self.active / "Contents" / "MacOS" / EXECUTABLE
        read_fd = write_fd = None
        try:
            if proof:
                read_fd, write_fd = os.pipe()
                options = options + [str(write_fd)]
            code, out, _ = self.command([str(binary)] + options, pass_fds=(write_fd,) if proof else (), timeout=20)
            # This is a controlled CLI. Log only expected status lines, never arbitrary data.
            for line in out.decode(errors="replace").splitlines():
                if line.startswith(("REAL Keychain ", "Exact cleanup ", "SELF SIGNING ")):
                    self.emit(line)
            if code:
                raise ProbeFailure("Real signed Keychain step failed; no entitlement expansion/retry")
            if proof:
                os.close(write_fd)
                write_fd = None
                value = os.read(read_fd, 33)
                if len(value) != 32:
                    raise ProbeFailure("Invalid memory-only proof framing")
                return value
        finally:
            if read_fd is not None:
                os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)

    def cleanup_pending(self):
        pending = self.work / "state"
        if not pending.exists():
            return
        tickets = sorted(pending.glob("*.json"))
        self.emit("pending_exact_cleanup_ticket_count: " + str(len(tickets)))
        if tickets and not self.signature_verified:
            raise ProbeFailure("Do not execute unverified cleanup code; retain exact ticket")
        for ticket in tickets:
            self.run_probe(["--keychain-handoff-cleanup", str(ticket)])
        if list(pending.glob("*.json")):
            raise ProbeFailure("Exact cleanup tickets remain; do not discard or start another run")

    def handoff(self, name, between=None):
        state = self.work / "state"
        state.mkdir(mode=0o700, exist_ok=True)
        os.chmod(state, 0o700)
        ticket = state / (name + ".json")
        first = self.run_probe(["--keychain-handoff-create", str(ticket)], proof=True)
        if between:
            between()
        second = self.run_probe(["--keychain-handoff-read-delete", str(ticket)], proof=True)
        matches = hmac.compare_digest(first, second)
        self.emit(name + "_memory_proof_matches: " + str(matches))
        self.emit(name + "_cleanup_ticket_removed: " + str(not ticket.exists()))
        if not matches or ticket.exists():
            raise ProbeFailure("Cross-launch proof mismatch or incomplete cleanup")

    def execute(self, cleanup_only=False, diagnostics_only=False):
        self.emit("Task P1-03-R1; experimental local bundle only; no product signing/notarization")
        self.emit("fixture_run_uuid: " + str(self.run_id))
        self.emit("signing_timestamp_network_request: False")
        identity = self.discover_identity()
        if cleanup_only:
            self.verify_bundle(self.active)
            self.cleanup_pending()
            return
        unresolved = list(STORE.glob("*/state/*.json"))
        if unresolved:
            self.emit("unresolved_cleanup_ticket_count: " + str(len(unresolved)))
            raise ProbeFailure("Resolve prior probe tickets with --cleanup-run before creating another fixture")
        self.work.mkdir(mode=0o700, parents=True)
        args = ["/usr/bin/swift", "build", "--package-path", str(ROOT), "-c", "release"] + FLAGS
        code, _, _ = self.command(args, timeout=120)
        if code:
            raise ProbeFailure("Release build failed")
        args = ["/usr/bin/swift", "build", "--package-path", str(ROOT), "-c", "release", "--show-bin-path"]
        code, out, _ = self.command(args)
        binary = Path(out.decode().strip()) / "openlxssh-credential-key-probe"
        if code or not binary.is_file() or ROOT / ".build" not in binary.parents:
            raise ProbeFailure("Unexpected binary location")
        replacement = self.work / "version2" / "KeychainProbe.app"
        self.build_bundle(self.active, binary, 1)
        self.sign(self.active, identity)
        first_hash, first_requirement = self.verify_bundle(self.active)
        self.run_probe(["--signing-diagnostics"])
        if diagnostics_only:
            self.emit("Diagnostics only; no Keychain operation requested")
            return
        self.run_probe(["--keychain"])
        self.run_probe(["--keychain"])
        self.build_bundle(replacement, binary, 2)
        self.sign(replacement, identity)
        second_hash, second_requirement = self.verify_bundle(replacement)
        # codesign -r prints its bundle path before the designated requirement. Compare
        # only the requirement itself, while retaining all identity values in memory.
        requirement = lambda value: value.split(b"designated => ", 1)[-1].strip()
        same_requirement = requirement(first_requirement) == requirement(second_requirement)
        self.emit("replacement_code_hash_changed: " + str(first_hash != second_hash))
        self.emit("replacement_designated_requirement_matches: " + str(same_requirement))
        if first_hash == second_hash or not same_requirement:
            raise ProbeFailure("Replacement must change signed version while preserving code identity")
        self.handoff("same-version-relaunch")

        def activate_replacement():
            self.backup.parent.mkdir(mode=0o700)
            self.signature_verified = False
            self.active.rename(self.backup)
            replacement.rename(self.active)
            self.verify_bundle(self.active)

        self.handoff("same-identity-version-replacement", activate_replacement)
        self.run_probe(["--keychain"])
        self.emit("REAL signed Keychain CRUD/relaunch/replacement PASS; exact cleanup complete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.add_mutually_exclusive_group()
    options.add_argument("--cleanup-run", type=uuid.UUID)
    options.add_argument("--diagnostics-only", action="store_true")
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("Do not use sudo/root for this per-user probe")
    STORE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STORE, 0o700)
    harness = Harness(args.cleanup_run or uuid.uuid4())
    code = 0
    try:
        harness.execute(cleanup_only=args.cleanup_run is not None, diagnostics_only=args.diagnostics_only)
    except (ProbeFailure, OSError, ValueError, KeyboardInterrupt) as error:
        # OSError may contain a sensitive pathname; only known sanitized failures get text.
        harness.emit("INCOMPLETE: " + (str(error) if isinstance(error, ProbeFailure) else type(error).__name__))
        code = 1
    finally:
        try:
            harness.cleanup_pending()
        except (ProbeFailure, OSError, ValueError):
            harness.emit("CLEANUP INCOMPLETE; retain exact UUID ticket; do not discard state")
            harness.emit("recovery: /usr/bin/python3 " + str(Path(__file__).resolve()) + " --cleanup-run " + str(harness.run_id))
            code = 3
        harness.emit("script_exit: " + str(code))
        harness.log.close()
    return code


if __name__ == "__main__":
    sys.exit(main())
