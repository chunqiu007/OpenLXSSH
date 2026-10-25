#!/usr/bin/env python3
"""Build/sign only this package's local fixture. Existing identity, offline, no ACL edits.

The reviewed R2 identity discovery/command redaction is a test-script dependency only;
no experiment is linked into OpenLXSSHSecurity. Bundle outputs stay in ignored .build.
"""
import os
from pathlib import Path
import plistlib
import re
import shutil
import sys
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT.parents[1] / "Experiments" / "P1-03-CredentialKeyProbe" / "Scripts"
sys.path.insert(0, str(EXPERIMENT))
import verify_signed_keychain as reviewed
reviewed.ROOT = ROOT
reviewed.STORE = ROOT / ".build" / "signed-fixtures"
reviewed.VERIFY = ROOT / ".build" / "verification"


def main():
    if os.geteuid() == 0:
        return 64
    harness = reviewed.Harness(uuid.uuid4())
    result = 0
    try:
        identity = harness.discover_identity()
        harness.work.mkdir(parents=True, mode=0o700)
        code, _, _ = harness.command(["/usr/bin/swift", "build", "--package-path", str(ROOT), "-c", "release"] + reviewed.FLAGS, timeout=120)
        if code:
            raise reviewed.ProbeFailure("Security package Release build failed")
        code, out, _ = harness.command(["/usr/bin/swift", "build", "--package-path", str(ROOT), "-c", "release", "--show-bin-path"])
        binary = Path(out.decode().strip()) / "OpenLXSSHSecurityFixture"
        bundle = harness.work / "OpenLXSSHSecurityFixture.app"
        executable = bundle / "Contents" / "MacOS" / "OpenLXSSHSecurityFixture"
        executable.parent.mkdir(parents=True, mode=0o700)
        shutil.copy2(binary, executable)
        os.chmod(executable, 0o700)
        with (bundle / "Contents" / "Info.plist").open("wb") as output:
            plistlib.dump({"CFBundleExecutable": executable.name, "CFBundleIdentifier": "org.openlxssh.security.PackageFixture",
                          "CFBundleName": "OpenLXSSH Security Package Fixture", "CFBundlePackageType": "APPL",
                          "CFBundleVersion": "1", "LSMinimumSystemVersion": "15.0", "LSUIElement": True}, output)
        args = ["/usr/bin/codesign", "--force", "--sign", identity, "--options", "runtime", "--timestamp=none", str(bundle)]
        shown = list(args); shown[shown.index(identity)] = "<existing-Apple-Development-identity>"
        code, _, _ = harness.command(args, shown=shown, timeout=15)
        if code:
            raise reviewed.ProbeFailure("Existing identity signing failed; no ACL changes or authorization supplied")
        code, _, _ = harness.command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(bundle)])
        if code:
            raise reviewed.ProbeFailure("Strict signature validation failed")
        code, out, error = harness.command(["/usr/bin/codesign", "--display", "--verbose=4", str(bundle)])
        text = (out + error).decode(errors="replace")
        matches = re.findall(r"^TeamIdentifier=(.+)$", text, re.M) == [harness.team]
        runtime = bool(re.search(r"^CodeDirectory.*\bruntime\b", text, re.M))
        harness.emit("signature_team_matches_existing_identity: " + str(matches))
        harness.emit("signature_hardened_runtime: " + str(runtime))
        if code or not matches or not runtime or "Signature=adhoc" in text:
            raise reviewed.ProbeFailure("Unexpected fixture signature")
        code, out, _ = harness.command([str(executable)], timeout=20)
        for line in out.decode(errors="replace").splitlines():
            if line.startswith("SECURITY FIXTURE "):
                harness.emit(line)
        if code:
            raise reviewed.ProbeFailure("Real signed Security package fixture failed")
    except (reviewed.ProbeFailure, OSError, ValueError) as error:
        harness.emit("INCOMPLETE: " + (str(error) if isinstance(error, reviewed.ProbeFailure) else type(error).__name__))
        result = 1
    finally:
        harness.emit("script_exit: " + str(result))
        harness.log.close()
    return result


if __name__ == "__main__":
    sys.exit(main())
