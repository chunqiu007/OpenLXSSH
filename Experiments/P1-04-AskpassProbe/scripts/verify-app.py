#!/usr/bin/env python3
"""P1-06A runtime/non-Sandbox .app + actual local OpenSSH readpass probe."""
from pathlib import Path
import os
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CONFIG = sys.argv[1] if len(sys.argv) == 2 else "debug"
if CONFIG not in ("debug", "release"):
    raise SystemExit(64)
LOG = ROOT / ".build" / "verification"
LOG.mkdir(parents=True, exist_ok=True)


def run(name, args, *, sensitive=False, timeout=20):
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True, text=True)
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=2)
        (LOG / f"{CONFIG}-app-{name}.log").write_text("timeout=True\n")
        raise SystemExit(75)
    text = f"success={process.returncode == 0}\noutput_withheld=True\n" if sensitive else output
    (LOG / f"{CONFIG}-app-{name}.log").write_text(text + f"exit={process.returncode}\n")
    print(f"app-{name} exit={process.returncode}")
    if process.returncode:
        if not sensitive:
            print(output)
        raise SystemExit(process.returncode)
    return output


run("build", ["swift", "build", "--package-path", str(ROOT), "-c", CONFIG,
              "-Xswiftc", "-warnings-as-errors", "-Xcc", "-Wall", "-Xcc", "-Wextra", "-Xcc", "-Werror"], timeout=120)
run("fixture-signatures", ["/bin/bash", str(ROOT / "scripts/package-fixtures.sh"), CONFIG], timeout=70)
identities = subprocess.run(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"], capture_output=True, text=True, timeout=10)
candidates = re.findall(r'\b([A-Fa-f0-9]{40})\s+"Apple Development:[^"\n]*"', identities.stdout)
if identities.returncode or len(candidates) != 1:
    print("unique_existing_development_identity=False")
    raise SystemExit(76)
bin_path = Path(subprocess.run(["swift", "build", "--package-path", str(ROOT), "-c", CONFIG, "--show-bin-path"],
                               capture_output=True, text=True, check=True, timeout=20).stdout.strip())
# Dedicated experiment-owned random directory; remove only this owned .app after
# it has exited. Keys are separately created/deleted inside the running App.
parent = ROOT / ".build" / "app-probes"
parent.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix=f"{CONFIG}-", dir=parent) as temporary:
    app = Path(temporary) / "OpenLXSSHAuthenticationProbe.app"
    macos = app / "Contents/MacOS"
    helpers = app / "Contents/Helpers"
    macos.mkdir(parents=True)
    helpers.mkdir()
    info = {
        "CFBundleName": "OpenLXSSHAuthenticationProbe",
        "CFBundleDisplayName": "OpenLXSSHAuthenticationProbe",
        "CFBundleIdentifier": "org.openlxssh.p104c.broker",
        "CFBundleExecutable": "OpenLXSSHAuthenticationProbe",
        "CFBundlePackageType": "APPL",
        "CFBundleVersion": "1",
        "CFBundleShortVersionString": "0.1",
        "LSMinimumSystemVersion": "15.0",
        "LSUIElement": True,
        "NSHighResolutionCapable": True,
    }
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
    executable = macos / "OpenLXSSHAuthenticationProbe"
    shutil.copyfile(bin_path / executable.name, executable)
    executable.chmod(0o755)
    helper = helpers / "openlxssh-askpass-helper"
    shutil.copyfile(ROOT / ".build/fixtures" / CONFIG / helper.name, helper)
    helper.chmod(0o755)
    run("helper-verify", ["/usr/bin/codesign", "--verify", "--strict", str(helper)], sensitive=True)
    run("sign", ["/usr/bin/codesign", "--force", "--sign", candidates[0], "--options", "runtime", "--identifier",
                 "org.openlxssh.p104c.broker", "--timestamp=none", str(app)], sensitive=True)
    run("verify", ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], sensitive=True)
    # Launch actual AppKit NSApplication from a genuine signed .app, with stdout
    # captured by parent. Finder/LaunchServices activation is not claimed here.
    output = run("readpass", [str(executable)], timeout=30)
    for index, service in enumerate(re.findall(r"^POSTEXIT_SERVICE (\S+)$", output, re.M)):
        run(f"post-exit-{index}", [str(ROOT / ".build/fixtures" / CONFIG / "openlxssh-askpass-probe"), "--lookup", service])
    if "APP-PROBE PASS scenarios=3" not in output:
        raise SystemExit(1)
print("PASS owned temporary .app removed")
print("NOT VERIFIED real SSH server authentication/MFA, macOS26, Sandbox, DeveloperID, notarization, Finder launch")
