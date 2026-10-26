#!/usr/bin/env python3
"""Build/test and sign an owned host fixture; no remote SSH, cert creation or upload."""
from pathlib import Path
import os
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
CONFIG = sys.argv[1] if len(sys.argv) > 1 else "debug"
if CONFIG not in ("debug", "release"):
    raise SystemExit(64)
LOG = ROOT / ".build/verification"
LOG.mkdir(parents=True, exist_ok=True)
env = dict(os.environ, OPENLXSSH_TRANSPORT_HOST_PROBE="1")
base = ["/bin/bash", str(ROOT / "Scripts/offline.sh"), "swift"]
common = ["--package-path", str(ROOT), "-c", CONFIG, "--disable-automatic-resolution", "--cache-path", str(ROOT / ".build/cache")]

def run(name, command, timeout=180, sensitive=False, custom_env=None):
    child = subprocess.Popen(command, cwd=ROOT, env=custom_env or env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, start_new_session=True)
    try:
        output, _ = child.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.communicate(timeout=3)
        (LOG / f"{CONFIG}-{name}.log").write_text("TIMEOUT\nexit=124\n")
        raise SystemExit(124)
    text = f"output_withheld=True\n" if sensitive else output
    (LOG / f"{CONFIG}-{name}.log").write_text(text + f"exit={child.returncode}\n")
    print(f"{name} exit={child.returncode}", flush=True)
    if child.returncode:
        if not sensitive:
            print(output)
        raise SystemExit(child.returncode)
    return output

run("build", base + ["build"] + common + ["-Xswiftc", "-warnings-as-errors", "-Xcc", "-Wall", "-Xcc", "-Wextra"], timeout=300)
run("test", base + ["test"] + common, timeout=180)
bin_path = Path(run("bin-path", base + ["build"] + common + ["--show-bin-path"]).strip())
# Inspect existing identities only in memory. Never print/store their subjects,
# fingerprints or signing-tool authorization output; do not create certs or ACLs.
ids = subprocess.run(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"], capture_output=True, text=True, check=True, timeout=10)
candidates = re.findall(r'\b([A-Fa-f0-9]{40})\s+"Apple Development:[^"\n]*"', ids.stdout)
if len(candidates) != 1:
    raise SystemExit("exactly one existing Development identity required")
parent = ROOT / ".build/signed-fixtures" / CONFIG
parent.mkdir(parents=True, exist_ok=True)
# New inodes/UUID paths avoid stale SecCode caches; delete only this owned tree.
with tempfile.TemporaryDirectory(prefix=f"{uuid.uuid4()}-", dir=parent) as temporary:
    owned = Path(temporary)
    owned.chmod(0o700)
    app = owned / "OpenLXSSHTransport 'quoted' % Fixture.app"
    macos = app / "Contents/MacOS"
    helpers = app / "Contents/Helpers"
    macos.mkdir(parents=True)
    helpers.mkdir()
    exe = macos / "OpenLXSSHTransportFixture"
    helper = helpers / "openlxssh-askpass"
    shutil.copy2(bin_path / "openlxssh-transport-fixture", exe)
    shutil.copy2(bin_path / "openlxssh-askpass", helper)
    # SwiftTerm currently has no resources, but retain resource bundles if added.
    for resource in bin_path.glob("*.bundle"):
        shutil.copytree(resource, macos / resource.name)
    info = {"CFBundleName": "OpenLXSSHTransportFixture", "CFBundleIdentifier": "org.openlxssh.OpenLXSSH",
            "CFBundleExecutable": exe.name, "CFBundlePackageType": "APPL", "CFBundleVersion": "1",
            "LSMinimumSystemVersion": "15.0", "LSUIElement": True}
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
    mirrors = owned / "mirrors"
    mirrors.mkdir()
    for name, identifier, signer in [("helper", "org.openlxssh.askpass", candidates[0]),
                                     ("wrong-identifier", "org.openlxssh.adversarial-helper", candidates[0]),
                                     ("adhoc-helper", "org.openlxssh.askpass", "-")]:
        path = mirrors / name
        shutil.copy2(bin_path / "openlxssh-transport-fixture", path)
        run(f"sign-mirror-{name}", ["/usr/bin/codesign", "--force", "--sign", signer, "--options", "runtime", "--identifier", identifier, "--timestamp=none", str(path)], sensitive=True, timeout=20)
        run(f"verify-mirror-{name}", ["/usr/bin/codesign", "--verify", "--strict", str(path)])
    for name, path, identifier in [("helper", helper, "org.openlxssh.askpass"), ("app", app, "org.openlxssh.OpenLXSSH")]:
        run(f"sign-{name}", ["/usr/bin/codesign", "--force", "--sign", candidates[0], "--options", "runtime", "--identifier", identifier, "--timestamp=none", str(path)], sensitive=True, timeout=20)
        run(f"verify-{name}", ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(path)])
    work = owned / "runtime"
    work.mkdir(mode=0o700)
    ipc_env = dict(env, TRANSPORT_FIXTURE_WORK=str(work), TRANSPORT_ADVERSARY_MIRRORS=str(mirrors))
    output = run("ipc", [str(exe), "--ipc"], timeout=45, custom_env=ipc_env)
    if "TRANSPORT IPC PASS real-system-readpass scenarios=6 events=4" not in output:
        raise SystemExit(1)
    services = re.findall(r"^POSTEXIT_SERVICE (\S+)$", output, re.M)
    if len(services) != 10:
        raise SystemExit("expected ten retained readpass/event services")
    for index, service in enumerate(services):
        run(f"post-exit-{index}", [str(exe), "--lookup", service])
    output = run("adversarial", [str(exe), "--adversarial"], timeout=100, custom_env=ipc_env)
    if "TRANSPORT ADVERSARIAL PASS scenarios=28 raw-kinds=14" not in output:
        raise SystemExit(1)
    services = re.findall(r"^POSTEXIT_SERVICE (\S+)$", output, re.M)
    if len(services) != 28:
        raise SystemExit("expected twenty-eight adversarial services")
    for index, service in enumerate(services):
        run(f"adversarial-post-exit-{index}", [str(exe), "--lookup", service])
    run("dependencies", ["/usr/bin/otool", "-L", str(exe)])
print("PASS owned UUID fixture removed; host runtime only; second Apple Team not available/tested")
print("NOT VERIFIED SSH server authentication/MFA, macOS26 runtime, Sandbox or distribution")
