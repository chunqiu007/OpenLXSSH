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
ids = subprocess.run(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"], capture_output=True, text=True, check=True)
candidates = re.findall(r'\b([A-Fa-f0-9]{40})\s+"Apple Development:[^"\n]*"', ids.stdout)
if len(candidates) != 1:
    raise SystemExit("exactly one existing Development identity required")
# Only new UUID-owned app paths under this package's .build.
parent = ROOT / ".build/signed-fixtures" / CONFIG
parent.mkdir(parents=True, exist_ok=True)
app = parent / "OpenLXSSHTransport 'quoted' % Fixture.app"
if app.exists():
    shutil.rmtree(app)
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
for name, path, identifier in [("helper", helper, "org.openlxssh.askpass"), ("app", app, "org.openlxssh.OpenLXSSH")]:
    run(f"sign-{name}", ["/usr/bin/codesign", "--force", "--sign", candidates[0], "--options", "runtime", "--identifier", identifier, "--timestamp=none", str(path)], sensitive=True)
    run(f"verify-{name}", ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(path)])
work = ROOT / ".build/ipc-runtime"
work.mkdir(exist_ok=True)
ipc_env = dict(env, TRANSPORT_FIXTURE_WORK=str(work))
output = run("ipc", [str(exe), "--ipc"], timeout=45, custom_env=ipc_env)
if "TRANSPORT IPC PASS" not in output:
    raise SystemExit(1)
for index, service in enumerate(re.findall(r"^POSTEXIT_SERVICE (\S+)$", output, re.M)):
    run(f"post-exit-{index}", [str(exe), "--lookup", service])
run("dependencies", ["/usr/bin/otool", "-L", str(exe)])
print("PASS host runtime only; no SSH server authentication, macOS26 runtime or Sandbox claim")
