#!/usr/bin/env python3
"""Compile the default shipping graph for macOS26; never execute on the host15."""
from pathlib import Path
import os
import subprocess
ROOT = Path(__file__).resolve().parents[1]
LOG = ROOT / ".build/verification"
LOG.mkdir(parents=True, exist_ok=True)
env = dict(os.environ)
env.pop("OPENLXSSH_TRANSPORT_HOST_PROBE", None)
base = ["/bin/bash", str(ROOT / "Scripts/offline.sh"), "swift", "build", "--package-path", str(ROOT),
        "--scratch-path", str(ROOT / ".build/macos26"), "--cache-path", str(ROOT / ".build/cache"),
        "--disable-automatic-resolution", "--triple", "arm64-apple-macosx26.0"]
for config in ["debug", "release"]:
    args = base + ["-c", config]
    result = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
    (LOG / f"macos26-{config}-build.log").write_text(result.stdout + result.stderr + f"exit={result.returncode}\n")
    print(f"macos26-{config}-build exit={result.returncode}", flush=True)
    result.check_returncode()
    binary_dir = Path(subprocess.run(args + ["--show-bin-path"], cwd=ROOT, env=env, capture_output=True, text=True, check=True).stdout.strip())
    # Helper executable and actual transport object must both declare minos26.
    objects = [binary_dir / "openlxssh-askpass", binary_dir / "OpenLXSSHTransport.build/DirectSSHSession.swift.o"]
    for index, path in enumerate(objects):
        result = subprocess.run(["/usr/bin/xcrun", "vtool", "-show-build", str(path)], capture_output=True, text=True, check=True)
        (LOG / f"macos26-{config}-metadata-{index}.log").write_text(result.stdout + result.stderr)
        if "minos 26.0" not in result.stdout or "sdk 26." not in result.stdout:
            raise SystemExit("incorrect deployment metadata")
print("PASS compile-only minos26; macOS26 runtime not tested")
