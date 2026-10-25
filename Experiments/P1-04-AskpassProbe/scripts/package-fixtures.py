#!/usr/bin/env python3
"""Local existing Development identity only; bounded signing, no ACL/upload."""
from pathlib import Path
import os
import re
import shutil
import signal
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
config = sys.argv[1] if len(sys.argv) == 2 else "debug"
if config not in ("debug", "release"):
    raise SystemExit(64)
identities = subprocess.run(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"],
                            capture_output=True, text=True, timeout=10)
candidates = re.findall(r'\b([A-Fa-f0-9]{40})\s+"Apple Development:[^"\n]*"', identities.stdout)
if identities.returncode or len(candidates) != 1:
    print("unique_existing_development_identity=False")
    raise SystemExit(76)
binary = Path(subprocess.run(["swift", "build", "--package-path", str(root), "-c", config, "--show-bin-path"],
                             capture_output=True, text=True, check=True, timeout=30).stdout.strip())
out = root / ".build" / "fixtures" / config
out.mkdir(parents=True, exist_ok=True)
for suffix, identifier in [("probe", "broker"), ("helper", "helper"), ("adversary", "adversary")]:
    image = out / f"openlxssh-askpass-{suffix}"
    image.unlink(missing_ok=True)  # New inode avoids stale signed-code caches.
    shutil.copyfile(binary / image.name, image)
    image.chmod(0o755)
    commands = [
        ["/usr/bin/codesign", "--force", "--sign", candidates[0], "--options", "runtime", "--identifier",
         f"org.openlxssh.p104c.{identifier}", "--timestamp=none", str(image)],
        ["/usr/bin/codesign", "--verify", "--strict", str(image)],
    ]
    for command in commands:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=2)
            print(f"{suffix} signing_timeout=True")
            raise SystemExit(75)
        # Never emit identity hash/subject or raw Security authorization output.
        if process.returncode:
            print(f"{suffix} signing_or_verify_ok=False exit={process.returncode}")
            raise SystemExit(process.returncode)
    print(f"{suffix} distinct_identifier_runtime_signature_ok=True")
# Wrong signer fixture still presents the correct helper identifier. This tests
# Apple-anchor rejection independently from the same-Team wrong-identifier case.
wrong = out / "openlxssh-askpass-wrong-signer"
wrong.unlink(missing_ok=True)
shutil.copyfile(out / "openlxssh-askpass-adversary", wrong)
wrong.chmod(0o755)
result = subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime", "--identifier",
                         "org.openlxssh.p104c.helper", "--timestamp=none", str(wrong)], capture_output=True, timeout=15)
print(f"wrong_signer_fixture_ready={result.returncode == 0}")
raise SystemExit(result.returncode)
