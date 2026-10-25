#!/usr/bin/env python3
"""Build/run only P1-04B public Mach feasibility probes; no A-protocol changes."""
from pathlib import Path
import os
import re
import signal
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / ".build" / "p104b-mach"
LOG = ROOT / ".build" / "verification"
BUILD.mkdir(parents=True, exist_ok=True)
LOG.mkdir(parents=True, exist_ok=True)
SOURCE = ROOT / "Probes" / "MachRendezvous"


def run(name, args, *, expect=0, timeout=15, sensitive=False):
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, start_new_session=True)
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Codesign is bounded. Never answer authorization dialogs or modify ACLs.
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=0.5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=2)
        (LOG / f"{name}.log").write_text("timeout=True\noutput_withheld=True\n")
        print(f"{name} timeout=True")
        raise SystemExit(75)
    content = (f"success={process.returncode == expect}\noutput_withheld=True\n" if sensitive else output)
    (LOG / f"{name}.log").write_text(content + f"exit={process.returncode}\n")
    print(f"{name} success={process.returncode == expect} exit={process.returncode}")
    if process.returncode != expect:
        if not sensitive:
            print(output)
            # Probe logs contain only public markers and random rendezvous names.
            # Verify the service disappears on a failed scenario too.
            for service in re.findall(r"service_name=(\S+)", output):
                subprocess.run([str(BUILD / "bootstrap-availability"), "--lookup", service],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        raise SystemExit(process.returncode or 1)
    return output


sdk = subprocess.run(["xcrun", "--show-sdk-path"], capture_output=True, text=True, timeout=10)
(LOG / "p104b-environment.log").write_text(
    f"shell_directory={Path.cwd()}\nprobe_directory={SOURCE}\n" +
    subprocess.run(["sw_vers"], capture_output=True, text=True, timeout=10).stdout +
    f"sdk={sdk.stdout.strip()}\n")
base = ["xcrun", "clang", "-arch", "arm64", "-mmacosx-version-min=15.0", "-O2",
        "-Wall", "-Wextra", "-Werror", "-Wno-error=deprecated-declarations"]
frameworks = ["-framework", "Security", "-framework", "CoreFoundation", "-lbsm"]
availability = BUILD / "bootstrap-availability"
run("p104b-availability-build", base + [str(SOURCE / "BootstrapAvailability.c")] + frameworks + ["-o", str(availability)])
text = run("p104b-availability-run", [str(availability)])
name = next(line.split("=", 1)[1] for line in text.splitlines() if line.startswith("service_name="))
run("p104b-availability-post-exit", [str(availability), "--lookup", name])

# Read metadata only. Identity subject/hash never enters a log or persisted file.
identities = subprocess.run(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"],
                            capture_output=True, text=True, timeout=10)
candidates = re.findall(r'\b([A-Fa-f0-9]{40})\s+"Apple Development:[^"\n]*"', identities.stdout)
(LOG / "p104b-signing-availability.log").write_text(
    f"find_identity_exit={identities.returncode}\nunique_apple_development_identity={len(candidates) == 1}\n")
if identities.returncode or len(candidates) != 1:
    print("PARTIAL unique existing Apple Development identity unavailable")
    raise SystemExit(76)

for role, define, identifier in [
    ("broker", [], "org.openlxssh.p104b.broker"),
    ("helper", ["-DP104B_HELPER=1"], "org.openlxssh.p104b.helper"),
]:
    binary = BUILD / role
    # Unlink only the previous owned image. Do not rewrite an inode that AMFI
    # may still have cached after earlier Development-signed execution.
    binary.unlink(missing_ok=True)
    run(f"p104b-{role}-build", base + define + [str(SOURCE / "MachAuditFeasibility.c")] + frameworks + ["-o", str(binary)])
    run(f"p104b-{role}-sign", ["/usr/bin/codesign", "--force", "--sign", candidates[0], "--options", "runtime",
                              "--identifier", identifier, "--timestamp=none", str(binary)], sensitive=True)
    run(f"p104b-{role}-verify", ["/usr/bin/codesign", "--verify", "--strict", str(binary)], sensitive=True)

# Two different images and fixed different identifiers share the existing trusted
# Apple-issued certificate. Each validates its own signed Team then derives peer
# requirement. No environment/socket-supplied policy and no ad-hoc hash cycle.
for scenario in ["normal", "wrong-parent", "wrong-identifier", "queued-exec"]:
    helper = BUILD / ("broker" if scenario == "wrong-identifier" else "helper")
    run(f"p104b-{scenario}", [str(BUILD / "broker"), "--receive", str(helper), scenario])
    copy = BUILD / "lookup-probe"
    text = (LOG / f"p104b-{scenario}.log").read_text()
    service = re.search(r"service_name=(\S+)", text).group(1)
    run(f"p104b-{scenario}-post-exit", [str(availability), "--lookup", service])

# A same-certificate wrong-identifier server can offer the random name, but its
# audit trailer cannot satisfy helper's fixed broker identifier requirement.
run("p104b-fake-broker", [str(BUILD / "helper"), "--receive", str(BUILD / "helper"), "fake-broker"])
fake_log = (LOG / "p104b-fake-broker.log").read_text()
fake_service = re.search(r"service_name=(\S+)", fake_log).group(1)
run("p104b-fake-broker-post-exit", [str(availability), "--lookup", fake_service])
print("PASS P1-04B public temporary Mach rendezvous + frozen audit token feasibility")
print("NOT IMPLEMENTED Askpass state machine migration, sensitive payloads, real SSH/MFA, macOS26, bundled service")
