#!/usr/bin/env python3
"""Existing Development identity only; offline App signing; isolated exact UUID cleanup.
No certificate/profile creation, no ACL/search-list edits and no supplied authorization.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOGS = ROOT / 'DerivedData/Verification'

def command(args, timeout=60):
    # Never print command arrays: signing identity details stay in process memory.
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)

def checked_report(work, phase, returncode):
    path = work / f'smoke-{phase}.json'
    if returncode or not path.is_file():
        return None
    report = json.loads(path.read_text())
    checks = report.get('checks')
    if (report.get('kind') != 'HostProbe-native-GUI' or report.get('phase') != phase
            or report.get('passed') is not True or report.get('productRuntimeVerified') is not False
            or not isinstance(checks, list) or not checks
            or not all(isinstance(check, dict) and check.get('passed') is True for check in checks)):
        return None
    return report

def main():
    LOGS.mkdir(parents=True, exist_ok=True)
    found = command(['/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning'])
    match = re.search(rb'\b([A-F0-9]{40})\s+"Apple Development:', found.stdout)
    if found.returncode or not match:
        print('INCOMPLETE: no existing Apple Development signing identity.')
        return 1
    identity = match.group(1).decode()
    source = ROOT / 'DerivedData/HostProbe/Build/Products/HostProbe/OpenLXSSH.app'
    work = Path(tempfile.mkdtemp(prefix='OpenLXSSH-AppSmoke-')).resolve()
    os.chmod(work, 0o700)
    (work / '.openlxssh-app-smoke').write_text('OpenLXSSH isolated GUI smoke\n')
    (LOGS / 'signed-app-data-path.txt').write_text(str(work) + '\n')
    destination = ROOT / 'DerivedData/SignedHostProbe' / work.name / 'OpenLXSSH.app'
    destination.parent.mkdir(parents=True, exist_ok=False)
    shutil.copytree(source, destination)
    (LOGS / 'signed-app-bundle-path.txt').write_text(str(destination) + '\n')
    helper = destination / 'Contents/Helpers/openlxssh-askpass'
    if not helper.is_file():
        print('INCOMPLETE: embedded askpass helper missing.')
        return 1
    helper_sign = command(['/usr/bin/codesign', '--force', '--sign', identity, '--identifier', 'org.openlxssh.askpass', '--options', 'runtime', '--timestamp=none', str(helper)])
    if helper_sign.returncode or command(['/usr/bin/codesign', '--verify', '--strict', str(helper)]).returncode:
        print('INCOMPLETE: existing-identity helper signing failed; no authorization was supplied.')
        return 1
    signed = command(['/usr/bin/codesign', '--force', '--sign', identity, '--options', 'runtime', '--timestamp=none', str(destination)])
    if signed.returncode:
        print('INCOMPLETE: existing-identity App signing failed; no authorization was supplied.')
        return 1
    verify = command(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(destination)])
    display = command(['/usr/bin/codesign', '--display', '--verbose=4', str(destination)])
    runtime = bool(re.search(rb'^CodeDirectory.*\bruntime\b', display.stdout + display.stderr, re.M))
    if verify.returncode or not runtime:
        print('INCOMPLETE: strict App signature/runtime verification failed.')
        return 1
    binary = destination / 'Contents/MacOS/OpenLXSSH'
    result = 0
    try:
        for phase in ('transport-config', 'security', 'security-read'):
            run = command([str(binary), '--self-test-data-dir', str(work), '--self-test-phase', phase], timeout=120)
            # Only native harness JSON and sanitized static diagnostics; no identity output.
            (LOGS / f'signed-app-{phase}.log').write_bytes(run.stdout)
            report = checked_report(work, phase, run.returncode)
            if report is None:
                print(f'INCOMPLETE: signed App {phase} failed; inspect sanitized JSON.')
                result = 1
                break
            print(f'Signed HostProbe App {phase}: {len(report["checks"])} checks passed')
    finally:
        cleanup = command([str(binary), '--self-test-data-dir', str(work), '--self-test-phase', 'security-cleanup'], timeout=120)
        (LOGS / 'signed-app-cleanup.log').write_bytes(cleanup.stdout)
        report = checked_report(work, 'security-cleanup', cleanup.returncode)
        if report is None:
            print('INCOMPLETE: exact isolated cleanup requires retry using preserved App/data path.')
            result = 1
        else:
            print(f'Signed HostProbe App exact cleanup: {len(report["checks"])} checks passed')
    print('Strict existing Development signature / Hardened Runtime: passed; no identity details emitted.')
    print('Isolated signed App evidence:', work)
    print('Not macOS 26, Developer ID, locked user Keychain or transport acceptance.')
    return result

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print('INCOMPLETE: local signed App command failed or timed out; inspect preserved isolated recovery records.')
        raise SystemExit(1)
