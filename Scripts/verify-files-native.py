#!/usr/bin/env python3
"""Verify existing reviewed Files native outputs; never download/rebuild upstream libraries."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def verify():
    package = ROOT / 'Packages/OpenLXSSHFiles'
    native = package / '.build/native'
    manifest = json.loads((native / 'manifest.json').read_text())
    if sha(package / 'native-inputs.json') != manifest['inputs']['lockSHA256'] or sha(package / 'Scripts/build-native.py') != manifest['inputs']['scriptSHA256']:
        raise ValueError('Native input fingerprint changed')
    if len(manifest['outputs']) != 160 or len(manifest['licenseSHA256']) != 7:
        raise ValueError('Reviewed native output set changed')
    for relative, digest in manifest['outputs'].items():
        if sha(native / relative) != digest:
            raise ValueError('Native output changed')
    for relative, digest in manifest['licenseSHA256'].items():
        if sha(native / 'install/licenses' / relative) != digest:
            raise ValueError('Native license changed')
    print('Files native 160 output hashes and 7 license/notice hashes verified; no native rebuild.')

if __name__ == '__main__':
    try:
        verify()
    except (OSError, ValueError, KeyError):
        print('STOP: Files native artifacts differ from reviewed inputs/output hashes.', file=sys.stderr)
        raise SystemExit(1)
