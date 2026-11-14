#!/usr/bin/env python3
"""Prepare a marked PUBLIC native-liveness reference from an already approved material case.

No collect, Docker, credentials, relay, socket or build. Explicit `prepare` reads only the
material JSON and public provenance timestamp; it never opens secret key/password files.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

sys.dont_write_bytecode = True
from supervise_native import BUILD, ROOT, directory, public_read, save
from liveness_protocol import Refused, validate_contract
from public_files import material_object, provenance_object


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='help', choices=['help', 'prepare'])
    parser.add_argument('--approved-material-contract', type=Path)
    parser.add_argument('--role', choices=['normal', 'blackhole', 'maxsessions'])
    args = parser.parse_args(argv)
    if args.action == 'help': parser.print_help(); return 0
    if args.approved_material_contract is None or args.role is None: return 64
    os.umask(0o077); directory(BUILD)
    material_path = str(args.approved_material_contract)
    prefix_path, suffix_path = str(BUILD) + '/sftp-auth-case-', '/sftp-auth.json'
    if (not material_path.startswith(prefix_path) or not material_path.endswith(suffix_path) or
            not re.fullmatch('[0-9a-f]{12}', material_path[len(prefix_path):-len(suffix_path)])):
        raise Refused('fixed-approved-material-path')
    directory(args.approved_material_contract.parent)
    material = material_object(public_read(args.approved_material_contract, 8192, 0o600))
    prefix = str(ROOT / 'Tests/IntegrationEnvironment/.runtime/keyonly/credentials-')
    folder = material.get('credentialDirectory')
    if not isinstance(folder, str) or not folder.startswith(prefix) or not re.fullmatch('[0-9a-f]{12}', folder[len(prefix):]):
        raise Refused('fixed-disposable-generation')
    directory(folder)
    provenance = provenance_object(public_read(Path(folder) / 'provenance.json', 4096, 0o600), material=material)
    run = uuid.uuid4().hex; path = BUILD / ('native-liveness-case-' + uuid.uuid4().hex[:12]) / 'liveness.json'
    value = {'schema': 1, 'taskID': 'NATIVE-LIVENESS-SUPERVISOR-R2', 'run': run, 'role': args.role,
             'materialContractPath': str(args.approved_material_contract), 'issuedAt': time.time(), 'collectedAt': provenance['collected_at']}
    validate_contract(value, str(path), str(BUILD), time.time())
    path.parent.mkdir(mode=0o700)
    marker = path.parent / '.native-liveness-case-owner'
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream: stream.write(b'NATIVE-LIVENESS-SUPERVISOR-R2\n')
    save(path, value)
    print(str(path))
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception:
        sys.stderr.write('Native liveness preparation refused; no private details.\n'); raise SystemExit(2)
