#!/usr/bin/env python3
"""Only exact946c PUBLIC leftovers. Default/help/validate are inert; --plan reads
public host evidence only. No recovery authority comes from an arbitrary receipt.
--apply is a later explicitly authorized action, never invoked by --plan/tests.
Never writes auth/key/config, signals processes, adopts unknowns, or deletes host evidence.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import fd_safety as fs
import host_case as host
import remote_bootstrap as bootstrap
import session_metadata as proc

EVIDENCE = host.HERE / '.runtime/live-946c9663fdba40c3894fb3239f23dd14'
NONCE = 'd8bbe17ac7f749158014c2505bf0ba74'
AUTH_SHA256 = 'e1446ceb1b05243bf40db4eab4eb482cef084f0fb170fb7d705087e170afe0ae'
CONFIG_SHA256 = '0e1b32cfda7e0f60ae521dbc66a5a9a9f1db6e003f5290db5f857ac710e98616'
KNOWN_SHA256 = 'a8a54b0d6e9968d9d788e9f023e2beb8dbacba83704e15bdba5b5476175cf9cc'
MASTER = (21, 7980921)
EXPORT_SHA256 = 'f47999ef31e4b2b9600faceba50800781ead901c59b01f10ad7754d2aa5ab056'
RECEIPT_HASHES = {
    'appended.json': 'ee50d2a8500d660d35cc9fa644f9a4bc24a247ac95c763e428975ab1300a1969',
    'integrated-plan.json': '71700e9cfe6dc4ceb80ad0aeed71a85a03bcf3486b0a6998ff58547009b402e1',
    'prepared.json': 'e1bd1b8471c248ccc938795c2959e9e67f92126cf01db6ffc8fe5a8b03879aef',
    'restore-intent.json': 'c0ce0a9f2c1005e7b70579ad09ca54e02437615dee1b974001bd898129340bcd',
    'restored.json': '344cc23d067cb7929aa863a89dba9f66f48d6bcda9c35742a657dbd99b48ee5f',
}


def payload():
    plan, envelope = host.bundle()  # Public only; no RootAdapter/Docker.
    host.require(plan['nonce'] == NONCE)
    exported = json.loads(host.public(EVIDENCE / 'aborted-receipt-export.json', 0o600))
    export_hash = exported.pop('receipt_export_sha256')
    host.require(export_hash == EXPORT_SHA256 == host.sha(json.dumps(exported, sort_keys=True, separators=(',', ':')).encode()))
    host.require(exported['workplan_sha256'] == host.PLAN_SHA256 and set(exported['receipts_base64']) == bootstrap.RECEIPTS)
    stage = {name + '.py': encoded for name, encoded in envelope['modules_base64'].items()}
    stage['workplan.json'] = envelope['workplan_base64']
    return {'nonce': NONCE, 'stage': stage, 'receipts': exported['receipts_base64']}


def expected_files(value):
    host.require(set(value) == {'nonce', 'stage', 'receipts'} and value['nonce'] == NONCE)
    host.require(set(value['stage']) == {name + '.py' for name in bootstrap.NAMES} | {'workplan.json'})
    host.require(set(value['receipts']) == bootstrap.RECEIPTS)
    stage = {name: base64.b64decode(data, validate=True) for name, data in value['stage'].items()}
    receipts = {name: base64.b64decode(data, validate=True) for name, data in value['receipts'].items()}
    host.require(host.sha(stage['workplan.json']) == bootstrap.PLAN_SHA256)
    plan = json.loads(stage['workplan.json'])
    host.require(plan['nonce'] == NONCE)
    for name, data in stage.items():
        if name != 'workplan.json':
            host.require(host.sha(data) == plan['source_sha256'][name])
    host.require(all(host.sha(data) == RECEIPT_HASHES[name] for name, data in receipts.items()))
    return [('nested-source-' + NONCE, stage), ('nested-' + NONCE, receipts)]


def baseline(fixture):
    fixture.verify()
    reader = proc.ProcReader(fixture.fd)
    try:
        host.require(reader.master.token == MASTER)
        proc.SessionGate(reader, (), ()).check(closed=True)  # Requires globalidle, no caller flag.
    finally:
        reader.close()
    for name, mode, expected in (('authorized_keys', 0o644, AUTH_SHA256), ('sshd_config', 0o600, CONFIG_SHA256)):
        fd = os.open(name, os.O_RDONLY | fs.NOFOLLOW, dir_fd=fixture.fd)
        try:
            host.require(host.sha(fs.read_held(fixture.fd, name, fd, 0, mode)) == expected)
        finally:
            os.close(fd)
    home = fs.Directories((('fixture', 0, 0o755), ('home', 10000, 0o700)))
    try:
        try:
            os.stat('.openlxssh-nested-' + NONCE, dir_fd=home.fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('new-key-directory-still-present')
    finally:
        home.close()
    trust = fs.Directories((('fixture', 0, 0o755), ('home', 10000, 0o700), ('.ssh', 10000, 0o700)))
    try:
        fd = os.open('known_hosts', os.O_RDONLY | fs.NOFOLLOW, dir_fd=trust.fd)
        try:
            known = fs.read_held(trust.fd, 'known_hosts', fd, 10000, 0o600, 4096)
        finally:
            os.close(fd)
        host.require(host.sha(known) == KNOWN_SHA256)
        fields = known.decode('ascii').split()
        host.require(len(fields) == 3 and fields[:2] == ['[127.0.0.1]:2222', 'ssh-ed25519'])
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(fields[2], validate=True)).digest()).decode().rstrip('=')
        host.require(fingerprint == host.FP)
    finally:
        trust.close()
    for name in ('nested-management.lock',):
        try:
            os.stat(name, dir_fd=fixture.fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise ValueError('management-owner-present')


def recover(value):
    fs.linux_user(0)
    expected = expected_files(value)
    fixture = fs.Directories((('run', 0, 0o755), ('openlxssh-fixture', 0, 0o755)))
    directories, files = [], []
    try:
        baseline(fixture)
        for directory_name, contents in expected:
            fd = os.open(directory_name, os.O_RDONLY | os.O_DIRECTORY | fs.NOFOLLOW, dir_fd=fixture.fd)
            directories.append((directory_name, fd, fs.identity(os.fstat(fd))[:5]))
            info = os.fstat(fd)
            host.require(info.st_uid == info.st_gid == 0 and info.st_mode == 0o40700)
            host.require(set(os.listdir(fd)) == set(contents))
            for name, data in contents.items():
                held = os.open(name, os.O_RDONLY | fs.NOFOLLOW, dir_fd=fd)
                files.append((fd, name, held, fs.version(os.fstat(held)), data))
                host.require(fs.read_held(fd, name, held, 0, 0o600) == data)
        # ALL14 checked twice before first deletion, then exact named/held identities.
        baseline(fixture)
        for name, fd, identity in directories:
            host.require(fs.identity(os.fstat(fd))[:5] == identity == fs.identity(os.stat(name, dir_fd=fixture.fd, follow_symlinks=False))[:5])
            host.require(set(os.listdir(fd)) == set(dict(expected)[name]))
        for parent, name, fd, identity, data in files:
            host.require(fs.version(os.fstat(fd)) == identity and fs.read_held(parent, name, fd, 0, 0o600) == data)
        for parent, name, fd, identity, _data in files:
            fixture.verify()
            host.require(fs.version(os.fstat(fd)) == identity == fs.version(os.stat(name, dir_fd=parent, follow_symlinks=False)))
            os.unlink(name, dir_fd=parent)
        for name, fd, identity in reversed(directories):
            host.require(not os.listdir(fd) and fs.identity(os.stat(name, dir_fd=fixture.fd, follow_symlinks=False))[:5] == identity)
            os.fsync(fd)
            os.rmdir(name, dir_fd=fixture.fd)
        os.fsync(fixture.fd)
        baseline(fixture)
        return {'event': 'RECOVERED-PUBLIC-ONLY', 'nonce': NONCE, 'removedFiles': len(files), 'removedDirectories': 2,
                'authorized_keys_sha256': AUTH_SHA256, 'daemon': MASTER}
    finally:
        for _parent, _name, fd, _identity, _data in files:
            os.close(fd)
        for _name, fd, _identity in directories:
            os.close(fd)
        fixture.close()


def remote_code():
    # Only fixed public read-only modules; no bridge/staging or private values.
    names = ('management_prep', 'fd_safety', 'session_metadata')
    sources = {name: host.public(host.HERE / (name + '.py')).decode() for name in names}
    own = host.public(Path(__file__).absolute()).decode()
    setup = "import sys,types,json,signal\nsources=" + repr(sources) + "\nfor name,source in sources.items():\n m=types.ModuleType(name);sys.modules[name]=m;exec(compile(source,'<public-recovery-input>','exec'),m.__dict__)\n"
    setup += "sys.modules['host_case']=types.SimpleNamespace(HERE=__import__('pathlib').Path('/unused'),require=lambda value:value or (_ for _ in ()).throw(ValueError('refused')),sha=lambda value:__import__('hashlib').sha256(value).hexdigest(),FP=" + repr(host.FP) + ")\n"
    setup += "sys.modules['remote_bootstrap']=types.SimpleNamespace(NAMES=" + repr(bootstrap.NAMES) + ",RECEIPTS=" + repr(bootstrap.RECEIPTS) + ",PLAN_SHA256=" + repr(bootstrap.PLAN_SHA256) + ")\n"
    setup += "module=types.ModuleType('fixed_recovery');sys.modules['fixed_recovery']=module\nexec(compile(" + repr(own) + ",'<fixed-recovery>','exec'),module.__dict__)\nsignal.signal(signal.SIGALRM,lambda *_args:(_ for _ in ()).throw(ValueError('deadline')));signal.alarm(25)\nprint(json.dumps(module.recover(json.loads(sys.stdin.readline(196609))),sort_keys=True))\n"
    return setup


def apply():
    value = payload()
    result = subprocess.run(host.DOCKER + ['exec', '-i', '--user', '0:0', host.CID, '/usr/bin/python3', '-B', '-c', remote_code()],
                            cwd=host.HERE, env=host.ENV, input=json.dumps(value).encode() + b'\n', capture_output=True, timeout=30)
    host.require(result.returncode == 0 and len(result.stdout) <= 4096)
    print(result.stdout.decode().strip())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', action='store_true')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--authorized-local-fixture', action='store_true')
    args = parser.parse_args(argv)
    if args.apply:
        host.require(args.authorized_local_fixture and not args.plan)
        apply()
    elif args.plan:
        host.require(not args.authorized_local_fixture)
        value = payload()
        print(json.dumps({'nonce': NONCE, 'directories': [{'name': name, 'publicFiles': sorted(contents)} for name, contents in expected_files(value)],
                          'runtimeExecuted': False}, sort_keys=True))
    else:
        host.require(not args.authorized_local_fixture)
        print('Fixed public recovery inert; --plan reads public evidence only; --apply needs later authorization.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        sys.stderr.write('Fixed public recovery refused; no private details.\n')
        sys.exit(2)
