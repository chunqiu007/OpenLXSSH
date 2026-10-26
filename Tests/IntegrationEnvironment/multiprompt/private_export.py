#!/usr/bin/env python3
"""Retain docker-cp JSON privately; never print secret values or invoke Docker."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ROOT = Path(__file__).resolve().parent / '.runtime'
ID = re.compile(r'^[0-9a-f]{24}$')


def prepare():
    if ROOT.is_symlink() or ROOT.resolve() != ROOT:
        raise ValueError('unsafe runtime path')
    ROOT.mkdir(mode=0o700, exist_ok=True)
    info = ROOT.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('runtime must be owned 0700')


def incoming():
    source = ROOT / 'incoming.json'
    try:
        info = source.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or info.st_size > 4096):
            raise ValueError('unsafe incoming file')
        # docker cp can preserve the container mode; private parent already protected the transfer.
        source.chmod(0o600)
        return json.loads(source.read_text())
    finally:
        if source.is_file() and not source.is_symlink():
            source.unlink()


def remove_created_file(target, fd):
    # Keep the original inode open until cleanup; never follow/remove a replacement symlink.
    created = os.fstat(fd)
    try:
        current = target.lstat()
    except FileNotFoundError:
        return
    if (stat.S_ISREG(current.st_mode) and current.st_uid == os.getuid()
            and (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino)):
        target.unlink()


@contextlib.contextmanager
def created_file(name, value, *, temporary=False):
    target = ROOT / name
    fd = None
    completed = False
    try:
        # An O_EXCL refusal never establishes ownership and must leave the existing file alone.
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w', closefd=False) as stream:
            stream.write(value)
        yield target
        completed = True
    finally:
        if fd is not None:
            try:
                if temporary or not completed:
                    remove_created_file(target, fd)
            finally:
                os.close(fd)


def write(name, value):
    with created_file(name, value) as target:
        return target


def retain_challenge(data, attempt):
    if (set(data) != {'attempt', 'expires_at', 'responses', 'echo'} or data['attempt'] != attempt
            or data['echo'] != [False, True] or len(data['responses']) != 2
            or any(not isinstance(v, str) or not re.fullmatch(r'[0-9]{10}', v) for v in data['responses'])
            or not time.time() < data['expires_at'] <= time.time() + 75):
        raise ValueError('invalid/expired challenge')
    with created_file('challenge-' + attempt + '.json', json.dumps(data), temporary=True) as target:
        print(str(target), flush=True)
        deadline = time.monotonic() + max(0, data['expires_at'] - time.time())
        while time.monotonic() < deadline:
            time.sleep(min(0.25, max(0, deadline - time.monotonic())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'trust', 'challenge'))
    parser.add_argument('--attempt')
    args = parser.parse_args()
    if args.action == 'challenge' and not ID.fullmatch(args.attempt or ''):
        parser.error('24-hex attempt ID required')
    prepare()
    if args.action == 'prepare':
        if (ROOT / 'incoming.json').exists() or (ROOT / 'incoming.json').is_symlink():
            raise ValueError('stale incoming file; inspect before continuing')
    elif args.action == 'challenge':
        retain_challenge(incoming(), args.attempt)
    else:
        data = incoming()
        known = data.get('known_hosts', '')
        finger = data.get('fingerprint', '')
        if (set(data) != {'known_hosts', 'fingerprint'}
                or not re.fullmatch(r'\[127\.0\.0\.1\]:22225 ssh-rsa [A-Za-z0-9+/=]+\n', known)
                or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]+', finger)):
            raise ValueError('invalid public trust export')
        # Unique generations never silently replace existing host trust.
        name = 'trust-' + os.urandom(6).hex()
        directory = ROOT / name
        directory.mkdir(mode=0o700)
        write(name + '/known_hosts', known)
        write(name + '/fingerprint.txt', finger + '\n')
        print(str(directory))


if __name__ == '__main__':
    try:
        os.umask(0o077)
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except (OSError, ValueError, KeyError, TypeError):
        sys.stderr.write('Private export refused; no secret output emitted.\n')
        sys.exit(1)
