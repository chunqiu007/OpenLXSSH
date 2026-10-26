#!/usr/bin/env python3
"""Container-only file control; no network listener, secret stdout or user-supplied paths."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ROOT = Path('/run/openlxssh-multiprompt')
SCENARIOS = ('two', 'zero-accept', 'zero-reject', 'approval', 'reject', 'cancel', 'timeout')
ATTEMPT = re.compile(r'^[0-9a-f]{24}$')


def safe_file(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise ValueError('unsafe container metadata')
    return path


def check_root():
    if os.getuid() != 10000 or ROOT.is_symlink():
        raise ValueError('container UID 10000 required')
    info = ROOT.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('private container tmpfs required')


def atomic_policy(scenario, delay):
    temporary = ROOT / 'scenario.control-new'
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write('%s %d\n' % (scenario, delay))
        os.replace(str(temporary), str(ROOT / 'scenario'))
    finally:
        if temporary.exists():
            temporary.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('scenario', 'health', 'check-challenge', 'status'))
    parser.add_argument('--authorized-run', action='store_true')
    parser.add_argument('--scenario', choices=SCENARIOS)
    parser.add_argument('--delay', type=int, default=8)
    parser.add_argument('--attempt')
    args = parser.parse_args()
    if not args.authorized_run:
        parser.error('explicit authorization acknowledgement required')
    if not 1 <= args.delay <= 60:
        parser.error('delay must be 1..60 seconds')
    if args.action == 'scenario' and args.scenario is None:
        parser.error('scenario is required')
    if args.action == 'check-challenge' and not ATTEMPT.fullmatch(args.attempt or ''):
        parser.error('24-hex non-secret attempt ID required')
    check_root()
    if args.action == 'scenario':
        atomic_policy(args.scenario, args.delay)
    elif args.action == 'health':
        safe_file(ROOT / 'ready')
    elif args.action == 'check-challenge':
        path = safe_file(ROOT / 'attempts' / (args.attempt + '.json'))
        if path.stat().st_size > 2048:
            raise ValueError('oversize challenge file')
        data = json.loads(path.read_text())
        if data['attempt'] != args.attempt or not time.time() < data['expires_at'] <= time.time() + 75:
            raise ValueError('expired/invalid attempt')
    elif args.action == 'status':
        # status.json contains IDs, counts and outcomes only, never response values.
        data = json.loads(safe_file(ROOT / 'status.json').read_text())
        allowed = {'generated', 'response_callbacks', 'zero_response_callbacks', 'ignored_late_results',
                   'sessions', 'scheduler_queue', 'pending', 'outcomes'}
        if set(data) != allowed:
            raise ValueError('unexpected status schema')
        print(json.dumps(data, sort_keys=True))


if __name__ == '__main__':
    try:
        os.umask(0o077)
        main()
    except (OSError, ValueError, KeyError, TypeError):
        sys.stderr.write('Container management refused; no secret output emitted.\n')
        sys.exit(1)
