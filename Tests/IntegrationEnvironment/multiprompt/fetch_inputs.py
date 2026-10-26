#!/usr/bin/env python3
"""Fetch fixed public inputs, verify SHA512 before use; never run downloaded code."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
ALLOWED_HOSTS = {'repo.maven.apache.org', 'downloads.apache.org'}


class SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        before = urllib.parse.urlparse(request.full_url)
        after = urllib.parse.urlparse(newurl)
        if after.scheme != 'https' or before.netloc != after.netloc:
            raise ValueError('cross-host or non-HTTPS redirect refused')
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def lock_data():
    lock = json.loads((ROOT / 'inputs.lock.json').read_text())
    for item in lock['artifacts']:
        parsed = urllib.parse.urlparse(item['url'])
        if (parsed.scheme != 'https' or parsed.hostname not in ALLOWED_HOSTS
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or Path(item['file']).name != item['file']
                or len(item['sha512']) != 128
                or any(c not in '0123456789abcdef' for c in item['sha512'])):
            raise ValueError('invalid immutable public input')
    return lock


def verify(data, item):
    if hashlib.sha512(data).hexdigest() != item['sha512']:
        raise ValueError('public input SHA512 mismatch: ' + item['file'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-cache', action='store_true')
    parser.add_argument('--authorized-download', action='store_true')
    parser.add_argument('--destination', type=Path, default=ROOT / '.cache')
    args = parser.parse_args()
    if not args.verify_cache and not args.authorized_download:
        parser.error('explicit authorized-download or offline verify-cache required')
    items = lock_data()['artifacts']
    if args.verify_cache:
        for item in items:
            verify((args.destination / item['file']).read_bytes(), item)
        print('Verified %d fixed public inputs; no code executed.' % len(items))
        return
    if args.destination.is_symlink():
        raise ValueError('symlink destination refused')
    args.destination.mkdir(parents=True, exist_ok=True)
    opener = urllib.request.build_opener(SameHostRedirect())
    for item in items:
        # Binary release is provenance-only; it never enters the runtime classpath.
        destination = args.destination / item['file']
        if destination.is_symlink():
            raise ValueError('symlink public input refused')
        if destination.exists():
            verify(destination.read_bytes(), item)
            continue
        with opener.open(item['url'], timeout=60) as response:
            data = response.read(32 * 1024 * 1024 + 1)
        if len(data) > 32 * 1024 * 1024:
            raise ValueError('public input exceeds bounded download size')
        verify(data, item)
        with destination.open('xb') as stream:
            stream.write(data)
    print('Downloaded and verified %d fixed public inputs; no code executed.' % len(items))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError):
        sys.stderr.write('Public input verification failed; nothing was executed.\n')
        sys.exit(1)
