#!/usr/bin/env python3
"""Prepare, never build/sign/launch, a review-only .app from explicit local inputs.

Default help and validate are read-only. This script does not inspect Keychain or
signing identities and cannot start a Transport session.
"""
import argparse
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import sys

HERE = Path(__file__).resolve().parent
DESTINATION = HERE / '.build' / 'wrapper' / 'OpenLXSSHStability.app'


def checked_binary(value):
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts or path.resolve() != path:
        raise ValueError('unsafe input path')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 or not info.st_mode & 0o100:
        raise ValueError('unsafe local executable')
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=('help', 'validate', 'prepare'), default='help')
    parser.add_argument('--driver', help='already compiled real SignedDriver executable; no compilation here')
    parser.add_argument('--helper', help='already compiled production openlxssh-askpass; no substitute')
    parser.add_argument('--revision', help='reviewed source Git revision, 40 lowercase hex')
    parser.add_argument('--prepare-reviewed-wrapper', action='store_true', help='local packaging only; NOT run authorization')
    args = parser.parse_args(argv)
    if args.action == 'help':
        parser.print_help()
        return 0
    if args.action == 'prepare' and not args.prepare_reviewed_wrapper:
        raise ValueError('explicit local packaging acknowledgement required')
    if not args.driver or not args.helper or not re.fullmatch(r'[0-9a-f]{40}', args.revision or ''):
        raise ValueError('explicit local binaries and reviewed revision required')
    driver, helper = checked_binary(args.driver), checked_binary(args.helper)
    if args.action == 'validate':
        print('Local input metadata valid only; no write, build, signature validation, signing or launch.')
        return 0
    # One fixed fixture-local destination, never overwrite an existing bundle.
    parent = DESTINATION.parent
    if parent.resolve() != parent or DESTINATION.exists() or DESTINATION.is_symlink():
        raise ValueError('unsafe or existing output path')
    os.umask(0o077)
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for candidate in (HERE / '.build', parent):
        info = candidate.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError('unsafe packaging parent')
    contents = DESTINATION / 'Contents'
    (contents / 'MacOS').mkdir(parents=True, mode=0o700)
    (contents / 'Helpers').mkdir(mode=0o700)
    for source, target in ((driver, contents / 'MacOS' / 'OpenLXSSHStability'),
                           (helper, contents / 'Helpers' / 'openlxssh-askpass')):
        with source.open('rb') as incoming, target.open('xb') as outgoing:
            shutil.copyfileobj(incoming, outgoing)
        target.chmod(0o700)
    info = {'CFBundleIdentifier': 'org.openlxssh.OpenLXSSH',
            'CFBundleExecutable': 'OpenLXSSHStability', 'CFBundleName': 'OpenLXSSH Stability Acceptance',
            'CFBundleDisplayName': 'OpenLXSSH Stability Acceptance', 'CFBundlePackageType': 'APPL',
            'CFBundleVersion': '1', 'CFBundleShortVersionString': '1.0',
            'LSMinimumSystemVersion': '26.0', 'LSUIElement': True,
            'StabilitySourceRevision': args.revision,
            'NSHighResolutionCapable': True}
    with (contents / 'Info.plist').open('xb') as stream:
        plistlib.dump(info, stream, sort_keys=True)
    print('Prepared UNSIGNED, NOT RUNNABLE acceptance bundle at ' + str(DESTINATION))
    print('Review provenance; later use the existing approved strict Development signing workflow. This script never signs or runs.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError):
        sys.stderr.write('Wrapper preparation refused; input/error details withheld. See help.\n')
        sys.exit(2)
