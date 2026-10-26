#!/usr/bin/env python3
"""Prepare, never build/sign/launch, a review-only .app from verified local build metadata.

Default help and legacy 'validate' are read-only metadata checks, NOT executable
or provenance validation. 'prepare' requires build_driver.py's linked-build.json,
checks source/object/artifact hashes, and creates only that build's exclusive UUID
wrapper. No caller-supplied revision is used as binary provenance.
"""
import argparse
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
# Legacy metadata-only interface sentinel. No longer a packaging destination.
DESTINATION = HERE / '.build' / 'wrapper' / 'OpenLXSSHStability.app'


def checked_binary(value):
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts or path.resolve() != path:
        raise ValueError('unsafe input path')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 or not info.st_mode & 0o100:
        raise ValueError('unsafe local executable')
    return path


def prepare_verified(record_path):
    # Local import avoids any work at help/legacy-metadata validation time.
    import build_driver as recipe
    record_path = recipe.checked_path(record_path)
    work = recipe.checked_path(record_path.parent, directory=True)
    if (work.parent != HERE / '.build' or not re.fullmatch(r'driver-[0-9a-f-]{36}', work.name)
            or record_path.name != 'linked-build.json'):
        raise ValueError('exclusive local build record required')
    record = json.loads(record_path.read_text())
    if (record.get('kind') != recipe.KIND or record.get('status') != 'linked-not-run'
            or record.get('target') != recipe.TARGET or record.get('driverExecuted') is not False):
        raise ValueError('real linked min26 build record required')
    layout = recipe.validate_source_record(record, work)
    recipe.validate_link_record(record, work, layout)
    commit = record['gitStart']['commit']
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('actual compiler-source commit required')
    objects = {}
    for item in record['objects']:
        path = recipe.checked_path(item['path'])
        if path.parent != work / 'objects' or recipe.digest(path) != item['sha256']:
            raise ValueError('linked object changed')
        if recipe.macho_metadata(path) != item['metadata']:
            raise ValueError('linked object metadata changed')
        objects[str(path)] = item
    binaries = {}
    for label, name in (('driver', 'OpenLXSSHStability'), ('helper', 'openlxssh-askpass')):
        artifact = record['artifacts'][label]
        path = checked_binary(artifact['path'])
        if path != work / 'artifacts' / name or recipe.digest(path) != artifact['sha256']:
            raise ValueError('linked executable changed')
        if recipe.macho_metadata(path, executable=True) != artifact['metadata']:
            raise ValueError('linked executable metadata changed')
        if not artifact['linkedObjects'] or not all(p in objects for p in artifact['linkedObjects']):
            raise ValueError('linked object inventory unavailable')
        binaries[label] = path
    parent = work / 'wrapper'
    parent.mkdir(mode=0o700)  # Exclusive: no overwrite, merge or fixed shared bundle.
    destination = parent / 'OpenLXSSHStability.app'
    contents = destination / 'Contents'
    (contents / 'MacOS').mkdir(parents=True, mode=0o700)
    (contents / 'Helpers').mkdir(mode=0o700)
    for source, target in ((binaries['driver'], contents / 'MacOS/OpenLXSSHStability'),
                           (binaries['helper'], contents / 'Helpers/openlxssh-askpass')):
        with source.open('rb') as incoming, target.open('xb') as outgoing:
            shutil.copyfileobj(incoming, outgoing)
        target.chmod(0o700)
        if recipe.digest(target) != recipe.digest(source):
            raise ValueError('copied executable changed')
    info = {'CFBundleIdentifier': 'org.openlxssh.OpenLXSSH',
            'CFBundleExecutable': 'OpenLXSSHStability', 'CFBundleName': 'OpenLXSSH Stability Acceptance',
            'CFBundleDisplayName': 'OpenLXSSH Stability Acceptance', 'CFBundlePackageType': 'APPL',
            'CFBundleVersion': '1', 'CFBundleShortVersionString': '1.0',
            'LSMinimumSystemVersion': '26.0', 'LSUIElement': True,
            'StabilitySourceRevision': commit, 'StabilitySourceDirty': record['gitStart']['dirty'],
            'StabilityInputSetSHA256': record['inputSetSHA256'],
            'StabilityLinkedBuildRecordSHA256': recipe.digest(record_path),
            'NSHighResolutionCapable': True}
    with (contents / 'Info.plist').open('xb') as stream:
        plistlib.dump(info, stream, sort_keys=True)
    return destination


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=('help', 'validate', 'prepare'), default='help')
    parser.add_argument('--driver', help='legacy metadata-only validate input, never used for prepare')
    parser.add_argument('--helper', help='legacy metadata-only validate input, never used for prepare')
    parser.add_argument('--revision', help='legacy metadata-only validate input; not binary provenance')
    parser.add_argument('--build-record', help='prepare: exact linked-build.json from a real UUID recipe build')
    parser.add_argument('--prepare-reviewed-wrapper', action='store_true', help='local packaging only; NOT run authorization')
    args = parser.parse_args(argv)
    if args.action == 'help':
        parser.print_help()
        return 0
    if args.action == 'prepare':
        if not args.prepare_reviewed_wrapper or not args.build_record or any((args.driver, args.helper, args.revision)):
            raise ValueError('explicit local build record and packaging acknowledgement required')
        os.umask(0o077)
        app = prepare_verified(Path(args.build_record))
        print('Prepared UNSIGNED, NOT EXECUTED acceptance bundle at ' + str(app))
        return 0
    if args.build_record or not args.driver or not args.helper or not re.fullmatch(r'[0-9a-f]{40}', args.revision or ''):
        raise ValueError('explicit legacy metadata-only inputs required')
    checked_binary(args.driver)
    checked_binary(args.helper)
    print('Local input metadata valid only; no write, build, signature validation, signing or launch; NOT executable provenance.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError):
        sys.stderr.write('Wrapper preparation refused; input/error details withheld. See help.\n')
        sys.exit(2)
