#!/usr/bin/env python3
"""Bounded streaming AC-31 corpus; run only inside an authorized fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

GIB = 1024 ** 3
DEFAULT_LARGE = 2 * GIB
DEFAULT_COUNT = 1000
FIXTURE_HOME = Path('/fixture/home')


def fresh_destination(parent, name):
    if parent.is_symlink() or not parent.is_dir() or parent.resolve() != parent:
        raise ValueError('corpus parent must be a real directory')
    destination = parent / name
    if destination.exists() or destination.is_symlink():
        raise ValueError('refusing to overwrite existing corpus')
    destination.mkdir(mode=0o700)
    return destination


def write_payload(path, size, seed):
    # Deterministic non-secret test data, not credentials. Write every byte:
    # neither sparse holes nor a tiny file is a 2 GiB transfer benchmark.
    block = (hashlib.sha256(seed.encode()).digest() * (1024 * 1024 // 32))
    digest = hashlib.sha256()
    remaining = size
    with path.open('xb') as stream:
        os.chmod(str(path), 0o600)
        while remaining:
            chunk = block[:min(remaining, len(block))]
            stream.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    return {'path': None, 'bytes': size, 'sha256': digest.hexdigest()}


def generate(parent, large_bytes=DEFAULT_LARGE, small_count=DEFAULT_COUNT):
    if not 1 <= large_bytes <= 4 * GIB or not 1 <= small_count <= 10000:
        raise ValueError('corpus bounds exceeded')
    # Keep 256 MiB headroom for metadata, small files and SFTP temporary names.
    if shutil.disk_usage(str(parent)).free < large_bytes + small_count * 8192 + 256 * 1024 * 1024:
        raise ValueError('insufficient free named-volume space')
    root = fresh_destination(parent, 'corpus')
    entries = []

    def payload(relative, size):
        record = write_payload(root / relative, size, relative)
        record['path'] = relative
        entries.append(record)

    payload('large-2GiB.bin' if large_bytes == DEFAULT_LARGE else 'large-SMALL-SAMPLE.bin', large_bytes)
    small = root / '1000-small-files'
    small.mkdir(mode=0o700)
    for number in range(small_count):
        name = '1000-small-files/文件 {:04d} [#; $].txt'.format(number)
        payload(name, 1024 + number % 3072)
    (root / '目录 with spaces').mkdir(mode=0o700)
    payload('目录 with spaces/Unicode e\u0301 中文.txt', 4096)
    (root / 'links').mkdir(mode=0o700)
    (root / 'links' / 'relative-file').symlink_to('../目录 with spaces/Unicode e\u0301 中文.txt')
    (root / 'links' / 'cycle').symlink_to('../links')
    (root / 'links' / 'outside-corpus').symlink_to('/fixture/protected/denied.txt')
    manifest = {'format': 1, 'complete_ac31_size': large_bytes >= DEFAULT_LARGE and small_count >= DEFAULT_COUNT,
                'large_bytes': large_bytes, 'small_file_count': small_count, 'files': entries,
                'symlinks': ['links/relative-file', 'links/cycle', 'links/outside-corpus']}
    target = root / 'manifest.json'
    with target.open('x', encoding='utf-8') as stream:
        target.chmod(0o600)
        json.dump(manifest, stream, ensure_ascii=False, indent=2)
    return manifest


def verify(root):
    if root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise ValueError('verify root must be a real absolute directory')
    manifest_path = root / 'manifest.json'
    if manifest_path.is_symlink():
        raise ValueError('manifest must not be a symlink')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if not isinstance(manifest.get('files'), list) or len(manifest['files']) > 10010:
        raise ValueError('invalid manifest')
    seen_paths = set()
    for record in manifest['files']:
        relative = Path(record['path'])
        if str(relative) in seen_paths:
            raise ValueError('duplicate manifest path')
        seen_paths.add(str(relative))
        if relative.is_absolute() or not relative.parts or any(part in ('.', '..') for part in relative.parts):
            raise ValueError('unsafe manifest path')
        path = root
        for part in relative.parts:
            path = path / part
            if path.is_symlink():
                raise ValueError('refusing to follow corpus symlink')
        if not path.is_file() or path.resolve().parent != (root / relative.parent).resolve():
            raise ValueError('invalid manifest file')
        if root not in path.resolve().parents:
            raise ValueError('manifest path escapes root')
        digest = hashlib.sha256()
        total = 0
        with path.open('rb') as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                digest.update(block)
        if total != record['bytes'] or digest.hexdigest() != record['sha256']:
            raise ValueError('corpus hash or size mismatch')
    files = manifest['files']
    observed_small = sum(1 for item in files if Path(item['path']).parent == Path('1000-small-files'))
    observed_large = max((item['bytes'] for item in files if len(Path(item['path']).parts) == 1), default=0)
    manifest['complete_ac31_size'] = observed_large >= DEFAULT_LARGE and observed_small >= DEFAULT_COUNT
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('generate', 'verify'))
    parser.add_argument('--authorized-run', action='store_true')
    parser.add_argument('--root', help='explicit downloaded corpus root for verification')
    args = parser.parse_args()
    if not args.authorized_run:
        parser.error('requires --authorized-run AND prior user authorization')
    if args.action == 'generate':
        if sys.platform != 'linux' or os.geteuid() != 10000 or not Path('/.dockerenv').is_file():
            parser.error('generation is container-only as the unprivileged fixture user')
        if not Path('/fixture').is_mount() or FIXTURE_HOME.is_symlink():
            parser.error('expected dedicated named volume')
        generate(FIXTURE_HOME)
    else:
        if not args.root:
            parser.error('verification requires --root')
        manifest = verify(Path(args.root))
        print('Hash verification passed for {} files; AC-31 size: {}'.format(
            len(manifest['files']), manifest['complete_ac31_size']))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError):
        sys.stderr.write('corpus operation failed; no files removed or overwritten\n')
        sys.exit(1)
