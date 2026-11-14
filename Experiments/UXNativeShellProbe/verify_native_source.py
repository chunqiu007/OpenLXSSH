#!/usr/bin/env python3
"""Offline public-source gate for the optional native channel-open liveness candidate.

Default/help/validate are inert. `verify` reads ONLY pinned public build inputs; no build,
archive extraction, dependency resolution, fixture, credentials, process or socket access.
The original native archives/manifest/pins are never modified.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import stat
import tarfile

HERE = Path(__file__).absolute().parent
ROOT = HERE.parent.parent
NATIVE = ROOT / 'Packages/OpenLXSSHFiles/.build/native'
ARCHIVE_SHA256 = 'd9ec76cbe34db98eec3539fe2c899d26b0c837cb3eb466a56b0f109cabf658f7'
LIBRARY_SHA256 = '10fc6628e526f2d51f74ddf32004bdf766b37cfa09b58c5187de20495d28eb10'
SOURCES = {
    'src/channel.c': '79c49c36e65178847087eb3a1c140772c291899b838c705b579214929a14742e',
    'src/packet.c': 'd8d433c7bb61f277abbd9985f0437378d26781737e173e6bd77415fb3726e54f',
    'src/session.c': '9f9c0a55ee7ca5204f73f2eb6e6c37957d1fe3f160ea7a819248310e1a58d8aa',
    'src/session.h': '19ebee873e9f5e1f56850bf263053d2527c28a184f30ac42f66aa09fb38d1b5a',
}
MESSAGES = (
    'Channel open failure (administratively prohibited)',
    'Channel open failure (connect failed)',
    'Channel open failure (unknown channel type)',
    'Channel open failure (resource shortage)',
    'Channel open failure',
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def assert_origin(channel, packet, session, wrapper):
    """Only exact immutable upstream source can authorize the error-origin assumption."""
    for name, value in [('src/channel.c', channel), ('src/packet.c', packet),
                        ('src/session.c', session), ('src/session.h', wrapper)]:
        if digest(value) != SOURCES[name]:
            raise ValueError('fixed-public-source-changed')
    text = channel.decode('ascii')
    start = text.index('_libssh2_channel_open(LIBSSH2_SESSION')
    end = text.index('libssh2_channel_open_ex(LIBSSH2_SESSION', start)
    body = text[start:end]
    failure = body[body.index('if(session->open_data[0] == SSH_MSG_CHANNEL_OPEN_FAILURE)'):]
    if body.count('LIBSSH2_ERROR_CHANNEL_FAILURE') != 5 or failure.count('LIBSSH2_ERROR_CHANNEL_FAILURE') != 5:
        raise ValueError('channel-failure-origin')
    for message in MESSAGES:
        # Whitespace between adjacent C string literals is immutable/source-hashed above.
        if message == MESSAGES[0]:
            expected = '"Channel open failure "\n                               "(administratively prohibited)"'
        else:
            expected = json.dumps(message)
        if failure.count(expected) != 1:
            raise ValueError('channel-failure-message')
    if '"Unexpected error"' not in body or '"Unable to send channel-open request"' not in body:
        raise ValueError('local-origin-not-distinct')
    if 'libssh2_session_set_read_timeout' not in session.decode('ascii'):
        raise ValueError('public-read-timeout-missing')


def verify(read_source=None):
    if read_source is None:
        # Imported only for explicit verification; it does not instantiate Builder or run tools.
        from build_live import read_source
    archive = NATIVE / 'downloads/libssh2-1.11.1.tar.gz'
    raw = read_source(archive, exported=True)
    if digest(raw) != ARCHIVE_SHA256:
        raise ValueError('pinned-public-archive-changed')
    import io
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as handle:
        sources = {}
        for name, expected in SOURCES.items():
            member = handle.getmember('libssh2-1.11.1/' + name)
            if not member.isfile() or member.size > 512 * 1024:
                raise ValueError('public-source-member')
            value = handle.extractfile(member).read()
            if digest(value) != expected:
                raise ValueError('public-source-digest')
            sources[name] = value
    assert_origin(*(sources[name] for name in SOURCES))
    manifest = json.loads(read_source(NATIVE / 'manifest.json'))
    if manifest['dependencies']['libssh2']['sha256'] != ARCHIVE_SHA256:
        raise ValueError('manifest-public-archive-binding')
    library = read_source(NATIVE / 'install/lib/libssh2.a', exported=True)
    if digest(library) != LIBRARY_SHA256 or manifest['outputs']['install/lib/libssh2.a'] != LIBRARY_SHA256:
        raise ValueError('linked-library-changed')
    return {'gate': 'libssh2-1.11.1-exact-open-failure-origin-v1', 'sourceSHA256': SOURCES,
            'publicArchiveSHA256': ARCHIVE_SHA256, 'linkedArchiveSHA256': LIBRARY_SHA256,
            'messages': list(MESSAGES), 'nativeRebuilt': False, 'liveExecuted': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='help', choices=['help', 'validate', 'verify'])
    args = parser.parse_args(argv)
    if args.action == 'help':
        parser.print_help()
    elif args.action == 'validate':
        print('Syntax only; no build inputs or fixture files read.')
    else:
        print(json.dumps(verify(), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
