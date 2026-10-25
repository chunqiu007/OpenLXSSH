#!/usr/bin/env python3
"""Authorized local-only Docker fixture driver; defaults to no side effects."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / '.runtime'
IMAGE = 'openlxssh-integration-environment:ubuntu24.04-arm64'
LABEL = 'org.openlxssh.fixture'
LABEL_VALUE = 'env-fixture-a'
SERVICES = ('keyonly', 'passwordonly', 'key-kbd', 'password-kbd')
SCENARIOS = ('multi', 'zero', 'approval', 'reject', 'cancel')
DIGEST_RE = re.compile(r'^docker\.io/library/ubuntu:24\.04@sha256:[0-9a-f]{64}$')
PROJECT_RE = re.compile(r'^openlxssh-fixture-[0-9a-f]{12}$')
SESSION_RE = re.compile(r'^[0-9a-f]{24}$')
ACTIONS = ('build', 'up', 'stop', 'remove', 'collect', 'scenario', 'rotate-host',
           'challenge', 'data', 'disconnect', 'start', 'inspect')


class FixtureError(Exception):
    pass


def private_dir(path):
    if path.is_symlink() or path.resolve() != path:
        raise FixtureError('refusing symlink/aliased directory')
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise FixtureError('runtime directory must be owned by current user and 0700')
    if path.resolve() != path:
        raise FixtureError('refusing aliased runtime directory')


def private_write(path, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def image_input():
    image = os.environ.get('OPENLXSSH_UBUNTU_IMAGE', '')
    if not DIGEST_RE.fullmatch(image):
        raise FixtureError('set official docker.io/library/ubuntu:24.04@sha256:<64 lowercase hex> after review')
    return image


def load_state():
    if RUNTIME.is_symlink() or RUNTIME.resolve() != RUNTIME:
        raise FixtureError('unsafe runtime path')
    path = RUNTIME / 'state.json'
    if path.is_symlink() or not path.is_file():
        raise FixtureError('no private fixture state; run authorized build first')
    for item, mode in ((RUNTIME, 0o700), (path, 0o600)):
        info = item.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode:
            raise FixtureError('unsafe fixture state permissions')
    state = json.loads(path.read_text())
    if state.get('version') != 1 or not PROJECT_RE.fullmatch(state.get('project', '')):
        raise FixtureError('invalid fixture state')
    if not DIGEST_RE.fullmatch(state.get('image', '')):
        raise FixtureError('unlocked base image in state')
    return state


def new_state():
    image = image_input()
    private_dir(RUNTIME)
    if (RUNTIME / 'state.json').exists():
        state = load_state()
        if state['image'] != image:
            raise FixtureError('image differs from current fixture; remove the old environment first')
        return state
    # Refuse adopting arbitrary runtime content from a previous interrupted run.
    if list(RUNTIME.iterdir()):
        raise FixtureError('runtime directory is not empty and has no state')
    state = {'version': 1, 'project': 'openlxssh-fixture-' + secrets.token_hex(6), 'image': image}
    private_write(RUNTIME / 'state.json', json.dumps(state))
    return state


def docker(argv, input_data=None, capture=False):
    env = dict(os.environ, DOCKER_CONTEXT='default', DOCKER_HOST='unix:///var/run/docker.sock')
    env.pop('DOCKER_TLS_VERIFY', None)
    env.pop('DOCKER_CERT_PATH', None)
    # Do not honor remote Docker contexts. The socket is never mounted inside
    # any container; it is only the explicitly authorized host CLI endpoint.
    result = subprocess.run(['docker', '--context', 'default'] + argv, input=input_data,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None,
                            env=env, check=False, cwd=str(ROOT))
    if result.returncode:
        raise FixtureError('Docker command failed (secret output suppressed)' if capture else 'Docker command failed')
    return result.stdout if capture else b''


def require_local_engine():
    if os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT') not in (None, '', 'default'):
        raise FixtureError('unset remote/custom DOCKER_HOST and DOCKER_CONTEXT before using fixture')
    description = json.loads(docker(['context', 'inspect', 'default'], capture=True))
    endpoint = description[0]['Endpoints']['docker']['Host']
    if not endpoint.startswith('unix:///'):
        raise FixtureError('default Docker context must be a local Unix socket')


def compose(state, args):
    previous = os.environ.get('OPENLXSSH_UBUNTU_IMAGE')
    os.environ['OPENLXSSH_UBUNTU_IMAGE'] = state['image']
    try:
        return docker(['compose', '--project-name', state['project'], '--file', str(ROOT / 'compose.yaml')] + args)
    finally:
        if previous is None:
            os.environ.pop('OPENLXSSH_UBUNTU_IMAGE', None)
        else:
            os.environ['OPENLXSSH_UBUNTU_IMAGE'] = previous


def resources(state, kind):
    commands = {'container': ['ps', '-a', '-q'], 'volume': ['volume', 'ls', '-q'],
                'network': ['network', 'ls', '-q']}
    # Check both labeled resources and name collisions: an unlabeled volume
    # with a Compose-generated name must never be silently adopted by `up`.
    ids = set()
    for selector in ('label=com.docker.compose.project=' + state['project'], 'name=' + state['project']):
        raw = docker(commands[kind] + ['--filter', selector], capture=True)
        ids.update(raw.decode().split())
    ids = sorted(ids)
    for identifier in ids:
        query = ['inspect'] if kind == 'container' else [kind, 'inspect']
        objects = json.loads(docker(query + [identifier], capture=True))
        item = objects[0]
        labels = (item.get('Config', {}).get('Labels') or {}) if kind == 'container' else (item.get('Labels') or {})
        if labels.get(LABEL) != LABEL_VALUE or labels.get('com.docker.compose.project') != state['project']:
            raise FixtureError('refusing resource without both ownership labels')
    return ids


def container_id(state, service):
    matches = []
    for identifier in resources(state, 'container'):
        item = json.loads(docker(['inspect', identifier], capture=True))[0]
        if item['Config']['Labels'].get('com.docker.compose.service') == service:
            matches.append(identifier)
    if len(matches) != 1:
        raise FixtureError('expected exactly one labeled service container')
    return matches[0]


def verify_image(state, reference):
    item = json.loads(docker(['image', 'inspect', reference], capture=True))[0]
    labels = item['Config'].get('Labels') or {}
    if (labels.get(LABEL) != LABEL_VALUE or labels.get('org.openlxssh.fixture.base') != state['image']
            or item.get('Architecture') != 'arm64'):
        raise FixtureError('built image does not match the reviewed base/platform')


def validate_ownership(state):
    for kind in ('container', 'volume', 'network'):
        resources(state, kind)


def exec_server(state, service, args):
    identifier = container_id(state, service)
    docker(['exec', '--user', '0:0', identifier, 'python3', '/opt/openlxssh-fixture/server.py']
           + args + ['--authorized-run'], capture=True)
    return identifier


def copy_private_json(identifier, source, destination):
    if destination.exists() or destination.is_symlink():
        raise FixtureError('refusing existing export path')
    # Docker cp writes a file, never terminal stdout; parent is private 0700.
    try:
        docker(['cp', identifier + ':' + source, str(destination)], capture=True)
        if destination.is_symlink() or not destination.is_file():
            raise FixtureError('invalid copied metadata')
        destination.chmod(0o600)
        return json.loads(destination.read_text())
    finally:
        if destination.is_file() and not destination.is_symlink():
            destination.unlink()


def collect(state, service):
    identifier = exec_server(state, service, ['export'])
    destination = RUNTIME / service
    private_dir(destination)
    # Unique generations preserve prior trust for host-key mismatch tests.
    generation = destination / ('credentials-' + secrets.token_hex(6))
    private_dir(generation)
    metadata = copy_private_json(identifier, '/run/openlxssh-fixture/export/metadata.json', generation / 'metadata.json')
    private_write(generation / 'password.txt', metadata['password.txt'] + '\n')
    private_write(generation / 'key-passphrase.txt', metadata['key-passphrase.txt'] + '\n')
    private_write(generation / 'known_hosts', metadata['known_hosts'])
    private_write(generation / 'fingerprint.txt', metadata['fingerprint'] + '\n')
    private_write(generation / 'packages.txt', metadata['packages'])
    inspected = json.loads(docker(['inspect', identifier], capture=True))[0]
    private_write(generation / 'provenance.json', json.dumps({'base_image': state['image'],
                  'built_image_id': inspected['Image'], 'service': service, 'collected_at': time.time()}))
    allowed = {name + suffix for name in ('id_ed25519', 'id_ed25519_encrypted', 'id_rsa', 'id_rsa_encrypted')
               for suffix in ('', '.pub')}
    if set(metadata['keys']) != allowed:
        raise FixtureError('unexpected key export filenames')
    for name, value in metadata['keys'].items():
        private_write(generation / name, value)
    print('Private files written to ' + str(generation) + '; contents were not printed.')


def challenge(state, service, session):
    if not SESSION_RE.fullmatch(session or ''):
        raise FixtureError('use the 24-hex non-secret session ID shown in the pending prompt')
    identifier = exec_server(state, service, ['challenge', '--session', session])
    destination = RUNTIME / service
    private_dir(destination)
    data = copy_private_json(identifier, '/run/openlxssh-fixture/export/challenge-' + session + '.json',
                             destination / ('.export-' + session + '.json'))
    if data['expires_at'] <= time.time():
        raise FixtureError('challenge expired')
    target = destination / ('challenge-' + session + '.json')
    private_write(target, json.dumps(data))
    print('One-use responses saved to ' + str(target) + '; open privately, never log or capture. '
          'This foreground command removes them at expiry (Ctrl+C also cleans up).', flush=True)
    try:
        while time.time() < data['expires_at']:
            time.sleep(max(0, min(0.25, data['expires_at'] - time.time())))
    finally:
        if target.is_file() and not target.is_symlink():
            target.unlink()


def cleanup_local():
    if RUNTIME.is_symlink() or RUNTIME.resolve() != RUNTIME:
        raise FixtureError('refusing unsafe cleanup path')
    # Only the explicitly named ignored directory inside this fixture, never
    # a user-supplied path or an SSH/production directory.
    for directory, dirs, files in os.walk(str(RUNTIME), followlinks=False):
        for name in dirs + files:
            if (Path(directory) / name).is_symlink():
                raise FixtureError('unexpected symlink in runtime; refusing cleanup')
    shutil.rmtree(str(RUNTIME))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=ACTIONS)
    parser.add_argument('--authorized-run', action='store_true',
                        help='safety acknowledgement only; prior user authorization is still required')
    parser.add_argument('--service', choices=SERVICES)
    parser.add_argument('--scenario', choices=SCENARIOS)
    parser.add_argument('--delay', type=int, default=8)
    parser.add_argument('--session')
    args = parser.parse_args()
    if not args.authorized_run:
        parser.error('refusing side effects: --authorized-run AND explicit user authorization required')
    needs_service = args.action in ('scenario', 'rotate-host', 'challenge', 'data', 'disconnect', 'start')
    if needs_service and args.service is None:
        parser.error('this action requires --service')
    if args.action == 'scenario' and (args.service not in ('key-kbd', 'password-kbd') or args.scenario is None):
        parser.error('scenario requires a kbd service and --scenario')
    if not 1 <= args.delay <= 60:
        parser.error('delay must be 1..60 seconds')
    os.umask(0o077)
    # Guard and argument checks deliberately run before any Docker call/write.
    if args.action == 'build':
        image_input()
        require_local_engine()
        state = new_state()
        for identifier in resources(state, 'container'):
            item = json.loads(docker(['inspect', identifier], capture=True))[0]
            if item['State']['Running']:
                raise FixtureError('stop running fixture before rebuilding its image')
        existing = docker(['image', 'ls', '--quiet', IMAGE], capture=True).decode().split()
        for identifier in existing:
            labels = json.loads(docker(['image', 'inspect', identifier], capture=True))[0]['Config'].get('Labels') or {}
            if labels.get(LABEL) != LABEL_VALUE:
                raise FixtureError('refusing to overwrite non-fixture image tag')
    else:
        state = load_state()
        require_local_engine()
    if args.action == 'build':
        compose(state, ['build', '--pull', 'keyonly'])
        verify_image(state, IMAGE)
    elif args.action == 'up':
        validate_ownership(state)
        verify_image(state, IMAGE)
        compose(state, ['up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '120'])
    elif args.action == 'collect':
        for service in (args.service,) if args.service else SERVICES:
            collect(state, service)
    elif args.action == 'scenario':
        exec_server(state, args.service, ['scenario', '--scenario', args.scenario, '--delay', str(args.delay)])
    elif args.action == 'rotate-host':
        exec_server(state, args.service, ['rotate-host'])
        print('Server host key rotated. Existing client known_hosts were NOT changed.')
    elif args.action == 'challenge':
        challenge(state, args.service, args.session)
    elif args.action == 'data':
        identifier = container_id(state, args.service)
        docker(['exec', '--user', '10000:10000', identifier, 'python3', '/opt/openlxssh-fixture/generate_data.py',
                'generate', '--authorized-run'], capture=True)
        print('2 GiB + 1000-file corpus prepared at /fixture/home/corpus; verify downloaded hashes separately.')
    elif args.action == 'disconnect':
        identifier = container_id(state, args.service)
        docker(['stop', '--time', '1', identifier])
        print('Only the selected owned service stopped; active SSH/SFTP connections were interrupted.')
    elif args.action == 'start':
        identifier = container_id(state, args.service)
        item = json.loads(docker(['inspect', identifier], capture=True))[0]
        if item['State']['Running']:
            raise FixtureError('selected service is already running; no new credentials were generated')
        verify_image(state, item['Image'])
        docker(['start', identifier])
        print('Service restarted with new ephemeral keys/password. Explicitly verify new host identity.')
    elif args.action == 'inspect':
        identifiers = resources(state, 'container')
        for identifier in identifiers:
            item = json.loads(docker(['inspect', identifier], capture=True))[0]
            print(item['Config']['Labels']['com.docker.compose.service'] + ': ' + item['State']['Status'])
    elif args.action == 'stop':
        validate_ownership(state)
        compose(state, ['stop', '--timeout', '5'])
    elif args.action == 'remove':
        validate_ownership(state)
        compose(state, ['down', '--volumes', '--timeout', '5'])
        cleanup_local()
        print('Removed only this project\'s labeled containers/network/volumes and ignored runtime files.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write('Fixture operation cancelled; inspect owned resource status before continuing.\n')
        sys.exit(130)
    except (FixtureError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        sys.stderr.write('Fixture command failed or was refused; no secret output emitted. '
                         'Check authorization, arguments, local Docker, state permissions and README.\n')
        sys.exit(1)
