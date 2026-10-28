#!/usr/bin/env python3
"""Authorized local-only Docker fixture driver; defaults to no side effects."""
import argparse
import contextlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

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
           'challenge', 'data', 'disconnect', 'start', 'inspect', 'relay', 'recreate-keyonly')
BASE_CAPABILITIES = ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETUID', 'SETGID', 'SYS_CHROOT', 'KILL')
KEYONLY_RECREATE_PROJECT = 'openlxssh-fixture-61ed25328c13'
KEYONLY_RECREATE_IMAGE = 'sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363'
LOCAL_CONTEXTS = ('default', 'desktop-linux')
VERIFIED_CONTEXT = None
VERIFIED_ENDPOINT = None


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


def docker_environment(context=None):
    # Never inherit another daemon, builder or Compose-file selection. The
    # builtin docker-driver builder follows the explicitly pinned CLI context.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('DOCKER_', 'BUILDX_', 'BUILDKIT_', 'COMPOSE_'))}
    env['BUILDX_CONFIG'] = str(Path.home() / '.docker' / 'buildx')
    env['COMPOSE_BAKE'] = 'false'
    env['LC_ALL'] = 'C'
    env['NO_COLOR'] = '1'
    if context is not None:
        env['DOCKER_CONTEXT'] = context
        env['BUILDX_BUILDER'] = context
    return env


def docker_cli(argv, input_data=None, capture=False, context=None):
    if context is not None and context not in LOCAL_CONTEXTS:
        raise FixtureError('unsupported Docker context')
    command = ['docker'] + (['--context', context] if context is not None else []) + argv
    result = subprocess.run(command, input=input_data,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None,
                            env=docker_environment(context), check=False, cwd=str(ROOT))
    if result.returncode:
        raise FixtureError('Docker command failed (secret output suppressed)' if capture else 'Docker command failed')
    return result.stdout if capture else b''


def docker(argv, input_data=None, capture=False):
    if VERIFIED_CONTEXT is None:
        raise FixtureError('verify the local Docker context before issuing commands')
    return docker_cli(argv, input_data=input_data, capture=capture, context=VERIFIED_CONTEXT)


def local_endpoint(endpoint):
    if not isinstance(endpoint, str):
        raise FixtureError('Docker endpoint must be an absolute local Unix socket')
    parsed = urlsplit(endpoint)
    path = Path(parsed.path)
    if (parsed.scheme != 'unix' or parsed.netloc or parsed.query or parsed.fragment
            or not path.is_absolute() or parsed.path.startswith('//') or '..' in path.parts or not path.name
            or '%' in endpoint or endpoint != 'unix://' + str(path)
            or any(ord(char) <= 32 for char in endpoint)):
        raise FixtureError('Docker endpoint must be a normalized absolute local Unix socket')
    return endpoint


def require_local_engine():
    global VERIFIED_CONTEXT, VERIFIED_ENDPOINT
    VERIFIED_CONTEXT = VERIFIED_ENDPOINT = None
    if (os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_TLS_VERIFY')
            or os.environ.get('DOCKER_CERT_PATH') or os.environ.get('DOCKER_TLS')
            or os.environ.get('DOCKER_CONTEXT') not in (None, '') + LOCAL_CONTEXTS):
        raise FixtureError('unset remote/custom Docker host, context and TLS overrides before using fixture')
    context = os.environ.get('DOCKER_CONTEXT') or docker_cli(['context', 'show'], capture=True).decode().strip()
    if context not in LOCAL_CONTEXTS:
        raise FixtureError('only the local default or desktop-linux Docker context is supported')
    description = json.loads(docker_cli(['context', 'inspect', context], capture=True, context=context))
    if len(description) != 1 or description[0].get('Name') != context:
        raise FixtureError('unexpected Docker context metadata')
    endpoint = local_endpoint(description[0]['Endpoints']['docker']['Host'])
    VERIFIED_CONTEXT, VERIFIED_ENDPOINT = context, endpoint
    return context


def parse_builder_inspect(raw):
    # Buildx v0.38.1 inspect has no --format. Its selected-builder output uses
    # unindented metadata/Nodes fields; indented device Name fields are not
    # nodes. Reject ambiguous/oversized output instead of guessing or using ls
    # (which could probe unrelated user builders, including remote endpoints).
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 64 * 1024:
        raise FixtureError('unexpected builder inspection size')
    text = raw.decode('utf-8')
    if any((ord(char) < 32 and char not in '\n\t') or ord(char) == 127 for char in text):
        raise FixtureError('unexpected control characters in builder inspection')
    lines = text.splitlines()
    if len(lines) > 512 or any(len(line) > 4096 for line in lines):
        raise FixtureError('builder inspection bounds exceeded')
    metadata, node = {}, {}
    in_nodes = False
    last_activity_seen = False
    section = None
    for line in lines:
        if not line:
            continue
        if re.fullmatch(r'Last Activity:[ \t]+[0-9]{4}-[0-9]{2}-[0-9]{2} '
                        r'[0-9]{2}:[0-9]{2}:[0-9]{2} \+0000 UTC[ \t]*', line):
            if in_nodes or last_activity_seen or set(metadata) != {'Name', 'Driver'}:
                raise FixtureError('duplicate or misplaced builder activity')
            last_activity_seen = True
            continue
        if line == 'Nodes:':
            if in_nodes or set(metadata) != {'Name', 'Driver'}:
                raise FixtureError('unexpected builder header or duplicate Nodes section')
            in_nodes = True
            continue
        field = re.fullmatch(r'(Name|Driver|Endpoint):[ \t]+(\S+)[ \t]*', line)
        if field is not None:
            key, value = field.groups()
            target = node if in_nodes else metadata
            allowed = ('Name', 'Endpoint') if in_nodes else ('Name', 'Driver')
            if key not in allowed or key in target:
                raise FixtureError('duplicate or misplaced builder field/node')
            target[key] = value
            section = None
        elif not in_nodes or set(node) != {'Name', 'Endpoint'}:
            raise FixtureError('incomplete builder identity or node')
        elif re.match(r'[ \t]*(?:Name|Driver|Endpoint|Nodes)\s*:', line):
            # Native output has an indented device Name. Do not accidentally
            # accept an indented second node or endpoint as unrelated detail.
            if not (section == 'Devices' and re.fullmatch(r' +Name:[ \t]+\S+[ \t]*', line)):
                raise FixtureError('malformed or extra builder identity field')
        elif re.match(r'[ \t]*(?:Error|Errors|Err)\s*:', line):
            raise FixtureError('builder inspection reported an error')
        elif not line[0].isspace():
            section = line.partition(':')[0]
    if not in_nodes or set(node) != {'Name', 'Endpoint'}:
        raise FixtureError('expected exactly one builder node')
    return metadata['Name'], metadata['Driver'], node['Name'], node['Endpoint']


def require_local_builder():
    # No --bootstrap and no global ls: inspect only the pinned builtin builder.
    raw = docker(['buildx', 'inspect', VERIFIED_CONTEXT, '--timeout', '10s'], capture=True)
    name, driver, node_name, endpoint = parse_builder_inspect(raw)
    if name != VERIFIED_CONTEXT or driver != 'docker' or node_name != VERIFIED_CONTEXT:
        raise FixtureError('build requires the selected context\'s single builtin docker-driver node')
    if endpoint not in (VERIFIED_CONTEXT, VERIFIED_ENDPOINT):
        raise FixtureError('builder endpoint differs from the verified local Docker context')


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
    return item


def validate_capabilities(host, service, *, legacy_keyonly=False):
    if service not in SERVICES:
        raise FixtureError('unknown root fixture service')
    expected = set(BASE_CAPABILITIES)
    # Only the historical keyonly-before snapshot may retain seven caps.
    # Current root services, including the other auth modes, require all eight.
    if not (service == 'keyonly' and legacy_keyonly):
        expected.add('AUDIT_WRITE')
    values = host.get('CapAdd')
    if (not isinstance(values, list) or any(not isinstance(value, str) for value in values)
            or host.get('CapDrop') != ['ALL']):
        raise FixtureError('fixture capability metadata refused')
    normalized = [value[4:] if value.startswith('CAP_') else value for value in values]
    if len(normalized) != len(expected) or set(normalized) != expected:
        raise FixtureError('fixture requires the exact service capability set')


# Only public host-key material, never server export/metadata.json or client keys.
PUBLIC_KEYONLY_FINGERPRINT = r'''
import base64,hashlib,os,re,stat
folder=os.open('/run/openlxssh-fixture',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
    fd=os.open('host_known_hosts',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=folder)
    try:
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_nlink!=1
                or stat.S_IMODE(before.st_mode)!=0o600 or not 0<before.st_size<1024):
            raise SystemExit(65)
        data=os.read(fd,1024)
        after=os.fstat(fd)
        identity=lambda info:(info.st_dev,info.st_ino,info.st_uid,info.st_mode,info.st_nlink,
                              info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        if identity(before)!=identity(after) or len(data)!=before.st_size: raise SystemExit(65)
    finally: os.close(fd)
finally: os.close(folder)
match=re.fullmatch(rb'\[127\.0\.0\.1\]:22221 ssh-ed25519 ([A-Za-z0-9+/=]+)\n',data)
if match is None: raise SystemExit(65)
blob=base64.b64decode(match[1],validate=True)
if len(blob)!=51 or blob[:19]!=b'\0\0\0\x0bssh-ed25519\0\0\0 ': raise SystemExit(65)
print('SHA256:'+base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('='))
'''


def keyonly_fingerprint(identifier):
    raw = docker(['exec', '--user', '0:0', identifier, '/usr/bin/python3', '-c',
                  PUBLIC_KEYONLY_FINGERPRINT], capture=True)
    if not re.fullmatch(rb'SHA256:[A-Za-z0-9+/]{43}\n', raw):
        raise FixtureError('public keyonly fingerprint refused')
    return raw.decode().strip()


def keyonly_recreate_snapshot(state, *, before):
    identifiers = resources(state, 'container')
    volumes = resources(state, 'volume')
    networks = resources(state, 'network')
    volume_keys = ('key-data', 'password-data', 'key-kbd-data', 'password-kbd-data')
    if (len(identifiers) != 4 or len(networks) != 1
            or set(volumes) != {state['project'] + '_' + key for key in volume_keys}):
        raise FixtureError('recreate requires the existing four-service project')
    objects = json.loads(docker(['inspect'] + identifiers, capture=True))
    if len(objects) != 4:
        raise FixtureError('incomplete recreate container batch')
    found = {}
    network_ids = set()
    for item in objects:
        labels = item['Config'].get('Labels') or {}
        service = labels.get('com.docker.compose.service')
        identifier = item['Id']
        if (service not in SERVICES or service in found or not re.fullmatch(r'[0-9a-f]{64}', identifier)
                or sum(identifier.startswith(short) for short in identifiers
                       if re.fullmatch(r'[0-9a-f]{12,64}', short)) != 1
                or item['Image'] != KEYONLY_RECREATE_IMAGE
                or item['Config'].get('Image') not in (IMAGE, KEYONLY_RECREATE_IMAGE)
                or item['Config'].get('Entrypoint') != ['python3', '/opt/openlxssh-fixture/server.py']
                or item['Config'].get('Cmd') != ['serve', '--authorized-run', '--mode', service]
                or labels.get(LABEL) != LABEL_VALUE or labels.get('com.docker.compose.project') != state['project']
                or item['Name'] != '/' + state['project'] + '-' + service + '-1'
                or item['State']['Running'] is not True or item['State'].get('Health', {}).get('Status') != 'healthy'):
            raise FixtureError('recreate container identity/state refused')
        host = item['HostConfig']
        validate_capabilities(host, service, legacy_keyonly=before)
        index = SERVICES.index(service)
        volume_name = state['project'] + '_' + volume_keys[index]
        network_name = state['project'] + '_fixture'
        expected = {'ReadonlyRootfs': True, 'Privileged': False, 'Init': True,
                    'Memory': 402653184, 'MemorySwap': 402653184, 'NanoCpus': 500000000, 'PidsLimit': 128,
                    'Ulimits': [{'Name': 'nofile', 'Soft': 1024, 'Hard': 1024}],
                    'Tmpfs': {'/run': 'rw,nosuid,nodev,noexec,size=96m,mode=0755',
                              '/tmp': 'rw,nosuid,nodev,noexec,size=32m,mode=1777'},
                    'LogConfig': {'Type': 'none', 'Config': {}}, 'NetworkMode': network_name,
                    'Binds': [volume_name + ':/fixture:rw'],
                    'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                    'PortBindings': {'2222/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(22221 + index)}]}}
        if (any(host.get(key) != value for key, value in expected.items())
                or host.get('SecurityOpt') not in (['no-new-privileges:true'], ['no-new-privileges'])
                or any(host.get(key) for key in ('Devices', 'DeviceRequests', 'VolumesFrom', 'PidMode',
                                                'UTSMode', 'UsernsMode', 'PublishAllPorts'))
                or host.get('IpcMode', 'private') != 'private'):
            raise FixtureError('recreate container confinement refused')
        mounts = item['Mounts']
        if (len(mounts) != 1 or mounts[0].get('Type') != 'volume' or mounts[0].get('Name') != volume_name
                or mounts[0].get('Destination') != '/fixture' or mounts[0].get('Driver') != 'local'
                or mounts[0].get('RW') is not True):
            raise FixtureError('recreate must retain the existing named data volume')
        attached = item['NetworkSettings']['Networks']
        if set(attached) != {network_name} or not re.fullmatch(r'[0-9a-f]{64}', attached[network_name]['NetworkID']):
            raise FixtureError('recreate internal network identity refused')
        network_ids.add(attached[network_name]['NetworkID'])
        found[service] = item
    if (len(network_ids) != 1 or len({item['Id'] for item in objects}) != 4
            or any(sum(item['Id'].startswith(short) for item in objects) != 1 for short in identifiers)):
        raise FixtureError('ambiguous recreate container/network identities')
    network_id, = network_ids
    if not network_id.startswith(networks[0]):
        raise FixtureError('recreate network ownership mismatch')
    network, = json.loads(docker(['network', 'inspect', network_id], capture=True))
    if (network['Id'] != network_id or network['Name'] != state['project'] + '_fixture'
            or network['Internal'] is not True or network['Driver'] != 'bridge'
            or network['Labels'].get(LABEL) != LABEL_VALUE
            or network['Labels'].get('com.docker.compose.project') != state['project']
            or set(network['Containers']) != {item['Id'] for item in objects}):
        raise FixtureError('recreate requires the unchanged owned internal bridge')
    volume, = json.loads(docker(['volume', 'inspect', state['project'] + '_key-data'], capture=True))
    if (volume.get('Name') != state['project'] + '_key-data' or volume.get('Driver') != 'local'
            or volume.get('Scope') != 'local' or volume.get('Options') not in (None, {})
            or volume['Labels'].get(LABEL) != LABEL_VALUE
            or volume['Labels'].get('com.docker.compose.project') != state['project']
            or volume['Labels'].get('com.docker.compose.volume') != 'key-data'):
        raise FixtureError('recreate named volume ownership/driver refused')
    return found, network_id, volume


def recreate_identities(objects):
    return {service: {'container_id': item['Id'], 'image_id': item['Image'],
                      'started_at': item['State']['StartedAt'],
                      'data_volume': item['Mounts'][0]['Name'],
                      'cap_add': sorted(value[4:] if value.startswith('CAP_') else value
                                        for value in item['HostConfig']['CapAdd'])}
            for service, item in objects.items()}


# Exact-container /proc metadata only: counts, no argv, session output or secrets.
PUBLIC_IDLE_COUNTS = r'''
import json,os,re
from pathlib import Path
master=int(Path('/run/openlxssh-fixture/sshd.pid').read_text())
if Path('/proc',str(master),'comm').read_text().strip()!='sshd': raise SystemExit(65)
counts={'user_processes':0,'sshd_children':0}
for folder in Path('/proc').iterdir():
    if not re.fullmatch(r'[0-9]+',folder.name): continue
    try:
        status=(folder/'status').read_text()
        name=(folder/'comm').read_text().strip()
    except FileNotFoundError: continue
    uid=re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$',status,re.M)
    if uid is None: raise SystemExit(65)
    if 10000 in map(int,uid.groups()): counts['user_processes']+=1
    if name=='sshd' and int(folder.name)!=master: counts['sshd_children']+=1
print(json.dumps(counts))
'''


def validate_idle_counts(counts):
    if (not isinstance(counts, dict) or set(counts) != {'user_processes', 'sshd_children'}
            or any(type(value) is not int or value != 0 for value in counts.values())):
        raise FixtureError('recreate requires no active fixture sessions/test processes')


@contextlib.contextmanager
def keyonly_recreate_idle(objects):
    # Reserve only the five approved fixed loopbacks, WITHOUT listen/connect.
    # An active relay/listener refuses the action. Reservations cover preflight
    # only; release every socket before Compose requests its published ports.
    with contextlib.ExitStack() as cleanup:
        for port in range(22221, 22226):
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cleanup.callback(probe.close)
            try:
                probe.bind(('127.0.0.1', port))
            except OSError:
                raise FixtureError('stop the exact managed relay/listener before keyonly recreate') from None
        counts = {}
        for service in SERVICES:
            raw = docker(['exec', '--user', '0:0', objects[service]['Id'], '/usr/bin/python3', '-c',
                          PUBLIC_IDLE_COUNTS], capture=True)
            counts[service] = json.loads(raw)
            validate_idle_counts(counts[service])
        yield counts


def recreate_keyonly(state):
    # Deliberately a one-campaign action, never a general service selector or up alias.
    if state.get('project') != KEYONLY_RECREATE_PROJECT:
        raise FixtureError('keyonly recreate is restricted to the reviewed existing project')
    if verify_image(state, KEYONLY_RECREATE_IMAGE).get('Id') != KEYONLY_RECREATE_IMAGE:
        raise FixtureError('keyonly recreate image identity differs')
    old, network_id, volume = keyonly_recreate_snapshot(state, before=True)
    with keyonly_recreate_idle(old) as idle:
        pass
    apply_keyonly_recreate(state, old, network_id, volume, idle)


def apply_keyonly_recreate(state, old, network_id, volume, idle):
    old_fingerprint = keyonly_fingerprint(old['keyonly']['Id'])
    private_dir(RUNTIME / 'keyonly')
    directory = RUNTIME / 'keyonly' / ('recreate-' + secrets.token_hex(6))
    private_dir(directory)
    preflight = {'project': state['project'], 'image_id': KEYONLY_RECREATE_IMAGE, 'network_id': network_id,
                 'before': recreate_identities(old), 'old_fingerprint': old_fingerprint, 'data_volume': volume,
                 'idle_counts': idle, 'preflight_reserved_not_listening_ports': list(range(22221, 22226)),
                 'ports_released_before_compose': True,
                 'ephemeral_identity_changes_expected': True, 'old_secrets_preserved': False}
    private_write(directory / 'preflight.json', json.dumps(preflight, indent=2) + '\n')
    # The private, fixed overlay prevents tag races without changing shared Compose image/build semantics.
    pin = directory / 'compose-pin.json'
    private_write(pin, json.dumps({'services': {'keyonly': {'image': KEYONLY_RECREATE_IMAGE}}}) + '\n')
    print('Public preflight: ' + str(directory / 'preflight.json') +
          '; keyonly CID/host key/client keys will change; old secrets are NOT preserved.', flush=True)
    result = {'status': 'incomplete', 'preflight': str(directory / 'preflight.json')}
    stage = 'compose'
    try:
        compose(state, ['--file', str(pin), 'up', '-d', '--no-deps', '--force-recreate', '--no-build',
                        '--pull', 'never', '--wait', '--wait-timeout', '120', 'keyonly'])
        stage = 'postcheck'
        new, new_network_id, new_volume = keyonly_recreate_snapshot(state, before=False)
        if new_network_id != network_id or new_volume != volume or new['keyonly']['Mounts'] != old['keyonly']['Mounts']:
            raise FixtureError('recreate changed the existing network/data volume')
        for service in SERVICES[1:]:
            for field in ('Id', 'Image', 'Config', 'HostConfig', 'Mounts'):
                if new[service][field] != old[service][field]:
                    raise FixtureError('another fixture service changed during keyonly recreate')
            if new[service]['State']['StartedAt'] != old[service]['State']['StartedAt']:
                raise FixtureError('another fixture service restarted during keyonly recreate')
        new_fingerprint = keyonly_fingerprint(new['keyonly']['Id'])
        if new['keyonly']['Id'] == old['keyonly']['Id'] or new_fingerprint == old_fingerprint:
            raise FixtureError('keyonly recreate did not create the expected new identity')
        result.update(status='recreated', after=recreate_identities(new), new_fingerprint=new_fingerprint,
                      data_volume=new_volume, network_id=new_network_id)
    except BaseException as error:
        result.update(failed_stage=stage, error_class='cancelled' if isinstance(error, (KeyboardInterrupt, SystemExit))
                      else 'FixtureError' if isinstance(error, FixtureError) else 'operation-error')
        raise
    finally:
        private_write(directory / 'result.json', json.dumps(result, indent=2) + '\n')
        print('Public recreate result: ' + str(directory / 'result.json'), flush=True)


def run_keyonly_recreate():
    from relay import _bounded_stdout
    import threading
    deadline = time.monotonic() + 300.0
    cancelled = threading.Event()
    executable = shutil.which('docker', path=os.environ.get('PATH', os.defpath))
    if executable is None:
        raise FixtureError('local Docker CLI unavailable')
    executable = str(Path(executable).resolve(strict=True))
    original_cli = globals()['docker_cli']
    prior = {signum: signal.signal(signum, lambda *_args: cancelled.set())
             for signum in (signal.SIGINT, signal.SIGTERM)}
    def bounded_cli(argv, input_data=None, capture=False, context=None):
        if input_data is not None or context not in (None,) + LOCAL_CONTEXTS:
            raise FixtureError('invalid recreate Docker route/input')
        environment = docker_environment(context)
        environment.pop('DOCKER_CONTEXT', None)
        if argv in (['context', 'show'], ['context', 'inspect', context]):
            command = [executable] + (['--context', context] if context else []) + argv
        else:
            if VERIFIED_ENDPOINT is None:
                raise FixtureError('recreate endpoint not verified')
            command = [executable, '--host', local_endpoint(VERIFIED_ENDPOINT)] + argv
        try:
            return _bounded_stdout(command, environment, deadline, cancelled)
        except Exception:
            raise FixtureError('bounded keyonly recreate failed; inspect public result before any retry') from None
    globals()['docker_cli'] = bounded_cli
    try:
        state = load_state()
        require_local_engine()
        recreate_keyonly(state)
    finally:
        globals()['docker_cli'] = original_cli
        for signum, handler in prior.items():
            signal.signal(signum, handler)


def validate_ownership(state):
    for kind in ('container', 'volume', 'network'):
        resources(state, kind)


def exec_server(state, service, args):
    identifier = container_id(state, service)
    docker(['exec', '--user', '0:0', identifier, 'python3', '/opt/openlxssh-fixture/server.py']
           + args + ['--authorized-run'], capture=True)
    return identifier


EXPORT_LIMIT = 64 * 1024
EXPORT_TIMEOUT = 15.0
EXPORT_SOURCE_RE = re.compile(r'/run/openlxssh-fixture/export/(?:metadata\.json|challenge-[0-9a-f]{24}\.json)')
EXPORT_KEY_NAMES = frozenset(name + suffix for name in
    ('id_ed25519', 'id_ed25519_encrypted', 'id_rsa', 'id_rsa_encrypted') for suffix in ('', '.pub'))

# Fixed non-shell program. It reads a single allowed tmpfs file through pinned
# directory fds, validates everything before emitting any bytes, and never logs.
PRIVATE_EXPORT_READER = r'''
import os,re,stat,sys
fds=[]
try:
    source=sys.argv[1]
    if not re.fullmatch(r'/run/openlxssh-fixture/export/(metadata\.json|challenge-[0-9a-f]{24}\.json)',source):
        raise ValueError()
    directory=os.open('/run',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    fds.append(directory)
    for name,mode in (('openlxssh-fixture',0o755),('export',0o700)):
        directory=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
        fds.append(directory)
        info=os.fstat(directory)
        if info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=mode: raise ValueError()
    fd=os.open(source.rsplit('/',1)[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    fds.append(fd)
    before=os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_nlink!=1
            or stat.S_IMODE(before.st_mode)!=0o600 or not 0<before.st_size<=65536):
        raise ValueError()
    data=bytearray()
    while len(data)<=65536:
        block=os.read(fd,min(8192,65537-len(data)))
        if not block: break
        data.extend(block)
    after=os.fstat(fd)
    identity=lambda info:(info.st_dev,info.st_ino,info.st_uid,info.st_mode,info.st_nlink,
                          info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    if len(data)!=before.st_size or identity(before)!=identity(after): raise ValueError()
    view=memoryview(data)
    while view:
        count=os.write(1,view)
        if count<=0: raise OSError()
        view=view[count:]
except Exception:
    os.write(2,b'private fixture export refused; contents suppressed\n')
    raise SystemExit(1)
finally:
    for fd in reversed(fds): os.close(fd)
'''


def validate_private_json(raw, source):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise FixtureError('duplicate private metadata field')
            result[key] = value
        return result
    try:
        if (not isinstance(source, str) or not EXPORT_SOURCE_RE.fullmatch(source)
                or not isinstance(raw, bytes) or not 0 < len(raw) <= EXPORT_LIMIT):
            raise FixtureError('private metadata size/source refused')
        data = json.loads(raw, object_pairs_hook=unique_object,
                          parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
        if not isinstance(data, dict):
            raise FixtureError('private metadata must be one JSON object')
        if source.endswith('/metadata.json'):
            expected = {'password.txt', 'key-passphrase.txt', 'keys', 'known_hosts', 'fingerprint', 'packages'}
            if (set(data) != expected or not isinstance(data['keys'], dict)
                    or set(data['keys']) != EXPORT_KEY_NAMES
                    or any(not isinstance(data[key], str) or not data[key] or '\0' in data[key]
                           for key in expected - {'keys'})
                    or any(not isinstance(value, str) or not value or '\0' in value
                           for value in data['keys'].values())):
                raise FixtureError('private metadata schema refused')
        else:
            session = source.rsplit('/', 1)[1][len('challenge-'):-len('.json')]
            if (set(data) != {'session', 'expires_at', 'scenario', 'responses'} or data['session'] != session
                    or data['scenario'] != 'multi' or not isinstance(data['responses'], list)
                    or len(data['responses']) != 3
                    or any(not isinstance(value, str) or not re.fullmatch(r'[0-9]{8}', value)
                           for value in data['responses'])
                    or type(data['expires_at']) not in (int, float) or not math.isfinite(data['expires_at'])
                    or data['expires_at'] <= time.time()):
                raise FixtureError('private challenge schema/expiry refused')
        return data
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, FixtureError):
        raise FixtureError('private export JSON was refused; contents suppressed') from None


def copy_private_json(identifier, source, destination, *, state, service):
    # No temporary secret file or archive extraction. The destination argument
    # remains an existence/path guard; only validated fields are persisted later.
    from relay import _bounded_stdout
    import threading
    if (not isinstance(source, str) or not EXPORT_SOURCE_RE.fullmatch(source)
            or not re.fullmatch(r'[0-9a-f]{12,64}', identifier) or service not in SERVICES
            or VERIFIED_CONTEXT not in LOCAL_CONTEXTS or VERIFIED_ENDPOINT is None):
        raise FixtureError('private export target/source refused')
    if destination.exists() or destination.is_symlink():
        raise FixtureError('refusing existing export path')
    local_endpoint(VERIFIED_ENDPOINT)
    environment = docker_environment(VERIFIED_CONTEXT)
    environment.pop('DOCKER_CONTEXT', None)
    executable = shutil.which('docker', path=environment.get('PATH', os.defpath))
    if executable is None:
        raise FixtureError('local Docker CLI unavailable')
    command = [str(Path(executable).resolve(strict=True)), '--host', VERIFIED_ENDPOINT]
    deadline = time.monotonic() + EXPORT_TIMEOUT
    cancelled = threading.Event()
    try:
        raw = _bounded_stdout(command + ['inspect', identifier], environment, deadline, cancelled)
        objects = json.loads(raw)
        if len(objects) != 1:
            raise FixtureError('ambiguous private export container')
        item = objects[0]
        labels = item['Config'].get('Labels') or {}
        exact = item['Id']
        if (not re.fullmatch(r'[0-9a-f]{64}', exact) or not exact.startswith(identifier)
                or labels.get(LABEL) != LABEL_VALUE or labels.get('com.docker.compose.project') != state['project']
                or labels.get('com.docker.compose.service') != service or item['State']['Running'] is not True):
            raise FixtureError('private export ownership refused')
        raw = _bounded_stdout(command + ['exec', '--user', '0:0', exact, '/usr/bin/python3', '-c',
                                        PRIVATE_EXPORT_READER, source], environment, deadline, cancelled,
                              limit=EXPORT_LIMIT)
        return validate_private_json(raw, source)
    except Exception:
        raise FixtureError('private export pipe failed or was refused; contents suppressed') from None


def collect(state, service):
    identifier = exec_server(state, service, ['export'])
    destination = RUNTIME / service
    private_dir(destination)
    # Unique generations preserve prior trust for host-key mismatch tests.
    generation = destination / ('credentials-' + secrets.token_hex(6))
    private_dir(generation)
    metadata = copy_private_json(identifier, '/run/openlxssh-fixture/export/metadata.json', generation / 'metadata.json',
                                 state=state, service=service)
    inspected = json.loads(docker(['inspect', identifier], capture=True))[0]
    private_write(generation / 'password.txt', metadata['password.txt'] + '\n')
    private_write(generation / 'key-passphrase.txt', metadata['key-passphrase.txt'] + '\n')
    private_write(generation / 'known_hosts', metadata['known_hosts'])
    private_write(generation / 'fingerprint.txt', metadata['fingerprint'] + '\n')
    private_write(generation / 'packages.txt', metadata['packages'])
    private_write(generation / 'provenance.json', json.dumps({'base_image': state['image'],
                  'built_image_id': inspected['Image'], 'service': service, 'collected_at': time.time()}))
    for name, value in metadata['keys'].items():
        private_write(generation / name, value)
    print('Private files written to ' + str(generation) + '; contents were not printed.')


@contextlib.contextmanager
def temporary_challenge_file(target, value):
    # Keep the created inode open through write, print/flush and TTL cleanup.
    # O_EXCL refusal never establishes ownership of an existing target.
    fd = None
    try:
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        pending = memoryview(value.encode('utf-8'))
        while pending:
            try:
                written = os.write(fd, pending)
            except InterruptedError:
                continue
            if written <= 0:
                raise OSError('challenge file write failed')
            pending = pending[written:]
        yield target
    finally:
        if fd is not None:
            try:
                created = os.fstat(fd)
                try:
                    current = target.lstat()
                except FileNotFoundError:
                    current = None
                if (current is not None and stat.S_ISREG(current.st_mode) and current.st_uid == os.getuid()
                        and (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino)):
                    target.unlink()
            finally:
                os.close(fd)


def challenge(state, service, session):
    if not SESSION_RE.fullmatch(session or ''):
        raise FixtureError('use the 24-hex non-secret session ID shown in the pending prompt')
    identifier = exec_server(state, service, ['challenge', '--session', session])
    destination = RUNTIME / service
    private_dir(destination)
    data = copy_private_json(identifier, '/run/openlxssh-fixture/export/challenge-' + session + '.json',
                             destination / ('.export-' + session + '.json'), state=state, service=service)
    if data['expires_at'] <= time.time():
        raise FixtureError('challenge expired')
    target = destination / ('challenge-' + session + '.json')
    with temporary_challenge_file(target, json.dumps(data)):
        print('One-use responses saved to ' + str(target) + '; open privately, never log or capture. '
              'This foreground command removes them at expiry (Ctrl+C also cleans up).', flush=True)
        deadline = time.monotonic() + max(0, data['expires_at'] - time.time())
        while time.monotonic() < deadline:
            time.sleep(max(0, min(0.25, deadline - time.monotonic())))


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


def relay(state, max_duration, *, startup_deadline=None, cancelled=None):
    # Relay-only bounded routing; the four shared context/build helpers remain
    # unchanged. One resource enumeration, one exact batch, no service rescans.
    from relay import FrozenDockerTarget, RelayError, serve
    identifiers = resources(state, 'container')
    resources(state, 'volume')
    resources(state, 'network')
    if len(identifiers) != len(SERVICES):
        raise FixtureError('relay requires exactly the four existing services')
    objects = json.loads(docker(['inspect'] + identifiers, capture=True))
    if len(objects) != len(identifiers):
        raise FixtureError('relay container batch was incomplete')
    services = {}
    full_ids = set()
    for item in objects:
        labels = item['Config'].get('Labels') or {}
        identifier = item['Id']
        service = labels.get('com.docker.compose.service')
        # ps -q can return short IDs; each must unambiguously match exactly one
        # full inspected ID, and no extra/missing/duplicate/foreign is adopted.
        matches = [short for short in identifiers if re.fullmatch(r'[0-9a-f]{12,64}', short)
                   and identifier.startswith(short)]
        if (not re.fullmatch(r'[0-9a-f]{64}', identifier) or len(matches) != 1
                or identifier in full_ids or service not in SERVICES or service in services
                or labels.get(LABEL) != LABEL_VALUE
                or labels.get('com.docker.compose.project') != state['project']):
            raise FixtureError('relay container batch identity refused')
        services[service] = item
        full_ids.add(identifier)
    if any(sum(identifier.startswith(short) for identifier in full_ids) != 1 for short in identifiers):
        raise FixtureError('relay ambiguous or missing container ID')
    for image in sorted({item['Image'] for item in objects}):
        verify_image(state, image)
    targets = []
    for service, port in zip(SERVICES, range(22221, 22225)):
        item = services[service]
        networks = item['NetworkSettings']['Networks']
        if len(networks) != 1:
            raise FixtureError('relay requires exactly one internal test network')
        targets.append(FrozenDockerTarget(VERIFIED_CONTEXT, VERIFIED_ENDPOINT, item['Id'], item['Image'],
                                         state['project'], service, LABEL_VALUE,
                                         next(iter(networks.values()))['NetworkID'], port))
    if cancelled is not None and cancelled.is_set():
        raise RelayError('relay preflight cancelled')
    serve(targets, max_duration=max_duration, startup_deadline=startup_deadline)


def run_relay(max_duration):
    # Bound the ENTIRE authorized relay path, including initial context checks
    # and discovery, without modifying the four shared helpers used by MINA.
    from relay import PREFLIGHT_TIMEOUT, _bounded_stdout
    import threading
    deadline = time.monotonic() + PREFLIGHT_TIMEOUT
    cancelled = threading.Event()
    original_cli = globals()['docker_cli']
    prior = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        prior[signum] = signal.signal(signum, lambda *_args: cancelled.set())
    def bounded_cli(argv, input_data=None, capture=False, context=None):
        if input_data is not None or context not in (None,) + LOCAL_CONTEXTS:
            raise FixtureError('invalid relay metadata command')
        command = ['docker'] + (['--context', context] if context is not None else []) + argv
        try:
            return _bounded_stdout(command, docker_environment(context), deadline, cancelled)
        except Exception:
            raise FixtureError('bounded relay preflight failed') from None
    globals()['docker_cli'] = bounded_cli
    try:
        state = load_state()
        require_local_engine()
        relay(state, max_duration, startup_deadline=deadline, cancelled=cancelled)
    finally:
        globals()['docker_cli'] = original_cli
        for signum, handler in prior.items():
            signal.signal(signum, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=ACTIONS)
    parser.add_argument('--authorized-run', action='store_true',
                        help='safety acknowledgement only; prior user authorization is still required')
    parser.add_argument('--service', choices=SERVICES)
    parser.add_argument('--manager-authorized-keyonly-recreate', action='store_true',
                        help='separate primary source-review/runtime release; only with recreate-keyonly')
    parser.add_argument('--scenario', choices=SCENARIOS)
    parser.add_argument('--delay', type=int, default=8)
    parser.add_argument('--session')
    parser.add_argument('--max-duration', type=int, default=1800,
                        help='relay foreground lifetime in seconds (1..90000; default 1800)')
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
    if not 1 <= args.max_duration <= 90000:
        parser.error('max-duration must be 1..90000 seconds')
    if args.action == 'relay' and args.service is not None:
        parser.error('root relay always uses exactly the four fixed services')
    if args.action == 'recreate-keyonly':
        if not args.manager_authorized_keyonly_recreate or args.service is not None:
            parser.error('recreate-keyonly requires separate manager authorization and no service selector')
    elif args.manager_authorized_keyonly_recreate:
        parser.error('manager recreate acknowledgement is only valid with recreate-keyonly')
    os.umask(0o077)
    if args.action == 'recreate-keyonly':
        run_keyonly_recreate()
        return 0
    if args.action == 'relay':
        try:
            run_relay(args.max_duration)
        except Exception:
            raise FixtureError('finite relay failed or was refused; no payload output') from None
        return 0
    # Guard and argument checks deliberately run before any Docker call/write.
    if args.action == 'build':
        image_input()
        require_local_engine()
        require_local_builder()
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
        # Compose v5.6.1's buildx shell-out failed context validation on the
        # reviewed local Desktop. Keep this inside the guarded wrapper and
        # invoke the already verified builtin directly; no extra contexts,
        # host networking, mounts or entitlements are passed.
        docker(['buildx', 'build', '--builder', VERIFIED_CONTEXT, '--platform', 'linux/arm64',
                '--pull', '--load', '--build-arg', 'UBUNTU_IMAGE=' + state['image'],
                '--tag', IMAGE, '--file', str(ROOT / 'Dockerfile'), str(ROOT)])
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
