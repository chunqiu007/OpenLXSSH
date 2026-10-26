#!/usr/bin/env python3
"""Managed MINA fixture only. Every operation needs --authorized-run; default/help are inert."""
import argparse
import contextlib
import dataclasses
import fcntl
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT / '.runtime'
LOGS = ROOT / '.logs'
IMAGE = 'openlxssh-auth-mina-fixture:2.20.0-arm64'
BASE = ('docker.io/library/ubuntu:24.04@sha256:'
        '18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d')
LABEL = 'org.openlxssh.fixture'
VALUE = 'auth-mina-fixture-a'
PROJECT_LABEL = 'com.docker.compose.project'
SOURCE_LABEL = 'org.openlxssh.fixture.source'
BASE_LABEL = 'org.openlxssh.fixture.base'
PROJECT = re.compile(r'^openlxssh-mina-[0-9a-f]{12}$')
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
IDENTIFIER = re.compile(r'^[0-9a-f]{64}$')
ATTEMPT = re.compile(r'^[0-9a-f]{24}$')
HASH = re.compile(r'^[0-9a-f]{64}$')
SCENARIOS = ('two', 'zero-accept', 'zero-reject', 'approval', 'reject', 'cancel', 'timeout')
ACTIONS = ('build', 'up', 'relay', 'inspect', 'scenario', 'status', 'trust', 'challenge', 'stop', 'remove')
RELAY_MAX_DURATION = 1800
RELAY_FIELDS = ('context', 'endpoint', 'container_id', 'image_id', 'project', 'service',
                'fixture_label_value', 'network_id', 'host_port')
TMPFS = {
    '/run/openlxssh-multiprompt': 'rw,nosuid,nodev,noexec,size=16m,mode=0700,uid=10000,gid=10000',
    '/tmp': 'rw,nosuid,nodev,noexec,size=32m,mode=1777',
}
SETTINGS = Path.home() / 'Library/Group Containers/group.com.docker/settings-store.json'
sys.dont_write_bytecode = True


class ManagedError(Exception):
    pass


def read_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def shared_helpers():
    # Parent module is read-only. Never call its main, state, Compose or root resource helpers.
    parent = read_module(ROOT.parent / 'fixture.py', 'openlxssh_parent_fixture')
    for name in ('require_local_engine', 'require_local_builder', 'docker_environment', 'local_endpoint'):
        if not callable(getattr(parent, name, None)):
            raise ManagedError('parent local-engine helper interface changed; coordinate review')
    return parent


def reject_overrides():
    if os.environ.get('DOCKER_CONTEXT') not in (None, '', 'default', 'desktop-linux'):
        raise ManagedError('unsupported context')
    if any(value and (name.startswith(('BUILDX_', 'BUILDKIT_', 'COMPOSE_'))
                      or name.startswith('DOCKER_') and name != 'DOCKER_CONTEXT')
           for name, value in os.environ.items()):
        raise ManagedError('unset Docker/builder/Compose overrides')


def private_dir(path, create=False):
    if path.is_symlink() or path.resolve() != path:
        raise ManagedError('aliased private directory refused')
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    info = path.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ManagedError('private directory must be owned 0700')


def read_private(path, limit=65536):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > limit):
            raise ManagedError('unsafe private metadata')
        with os.fdopen(fd, 'r', closefd=False) as stream:
            return stream.read(limit + 1)
    finally:
        os.close(fd)


def read_json(path, limit=65536):
    return json.loads(read_private(path, limit))


def static_preflight():
    # Pure local reads/hash/syntax checks; no Docker, Java or network. Never imports test runners.
    import ast
    for path in ROOT.glob('*.py'):
        ast.parse(path.read_text(), filename=str(path))
    fetch = read_module(ROOT / 'fetch_inputs.py', 'openlxssh_verified_inputs')
    lock = fetch.lock_data()
    if lock['ubuntu_image'] != BASE or lock['mina_version'] != '2.20.0':
        raise ManagedError('fixed public inputs differ')
    for item in lock['artifacts']:
        path = ROOT / '.cache' / item['file']
        if path.is_symlink():
            raise ManagedError('symlink fixed input refused')
        fetch.verify(path.read_bytes(), item)
    for name in ('.dockerignore', '.gitignore'):
        entries = (ROOT / name).read_text().splitlines()
        if any(not any(line.rstrip('/') == value for line in entries)
               for value in ('.cache', '.runtime', '.logs', '__pycache__')) or any(line.startswith('!') for line in entries):
            raise ManagedError('private runtime/logs must be excluded without negation')
    dockerfile = (ROOT / 'Dockerfile').read_text()
    bases = [line.split()[1] for line in dockerfile.splitlines() if line.startswith('FROM ')]
    if bases != [BASE, BASE] or '-proc:none --release 21 -Xlint:all' not in dockerfile:
        raise ManagedError('Dockerfile base/compiler contract differs')


def source_hash():
    digest = hashlib.sha256()
    files = [ROOT / name for name in ('Dockerfile', 'inputs.lock.json', 'fetch_inputs.py', 'control.py')]
    files += sorted((ROOT / 'src').rglob('*.java')) + sorted((ROOT / 'licenses').glob('*.txt'))
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ManagedError('unsafe/missing build input')
        digest.update(str(path.relative_to(ROOT)).encode() + b'\0' + path.read_bytes() + b'\0')
    return digest.hexdigest()


def validate_state(state):
    expected = {'version', 'project', 'label', 'image', 'base', 'context', 'endpoint', 'source'}
    if not isinstance(state, dict) or set(state) != expected:
        raise ManagedError('invalid immutable child state schema')
    if (type(state['version']) is not int or state['version'] != 1 or state['label'] != VALUE
            or state['image'] != IMAGE or state['base'] != BASE
            or not isinstance(state['project'], str) or not PROJECT.fullmatch(state['project'])
            or not isinstance(state['source'], str) or not HASH.fullmatch(state['source'])
            or state['context'] not in ('default', 'desktop-linux')
            or not isinstance(state['endpoint'], str)):
        raise ManagedError('invalid immutable child state')
    return state


def validate_record(record, state):
    if not isinstance(record, dict) or set(record) != {'version', 'project', 'image_id', 'source'}:
        raise ManagedError('invalid built-image record schema')
    if (type(record['version']) is not int or record['version'] != 1
            or record['project'] != state['project'] or record['source'] != state['source']
            or not isinstance(record['image_id'], str) or not DIGEST.fullmatch(record['image_id'])):
        raise ManagedError('invalid immutable built-image record')
    return record


def load_state():
    private_dir(RUNTIME)
    state = validate_state(read_json(RUNTIME / 'state.json'))
    validate_runtime(state)
    return state


def validate_runtime(state):
    # Unknown files, symlinks, directories or modes are never silently adopted/deleted.
    allowed = {'state.json', 'build.json', 'operation.lock'}
    for path in RUNTIME.iterdir():
        if path.name in allowed or re.fullmatch(r'challenge-[0-9a-f]{24}\.json', path.name):
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise ManagedError('unsafe runtime entry')
            if path.name == 'operation.lock' and info.st_size != 0:
                raise ManagedError('unexpected lock content')
            if path.name.startswith('challenge-'):
                validate_challenge(read_json(path, 4096), path.name[10:-5], active=False)
        elif re.fullmatch(r'trust-[0-9a-f]{12}', path.name):
            private_dir(path)
            if {p.name for p in path.iterdir()} != {'known_hosts', 'fingerprint.txt'}:
                raise ManagedError('unknown trust export contents')
            for child in path.iterdir():
                info = child.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != 0o600):
                    raise ManagedError('unsafe trust export')
            validate_trust({'known_hosts': read_private(path / 'known_hosts', 4096),
                            'fingerprint': read_private(path / 'fingerprint.txt', 256).removesuffix('\n')})
        else:
            raise ManagedError('unknown runtime content')
    if (RUNTIME / 'build.json').exists():
        validate_record(read_json(RUNTIME / 'build.json'), state)


@contextlib.contextmanager
def operation_lock():
    path = RUNTIME / 'operation.lock'
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ManagedError('unsafe child lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ManagedError('another child operation is active') from None
        yield
    finally:
        os.close(fd)


def desktop_settings():
    # Read only the already reviewed fields, never write or accept a legal/system prompt.
    if SETTINGS.is_symlink() or SETTINGS.stat().st_size > 1024 * 1024:
        raise ManagedError('unsafe Desktop settings')
    data = json.loads(SETTINGS.read_text())
    if (data.get('LicenseTermsVersion') != 2 or data.get('Cpus') != 2
            or data.get('MemoryMiB') != 4096 or data.get('DiskSizeMiB') != 40960
            or data.get('AutoStart') is not False):
        raise ManagedError('Desktop differs from reviewed 2CPU/4GiB/40GiB settings')


class Runner:
    def __init__(self, parent):
        self.parent = parent
        self.context = None
        self.endpoint = None
        self.relay_mode = False

    def preflight(self, build=False):
        reject_overrides()
        desktop_settings()
        self.context = self.parent.require_local_engine()
        self.endpoint = self.parent.VERIFIED_ENDPOINT
        if self.context not in ('default', 'desktop-linux'):
            raise ManagedError('unexpected helper context')
        self.parent.local_endpoint(self.endpoint)
        data = json.loads(self.docker(['info', '--format', '{{json .}}']))
        if (data.get('NCPU') != 2 or not isinstance(data.get('MemTotal'), int)
                or not 3900000000 <= data['MemTotal'] <= 4294967296
                or data.get('Architecture') not in ('aarch64', 'arm64')
                or data.get('OperatingSystem') != 'Docker Desktop'):
            raise ManagedError('engine resources/platform differ from reviewed Desktop')
        self.parent.require_local_builder()

    def docker(self, arguments, log=False):
        if self.context not in ('default', 'desktop-linux') or self.endpoint is None:
            raise ManagedError('local preflight required')
        env = self.parent.docker_environment(self.context)
        command = ['docker', '--context', self.context] + arguments
        if not log:
            result = subprocess.run(command, cwd=ROOT, env=env, check=False,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode:
                raise ManagedError('Docker operation failed; output suppressed')
            return result.stdout
        private_dir(LOGS, create=True)
        path = LOGS / ('build-' + secrets.token_hex(6) + '.log')
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            result = subprocess.run(command, cwd=ROOT, env=env, check=False,
                                    stdout=output, stderr=subprocess.STDOUT)
        print('Private build evidence: ' + str(path))
        if result.returncode:
            raise ManagedError('build failed; inspect the non-secret build log')
        return b''

    def bind(self, state, require_source=True):
        if state['context'] != self.context or state['endpoint'] != self.endpoint:
            raise ManagedError('state belongs to another local engine endpoint')
        if require_source and state['source'] != source_hash():
            raise ManagedError('build sources changed; review/remove is required')

    def inspect(self, kind, reference):
        query = ['inspect'] if kind == 'container' else [kind, 'inspect']
        items = json.loads(self.docker(query + [reference]))
        if not isinstance(items, list) or len(items) != 1:
            raise ManagedError('expected one exact inspected resource')
        return items[0]

    def labels(self, item, kind, state):
        labels = item.get('Config', {}).get('Labels') if kind in ('image', 'container') else item.get('Labels')
        if not isinstance(labels, dict) or labels.get(LABEL) != VALUE or labels.get(PROJECT_LABEL) != state['project']:
            raise ManagedError('resource lacks both child ownership labels')
        if kind in ('image', 'container') and (labels.get(BASE_LABEL) != BASE
                                               or labels.get(SOURCE_LABEL) != state['source']):
            raise ManagedError('resource base/source differs from state')
        return labels

    def resources(self, state, kind):
        commands = {'container': ['ps', '-a', '-q', '--no-trunc'], 'network': ['network', 'ls', '-q', '--no-trunc']}
        ids = set()
        for selector in ('label=' + PROJECT_LABEL + '=' + state['project'], 'name=' + state['project']):
            ids.update(self.docker(commands[kind] + ['--filter', selector]).decode().split())
        if any(not IDENTIFIER.fullmatch(identifier) for identifier in ids):
            raise ManagedError('unexpected resource ID')
        found = []
        for identifier in sorted(ids):
            item = self.inspect(kind, identifier)
            self.labels(item, kind, state)
            if item.get('Id') != identifier:
                raise ManagedError('resource ID differs from inspection')
            if kind == 'container':
                if item['Config']['Labels'].get('com.docker.compose.service') != 'multiprompt':
                    raise ManagedError('unknown service in child project')
                if item.get('Name') != '/' + state['project'] + '-multiprompt-1':
                    raise ManagedError('unexpected child container name')
            else:
                if item.get('Name') != state['project'] + '_multiprompt-private':
                    raise ManagedError('unexpected child network name')
                if item.get('Internal') is not True or item.get('Driver') != 'bridge':
                    raise ManagedError('network must be internal bridge')
            found.append(item)
        if len(found) > 1:
            raise ManagedError('expected at most one child resource per kind')
        return found

    def image(self, state, require_record=True):
        item = self.inspect('image', IMAGE)
        self.labels(item, 'image', state)
        if (item.get('Architecture') != 'arm64' or item.get('Os') != 'linux'
                or not DIGEST.fullmatch(item.get('Id', '')) or IMAGE not in (item.get('RepoTags') or [])):
            raise ManagedError('image tag/platform differs from reviewed child image')
        if require_record:
            record = validate_record(read_json(RUNTIME / 'build.json'), state)
            if item['Id'] != record['image_id']:
                raise ManagedError('tag no longer points to recorded child image')
        return item

    def owned(self, state):
        containers = self.resources(state, 'container')
        networks = self.resources(state, 'network')
        valid = {c['Id'] for c in containers}
        for network in networks:
            if not set((network.get('Containers') or {})) <= valid:
                raise ManagedError('foreign container attached to child network')
        # No named volumes are allowed; even matching/colliding volumes are never adopted.
        for selector in ('label=' + PROJECT_LABEL + '=' + state['project'], 'name=' + state['project']):
            if self.docker(['volume', 'ls', '-q', '--filter', selector]).strip():
                raise ManagedError('unexpected volume in tmpfs-only child project')
        return containers, networks

    def compose(self, state, arguments):
        return self.docker(['compose', '--project-name', state['project'], '--file',
                            str(ROOT / 'compose.contract.yaml')] + arguments)

    def configured(self, state):
        data = json.loads(self.compose(state, ['config', '--format', 'json']))
        validate_config(data, state)

    def container_resources(self, state):
        image = self.image(state)
        containers, networks = self.owned(state)
        if len(containers) != 1 or len(networks) != 1:
            raise ManagedError('expected one owned child container/internal network')
        item = containers[0]
        if any(item.get('Config', {}).get(key) != image.get('Config', {}).get(key)
               for key in ('Entrypoint', 'Cmd', 'Env', 'WorkingDir')):
            raise ManagedError('container command/environment differs from verified image')
        validate_container(item, networks[0], image['Id'], state, relay_mode=self.relay_mode)
        return item, networks[0]

    def container(self, state):
        return self.container_resources(state)[0]

    def execute(self, state, arguments):
        item = self.container(state)
        if not item.get('State', {}).get('Running'):
            raise ManagedError('child container is not running')
        return self.docker(['exec', '--user', '10000:10000', item['Id'], 'python3',
                            '/opt/multiprompt/control.py'] + arguments + ['--authorized-run'])

    def copy_json(self, state, source):
        # Docker cp cannot read mounted tmpfs reliably. Only these exact managed files
        # may cross a captured bounded exec-tar pipe; no shell or generic remote reader.
        import io
        import tarfile
        directory = '/run/openlxssh-multiprompt'
        if source == directory + '/trust.json':
            name = 'trust.json'
        elif re.fullmatch(re.escape(directory) + r'/attempts/[0-9a-f]{24}\.json', source):
            directory += '/attempts'
            name = Path(source).name
        else:
            raise ManagedError('unreviewed management export path')
        item = self.container(state)
        if item.get('State', {}).get('Running') is not True:
            raise ManagedError('management export requires a running owned child')
        raw = self.export_tar(item['Id'], directory, name)
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            members = archive.getmembers()
            if (len(members) != 1 or not members[0].isfile() or members[0].linkname
                    or members[0].name != name or members[0].size > 4096
                    or members[0].mode != 0o600):
                raise ManagedError('unexpected management archive content')
            data = json.loads(archive.extractfile(members[0]).read())
        if name == 'trust.json':
            validate_trust(data)
        else:
            validate_challenge(data, name[:-5])
        return data

    def export_tar(self, container_id, directory, name):
        if (not IDENTIFIER.fullmatch(container_id) or self.context not in ('default', 'desktop-linux')
                or self.endpoint is None
                or not (directory == '/run/openlxssh-multiprompt' and name == 'trust.json'
                        or directory == '/run/openlxssh-multiprompt/attempts'
                        and re.fullmatch(r'[0-9a-f]{24}\.json', name))):
            raise ManagedError('fixed owned management export required')
        self.parent.local_endpoint(self.endpoint)
        env = self.parent.docker_environment(self.context)
        env.pop('DOCKER_CONTEXT', None)
        # Bind the daemon call to the verified local Unix endpoint, not mutable context metadata.
        command = ['docker', '--host', self.endpoint, 'exec', '--user', '10000:10000', container_id,
                   '/usr/bin/tar', '-C', directory, '-cf', '-', '--', name]
        deadline = time.monotonic() + 15
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        raw = bytearray()
        try:
            os.set_blocking(process.stdout.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while time.monotonic() < deadline:
                    if not selector.select(min(0.05, max(0, deadline - time.monotonic()))):
                        continue
                    try:
                        chunk = os.read(process.stdout.fileno(), min(65536, 65537 - len(raw)))
                    except (BlockingIOError, InterruptedError):
                        continue
                    if not chunk:
                        if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
                            raise ManagedError('private management export failed; output suppressed')
                        return bytes(raw)
                    raw.extend(chunk)
                    if len(raw) > 65536:
                        raise ManagedError('oversize management export')
            raise ManagedError('private management export timed out')
        finally:
            raw.clear()
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        process.kill()
                process.wait(timeout=1)
            finally:
                process.stdout.close()


@contextlib.contextmanager
def shared_relay_imports(parent):
    # The shared library imports `fixture` lazily. Never resolve it from ambient sys.path/state.
    expected = ROOT.parent / 'fixture.py'
    if (expected.is_symlink() or expected.resolve() != expected
            or Path(getattr(parent, '__file__', '')).resolve() != expected):
        raise ManagedError('relay requires the exact read-only parent helper module')
    prior_path = list(sys.path)
    missing = object()
    prior_fixture = sys.modules.get('fixture', missing)
    prior_relay = sys.modules.get('openlxssh_child_shared_relay', missing)
    if prior_fixture is not missing and prior_fixture is not parent:
        raise ManagedError('foreign fixture module refused for shared relay')
    sys.path.insert(0, str(ROOT.parent))
    sys.modules['fixture'] = parent
    try:
        yield
    finally:
        sys.path[:] = prior_path
        for name, prior in (('fixture', prior_fixture), ('openlxssh_child_shared_relay', prior_relay)):
            if prior is missing:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prior


def valid_relay_serve(serve):
    if not callable(serve):
        return False
    parameters = inspect.signature(serve).parameters
    names = tuple(parameters)
    if names not in (('targets', 'max_duration'), ('targets', 'max_duration', 'startup_deadline')):
        return False
    if (any(parameters[name].kind is not inspect.Parameter.POSITIONAL_OR_KEYWORD
            for name in ('targets', 'max_duration'))
            or parameters['targets'].default is not inspect.Parameter.empty
            or parameters['max_duration'].default != RELAY_MAX_DURATION):
        return False
    return ('startup_deadline' not in parameters
            or parameters['startup_deadline'].kind is inspect.Parameter.KEYWORD_ONLY
            and parameters['startup_deadline'].default is None)


def require_reviewed_relay():
    # Fixed source location and frozen public API; no alternate library/path/target CLI inputs.
    path = ROOT.parent / 'relay.py'
    if path.is_symlink() or path.resolve() != path or not path.is_file():
        raise ManagedError('reviewed shared relay source is missing or aliased')
    spec = importlib.util.spec_from_file_location('openlxssh_child_shared_relay', path)
    library = importlib.util.module_from_spec(spec)
    prior = sys.modules.get(spec.name)
    sys.modules[spec.name] = library  # dataclasses requires its defining module during import
    try:
        spec.loader.exec_module(library)
    finally:
        if prior is None:
            sys.modules.pop(spec.name, None)
        else:
            sys.modules[spec.name] = prior
    target = getattr(library, 'FrozenDockerTarget', None)
    serve = getattr(library, 'serve', None)
    if (not inspect.isclass(target) or not dataclasses.is_dataclass(target)
            or not target.__dataclass_params__.frozen
            or tuple(field.name for field in dataclasses.fields(target)) != RELAY_FIELDS
            or tuple(inspect.signature(target).parameters) != RELAY_FIELDS
            or not valid_relay_serve(serve)
            or target.__module__ != library.__name__ or Path(inspect.getfile(serve)).resolve() != path):
        raise ManagedError('reviewed shared relay interface changed')
    return library


def relay_target(runner, state, library):
    validate_state(state)
    runner.bind(state)
    if runner.relay_mode is not True:
        raise ManagedError('relay requires explicit relay mode')
    item, network = runner.container_resources(state)
    if (item.get('State', {}).get('Running') is not True
            or item['State'].get('Health', {}).get('Status') != 'healthy'
            or item['Id'] not in (network.get('Containers') or {})):
        raise ManagedError('relay requires the exact healthy attached child target')
    with shared_relay_imports(runner.parent):
        return library.FrozenDockerTarget(context=runner.context, endpoint=runner.endpoint,
                                         container_id=item['Id'], image_id=item['Image'], project=state['project'],
                                         service='multiprompt', fixture_label_value=VALUE,
                                         network_id=network['Id'], host_port=22225)


def serve_relay(runner, state, library, target, max_duration):
    if type(max_duration) is not int or not 1 <= max_duration <= RELAY_MAX_DURATION:
        raise ManagedError('relay duration must be a finite integer from 1 to 1800 seconds')
    # Do not hold the child operation lock while serving: scenario/status/trust must remain usable.
    with shared_relay_imports(runner.parent):
        with operation_lock():
            if load_state() != state or relay_target(runner, state, library) != target:
                raise ManagedError('frozen child relay target changed before serve')
        print('Relay mode selected for 127.0.0.1:22225; host TCP/auth reachability is NOT verified.', flush=True)
        # The shared implementation owns listener/worker/signal cleanup, including cancellation.
        # No catch-and-retry, broad Docker cleanup, or captured wire/error data is emitted here.
        library.serve((target,), max_duration=max_duration)


def exact_bytes(value):
    if type(value) is int:
        parsed = value
    elif type(value) is str and len(value) <= 10 and re.fullmatch(r'[1-9][0-9]{0,9}', value):
        parsed = int(value)
    else:
        raise ManagedError('memory limit must be bounded canonical decimal bytes')
    if parsed != 536870912:
        raise ManagedError('memory limit must be exactly 512 MiB')


def validate_config(data, state):
    allowed_root = {'name', 'services', 'networks', 'volumes', 'secrets', 'configs'}
    if set(data) - allowed_root:
        raise ManagedError('unreviewed Compose root field')
    if set(data.get('services', {})) != {'multiprompt'} or data.get('name') != state['project']:
        raise ManagedError('unexpected Compose project/services')
    if set(data.get('networks', {})) != {'multiprompt-private'} or data.get('volumes') or data.get('secrets') or data.get('configs'):
        raise ManagedError('unexpected Compose resource types')
    network = data['networks']['multiprompt-private']
    if (network.get('internal') is not True or network.get('name') != state['project'] + '_multiprompt-private'
            or network.get('labels', {}).get(LABEL) != VALUE or network.get('driver', 'bridge') != 'bridge'
            or network.get('external', False)):
        raise ManagedError('Compose network is not private/owned')
    if network.get('labels') != {LABEL: VALUE}:
        raise ManagedError('unreviewed Compose network labels')
    if set(network) - {'internal', 'name', 'labels', 'driver', 'external', 'enable_ipv4', 'enable_ipv6', 'ipam'}:
        raise ManagedError('unreviewed Compose network field')
    if 'ipam' in network and (type(network['ipam']) is not dict or network['ipam']):
        raise ManagedError('only an omitted or exactly empty Compose IPAM object is allowed')
    if network.get('enable_ipv6') or network.get('enable_ipv4') is False:
        raise ManagedError('unreviewed Compose IP family')
    service = data['services']['multiprompt']
    allowed = {'build', 'image', 'platform', 'labels', 'user', 'read_only', 'privileged', 'init', 'restart',
               'cap_drop', 'security_opt', 'cpus', 'mem_limit', 'memswap_limit', 'pids_limit', 'ulimits',
               'tmpfs', 'networks', 'ports', 'logging', 'stop_grace_period', 'healthcheck', 'command', 'entrypoint'}
    if not set(service) <= allowed:
        raise ManagedError('unreviewed Compose service field')
    labels = service.get('labels', {})
    if labels != {LABEL: VALUE}:
        raise ManagedError('Compose fixture label mismatch')
    build = service.get('build', {})
    if set(build) - {'context', 'dockerfile'} or build.get('context') != str(ROOT) or build.get('dockerfile', 'Dockerfile') != 'Dockerfile':
        raise ManagedError('unreviewed build context')
    if service.get('privileged', False) is not False:
        raise ManagedError('Compose privileged must be absent or boolean false')
    if service.get('command') is not None or service.get('entrypoint') is not None:
        raise ManagedError('Compose must not override image command/entrypoint')
    exact_bytes(service.get('mem_limit'))
    exact_bytes(service.get('memswap_limit'))
    expected = {'image': IMAGE, 'platform': 'linux/arm64', 'user': '10000:10000', 'read_only': True,
                'init': True, 'restart': 'no', 'cap_drop': ['ALL'],
                'security_opt': ['no-new-privileges:true'], 'pids_limit': 128, 'stop_grace_period': '5s',
                'logging': {'driver': 'none'}}
    if (any(service.get(key) != value for key, value in expected.items())
            or type(service.get('cpus')) not in (int, float) or service['cpus'] != 0.5
            or service.get('read_only') is not True or service.get('init') is not True
            or type(service.get('pids_limit')) is not int):
        raise ManagedError('Compose resource/security limit differs')
    ulimits = service.get('ulimits')
    if (not isinstance(ulimits, dict) or set(ulimits) != {'nofile', 'core'}
            or ulimits['nofile'] != {'soft': 1024, 'hard': 1024}
            or any(type(value) is not int for value in ulimits['nofile'].values())
            or type(ulimits['core']) is not dict
            or ulimits['core'] not in ({}, {'soft': 0, 'hard': 0})
            or any(type(value) is not int for value in ulimits['core'].values())):
        raise ManagedError('Compose ulimits differ')
    if set(service.get('tmpfs', [])) != {path + ':' + value for path, value in TMPFS.items()}:
        raise ManagedError('Compose tmpfs differs')
    if service.get('networks') != {'multiprompt-private': None}:
        raise ManagedError('Compose extra network/options')
    ports = service.get('ports', [])
    if (len(ports) != 1 or set(ports[0]) - {'mode', 'host_ip', 'target', 'published', 'protocol'}
            or ports[0].get('host_ip') != '127.0.0.1' or ports[0].get('target') != 2222
            or str(ports[0].get('published')) != '22225' or ports[0].get('protocol') != 'tcp'
            or ports[0].get('mode', 'ingress') != 'ingress'):
        raise ManagedError('Compose must publish only loopback 22225')
    health = service.get('healthcheck', {})
    if health != {'test': ['CMD', 'python3', '/opt/multiprompt/control.py', 'health', '--authorized-run'],
                  'interval': '10s', 'timeout': '3s', 'retries': 3, 'start_period': '30s'}:
        raise ManagedError('unexpected Compose healthcheck')


def validate_container(item, network, image_id, state, *, relay_mode=False):
    if type(relay_mode) is not bool:
        raise ManagedError('relay mode must be explicitly boolean')
    options = network.get('Options')
    defaults = {'com.docker.network.enable_ipv4': 'true', 'com.docker.network.enable_ipv6': 'false'}
    if (network.get('EnableIPv6') or network.get('Attachable')
            or options is not None and (type(options) is not dict or options not in ({}, defaults))):
        raise ManagedError('actual network has unreviewed routing/options')
    host = item.get('HostConfig', {})
    config = item.get('Config', {})
    if item.get('Image') != image_id or config.get('Image') != IMAGE or config.get('User') != '10000:10000':
        raise ManagedError('actual container image/user mismatch')
    expected = {'ReadonlyRootfs': True, 'Privileged': False, 'Init': True, 'CapDrop': ['ALL'],
                'NanoCpus': 500000000, 'Memory': 536870912, 'MemorySwap': 536870912, 'PidsLimit': 128,
                'LogConfig': {'Type': 'none', 'Config': {}}, 'Tmpfs': TMPFS,
                'PortBindings': {'2222/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '22225'}]}}
    if any(host.get(key) != value for key, value in expected.items()):
        raise ManagedError('actual container confinement differs')
    if (host.get('CapAdd') or host.get('Binds') or host.get('Devices') or host.get('DeviceRequests')
            or host.get('VolumesFrom') or host.get('PidMode') or host.get('IpcMode') not in ('private', '')
            or host.get('NetworkMode') != state['project'] + '_multiprompt-private'
            or host.get('RestartPolicy') != {'Name': 'no', 'MaximumRetryCount': 0}
            or host.get('SecurityOpt') not in (['no-new-privileges:true'], ['no-new-privileges'])
            or item.get('Mounts')):
        raise ManagedError('actual container has extra privilege/mount/namespace')
    # Compose may omit zero-valued core fields, but actual inspection must report integer zeros.
    ulimits = host.get('Ulimits')
    if (type(ulimits) is not list or len(ulimits) != 2
            or any(type(limit) is not dict or set(limit) != {'Name', 'Soft', 'Hard'}
                   or type(limit['Name']) is not str
                   or type(limit['Soft']) is not int or type(limit['Hard']) is not int
                   for limit in ulimits)
            or {limit['Name']: (limit['Soft'], limit['Hard']) for limit in ulimits}
            != {'nofile': (1024, 1024), 'core': (0, 0)}):
        raise ManagedError('actual container ulimits differ')
    if config.get('Healthcheck') != {'Test': ['CMD', 'python3', '/opt/multiprompt/control.py', 'health', '--authorized-run'],
                                   'Interval': 10000000000, 'Timeout': 3000000000,
                                   'Retries': 3, 'StartPeriod': 30000000000}:
        raise ManagedError('actual container healthcheck differs')
    networks = item.get('NetworkSettings', {}).get('Networks', {})
    if set(networks) != {network['Name']} or networks[network['Name']].get('NetworkID') != network['Id']:
        raise ManagedError('actual container attached to unexpected network')
    if item.get('State', {}).get('Running'):
        ports = item.get('NetworkSettings', {}).get('Ports')
        requested = {'2222/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '22225'}]}
        # Only the exact observed internal-network empty binding is relay-compatible.
        # This is confinement metadata, never a host-listener/reachability assertion.
        if ports != requested and not (relay_mode is True and ports == {'2222/tcp': []}):
            raise ManagedError('actual published port is not host loopback only')


def create_state(runner, exporter):
    private_dir(RUNTIME, create=True)
    if (RUNTIME / 'state.json').exists():
        return load_state()
    if list(RUNTIME.iterdir()):
        raise ManagedError('refusing nonempty unowned runtime')
    state = {'version': 1, 'project': 'openlxssh-mina-' + secrets.token_hex(6), 'label': VALUE,
             'image': IMAGE, 'base': BASE, 'context': runner.context, 'endpoint': runner.endpoint,
             'source': source_hash()}
    exporter.write('state.json', json.dumps(state))
    return state


def build(runner, state, exporter):
    containers, _ = runner.owned(state)
    if containers:
        raise ManagedError('remove the owned container before building')
    existing = runner.docker(['image', 'ls', '--quiet', '--no-trunc', IMAGE]).decode().split()
    if existing:
        # Never overwrite even an owned tag; validated builds are reused, failures need explicit review.
        runner.image(state)
        raise ManagedError('fixed image tag already exists; build never overwrites images')
    if (RUNTIME / 'build.json').exists():
        raise ManagedError('recorded image missing; explicit review required')
    runner.docker(['buildx', 'build', '--builder', runner.context, '--platform', 'linux/arm64', '--pull', '--load',
                   '--label', PROJECT_LABEL + '=' + state['project'], '--label', SOURCE_LABEL + '=' + state['source'],
                   '--tag', IMAGE, '--file', str(ROOT / 'Dockerfile'), str(ROOT)], log=True)
    item = runner.image(state, require_record=False)
    exporter.write('build.json', json.dumps({'version': 1, 'project': state['project'],
                                           'image_id': item['Id'], 'source': state['source']}))
    print('Built only the owned MINA image; no service started.')


def validate_trust(data):
    if (not isinstance(data, dict) or set(data) != {'known_hosts', 'fingerprint'}
            or not isinstance(data['known_hosts'], str) or not isinstance(data['fingerprint'], str)
            or not re.fullmatch(r'\[127\.0\.0\.1\]:22225 ssh-rsa [A-Za-z0-9+/=]+\n', data['known_hosts'])
            or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]+', data['fingerprint'])):
        raise ManagedError('invalid trust export')


def validate_challenge(data, attempt, active=True):
    if (not isinstance(data, dict) or set(data) != {'attempt', 'expires_at', 'responses', 'echo'}
            or data['attempt'] != attempt or type(data['expires_at']) not in (int, float)
            or not isinstance(data['responses'], list) or len(data['responses']) != 2
            or any(not isinstance(value, str) or not re.fullmatch(r'[0-9]{10}', value)
                   for value in data['responses']) or data['echo'] != [False, True]):
        raise ManagedError('invalid challenge export')
    if active and not time.time() < data['expires_at'] <= time.time() + 75:
        raise ManagedError('challenge export expired')


def trust(runner, state, exporter):
    data = runner.copy_json(state, '/run/openlxssh-multiprompt/trust.json')
    validate_trust(data)
    name = 'trust-' + secrets.token_hex(6)
    directory = RUNTIME / name
    directory.mkdir(mode=0o700)
    exporter.write(name + '/known_hosts', data['known_hosts'])
    exporter.write(name + '/fingerprint.txt', data['fingerprint'] + '\n')
    print(str(directory))


def cleanup_exports(state):
    validate_runtime(state)
    for path in RUNTIME.glob('challenge-*.json'):
        path.unlink()


def remove(runner, state):
    runner.image(state)
    containers, networks = runner.owned(state)
    for item in containers:
        if item.get('State', {}).get('Running'):
            runner.docker(['stop', '--time', '5', item['Id']])
        runner.labels(runner.inspect('container', item['Id']), 'container', state)
        runner.docker(['rm', item['Id']])
    for item in networks:
        latest = runner.inspect('network', item['Id'])
        runner.labels(latest, 'network', state)
        if latest.get('Containers'):
            raise ManagedError('network remains in use')
        runner.docker(['network', 'rm', item['Id']])
    cleanup_exports(state)
    # Retain immutable state/build/trust and owned image so another project cannot adopt the fixed tag.
    print('Removed only owned child container/network; retained image, private state and public trust.')


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('action', choices=ACTIONS)
    result.add_argument('--authorized-run', action='store_true')
    result.add_argument('--allow-start', action='store_true', help='required for up/relay after primary runtime release')
    result.add_argument('--relay-mode', action='store_true', help='explicit internal-network relay confinement mode; not reachability proof')
    result.add_argument('--max-duration', type=int, help='relay foreground lifetime in seconds (1..1800; default 1800)')
    result.add_argument('--scenario', choices=SCENARIOS)
    result.add_argument('--delay', type=int)
    result.add_argument('--attempt')
    return result


def main(argv=None):
    arguments = parser()
    args = arguments.parse_args(argv)
    if not args.authorized_run:
        arguments.error('explicit --authorized-run required for every operation')
    if args.action in ('up', 'relay') and not args.allow_start:
        arguments.error('up/relay additionally require --allow-start after primary runtime release')
    if args.allow_start and args.action not in ('up', 'relay'):
        arguments.error('--allow-start only applies to up/relay')
    if args.action in ('up', 'relay') and not args.relay_mode:
        arguments.error('up/relay require explicit --relay-mode; published metadata is not reachability proof')
    if args.relay_mode and args.action == 'build':
        arguments.error('--relay-mode does not apply to build')
    if args.max_duration is not None and (args.action != 'relay' or not 1 <= args.max_duration <= RELAY_MAX_DURATION):
        arguments.error('max-duration applies only to relay and must be 1..1800 seconds')
    if args.action == 'scenario':
        if args.scenario is None or args.delay is not None and not 1 <= args.delay <= 60:
            arguments.error('scenario and delay 1..60 required')
    elif args.scenario is not None or args.delay is not None:
        arguments.error('scenario/delay only apply to scenario')
    if args.action == 'challenge':
        if not ATTEMPT.fullmatch(args.attempt or ''):
            arguments.error('challenge requires a 24-hex non-secret attempt ID')
    elif args.attempt is not None:
        arguments.error('attempt only applies to challenge')
    reject_overrides()
    library = require_reviewed_relay() if args.relay_mode else None
    static_preflight()
    os.umask(0o077)
    parent = shared_helpers()
    runner = Runner(parent)
    runner.relay_mode = args.relay_mode
    runner.preflight(build=args.action == 'build')
    exporter = read_module(ROOT / 'private_export.py', 'openlxssh_private_export')
    if exporter.ROOT != RUNTIME:
        raise ManagedError('private exporter runtime differs')
    state = create_state(runner, exporter) if args.action == 'build' else load_state()
    runner.bind(state, require_source=args.action not in ('stop', 'remove'))
    target = None
    with operation_lock():
        # Recheck immutable metadata after acquiring the child operation lock.
        if load_state() != state:
            raise ManagedError('state changed during operation')
        if args.action != 'build':
            runner.image(state)
        runner.configured(state)
        if args.action == 'build':
            build(runner, state, exporter)
        elif args.action == 'up':
            containers, _ = runner.owned(state)
            if containers:
                runner.container(state)
            try:
                runner.compose(state, ['up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '120'])
                runner.container(state)
                print('Owned container confinement inspected; host TCP reachability is NOT verified.')
            except BaseException:
                # Stop only inspected/owned IDs; never broaden cleanup on a verification failure.
                for item in runner.resources(state, 'container'):
                    runner.docker(['stop', '--time', '5', item['Id']])
                raise
        elif args.action == 'relay':
            target = relay_target(runner, state, library)
        elif args.action == 'inspect':
            item = runner.container(state)
            print('multiprompt: ' + item['State']['Status'] + '; host TCP reachability is NOT verified.')
        elif args.action == 'scenario':
            runner.execute(state, ['scenario', '--scenario', args.scenario, '--delay', str(args.delay or 8)])
        elif args.action == 'status':
            raw = runner.execute(state, ['status'])
            # Validate schema before allowing any captured management content to stdout.
            data = json.loads(raw)
            validate_status(data)
            print(json.dumps(data, sort_keys=True))
        elif args.action == 'trust':
            trust(runner, state, exporter)
        elif args.action == 'challenge':
            runner.execute(state, ['check-challenge', '--attempt', args.attempt])
            data = runner.copy_json(state, '/run/openlxssh-multiprompt/attempts/' + args.attempt + '.json')
            validate_challenge(data, args.attempt)
            exporter.retain_challenge(data, args.attempt)
        elif args.action == 'stop':
            runner.image(state)
            containers, _ = runner.owned(state)
            for item in containers:
                runner.docker(['stop', '--time', '5', item['Id']])
            cleanup_exports(state)
        elif args.action == 'remove':
            remove(runner, state)
    if args.action == 'relay':
        serve_relay(runner, state, library, target, args.max_duration or RELAY_MAX_DURATION)
    return 0


def validate_status(data):
    counters = {'generated', 'response_callbacks', 'zero_response_callbacks', 'ignored_late_results',
                'sessions', 'scheduler_queue'}
    if set(data) != counters | {'pending', 'outcomes'}:
        raise ManagedError('unexpected status schema')
    if any(type(data[name]) is not int or data[name] < 0 for name in counters):
        raise ManagedError('invalid status counters')
    if not isinstance(data['pending'], list) or len(data['pending']) > 8:
        raise ManagedError('invalid pending status')
    for item in data['pending']:
        if (set(item) != {'attempt', 'scenario', 'prompt_count', 'responded', 'expires_at'}
                or not ATTEMPT.fullmatch(item['attempt']) or item['scenario'] not in SCENARIOS
                or item['prompt_count'] != (2 if item['scenario'] == 'two' else 0)
                or type(item['responded']) is not bool or type(item['expires_at']) is not int):
            raise ManagedError('invalid pending status metadata')
    reasons = {'replaced', 'setup-failed', 'rejected', 'accepted', 'approved', 'expired', 'session-closed', 'shutdown'}
    if data['sessions'] > 8 or data['scheduler_queue'] > 16:
        raise ManagedError('status resource bounds exceeded')
    if (not isinstance(data['outcomes'], dict) or not set(data['outcomes']) <= reasons
            or any(type(value) is not int or value < 0 for value in data['outcomes'].values())):
        raise ManagedError('invalid outcome counters')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write('Managed operation cancelled; inspect only owned resources before retry.\n')
        sys.exit(130)
    except Exception:
        sys.stderr.write('Managed fixture refused/failed; no credential or captured Docker output emitted.\n')
        sys.exit(1)
