#!/usr/bin/env python3
"""Finite, opaque loopback transport for the explicitly authorized test fixtures.

Not product SSH forwarding. No SSH parser, wire log, TTY, shell, credentials or
payload snapshots. Start the root four-port fixture only via fixture.sh relay.
The managed MINA fixture may import FrozenDockerTarget/serve for port 22225.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from types import MappingProxyType
import uuid

BUFFER_LIMIT = 64 * 1024
MAX_ACTIVE = 16
MAX_PER_PORT = 8
MAX_DURATION = 90000
START_TIMEOUT = 8.0
PREFLIGHT_TIMEOUT = 120.0
TARGET_START_TIMEOUT = 32.0
IDLE_TIMEOUT = 600.0
CLEANUP_TIMEOUT = 5.0
REAP_TIMEOUT = 1.0
SHUTDOWN_TIMEOUT = START_TIMEOUT + CLEANUP_TIMEOUT + 3 * REAP_TIMEOUT
METADATA_LIMIT = 1024 * 1024
ROOT = Path(__file__).resolve().parent
ROOT_PORTS = {'keyonly': 22221, 'passwordonly': 22222, 'key-kbd': 22223, 'password-kbd': 22224}


class RelayError(Exception):
    pass


def pump(left_read, left_write, right_read, right_write, left_eof, right_eof,
         cancelled, idle_timeout=600.0, read_chunk=65536, deadline=None):
    """At most 64 KiB buffered per direction, including under backpressure.

    Each input EOF drains its buffered bytes before half-closing only the
    opposite output. A peer can still send its final response after that EOF.
    Cancellation, errors and deadlines abort; they never log or return bytes.
    """
    if not 0 < read_chunk <= BUFFER_LIMIT or not idle_timeout > 0:
        raise ValueError('invalid pump bounds')
    for fd in {left_read, left_write, right_read, right_write}:
        os.set_blocking(fd, False)
    directions = [dict(source=left_read, sink=right_write, data=bytearray(), eof=False,
                       shut=False, callback=left_eof),
                  dict(source=right_read, sink=left_write, data=bytearray(), eof=False,
                       shut=False, callback=right_eof)]
    last_activity = time.monotonic()
    selector = selectors.DefaultSelector()
    registered = set()
    try:
        while True:
            now = time.monotonic()
            if cancelled.is_set():
                return 'cancelled'
            if deadline is not None and now >= deadline:
                return 'duration-timeout'
            if now - last_activity >= idle_timeout:
                return 'idle-timeout'
            for direction in directions:
                if direction['eof'] and not direction['data'] and not direction['shut']:
                    direction['callback']()
                    direction['shut'] = True
            if all(direction['shut'] for direction in directions):
                return 'complete'
            desired = {}
            for direction in directions:
                if not direction['eof'] and len(direction['data']) < BUFFER_LIMIT:
                    desired[direction['source']] = desired.get(direction['source'], 0) | selectors.EVENT_READ
                if direction['data']:
                    desired[direction['sink']] = desired.get(direction['sink'], 0) | selectors.EVENT_WRITE
            for fd in registered - desired.keys():
                selector.unregister(fd)
            for fd, events in desired.items():
                if fd in registered:
                    selector.modify(fd, events)
                else:
                    selector.register(fd, events)
            registered = set(desired)
            delay = min(0.05, max(0, idle_timeout - (time.monotonic() - last_activity)))
            if deadline is not None:
                delay = min(delay, max(0, deadline - time.monotonic()))
            for key, events in selector.select(delay):
                for direction in directions:
                    room = BUFFER_LIMIT - len(direction['data'])
                    if (key.fd == direction['source'] and events & selectors.EVENT_READ
                            and not direction['eof'] and room):
                        try:
                            chunk = os.read(key.fd, min(read_chunk, room))
                        except (BlockingIOError, InterruptedError):
                            continue
                        except OSError:
                            return 'read-error'
                        if chunk:
                            direction['data'].extend(chunk)
                            last_activity = time.monotonic()
                        else:
                            direction['eof'] = True
                    if key.fd == direction['sink'] and events & selectors.EVENT_WRITE and direction['data']:
                        try:
                            written = os.write(key.fd, direction['data'])
                        except (BlockingIOError, InterruptedError):
                            continue
                        except OSError:
                            return 'write-error'
                        if written:
                            del direction['data'][:written]
                            last_activity = time.monotonic()
    finally:
        selector.close()
        for direction in directions:
            direction['data'].clear()


# Fixed argv programs, never shell strings. Only a non-secret random connection
# token crosses argv. dir_fd/O_NOFOLLOW and strict modes prevent path adoption.
CONTAINER_COMMON = r'''
import hashlib,json,os,re,select,signal,socket,stat,sys,threading,time
from pathlib import Path
import selectors
BUFFER_LIMIT=65536

def owned_directory(token):
    if os.getuid()!=10000 or not re.fullmatch(r'[0-9a-f]{32}',token):
        raise SystemExit(64)
    folder='/tmp/openlxssh-relay-'+token
    try: os.mkdir(folder,0o700)
    except FileExistsError: pass
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    info=os.fstat(fd)
    if info.st_uid!=10000 or stat.S_IMODE(info.st_mode)!=0o700:
        os.close(fd)
        raise SystemExit(65)
    return folder,fd

def private_file(directory,name,flags):
    fd=os.open(name,flags|os.O_NOFOLLOW,0o600,dir_fd=directory)
    info=os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=10000
            or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1):
        os.close(fd)
        raise SystemExit(65)
    return fd
'''
CONTAINER_BRIDGE = CONTAINER_COMMON + inspect.getsource(pump) + r'''
stop=threading.Event()
signal.signal(signal.SIGTERM,lambda *_:stop.set())
signal.signal(signal.SIGINT,lambda *_:stop.set())
if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):
    raise SystemExit(69)
token=sys.argv[1]
folder,directory=owned_directory(token)
connection=None
record_created=False
try:
    # Cleanup creates this tombstone BEFORE looking for owner.json. If an exec
    # starts late (including after its Docker CLI was killed), it cannot connect.
    try: os.stat('cancelled',dir_fd=directory,follow_symlinks=False)
    except FileNotFoundError: pass
    else: raise SystemExit(0)
    fd=private_file(directory,'owner.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL)
    record_created=True
    with os.fdopen(fd,'w') as stream:
        json.dump({'pid':os.getpid(),'uid':10000,'token':token},stream)
    try: os.stat('cancelled',dir_fd=directory,follow_symlinks=False)
    except FileNotFoundError: pass
    else: raise SystemExit(0)
    connection=socket.create_connection(('127.0.0.1',2222),timeout=3)
    if stop.is_set(): raise SystemExit(0)
    try: os.stat('cancelled',dir_fd=directory,follow_symlinks=False)
    except FileNotFoundError: pass
    else: raise SystemExit(0)
    sys.stderr.write('OPENLXSSH_RELAY_READY '+str(os.getpid())+'\n')
    sys.stderr.flush()
    def socket_eof():
        try: connection.shutdown(socket.SHUT_WR)
        except OSError: pass
    def stdout_eof():
        try: os.close(1)
        except OSError: pass
    pump(0,1,connection.fileno(),connection.fileno(),socket_eof,stdout_eof,stop,
         idle_timeout=600,deadline=time.monotonic()+90000)
except Exception:
    raise SystemExit(70)
finally:
    if connection is not None: connection.close()
    if record_created:
        try: os.unlink('owner.json',dir_fd=directory)
        except FileNotFoundError: pass
    os.close(directory)
    # A cancelled marker is deliberately kept until the disposable service is
    # removed/restarted: deleting it could admit a not-yet-started Docker exec.
    try: os.rmdir(folder)
    except OSError: pass
'''
BRIDGE_SHA256 = hashlib.sha256(CONTAINER_BRIDGE.encode()).hexdigest()

# Open pidfd BEFORE examining /proc, then require the exact UID, argv shape,
# code SHA and token. TERM/wait/KILL/wait use only that fd, never a numeric PID.
CONTAINER_CLEANUP = CONTAINER_COMMON + r'''
token,expected_hash=sys.argv[1:]
if not re.fullmatch(r'[0-9a-f]{64}',expected_hash): raise SystemExit(64)
if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):
    raise SystemExit(69)
folder,directory=owned_directory(token)
try:
    fd=private_file(directory,'cancelled',os.O_WRONLY|os.O_CREAT)
    os.close(fd)
    try: fd=private_file(directory,'owner.json',os.O_RDONLY)
    except FileNotFoundError: raise SystemExit(0)
    with os.fdopen(fd,'rb') as stream:
        raw=stream.read(1025)
    if len(raw)>1024: raise SystemExit(65)
    data=json.loads(raw)
    if (data.get('token')!=token or data.get('uid')!=10000
            or type(data.get('pid')) is not int or data['pid']<=1):
        raise SystemExit(65)
    pid=data['pid']
    try: handle=os.pidfd_open(pid,0)
    except ProcessLookupError: raise SystemExit(0)
    try:
        poller=select.poll()
        poller.register(handle,select.POLLIN)
        if poller.poll(0): raise SystemExit(0)
        process=Path('/proc')/str(pid)
        try:
            with (process/'cmdline').open('rb') as stream: raw=stream.read(65537)
            args=raw.split(b'\0')
            uids=(process/'status').read_text().split('Uid:',1)[1].splitlines()[0].split()
        except FileNotFoundError: raise SystemExit(0)
        if (len(raw)>65536 or [int(uid) for uid in uids]!=[10000]*4 or len(args)!=6
                or args[:3]!=[b'/usr/bin/python3',b'-u',b'-c'] or args[4]!=token.encode()
                or args[5]!=b'' or hashlib.sha256(args[3]).hexdigest()!=expected_hash):
            raise SystemExit(65)
        try: signal.pidfd_send_signal(handle,signal.SIGTERM)
        except ProcessLookupError: raise SystemExit(0)
        if not poller.poll(750):
            try: signal.pidfd_send_signal(handle,signal.SIGKILL)
            except ProcessLookupError: pass
            if not poller.poll(1000): raise SystemExit(70)
    finally: os.close(handle)
finally: os.close(directory)
'''


@dataclass(frozen=True)
class FrozenDockerTarget:
    context: str
    endpoint: str
    container_id: str
    image_id: str
    project: str
    service: str
    fixture_label_value: str
    network_id: str
    host_port: int

    def __post_init__(self):
        import fixture
        root_policy = (self.service in ROOT_PORTS and self.host_port == ROOT_PORTS[self.service]
                       and self.fixture_label_value == 'env-fixture-a'
                       and re.fullmatch(r'openlxssh-fixture-[0-9a-f]{12}', self.project))
        mina_policy = (self.service == 'multiprompt' and self.host_port == 22225
                       and self.fixture_label_value == 'auth-mina-fixture-a'
                       and re.fullmatch(r'openlxssh-mina-[0-9a-f]{12}', self.project))
        if (self.context not in fixture.LOCAL_CONTEXTS or fixture.local_endpoint(self.endpoint) != self.endpoint
                or not re.fullmatch(r'[0-9a-f]{64}', self.container_id)
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', self.image_id)
                or not re.fullmatch(r'[0-9a-f]{64}', self.network_id)
                or type(self.host_port) is not int or not (root_policy or mina_policy)):
            raise RelayError('invalid frozen test target/policy')


def reap_owned(process):
    """Reap only this Popen child, with a finite TERM then KILL wait."""
    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=REAP_TIMEOUT / 2)
            except subprocess.TimeoutExpired:
                process.kill()
        process.wait(timeout=REAP_TIMEOUT / 2)
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def _bounded_stdout(command, environment, deadline, cancelled, limit=METADATA_LIMIT):
    """Bound non-wire CLI metadata, time and child lifetime; suppress stderr."""
    if cancelled.is_set() or time.monotonic() >= deadline:
        raise RelayError('metadata deadline/cancellation')
    process = subprocess.Popen(command, env=environment, cwd=str(ROOT), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    data = bytearray()
    try:
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while not cancelled.is_set() and time.monotonic() < deadline:
                if not selector.select(min(0.05, max(0, deadline - time.monotonic()))):
                    continue
                try:
                    chunk = os.read(process.stdout.fileno(), min(BUFFER_LIMIT, limit + 1 - len(data)))
                except (BlockingIOError, InterruptedError):
                    continue
                if not chunk:
                    remaining = max(0.001, deadline - time.monotonic())
                    if process.wait(timeout=remaining) != 0:
                        raise RelayError('metadata command refused')
                    return bytes(data)
                data.extend(chunk)
                if len(data) > limit:
                    raise RelayError('metadata size refused')
        raise RelayError('metadata deadline/cancellation')
    finally:
        reap_owned(process)


class DockerTarget:
    """Frozen local executable/endpoint/environment; no arbitrary exec command."""
    def __init__(self, target):
        import fixture
        self.target = target
        environment = fixture.docker_environment(target.context)
        # Context metadata is checked each time, but the daemon call uses the
        # exact Unix endpoint, so a context-file TOCTOU cannot redirect exec.
        environment.pop('DOCKER_CONTEXT', None)
        executable = shutil.which('docker', path=environment.get('PATH', os.defpath))
        if executable is None:
            raise RelayError('local Docker CLI unavailable')
        self.environment = MappingProxyType(environment)
        self.executable = str(Path(executable).resolve(strict=True))
        self.command = (self.executable, '--host', target.endpoint)

    def metadata(self, args, deadline, cancelled, context_only=False):
        command = [self.executable] if context_only else list(self.command)
        raw = _bounded_stdout(command + args, self.environment, deadline, cancelled)
        return json.loads(raw)

    def validate(self, deadline, cancelled):
        target = self.target
        # Desktop's container inspect itself takes ~3 seconds. Run the four
        # independent exact reads together, never reuse a startup snapshot.
        # Every worker has this same absolute deadline and reaps its own CLI;
        # the executor context joins all of them before returning/raising.
        requests = [(['context', 'inspect', target.context], True),
                    (['inspect', target.container_id], False),
                    (['image', 'inspect', target.image_id], False),
                    (['network', 'inspect', target.network_id], False)]
        with ThreadPoolExecutor(max_workers=4, thread_name_prefix='relay-metadata') as workers:
            pending = [workers.submit(self.metadata, args, deadline, cancelled, context_only=context_only)
                       for args, context_only in requests]
            context, objects, images, network_objects = [item.result() for item in pending]
        if (len(context) != 1 or context[0]['Name'] != target.context
                or context[0]['Endpoints']['docker']['Host'] != target.endpoint):
            raise RelayError('frozen context changed')
        if len(objects) != 1:
            raise RelayError('ambiguous frozen container')
        item = objects[0]
        labels = item['Config'].get('Labels') or {}
        host = item['HostConfig']
        import fixture
        try:
            if target.service in ROOT_PORTS:
                fixture.validate_capabilities(host, target.service)
            elif host.get('CapAdd') not in (None, []) or host.get('CapDrop') != ['ALL']:
                raise fixture.FixtureError('MINA must retain zero added capabilities')
        except fixture.FixtureError:
            raise RelayError('frozen service capability set differs') from None
        networks = item['NetworkSettings']['Networks']
        if (item['Id'] != target.container_id or item['Image'] != target.image_id
                or labels.get('com.docker.compose.project') != target.project
                or labels.get('com.docker.compose.service') != target.service
                or labels.get('org.openlxssh.fixture') != target.fixture_label_value
                or item['State']['Running'] is not True or item['State'].get('Health', {}).get('Status') != 'healthy'
                or host['ReadonlyRootfs'] is not True or host['Privileged'] is not False
                or host['NetworkMode'] in ('host', 'none') or host['LogConfig']['Type'] != 'none'
                or len(networks) != 1 or next(iter(networks.values()))['NetworkID'] != target.network_id
                or host['PortBindings'] != {'2222/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(target.host_port)}]}):
            raise RelayError('frozen service changed or unhealthy')
        if len(images) != 1:
            raise RelayError('ambiguous frozen image')
        image = images[0]
        if (image['Id'] != target.image_id or image['Architecture'] != 'arm64' or image['Os'] != 'linux'
                or image['Config']['Labels'].get('org.openlxssh.fixture') != target.fixture_label_value):
            raise RelayError('frozen image changed')
        if len(network_objects) != 1:
            raise RelayError('ambiguous frozen network')
        network = network_objects[0]
        if (network['Id'] != target.network_id or network['Internal'] is not True or network['Driver'] != 'bridge'
                or network['Labels'].get('com.docker.compose.project') != target.project
                or network['Labels'].get('org.openlxssh.fixture') != target.fixture_label_value
                or target.container_id not in network['Containers']):
            raise RelayError('frozen internal network changed')

    def spawn(self, token):
        return subprocess.Popen(list(self.command) + ['exec', '-i', '--user', '10000:10000',
                                self.target.container_id, '/usr/bin/python3', '-u', '-c', CONTAINER_BRIDGE, token],
                                env=self.environment, cwd=str(ROOT), stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)

    def cleanup(self, token):
        # Cancellation tombstone also refuses an exec which starts after this
        # cleanup. There is no process discovery, shell, name/group/PID signal.
        command = list(self.command) + ['exec', '--user', '10000:10000', self.target.container_id,
                                       '/usr/bin/python3', '-c', CONTAINER_CLEANUP, token, BRIDGE_SHA256]
        _bounded_stdout(command, self.environment, time.monotonic() + CLEANUP_TIMEOUT,
                        threading.Event(), limit=0)


def wait_ready(process, cancelled, deadline):
    os.set_blocking(process.stderr.fileno(), False)
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stderr, selectors.EVENT_READ)
        while time.monotonic() < deadline and not cancelled.is_set():
            if not selector.select(min(0.05, max(0, deadline - time.monotonic()))):
                continue
            try:
                chunk = os.read(process.stderr.fileno(), 128 - len(data))
            except (BlockingIOError, InterruptedError):
                continue
            if not chunk:
                return False
            data.extend(chunk)
            if len(data) >= 128:
                return False
            if b'\n' in data:
                return re.fullmatch(rb'OPENLXSSH_RELAY_READY [1-9][0-9]*\n', bytes(data)) is not None
    return False


class Admission:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.ports = {}

    def acquire(self, port):
        with self.lock:
            if self.total >= MAX_ACTIVE or self.ports.get(port, 0) >= MAX_PER_PORT:
                return False
            self.total += 1
            self.ports[port] = self.ports.get(port, 0) + 1
            return True

    def release(self, port):
        with self.lock:
            self.total -= 1
            self.ports[port] -= 1


def _listen_loopback(port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # No REUSEADDR/REUSEPORT, fallback port, wildcard address or IPv6 bind.
        listener.bind(('127.0.0.1', port))
        listener.listen(MAX_PER_PORT)
        listener.setblocking(False)
        return listener
    except BaseException:
        listener.close()
        raise


class RelayServer:
    def __init__(self, targets, max_duration=1800, backend_factory=DockerTarget, *, startup_deadline=None):
        if (not isinstance(max_duration, (int, float)) or not math.isfinite(max_duration)
                or not 0 < max_duration <= MAX_DURATION or not 1 <= len(targets) <= 5
                or any(not isinstance(target, FrozenDockerTarget) for target in targets)):
            raise RelayError('invalid finite relay duration/targets')
        if len({target.host_port for target in targets}) != len(targets):
            raise RelayError('duplicate test port')
        self.targets = tuple(targets)
        self.backends = {target.host_port: backend_factory(target) for target in targets}
        self.max_duration = max_duration
        self.startup_deadline = startup_deadline
        self.deadline = None
        self.cancelled = threading.Event()
        self.admission = Admission()
        self.listeners = []
        self.workers = []
        self.ready = threading.Event()
        self.counters = {'accepted': 0, 'rejected': 0, 'finished': 0, 'cleanup_failed': 0}
        self.lock = threading.Lock()

    def count(self, name):
        with self.lock:
            self.counters[name] += 1

    def connect(self, connection, port):
        backend = self.backends[port]
        process = None
        token = uuid.uuid4().hex  # not a credential; exact-owned cleanup identity
        try:
            deadline = min(self.deadline, time.monotonic() + START_TIMEOUT)
            backend.validate(deadline, self.cancelled)  # never adopt a replacement
            if self.cancelled.is_set() or time.monotonic() >= deadline:
                raise RelayError('connection startup cancelled/timed out')
            process = backend.spawn(token)
            if not wait_ready(process, self.cancelled, deadline):
                raise RelayError('connection startup refused')
            def close_input():
                process.stdin.close()
            def half_close_client():
                try: connection.shutdown(socket.SHUT_WR)
                except OSError: pass
            pump(connection.fileno(), connection.fileno(), process.stdout.fileno(), process.stdin.fileno(),
                 close_input, half_close_client, self.cancelled, deadline=self.deadline)
        except Exception:
            # Static counters only: exceptions may originate while carrying wire.
            self.count('rejected')
        finally:
            if process is not None:
                try:
                    # Successful exec exit proves the bridge's finally ran.
                    # Otherwise leave a cancellation tombstone before CLI reap.
                    try: clean_exit = process.wait(timeout=0.1) == 0
                    except subprocess.TimeoutExpired: clean_exit = False
                    if not clean_exit:
                        backend.cleanup(token)
                except Exception:
                    self.count('cleanup_failed')
                finally:
                    try: reap_owned(process)
                    except Exception: self.count('cleanup_failed')
            connection.close()
            self.admission.release(port)
            self.count('finished')

    def run(self):
        if (len({target.host_port for target in self.targets}) != len(self.targets)
                or any(not isinstance(target, FrozenDockerTarget) for target in self.targets)):
            raise RelayError('invalid frozen targets')
        for target in self.targets:
            target.__post_init__()
        self.deadline = time.monotonic() + self.max_duration
        try:
            startup = min(self.deadline, time.monotonic() + TARGET_START_TIMEOUT)
            if self.startup_deadline is not None:
                startup = min(startup, self.startup_deadline)
            # Startup has a separate finite all-target budget. Admission still
            # uses START_TIMEOUT per connection and always fetches fresh reads.
            for target in self.targets:
                self.backends[target.host_port].validate(startup, self.cancelled)
            for target in self.targets:
                if self.cancelled.is_set() or time.monotonic() >= startup:
                    raise RelayError('relay startup cancelled/timed out')
                self.listeners.append(_listen_loopback(target.host_port))
            with selectors.DefaultSelector() as selector:
                for target, listener in zip(self.targets, self.listeners):
                    selector.register(listener, selectors.EVENT_READ, target.host_port)
                self.ready.set()
                print(json.dumps({'event': 'relay-ready', 'test_transport_only': True,
                                  'pid': os.getpid(), 'ports': [t.host_port for t in self.targets],
                                  'max_duration': self.max_duration}), flush=True)
                while time.monotonic() < self.deadline and not self.cancelled.is_set():
                    for key, _events in selector.select(min(0.05, max(0, self.deadline - time.monotonic()))):
                        try: connection, _address = key.fileobj.accept()
                        except BlockingIOError: continue
                        port = key.data
                        if self.cancelled.is_set() or not self.admission.acquire(port):
                            connection.close()
                            self.count('rejected')
                            continue
                        self.count('accepted')
                        worker = threading.Thread(target=self.connect, args=(connection, port), daemon=False)
                        try: worker.start()
                        except BaseException:
                            connection.close()
                            self.admission.release(port)
                            raise
                        self.workers.append(worker)
                    self.workers = [worker for worker in self.workers if worker.is_alive()]
        finally:
            self.cancelled.set()
            for listener in self.listeners:
                listener.close()
            drain_deadline = time.monotonic() + SHUTDOWN_TIMEOUT
            for worker in self.workers:
                worker.join(timeout=max(0, drain_deadline - time.monotonic()))
            if any(worker.is_alive() for worker in self.workers):
                self.count('cleanup_failed')
            print(json.dumps({'event': 'relay-stopped', 'counters': self.counters}), flush=True)
            if self.counters['cleanup_failed']:
                raise RelayError('owned relay cleanup failed; inspect exact target metadata')


def serve(targets, max_duration=1800, *, startup_deadline=None):
    server = RelayServer(targets, max_duration, startup_deadline=startup_deadline)
    prior = {}
    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGINT, signal.SIGTERM):
            prior[signum] = signal.signal(signum, lambda *_args: server.cancelled.set())
    try:
        server.run()
    finally:
        for signum, handler in prior.items():
            signal.signal(signum, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    parser.error('no standalone relay action; use fixture.sh relay --authorized-run after review/authorization')


if __name__ == '__main__':
    main()
