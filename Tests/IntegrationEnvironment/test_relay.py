#!/usr/bin/env python3
"""Offline relay tests: socketpairs, ephemeral loopback, owned Python children.

Never Docker, SSH, credentials or ports 22221..22225. Linux pidfd behavior is
checked with /proc/pidfd fakes on this macOS host, not claimed live validation.
"""
import contextlib
from dataclasses import FrozenInstanceError, replace
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.dont_write_bytecode = True
import fixture
import relay

ROOT = Path(__file__).resolve().parent
NONWIRE_CHILD = r'''
import os,sys
sys.stderr.write('OPENLXSSH_RELAY_READY '+str(os.getpid())+'\n')
sys.stderr.flush()
while True:
    data=os.read(0,4096)
    if not data: break
    view=memoryview(data)
    while view:
        count=os.write(1,view[:71])
        view=view[count:]
'''


def target(service='keyonly'):
    return relay.FrozenDockerTarget('desktop-linux', 'unix:///tmp/openlxssh-static-docker.sock',
                                    'a' * 64, 'sha256:' + 'b' * 64,
                                    'openlxssh-fixture-012345abcdef', service, 'env-fixture-a',
                                    'c' * 64, relay.ROOT_PORTS[service])


def child(code, stdin=subprocess.PIPE):
    return subprocess.Popen([sys.executable, '-u', '-c', code], stdin=stdin,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)


def wait_until(check, seconds=3):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(0.005)
    return False


class ThreadResult:
    def __init__(self, function):
        self.result = None
        self.error = None
        def run():
            try: self.result = function()
            except BaseException as error: self.error = error
        self.thread = threading.Thread(target=run)
        self.thread.start()

    def join(self, case, timeout=4):
        self.thread.join(timeout)
        case.assertFalse(self.thread.is_alive(), 'owned test thread did not drain')
        if self.error is not None:
            raise self.error
        return self.result


class OfflineTests(unittest.TestCase):
    def setUp(self):
        # Any unintended Docker call fails, including code in fixture helpers.
        self.docker_guard = mock.patch.object(relay.shutil, 'which', return_value='/usr/bin/true')
        self.docker_guard.start()
        self.addCleanup(self.docker_guard.stop)

    def test_frozen_allowlist_and_library_mina_only(self):
        frozen = target()
        with self.assertRaises(FrozenInstanceError):
            frozen.host_port = 1
        mina = replace(frozen, project='openlxssh-mina-012345abcdef', service='multiprompt',
                       fixture_label_value='auth-mina-fixture-a', host_port=22225)
        self.assertEqual(mina.host_port, 22225)
        for changes in ({'host_port': 22225}, {'host_port': 22}, {'service': 'unknown'},
                        {'host_port': 22222}, {'project': 'some-other-project'},
                        {'project': 'openlxssh-mina-012345abcdef'}, {'fixture_label_value': 'other'},
                        {'container_id': 'a' * 12}, {'image_id': 'mutable:tag'}, {'network_id': 'x' * 64},
                        {'context': 'remote'}, {'endpoint': 'tcp://127.0.0.1:2375'}):
            with self.subTest(changes=changes), self.assertRaises((relay.RelayError, fixture.FixtureError)):
                replace(frozen, **changes)
        with self.assertRaises(relay.RelayError):
            replace(mina, host_port=22224)

    def test_cli_guards_duration_and_no_arbitrary_target(self):
        for args in (['relay'], ['relay', '--authorized-run', '--max-duration', '0'],
                     ['relay', '--authorized-run', '--max-duration', '90001'],
                     ['relay', '--authorized-run', '--service', 'keyonly'],
                     ['relay', '--authorized-run', '--host', '0.0.0.0'],
                     ['relay', '--authorized-run', '--target', 'arbitrary']):
            with self.subTest(args=args), mock.patch.object(sys, 'argv', ['fixture.py'] + args), \
                    mock.patch.object(sys, 'stderr', io.StringIO()), \
                    mock.patch.object(fixture, 'load_state', side_effect=AssertionError('state read')), \
                    mock.patch.object(fixture, 'docker_cli', side_effect=AssertionError('Docker called')):
                with self.assertRaises(SystemExit) as raised: fixture.main()
                self.assertEqual(raised.exception.code, 2)
        with mock.patch.object(sys, 'argv', ['relay.py', '--authorized-run']), \
                mock.patch.object(sys, 'stderr', io.StringIO()):
            with self.assertRaises(SystemExit) as raised: relay.main()
            self.assertEqual(raised.exception.code, 2)

    def root_objects(self):
        return [{'Id': str(index)*64, 'Image': target().image_id,
                 'Config': {'Labels': {'com.docker.compose.project': target().project,
                                      'com.docker.compose.service': service,
                                      'org.openlxssh.fixture': 'env-fixture-a'}},
                 'NetworkSettings': {'Networks': {'private': {'NetworkID': target().network_id}}}}
                for index, service in enumerate(fixture.SERVICES, 1)]

    def test_root_action_freezes_only_four_targets(self):
        objects = self.root_objects()
        identifiers = [item['Id'][:12] for item in objects]
        state = {'project': target().project}
        def resources(state, kind):
            return identifiers if kind == 'container' else ['owned-'+kind]
        with mock.patch.object(fixture, 'resources', side_effect=resources) as ownership, \
                mock.patch.object(fixture, 'container_id', side_effect=AssertionError('per-service rescan')), \
                mock.patch.object(fixture, 'docker', return_value=json.dumps(objects).encode()) as docker, \
                mock.patch.object(fixture, 'verify_image') as image, \
                mock.patch.object(fixture, 'VERIFIED_CONTEXT', target().context), \
                mock.patch.object(fixture, 'VERIFIED_ENDPOINT', target().endpoint), \
                mock.patch.object(relay, 'serve') as serve:
            fixture.relay(state, 123)
        self.assertEqual([call.args[1] for call in ownership.call_args_list], ['container', 'volume', 'network'])
        docker.assert_called_once_with(['inspect']+identifiers, capture=True)
        image.assert_called_once_with(state, target().image_id)
        frozen = serve.call_args.args[0]
        self.assertEqual([item.host_port for item in frozen], [22221, 22222, 22223, 22224])
        self.assertEqual([item.container_id for item in frozen], [item['Id'] for item in objects])
        self.assertEqual(serve.call_args.kwargs, {'max_duration': 123, 'startup_deadline': None})

    def test_root_batch_refuses_foreign_duplicate_missing_and_ambiguous_identity(self):
        import copy
        baseline = self.root_objects()
        for kind in ('duplicate-service', 'foreign-label', 'foreign-project', 'wrong-full-id',
                     'duplicate-id', 'missing-object', 'unlisted-service', 'extra-object'):
            objects = copy.deepcopy(baseline)
            if kind == 'duplicate-service':
                objects[1]['Config']['Labels']['com.docker.compose.service'] = fixture.SERVICES[0]
            elif kind == 'foreign-label': objects[0]['Config']['Labels']['org.openlxssh.fixture'] = 'other'
            elif kind == 'foreign-project': objects[0]['Config']['Labels']['com.docker.compose.project'] = 'other'
            elif kind == 'wrong-full-id': objects[0]['Id'] = 'f'*64
            elif kind == 'duplicate-id': objects[1]['Id'] = objects[0]['Id']
            elif kind == 'missing-object': objects.pop()
            elif kind == 'extra-object': objects.append(copy.deepcopy(objects[0]))
            elif kind == 'unlisted-service': objects[0]['Config']['Labels']['com.docker.compose.service'] = 'foreign'
            identifiers = [item['Id'][:12] for item in baseline]
            with self.subTest(kind=kind), \
                    mock.patch.object(fixture, 'resources', side_effect=lambda state, resource: identifiers if resource=='container' else []), \
                    mock.patch.object(fixture, 'docker', return_value=json.dumps(objects).encode()), \
                    mock.patch.object(fixture, 'verify_image'), mock.patch.object(relay, 'serve') as serve:
                with self.assertRaises(fixture.FixtureError): fixture.relay({'project': target().project}, 123)
                serve.assert_not_called()

    def test_relay_preflight_bounded_before_context_and_restores_shared_helpers(self):
        original = fixture.docker_cli
        shared = [fixture.require_local_engine, fixture.require_local_builder, fixture.docker_environment, fixture.local_endpoint]
        began = time.monotonic()
        calls = []
        def metadata(command, environment, deadline, cancelled):
            calls.append((command, environment, deadline, cancelled))
            if command[-2:] == ['context', 'show']: return b'desktop-linux\n'
            return json.dumps([{'Name': target().context, 'Endpoints': {'docker': {'Host': target().endpoint}}}]).encode()
        with mock.patch.object(fixture, 'load_state', return_value={'project': target().project}), \
                mock.patch.object(relay, '_bounded_stdout', side_effect=metadata), \
                mock.patch.object(fixture, 'relay') as run, mock.patch.dict(os.environ, {}, clear=True):
            fixture.run_relay(480)
        self.assertIs(fixture.docker_cli, original)
        self.assertEqual([fixture.require_local_engine, fixture.require_local_builder, fixture.docker_environment, fixture.local_endpoint], shared)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][2], calls[1][2])
        self.assertGreaterEqual(calls[0][2], began+relay.PREFLIGHT_TIMEOUT)
        self.assertEqual(run.call_args.kwargs['startup_deadline'], calls[0][2])
        with mock.patch.object(fixture, 'load_state', return_value={'project': target().project}), \
                mock.patch.object(relay, '_bounded_stdout', side_effect=relay.RelayError('expired')), \
                mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(fixture.FixtureError): fixture.run_relay(480)
        self.assertIs(fixture.docker_cli, original)
        # The installed preflight handler cancels the next metadata read rather
        # than waiting through unbounded initial discovery or spawning a CLI.
        def cancel_on_load():
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            return {'project': target().project}
        def refuse_cancelled(command, env, deadline, cancellation):
            self.assertTrue(cancellation.is_set())
            raise relay.RelayError('cancelled')
        with mock.patch.object(fixture, 'load_state', side_effect=cancel_on_load), \
                mock.patch.object(relay, '_bounded_stdout', side_effect=refuse_cancelled), \
                mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(fixture.FixtureError): fixture.run_relay(480)
        self.assertIs(fixture.docker_cli, original)

    def test_frozen_environment_and_explicit_endpoint_have_one_route(self):
        env = {'PATH': '/usr/bin', 'DOCKER_CONTEXT': 'remote', 'DOCKER_HOST': 'ssh://forbidden',
               'DOCKER_TLS_VERIFY': '1', 'DOCKER_CONFIG': '/unreviewed', 'BUILDX_BUILDER': 'remote',
               'COMPOSE_FILE': '/unreviewed', 'BUILDKIT_HOST': 'tcp://forbidden'}
        with mock.patch.dict(os.environ, env, clear=True):
            backend = relay.DockerTarget(target())
        with mock.patch.dict(os.environ, {'DOCKER_HOST': 'ssh://changed', 'PATH': '/changed'}, clear=True), \
                mock.patch.object(relay.subprocess, 'Popen') as popen:
            backend.spawn('d' * 32)
        call = popen.call_args
        self.assertEqual(call.args[0][:3], ['/usr/bin/true', '--host', target().endpoint])
        self.assertNotIn('--context', call.args[0])
        self.assertEqual(call.args[0][3:8], ['exec', '-i', '--user', '10000:10000', target().container_id])
        self.assertEqual(call.args[0][8:], ['/usr/bin/python3', '-u', '-c', relay.CONTAINER_BRIDGE, 'd' * 32])
        for key in call.kwargs['env']:
            self.assertFalse(key.startswith('DOCKER_'))
        self.assertEqual(call.kwargs['env']['PATH'], '/usr/bin')
        with self.assertRaises(TypeError): backend.environment['DOCKER_HOST'] = 'bad'
        with mock.patch.object(relay, '_bounded_stdout', return_value=b'[]') as run:
            backend.metadata(['context', 'inspect', target().context], time.monotonic()+1,
                             threading.Event(), context_only=True)
        self.assertEqual(run.call_args.args[0], ['/usr/bin/true', 'context', 'inspect', target().context])

    def metadata_objects(self):
        frozen = target()
        return {
            'context': [{'Name': frozen.context, 'Endpoints': {'docker': {'Host': frozen.endpoint}}}],
            'container': [{'Id': frozen.container_id, 'Image': frozen.image_id,
                           'Config': {'Labels': {'com.docker.compose.project': frozen.project,
                                     'com.docker.compose.service': frozen.service,
                                     'org.openlxssh.fixture': frozen.fixture_label_value}},
                           'HostConfig': {'ReadonlyRootfs': True, 'Privileged': False, 'NetworkMode': 'private',
                                          'CapAdd': ['CAP_' + name for name in
                                              ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETUID', 'SETGID',
                                               'SYS_CHROOT', 'KILL', 'AUDIT_WRITE')], 'CapDrop': ['ALL'],
                                          'LogConfig': {'Type': 'none'},
                                          'PortBindings': {'2222/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '22221'}]}},
                           'State': {'Running': True, 'Health': {'Status': 'healthy'}},
                           'NetworkSettings': {'Networks': {'private': {'NetworkID': frozen.network_id}}}}],
            'image': [{'Id': frozen.image_id, 'Architecture': 'arm64', 'Os': 'linux',
                       'Config': {'Labels': {'org.openlxssh.fixture': frozen.fixture_label_value}}}],
            'network': [{'Id': frozen.network_id, 'Internal': True, 'Driver': 'bridge',
                         'Labels': {'com.docker.compose.project': frozen.project,
                                    'org.openlxssh.fixture': frozen.fixture_label_value},
                         'Containers': {frozen.container_id: {}}}],
        }

    def validate_objects(self, objects):
        backend = relay.DockerTarget(target())
        def metadata(args, *_args, **_kwargs):
            key = 'container' if args[0] == 'inspect' else args[0]
            return objects[key]
        with mock.patch.object(backend, 'metadata', side_effect=metadata):
            backend.validate(time.monotonic()+1, threading.Event())

    def test_every_metadata_identity_health_and_internal_boundary_fails_closed(self):
        import copy
        baseline = self.metadata_objects()
        self.validate_objects(baseline)
        changes = [
            ('context', ('Name',), 'default'),
            ('context', ('Endpoints', 'docker', 'Host'), 'unix:///tmp/changed.sock'),
            ('container', ('Id',), 'd'*64), ('container', ('Image',), 'sha256:'+'d'*64),
            ('container', ('Config', 'Labels', 'com.docker.compose.project'), 'other'),
            ('container', ('Config', 'Labels', 'com.docker.compose.service'), 'passwordonly'),
            ('container', ('Config', 'Labels', 'org.openlxssh.fixture'), 'other'),
            ('container', ('State', 'Running'), False),
            ('container', ('State', 'Health', 'Status'), 'unhealthy'),
            ('container', ('HostConfig', 'ReadonlyRootfs'), False),
            ('container', ('HostConfig', 'Privileged'), True),
            ('container', ('HostConfig', 'NetworkMode'), 'host'),
            ('container', ('HostConfig', 'LogConfig', 'Type'), 'json-file'),
            ('container', ('HostConfig', 'PortBindings'), {'2222/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '22221'}]}),
            ('container', ('NetworkSettings', 'Networks'), {}),
            ('container', ('NetworkSettings', 'Networks', 'private', 'NetworkID'), 'd'*64),
            ('image', ('Id',), 'sha256:'+'d'*64), ('image', ('Architecture',), 'amd64'),
            ('image', ('Config', 'Labels', 'org.openlxssh.fixture'), 'other'),
            ('network', ('Id',), 'd'*64), ('network', ('Internal',), False),
            ('network', ('Driver',), 'host'), ('network', ('Containers',), {}),
            ('network', ('Labels', 'com.docker.compose.project'), 'other'),
            ('network', ('Labels', 'org.openlxssh.fixture'), 'other'),
        ]
        for kind, path, value in changes:
            objects = copy.deepcopy(baseline)
            node = objects[kind][0]
            for part in path[:-1]: node = node[part]
            node[path[-1]] = value
            with self.subTest(kind=kind, field=path), self.assertRaises(relay.RelayError):
                self.validate_objects(objects)

    def test_exact_service_capabilities_reject_missing_extra_and_foreign_privilege(self):
        import copy
        original = target
        for service in fixture.SERVICES:
            frozen = original(service)
            objects = self.metadata_objects()
            item = objects['container'][0]
            item['Config']['Labels']['com.docker.compose.service'] = service
            item['HostConfig']['PortBindings']['2222/tcp'][0]['HostPort'] = str(frozen.host_port)
            if service != 'keyonly': item['HostConfig']['CapAdd'].remove('CAP_AUDIT_WRITE')
            with self.subTest(service=service), mock.patch(__name__ + '.target', return_value=frozen):
                self.validate_objects(objects)
                for capability in list(item['HostConfig']['CapAdd']):
                    invalid = copy.deepcopy(objects)
                    invalid['container'][0]['HostConfig']['CapAdd'].remove(capability)
                    with self.subTest(missing=capability), self.assertRaises(relay.RelayError):
                        self.validate_objects(invalid)
                for extra in ('AUDIT_CONTROL', 'AUDIT_READ', 'SYS_ADMIN', 'NET_ADMIN', 'SYS_TTY_CONFIG',
                              'CHOWN', 'AUDIT_WRITE'):
                    invalid = copy.deepcopy(objects)
                    invalid['container'][0]['HostConfig']['CapAdd'].append('CAP_' + extra)
                    with self.subTest(extra=extra), self.assertRaises(relay.RelayError):
                        self.validate_objects(invalid)
                for drop in ([], ['CHOWN'], ['ALL', 'NET_ADMIN']):
                    invalid = copy.deepcopy(objects)
                    invalid['container'][0]['HostConfig']['CapDrop'] = drop
                    with self.subTest(drop=drop), self.assertRaises(relay.RelayError):
                        self.validate_objects(invalid)
                # Both Docker spellings are accepted, never a capability subset.
                plain = copy.deepcopy(objects)
                plain['container'][0]['HostConfig']['CapAdd'] = [value[4:] for value in item['HostConfig']['CapAdd']]
                self.validate_objects(plain)
        mina = replace(original(), project='openlxssh-mina-012345abcdef', service='multiprompt',
                       fixture_label_value='auth-mina-fixture-a', host_port=22225)
        objects = self.metadata_objects()
        objects['container'][0]['Config']['Labels'].update({'com.docker.compose.project': mina.project,
            'com.docker.compose.service': mina.service, 'org.openlxssh.fixture': mina.fixture_label_value})
        objects['container'][0]['HostConfig']['CapAdd'] = None
        objects['container'][0]['HostConfig']['PortBindings']['2222/tcp'][0]['HostPort'] = '22225'
        objects['image'][0]['Config']['Labels']['org.openlxssh.fixture'] = mina.fixture_label_value
        objects['network'][0]['Labels'].update({'com.docker.compose.project': mina.project,
                                               'org.openlxssh.fixture': mina.fixture_label_value})
        with mock.patch(__name__ + '.target', return_value=mina):
            self.validate_objects(objects)
            objects['container'][0]['HostConfig']['CapAdd'] = ['CAP_AUDIT_WRITE']
            with self.assertRaises(relay.RelayError): self.validate_objects(objects)

    def test_parallel_metadata_is_fresh_same_deadline_and_joins_failures(self):
        objects = self.metadata_objects()
        backend = relay.DockerTarget(target())
        deadline = time.monotonic()+1
        barrier = threading.Barrier(4)
        seen = []
        def metadata(args, actual_deadline, cancelled, **_kwargs):
            self.assertEqual(actual_deadline, deadline)
            barrier.wait(timeout=0.5)  # sequential old implementation cannot pass
            key = 'container' if args[0]=='inspect' else args[0]
            seen.append(key)
            return objects[key]
        with mock.patch.object(backend, 'metadata', side_effect=metadata):
            backend.validate(deadline, threading.Event())
            # A second admission must fetch everything again, not use cache.
            objects['container'][0]['Config']['Labels']['org.openlxssh.fixture'] = 'foreign'
            with self.assertRaises(relay.RelayError): backend.validate(deadline, threading.Event())
        self.assertEqual(sorted(seen), sorted(['context','container','image','network']*2))
        barrier = threading.Barrier(4)
        finished = []
        def failed(args, actual_deadline, cancelled, **_kwargs):
            barrier.wait(timeout=0.5)
            if args[0]=='context': raise relay.RelayError('metadata refused')
            time.sleep(0.02)
            finished.append(args[0])
            return []
        with mock.patch.object(backend, 'metadata', side_effect=failed):
            with self.assertRaises(relay.RelayError): backend.validate(deadline, threading.Event())
        self.assertEqual(sorted(finished), ['image','inspect','network'])

    def test_parallel_metadata_owned_children_timeout_and_all_reaped(self):
        backend = relay.DockerTarget(target())
        processes = []
        lock = threading.Lock()
        real_popen = subprocess.Popen
        def spawn(*_args, **_kwargs):
            process = real_popen([sys.executable,'-u','-c','import time; time.sleep(30)'],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, bufsize=0)
            with lock: processes.append(process)
            return process
        started = time.monotonic()
        with mock.patch.object(relay.subprocess, 'Popen', side_effect=spawn):
            with self.assertRaises(relay.RelayError):
                backend.validate(time.monotonic()+0.08, threading.Event())
        self.assertEqual(len(processes), 4)
        self.assertLess(time.monotonic()-started, 2)
        for process in processes:
            self.assertIsNotNone(process.poll())
            with self.assertRaises(ChildProcessError): os.waitpid(process.pid, os.WNOHANG)

    def test_multitarget_startup_has_separate_bounded_budget(self):
        fake = self.fake_backend()
        targets = [replace(target(service), container_id=str(index)*64)
                   for index,service in enumerate(fixture.SERVICES,1)]
        server = relay.RelayServer(targets, max_duration=100, backend_factory=fake,
                                   startup_deadline=time.monotonic()+relay.PREFLIGHT_TIMEOUT)
        budgets = []
        def validate(deadline, cancelled):
            budgets.append(deadline-time.monotonic())
        for backend in server.backends.values(): backend.validate = validate
        # Stop at the first bind without touching any actual fixture port.
        with mock.patch.object(relay, '_listen_loopback', side_effect=OSError('test stop')), \
                mock.patch('sys.stdout', io.StringIO()):
            with self.assertRaises(OSError): server.run()
        self.assertEqual(len(budgets), 4)
        self.assertGreater(min(budgets), relay.START_TIMEOUT)
        self.assertLessEqual(max(budgets), relay.TARGET_START_TIMEOUT)
        server = relay.RelayServer(targets, max_duration=100, backend_factory=fake,
                                   startup_deadline=time.monotonic()-1)
        with mock.patch.object(relay, '_listen_loopback', side_effect=AssertionError('bind after deadline')), \
                mock.patch('sys.stdout', io.StringIO()):
            with self.assertRaises(relay.RelayError): server.run()

    def test_pump_large_duplex_partial_writes_and_eof_final_response(self):
        left, middle_left = socket.socketpair()
        middle_right, right = socket.socketpair()
        sockets = (left, middle_left, middle_right, right)
        for item in sockets:
            item.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2048)
            self.addCleanup(item.close)
        left.settimeout(3)
        right.settimeout(3)
        cancelled = threading.Event()
        self.addCleanup(cancelled.set)
        # Non-secret generated bytes only; no payload output or file snapshot.
        outgoing = bytes(range(256)) * 4096
        response = b'finite-non-ssh-response\0' * 19000
        original_write = os.write
        lengths = []
        def short_write(fd, data):
            lengths.append(len(data))
            return original_write(fd, data[:173])
        worker = ThreadResult(lambda: relay.pump(middle_left.fileno(), middle_left.fileno(),
                              middle_right.fileno(), middle_right.fileno(),
                              lambda: middle_right.shutdown(socket.SHUT_WR),
                              lambda: middle_left.shutdown(socket.SHUT_WR), cancelled, idle_timeout=3))
        def server():
            received = bytearray()
            time.sleep(0.03)  # fill relay buffers/backpressure before reading
            while True:
                data = right.recv(997)
                if not data: break
                received.extend(data)
            self.assertEqual(hashlib.sha256(received).digest(), hashlib.sha256(outgoing).digest())
            right.sendall(response)  # final bytes are sent only AFTER input EOF
            right.shutdown(socket.SHUT_WR)
        remote = ThreadResult(server)
        with mock.patch.object(relay.os, 'write', side_effect=short_write):
            left.sendall(outgoing)
            left.shutdown(socket.SHUT_WR)
            received = bytearray()
            while True:
                data = left.recv(811)
                if not data: break
                received.extend(data)
            self.assertEqual(hashlib.sha256(received).digest(), hashlib.sha256(response).digest())
            remote.join(self)
            self.assertEqual(worker.join(self), 'complete')
        self.assertTrue(lengths)
        self.assertLessEqual(max(lengths), relay.BUFFER_LIMIT)

    def test_pump_simultaneous_duplex_idle_cancel_and_deadline(self):
        for ending in ('idle-timeout', 'cancelled', 'duration-timeout'):
            left, a = socket.socketpair()
            b, right = socket.socketpair()
            with contextlib.ExitStack() as stack:
                for item in (left, a, b, right): stack.callback(item.close)
                cancelled = threading.Event()
                if ending == 'cancelled': cancelled.set()
                result = relay.pump(a.fileno(), a.fileno(), b.fileno(), b.fileno(),
                                    lambda: None, lambda: None, cancelled, idle_timeout=0.03,
                                    deadline=time.monotonic()-1 if ending == 'duration-timeout' else None)
                self.assertEqual(result, ending)
        left, a = socket.socketpair()
        b, right = socket.socketpair()
        for item in (left, a, b, right): self.addCleanup(item.close)
        cancelled = threading.Event()
        self.addCleanup(cancelled.set)
        worker = ThreadResult(lambda: relay.pump(a.fileno(), a.fileno(), b.fileno(), b.fileno(),
                              lambda: b.shutdown(socket.SHUT_WR), lambda: a.shutdown(socket.SHUT_WR),
                              cancelled, idle_timeout=2))
        first, second = b'left-non-ssh' * 10000, b'right-non-ssh' * 10000
        def exchange(endpoint, send, expected):
            endpoint.settimeout(2)
            sender = ThreadResult(lambda: (endpoint.sendall(send), endpoint.shutdown(socket.SHUT_WR)))
            result = bytearray()
            while True:
                data = endpoint.recv(4096)
                if not data: break
                result.extend(data)
            sender.join(self)
            self.assertEqual(hashlib.sha256(result).digest(), hashlib.sha256(expected).digest())
        left_side = ThreadResult(lambda: exchange(left, first, second))
        right_side = ThreadResult(lambda: exchange(right, second, first))
        left_side.join(self)
        right_side.join(self)
        self.assertEqual(worker.join(self), 'complete')

    def test_backpressure_bounds_when_both_peers_do_not_read(self):
        left, a = socket.socketpair()
        b, right = socket.socketpair()
        for item in (left, a, b, right):
            item.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
            self.addCleanup(item.close)
        cancelled = threading.Event()
        self.addCleanup(cancelled.set)
        reads = []
        original_read = os.read
        def tracked_read(fd, size):
            result = original_read(fd, size)
            reads.append((fd, len(result)))
            return result
        worker = ThreadResult(lambda: relay.pump(a.fileno(), a.fileno(), b.fileno(), b.fileno(),
                              lambda: None, lambda: None, cancelled, idle_timeout=1))
        with mock.patch.object(relay.os, 'read', side_effect=tracked_read):
            left.setblocking(False)
            right.setblocking(False)
            for _ in range(100):
                for item in (left, right):
                    try: item.send(b'x'*65536)
                    except BlockingIOError: pass
                time.sleep(0.001)
            before = len(reads)
            time.sleep(0.05)
            self.assertEqual(len(reads), before, 'backpressure should stop reads at buffer limit')
            for fd in (a.fileno(), b.fileno()):
                total = sum(size for read_fd, size in reads if read_fd == fd)
                self.assertLessEqual(total, relay.BUFFER_LIMIT + 8192)
            cancelled.set()
            self.assertEqual(worker.join(self), 'cancelled')

    def test_read_error_and_write_error_are_static_results(self):
        left, a = socket.socketpair()
        b, right = socket.socketpair()
        for item in (left, a, b, right): self.addCleanup(item.close)
        left.sendall(b'non-ssh')
        with mock.patch.object(relay.os, 'read', side_effect=OSError('not printed')):
            self.assertEqual(relay.pump(a.fileno(), a.fileno(), b.fileno(), b.fileno(),
                                       lambda: None, lambda: None, threading.Event()), 'read-error')
        with mock.patch.object(relay.os, 'write', side_effect=OSError('not printed')):
            self.assertEqual(relay.pump(a.fileno(), a.fileno(), b.fileno(), b.fileno(),
                                       lambda: None, lambda: None, threading.Event()), 'write-error')

    def test_admission_exact_per_port_and_total_limits(self):
        admission = relay.Admission()
        for _ in range(8): self.assertTrue(admission.acquire(22221))
        self.assertFalse(admission.acquire(22221))
        for _ in range(8): self.assertTrue(admission.acquire(22222))
        self.assertFalse(admission.acquire(22223))
        admission.release(22221)
        self.assertTrue(admission.acquire(22223))
        self.assertEqual(admission.total, 16)
        self.assertEqual(admission.ports[22221], 7)

    def test_loopback_ephemeral_collision_no_reuse(self):
        listener = relay._listen_loopback(0)
        self.addCleanup(listener.close)
        self.assertEqual(listener.getsockname()[0], '127.0.0.1')
        port = listener.getsockname()[1]
        self.assertNotIn(port, range(22221, 22226))
        self.assertEqual(listener.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR), 0)
        self.assertEqual(listener.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT), 0)
        with self.assertRaises(OSError): relay._listen_loopback(port)

    def test_wait_ready_own_child_good_bad_oversize_timeout_cancel(self):
        for code, expected in ((NONWIRE_CHILD, True),
                               ("import os; os.write(2,b'not-ready\\n')", False),
                               ("import os; os.write(2,b'x'*256)", False),
                               ("import time; time.sleep(30)", False)):
            process = child(code)
            try:
                self.assertEqual(relay.wait_ready(process, threading.Event(), time.monotonic()+0.15), expected)
            finally: relay.reap_owned(process)
            self.assertIsNotNone(process.poll())
        process = child(NONWIRE_CHILD)
        stop = threading.Event()
        stop.set()
        try: self.assertFalse(relay.wait_ready(process, stop, time.monotonic()+1))
        finally: relay.reap_owned(process)

    def test_reap_own_child_term_ignored_kill_and_no_unrelated_signal(self):
        process = child("import signal,time,os; signal.signal(signal.SIGTERM,signal.SIG_IGN); os.write(2,b'R'); time.sleep(30)")
        other = child('import time; time.sleep(30)')
        try:
            self.assertEqual(process.stderr.read(1), b'R')
            start = time.monotonic()
            relay.reap_owned(process)
            self.assertEqual(process.returncode, -signal.SIGKILL)
            self.assertLess(time.monotonic()-start, 2)
            self.assertIsNone(other.poll())
            with self.assertRaises(ChildProcessError): os.waitpid(process.pid, os.WNOHANG)
        finally:
            relay.reap_owned(process)
            relay.reap_owned(other)

    def test_bounded_metadata_children_size_deadline_cancel_and_reap(self):
        env = dict(os.environ)
        for code, limit, timeout in (("import os; os.write(1,b'x'*1000000)", 32, 1),
                                     ('import time; time.sleep(30)', 32, 0.05),
                                     ('raise SystemExit(1)', 32, 1)):
            with self.subTest(limit=limit, timeout=timeout):
                start = time.monotonic()
                with self.assertRaises(relay.RelayError):
                    relay._bounded_stdout([sys.executable, '-u', '-c', code], env,
                                          time.monotonic()+timeout, threading.Event(), limit=limit)
                self.assertLess(time.monotonic()-start, 2)
        self.assertEqual(relay._bounded_stdout([sys.executable, '-c', "print('[]')"], env,
                         time.monotonic()+1, threading.Event()), b'[]\n')
        cancelled = threading.Event()
        cancelled.set()
        with mock.patch.object(relay.subprocess, 'Popen', side_effect=AssertionError('spawn after cancellation')):
            with self.assertRaises(relay.RelayError):
                relay._bounded_stdout(['never'], env, time.monotonic()+1, cancelled)

    def fake_backend(self, reject=False, hang=False, cleanup_failure=False):
        case = self
        class Backend:
            def __init__(self, frozen):
                self.frozen = frozen
                self.validations = 0
                self.processes = []
                self.tokens = []
                self.cleanups = []
            def validate(self, deadline, cancelled):
                self.validations += 1
                if reject and self.validations > 1: raise relay.RelayError('metadata changed')
                if cancelled.is_set() or time.monotonic() >= deadline: raise relay.RelayError('expired')
            def spawn(self, token):
                case.assertRegex(token, r'^[0-9a-f]{32}$')
                self.tokens.append(token)
                code = ("import os,time; os.write(2,b'OPENLXSSH_RELAY_READY 123\\n'); time.sleep(30)"
                        if hang else NONWIRE_CHILD)
                process = child(code)
                self.processes.append(process)
                return process
            def cleanup(self, token):
                self.cleanups.append(token)
                if cleanup_failure: raise relay.RelayError('nonsecret test failure')
        return Backend

    def run_server(self, **kwargs):
        server = relay.RelayServer([target()], backend_factory=self.fake_backend(**kwargs), max_duration=0.45)
        listener = relay._listen_loopback(0)  # only ephemeral, never fixture ports
        self.addCleanup(listener.close)
        actual = listener.getsockname()
        patcher = mock.patch.object(relay, '_listen_loopback', return_value=listener)
        patcher.start()
        self.addCleanup(patcher.stop)
        runner = ThreadResult(server.run)
        self.addCleanup(server.cancelled.set)
        self.assertTrue(server.ready.wait(1))
        return server, actual, runner

    def test_server_own_child_full_bytes_halfclose_clean_exit(self):
        with mock.patch('sys.stdout', io.StringIO()) as output:
            server, address, runner = self.run_server()
            client = socket.create_connection(address, timeout=1)
            with client:
                payload = b'non-ssh-opaque\0' * 10000
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
                result = bytearray()
                while True:
                    data = client.recv(8192)
                    if not data: break
                    result.extend(data)
                self.assertEqual(hashlib.sha256(result).digest(), hashlib.sha256(payload).digest())
            runner.join(self)
            backend = server.backends[22221]
            self.assertEqual(backend.validations, 2)
            self.assertEqual(backend.cleanups, [])
            self.assertEqual(server.counters, {'accepted': 1, 'rejected': 0, 'finished': 1, 'cleanup_failed': 0})
            self.assertEqual(backend.processes[0].returncode, 0)
            self.assertNotIn('non-ssh-opaque', output.getvalue())
            self.assertEqual(server.admission.total, 0)
            self.assertEqual(server.listeners[0].fileno(), -1)

    def test_server_revalidates_every_admission_before_spawn(self):
        with mock.patch('sys.stdout', io.StringIO()):
            server, address, runner = self.run_server(reject=True)
            with socket.create_connection(address, timeout=1) as client:
                self.assertEqual(client.recv(1), b'')
            runner.join(self)
        backend = server.backends[22221]
        self.assertEqual(backend.validations, 2)
        self.assertEqual(backend.processes, [])
        self.assertEqual(server.counters['rejected'], 1)

    def test_server_finite_stop_cleans_hung_owned_child_and_listener(self):
        with mock.patch('sys.stdout', io.StringIO()):
            server, address, runner = self.run_server(hang=True)
            with socket.create_connection(address, timeout=1):
                self.assertTrue(wait_until(lambda: server.backends[22221].processes))
                self.assertIsNone(runner.join(self))
        backend = server.backends[22221]
        self.assertEqual(backend.cleanups, backend.tokens)
        self.assertEqual(len(backend.cleanups), 1)
        self.assertIsNotNone(backend.processes[0].poll())
        self.assertEqual(server.admission.total, 0)
        self.assertEqual(server.listeners[0].fileno(), -1)

    def test_server_cleanup_failure_still_reaps_cli_and_fails_closed(self):
        with mock.patch('sys.stdout', io.StringIO()):
            server, address, runner = self.run_server(hang=True, cleanup_failure=True)
            with socket.create_connection(address, timeout=1):
                self.assertTrue(wait_until(lambda: server.backends[22221].processes))
                with self.assertRaises(relay.RelayError): runner.join(self)
        self.assertEqual(server.counters['cleanup_failed'], 1)
        self.assertIsNotNone(server.backends[22221].processes[0].poll())

    def test_partial_init_bind_failure_closes_all_prior_listeners(self):
        server = relay.RelayServer([target(), target('passwordonly')], backend_factory=self.fake_backend())
        listener = relay._listen_loopback(0)
        with mock.patch.object(relay, '_listen_loopback', side_effect=[listener, OSError('collision')]), \
                mock.patch('sys.stdout', io.StringIO()):
            with self.assertRaises(OSError): server.run()
        self.assertEqual(listener.fileno(), -1)
        self.assertFalse(server.ready.is_set())
        self.assertTrue(server.cancelled.is_set())
        for duration in (0, -1, 90001, float('inf'), float('nan')):
            with self.assertRaises(relay.RelayError):
                relay.RelayServer([target()], max_duration=duration, backend_factory=self.fake_backend())

    def test_container_program_compiles_and_has_exact_no_shell_wire_contract(self):
        compile(relay.CONTAINER_BRIDGE, '<fixed-container-bridge>', 'exec')
        compile(relay.CONTAINER_CLEANUP, '<fixed-container-cleanup>', 'exec')
        self.assertEqual(hashlib.sha256(relay.CONTAINER_BRIDGE.encode()).hexdigest(), relay.BRIDGE_SHA256)
        for value in (relay.CONTAINER_BRIDGE, relay.CONTAINER_CLEANUP):
            for forbidden in ('subprocess', 'shell=True', 'logging', 'pty.', 'print(', 'os.kill('):
                self.assertNotIn(forbidden, value)
        self.assertIn("socket.create_connection(('127.0.0.1',2222),timeout=3)", relay.CONTAINER_BRIDGE)
        self.assertIn('def pump(', relay.CONTAINER_BRIDGE)
        self.assertIn('pidfd_open', relay.CONTAINER_CLEANUP)
        self.assertIn('pidfd_send_signal', relay.CONTAINER_CLEANUP)
        backend = relay.DockerTarget(target())
        with mock.patch.object(relay, '_bounded_stdout', return_value=b'') as run:
            backend.cleanup('d'*32)
        args = run.call_args.args[0]
        self.assertEqual(args[:3], ['/usr/bin/true', '--host', target().endpoint])
        self.assertEqual(args[3:8], ['exec', '--user', '10000:10000', target().container_id, '/usr/bin/python3'])
        self.assertEqual(args[8:], ['-c', relay.CONTAINER_CLEANUP, 'd'*32, relay.BRIDGE_SHA256])
        self.assertEqual(run.call_args.kwargs, {'limit': 0})

    def test_exact_container_bridge_in_owned_child_and_late_exec_tombstone(self):
        # Execute the exact fixed bridge, replacing only container UID/path and
        # its fixed connect with an inherited socketpair; no SSH/listener.
        setup = r'''
import os,signal,socket,sys,types
root,code,token,transport=sys.argv[1:]
real_open=os.open
real_fstat=os.fstat
real_mkdir=os.mkdir
os.getuid=lambda:10000
os.mkdir=lambda name,mode:real_mkdir(root+'/connection',mode)
def openfd(name,flags,mode=0o777,dir_fd=None):
    if str(name).startswith('/tmp/'): name=root+'/connection'
    return real_open(name,flags,mode,dir_fd=dir_fd)
os.open=openfd
def fstat(fd):
    info=real_fstat(fd)
    return types.SimpleNamespace(st_mode=info.st_mode,st_uid=10000,st_nlink=info.st_nlink)
os.fstat=fstat
real_rmdir=os.rmdir
os.rmdir=lambda name:real_rmdir(root+'/connection')
os.pidfd_open=lambda *_:None
signal.pidfd_send_signal=lambda *_:None
def connect(address,timeout):
    assert address==('127.0.0.1',2222) and timeout==3
    return socket.socket(fileno=int(transport))
socket.create_connection=connect
sys.argv=['-c',token]
exec(compile(code,'<exact-bridge>','exec'),{'__name__':'__main__'})
'''
        for late in (False, True):
            with self.subTest(late=late), tempfile.TemporaryDirectory(prefix='openlxssh-exact-bridge-') as raw:
                base = Path(raw).resolve()
                remote, transport = socket.socketpair()
                remote.settimeout(2)
                with remote, transport:
                    if late:
                        (base/'connection').mkdir(mode=0o700)
                        (base/'connection/cancelled').write_bytes(b'')
                        (base/'connection/cancelled').chmod(0o600)
                    process = subprocess.Popen([sys.executable, '-u', '-c', setup, str(base),
                                                relay.CONTAINER_BRIDGE, 'd'*32, str(transport.fileno())],
                                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                               pass_fds=(transport.fileno(),), bufsize=0)
                    try:
                        if late:
                            stdout, stderr = process.communicate(timeout=2)
                            self.assertEqual((process.returncode, stdout, stderr), (0, b'', b''))
                            self.assertTrue((base/'connection/cancelled').is_file())
                            self.assertFalse((base/'connection/owner.json').exists())
                        else:
                            self.assertTrue(relay.wait_ready(process, threading.Event(), time.monotonic()+2))
                            self.assertEqual((base/'connection').stat().st_mode & 0o777, 0o700)
                            self.assertEqual((base/'connection/owner.json').stat().st_mode & 0o777, 0o600)
                            payload, response = b'non-ssh-request'*17000, b'final-response-after-eof'*9000
                            def exchange():
                                received = bytearray()
                                while True:
                                    part = remote.recv(4096)
                                    if not part: break
                                    received.extend(part)
                                self.assertEqual(hashlib.sha256(received).digest(), hashlib.sha256(payload).digest())
                                remote.sendall(response)
                                remote.shutdown(socket.SHUT_WR)
                            peer = ThreadResult(exchange)
                            stdout, stderr = process.communicate(payload, timeout=3)
                            peer.join(self)
                            self.assertEqual(process.returncode, 0)
                            self.assertEqual(hashlib.sha256(stdout).digest(), hashlib.sha256(response).digest())
                            self.assertEqual(stderr, b'')
                            self.assertFalse((base/'connection').exists())
                    finally:
                        relay.reap_owned(process)

    def cleanup_harness(self, mode):
        # Execute the exact cleanup program in an owned host child. Only its
        # Linux os/pidfd/proc interfaces are replaced. No real PID is signaled.
        with tempfile.TemporaryDirectory(prefix='openlxssh-relay-cleanup-') as raw:
            base = str(Path(raw).resolve())
            setup = r'''
import io,json,os,pathlib,select,signal,stat,sys,types
REAL_OPEN=os.open
REAL_FSTAT=os.fstat
REAL_CLOSE=os.close
root=pathlib.Path(sys.argv[1])
mode=sys.argv[2]
code=sys.stdin.read()
sys.argv=['-c','d'*32,'EXPECTED_HASH']
program='exact-bridge-code'
import hashlib
sys.argv[2]=hashlib.sha256(program.encode()).hexdigest()
real_mkdir=os.mkdir
real_open=os.open
fake_handle=987654
signals=[]
trace=[]
real_path=pathlib.Path
class ProcPath:
    def __init__(self,value): self.value=str(value)
    def __truediv__(self,value): return ProcPath(self.value+'/'+str(value))
    def open(self,kind):
        args=[b'/usr/bin/python3',b'-u',b'-c',program.encode(),b'd'*32,b'']
        if mode=='bad-token': args[4]=b'e'*32
        if mode=='bad-sha': args[3]=b'wrong-code'
        return io.BytesIO(b'\0'.join(args))
    def read_text(self):
        return 'Uid:\t'+('9999\t9999\t9999\t9999' if mode=='bad-uid' else '10000\t10000\t10000\t10000')+'\n'
pathlib.Path=ProcPath
os.getuid=lambda:10000
def mkdir(name,permissions):
    trace.append('mkdir')
    real_mkdir(str(root/'connection'),permissions)
os.mkdir=mkdir
def openfd(name,flags,permissions=0o777,dir_fd=None):
    if str(name).startswith('/tmp/'):
        name=str(root/'connection')
    fd=real_open(name,flags,permissions,dir_fd=dir_fd)
    return fd
os.open=openfd
def fstat(fd):
    info=REAL_FSTAT(fd)
    return types.SimpleNamespace(st_mode=info.st_mode,st_uid=10000,st_nlink=info.st_nlink)
os.fstat=fstat
def pidfd(pid,flags):
    trace.append('pidfd')
    if mode=='gone': raise ProcessLookupError()
    return fake_handle
os.pidfd_open=pidfd
class Poll:
    def register(self,fd,event): assert fd==fake_handle
    def poll(self,wait):
        trace.append('wait'+str(wait))
        return [(fake_handle,1)] if mode=='term-exit' and wait else []
select.poll=Poll
def send(fd,sig):
    assert fd==fake_handle
    signals.append(sig)
signal.pidfd_send_signal=send
os.close=lambda fd: None if fd==fake_handle else REAL_CLOSE(fd)
connection=root/'connection'
connection.mkdir(mode=0o700)
(connection/'owner.json').write_text(json.dumps({'pid':12345,'uid':10000,'token':'d'*32}))
(connection/'owner.json').chmod(0o600)
result=0
try: exec(compile(code,'<exact-cleanup>','exec'),{'__name__':'__main__'})
except SystemExit as error: result=error.code
print(json.dumps({'exit':result,'signals':signals,'trace':trace,
                  'cancelled':(connection/'cancelled').exists(),
                  'mode':(connection/'cancelled').stat().st_mode & 0o777}))
'''
            result = subprocess.run([sys.executable, '-c', setup, base, mode], input=relay.CONTAINER_CLEANUP.encode(),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, check=False)
            self.assertEqual(result.returncode, 0, 'offline cleanup harness failed (no payload output)')
            return json.loads(result.stdout)

    def test_pidfd_cleanup_term_wait_kill_exact_identity_offline(self):
        result = self.cleanup_harness('term-exit')
        self.assertEqual(result['exit'], 0)
        self.assertEqual(result['signals'], [signal.SIGTERM])
        self.assertTrue(result['cancelled'])
        self.assertEqual(result['mode'], 0o600)
        self.assertLess(result['trace'].index('pidfd'), result['trace'].index('wait0'))
        for mode in ('bad-token', 'bad-uid', 'bad-sha'):
            with self.subTest(mode=mode):
                result = self.cleanup_harness(mode)
                self.assertEqual(result['exit'], 65)
                self.assertEqual(result['signals'], [])
        result = self.cleanup_harness('kill-wait-timeout')
        self.assertEqual(result['exit'], 70)
        self.assertEqual(result['signals'], [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(result['trace'][-2:], ['wait750', 'wait1000'])
        result = self.cleanup_harness('gone')
        self.assertEqual(result['exit'], 0)
        self.assertEqual(result['signals'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
