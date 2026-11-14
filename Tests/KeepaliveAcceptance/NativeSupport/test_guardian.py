#!/usr/bin/env python3
"""Guardian offline tests. No subprocess, Docker, sockets or real /proc access.

Exec below loads the literal READ-ONLY remote program into a non-main test namespace;
only its pure decoder and injected Target fake OS are invoked, never run().
"""
import copy
import hashlib
import json
import os
import stat
import threading
import time
import types
import unittest
from unittest.mock import patch

from guardian import (GuardianRegistry, OwnedGuardian, Request, SOURCE_SHA256, decode, remote_identity)
from guardian_remote import REMOTE_SOURCE
from liveness_protocol import Refused, arm_age_bounds
from relay_native import construct, load_original

TOKEN = 'a' * 32
INSTANCE = 'b' * 32


class FakeTargetProcess:
    def poll(self): return None


class FakeReceiptOS:
    O_RDONLY = os.O_RDONLY; O_DIRECTORY = os.O_DIRECTORY; O_NOFOLLOW = os.O_NOFOLLOW
    def __init__(self):
        self.receipt = {'pid': 1234, 'uid': 10000, 'token': TOKEN}; self.missing = False; self.partial = False
        self.mode = 0o600; self.links = 1; self.owner = 10000; self.ticks = 77; self.target_dead = False; self.closed = []
    def getuid(self): return 10000
    def open(self, path, flags, dir_fd=None):
        if path == 'owner.json':
            if self.missing: raise FileNotFoundError()
            return 2
        if path.endswith('/stat'): return 3
        if path.endswith('/status'): return 4
        return 1
    def fstat(self, fd):
        return types.SimpleNamespace(st_mode=(stat.S_IFDIR | 0o700) if fd == 1 else (stat.S_IFREG | self.mode),
            st_uid=self.owner, st_nlink=self.links, st_dev=1, st_ino=fd, st_size=len(self.raw()), st_mtime_ns=1, st_ctime_ns=1)
    def raw(self): return b'{' if self.partial else json.dumps(self.receipt).encode()
    def read(self, fd, limit):
        if fd == 2: return self.raw()
        if fd == 3: return ('1234 (python) ' + ' '.join(['S'] + ['0'] * 18 + [str(self.ticks)])).encode()
        if fd == 4: return b'Name:\tpython\nUid:\t10000\t10000\t10000\t10000\n'
        raise AssertionError('unexpected fake descriptor')
    def close(self, fd): self.closed.append(fd)
    def pidfd_open(self, pid, flags): return 8
    def poll_factory(self):
        owner = self
        class Poll:
            def register(self, *_): pass
            def poll(self, *_): return [(8, 1)] if owner.target_dead else []
        return Poll()


class GuardianTests(unittest.TestCase):
    def remote(self):
        namespace = {'__name__': 'offline_guardian_source'}
        exec(compile(REMOTE_SOURCE, '<fixed-public-guardian-source>', 'exec'), namespace)
        return namespace

    def owned(self):
        backend = types.SimpleNamespace(command=('fixed',), target=types.SimpleNamespace(container_id='c' * 64), environment={})
        return OwnedGuardian(backend, TOKEN, FakeTargetProcess(), time.monotonic() + 60, nonce=lambda: INSTANCE)

    def test_source_ready_does_not_read_target_and_queries_strict_receipt_each_time(self):
        source = self.remote(); fake = FakeReceiptOS(); target = source['Target'](TOKEN, fake, fake.poll_factory)
        self.assertIsNone(target.handle)  # READY would not call inspect.
        first = target.inspect(); self.assertEqual(set(first), {'pid', 'startTicks', 'uid', 'token', 'pidfdAlive'})
        self.assertEqual(first, target.inspect())
        fake.receipt['pid'] = 1235
        with self.assertRaises(ValueError): target.inspect()
        target.close()

    def test_missing_partial_mode_links_uid_token_dead_and_birth_changes_refuse(self):
        for change in ('missing', 'partial', 'mode', 'links', 'owner', 'token', 'dead', 'ticks'):
            source = self.remote(); fake = FakeReceiptOS(); target = source['Target'](TOKEN, fake, fake.poll_factory)
            if change == 'missing': fake.missing = True
            elif change == 'partial': fake.partial = True
            elif change == 'mode': fake.mode = 0o644
            elif change == 'links': fake.links = 2
            elif change == 'owner': fake.owner = 501
            elif change == 'token': fake.receipt['token'] = 'f' * 32
            elif change == 'dead': fake.target_dead = True
            else: target.inspect(); fake.ticks += 1
            with self.subTest(change=change), self.assertRaises((ValueError, FileNotFoundError)): target.inspect()
            target.close()

    def test_exact_spawn_once_returns_original_and_does_not_wait_for_prewarmer(self):
        process = FakeTargetProcess(); calls = []
        class FakeGuardian:
            def __init__(self, *args): self.args = args; self.started = False
            def start(self): self.started = True
            def query(self): return {'marker': True}
            def begin_close(self, deadline): pass
            def close(self, deadline): return {'success': True, 'startupJoined': True}
        backend = types.SimpleNamespace(spawn=lambda token: calls.append(token) or process)
        original = backend.spawn
        registry = GuardianRegistry(backend, time.monotonic() + 60, factory=FakeGuardian)
        self.assertIs(backend.spawn(TOKEN), process); self.assertEqual(calls, [TOKEN])
        self.assertTrue(registry.entries[TOKEN].started)
        self.assertEqual(registry.remote_alive(backend, TOKEN), {'marker': True})
        with self.assertRaises(Refused): registry.remote_alive(object(), TOKEN)
        with self.assertRaises(Refused): registry.remote_alive(backend, 'f' * 32)
        self.assertTrue(registry.close()['success']); self.assertIs(backend.spawn, original)
        error = RuntimeError('original')
        def fail(_): raise error
        backend = types.SimpleNamespace(spawn=fail); registry = GuardianRegistry(backend, time.monotonic() + 60, factory=FakeGuardian)
        with self.assertRaises(RuntimeError) as result: backend.spawn(TOKEN)
        self.assertIs(result.exception, error)

    def test_notready_busy_deadline_and_late_answer_never_return_cached_alive(self):
        guardian = self.owned()
        with self.assertRaises(Refused): guardian.query()
        guardian.ready = True; guardian.child = FakeTargetProcess(); guardian.busy = True
        with self.assertRaises(Refused): guardian.query()
        guardian.busy = False
        with patch('guardian.QUERY_SECONDS', 0.001):
            with self.assertRaises(Refused): guardian.query()
        self.assertTrue(guardian.failed); self.assertTrue(guardian.close_requested.is_set())

    def test_nonce_frame_types_exact_five_keys_and_guardian_birth(self):
        guardian = self.owned()
        frame = {'op': 'ready', 'token': TOKEN, 'instance': INSTANCE, 'sequence': 0, 'guardianPID': 123, 'guardianStartTicks': 55}
        guardian._frame(frame, op='ready', sequence=0)
        for key, changed in [('sequence', True), ('guardianPID', 124), ('instance', 'c' * 32), ('extra', 1)]:
            value = dict(frame); value[key] = changed
            with self.assertRaises(Refused): guardian._frame(value, op='ready', sequence=0)
        actual = {'pid': 1234, 'startTicks': 77, 'uid': 10000, 'token': TOKEN, 'pidfdAlive': True}
        self.assertEqual(remote_identity(actual, TOKEN), actual)
        for key, changed in [('pidfdAlive', 1), ('uid', True), ('extra', 'not-allowed'), ('token', 'f' * 32)]:
            value = dict(actual); value[key] = changed
            with self.assertRaises(Refused): remote_identity(value, TOKEN)
        with self.assertRaises(Refused): decode(b'{"op":"ready","op":"ready"}\n')
        with self.assertRaises(Refused): decode(b'{}\n{}\n')

    def test_arm_age_causal_bounds_are_conservative_without_wall_offset(self):
        value = arm_age_bounds(100, 100.01, 100.02, 100.2, 50.1, 50.11)
        self.assertLessEqual(value['maximumAge'], 1.5); self.assertGreaterEqual(value['minimumAge'], 0)
        for values in [(98, 100.01, 100.02, 100.2, 50.1, 50.11),
                       (100.02, 100.01, 100.03, 100.2, 50.1, 50.11),
                       (100, 100.01, 100.02, 100.03, 50.1, 51),
                       (100, 100.01, 100.02, 100.2, float('nan'), 50.11)]:
            with self.assertRaises(Refused): arm_age_bounds(*values)

    def test_terminal_ack_and_local_cli_exit_are_not_interchangeable(self):
        guardian = self.owned(); guardian.sequence = 2; guardian.sent = {1: 'c' * 32, 2: 'd' * 32}
        guardian.guardian_birth = (123, 55)
        terminal = {'op': 'ended', 'token': TOKEN, 'instance': INSTANCE, 'sequence': 2, 'nonce': 'd' * 32,
                    'guardianPID': 123, 'guardianStartTicks': 55, 'reason': 'target-gone'}
        guardian._terminal(terminal); self.assertEqual(guardian.cleanup['terminationFact'], 'target-gone')
        self.assertFalse(guardian.cleanup['remoteTerminated'])  # Still requires clean EOF and natural child exit.
        terminal['nonce'] = 'e' * 32
        with self.assertRaises(Refused): guardian._terminal(terminal)
        terminal['nonce'] = 'd' * 32; terminal['reason'] = 'lifetime'
        with self.assertRaises(Refused): guardian._terminal(terminal)

    def test_complete_owned_background_lifecycle_fresh_two_queries_and_terminal_cleanup(self):
        nonces = iter([INSTANCE, 'c' * 32, 'd' * 32, 'e' * 32]); exchanges = []
        actual = {'pid': 1234, 'startTicks': 77, 'uid': 10000, 'token': TOKEN, 'pidfdAlive': True}
        class PipeChild:
            def __init__(self, command, **kwargs):
                self.stdin = types.SimpleNamespace(fileno=lambda: 10)
                self.stdout = types.SimpleNamespace(fileno=lambda: 11)
                self.stderr = None; self.code = None; self.terminated = False
            def poll(self): return self.code
            def wait(self, timeout=None): self.code = 0; return 0
        backend = types.SimpleNamespace(command=('docker', '--host', 'fixed'), target=types.SimpleNamespace(container_id='c' * 64), environment={})
        child_holder = []
        def popen(command, **kwargs):
            child = PipeChild(command, **kwargs); child_holder.append(child); return child
        class Scripted(OwnedGuardian):
            def _read(self, deadline):
                value = {'op': 'ready' if self.sequence == 0 else 'alive', 'token': TOKEN, 'instance': INSTANCE,
                    'sequence': self.sequence, 'guardianPID': 123, 'guardianStartTicks': 55}
                if self.sequence:
                    value.update(nonce=self.last_nonce, actual=dict(actual))
                return value
            def _send(self, operation, deadline):
                nonce = self.nonce(); self.sequence += 1; self.last_nonce = nonce; self.sent[self.sequence] = nonce
                exchanges.append((operation, nonce)); return nonce
            def _finish_remote(self):
                self.cleanup.update(remoteTerminated=True, terminationFact='requested', localReaped=True,
                                    forcedLocalTermination=False, success=True)
        owner = Scripted(backend, TOKEN, FakeTargetProcess(), time.monotonic() + 10, popen=popen, nonce=lambda: next(nonces))
        with patch('guardian.os.set_blocking'):
            owner.start()
            deadline = time.monotonic() + 1
            while not owner.ready and time.monotonic() < deadline: time.sleep(.001)
            self.assertEqual(owner.query(), actual); self.assertEqual(owner.query(), actual)
            facts = owner.close(time.monotonic() + 1)
        self.assertEqual(exchanges, [('arm', 'c' * 32), ('result', 'd' * 32)])
        self.assertTrue(facts['success']); self.assertTrue(facts['startupJoined'])
        self.assertEqual(len(child_holder), 1)

    def test_cleanup_requires_real_terminal_eof_and_natural_exit_and_handles_broken_pipe(self):
        class Selector:
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def register(self, *_): pass
            def select(self, *_): return [(None, 1)]
        for has_terminal, natural in [(True, True), (False, True), (True, False)]:
            owner = self.owned(); owner.control_ready = True; owner.guardian_birth = (123, 55)
            class Child:
                def __init__(self):
                    self.code = None; self.stdin = types.SimpleNamespace(close=lambda: None)
                    self.stdout = types.SimpleNamespace(fileno=lambda: 11, close=lambda: None); self.stderr = None
                def poll(self): return self.code
                def wait(self, timeout=None): self.code = 0 if natural else 1; return self.code
                def terminate(self): self.code = 143
                def kill(self): self.code = 137
            owner.child = Child()
            terminal = {'op': 'ended', 'token': TOKEN, 'instance': INSTANCE, 'sequence': 0,
                        'guardianPID': 123, 'guardianStartTicks': 55, 'reason': 'control-eof'}
            if has_terminal: owner.terminal_frame = terminal
            with patch('guardian.selectors.DefaultSelector', return_value=Selector()), patch('guardian.os.read', return_value=b''), \
                 patch.object(owner, '_send', side_effect=BrokenPipeError()), patch.object(owner, '_read', return_value=terminal):
                owner._finish_remote()
            self.assertEqual(owner.cleanup['remoteTerminated'], natural)
            self.assertEqual(owner.cleanup['success'], natural)

    def test_startup_cancel_and_registry_capacity_never_turn_unknown_cleanup_green(self):
        owner = self.owned()
        owner._finish_remote(); self.assertEqual(owner.cleanup['terminationFact'], 'not-started')
        owner.cleanup['success'] = False
        class StuckThread:
            ident = 1
            def join(self, timeout=None): self.timeout = timeout
            def is_alive(self): return True
        owner.thread = StuckThread()
        facts = owner.close(time.monotonic())
        self.assertFalse(facts['startupJoined']); self.assertFalse(facts['success'])
        backend = types.SimpleNamespace(spawn=lambda token: FakeTargetProcess())
        class Entry:
            def __init__(self, *args): pass
            def start(self): pass
            def begin_close(self, deadline): pass
            def close(self, deadline): return {'success': False, 'startupJoined': True}
        registry = GuardianRegistry(backend, time.monotonic() + 10, factory=Entry)
        registry.spawn(TOKEN); registry.spawn(TOKEN)
        self.assertTrue(registry.launch_failed); self.assertFalse(registry.close()['success'])

    def test_cleanup_summary_cannot_claim_green_without_all_remote_facts(self):
        from diagnostics import guardian_cleanup_facts
        actual = {'tag': 'native-guardian-cleanup-v1', 'sourceSHA256': SOURCE_SHA256, 'count': 1,
                  'success': True, 'owned': [{'remoteTerminated': True, 'terminationFact': 'requested', 'localReaped': True,
                    'forcedLocalTermination': False, 'startupJoined': True, 'success': True}]}
        self.assertTrue(guardian_cleanup_facts((json.dumps(actual) + '\n').encode())['success'])
        for key, value in [('remoteTerminated', False), ('localReaped', False), ('startupJoined', False),
                           ('forcedLocalTermination', True), ('terminationFact', 'unknown')]:
            changed = copy.deepcopy(actual); changed['owned'][0][key] = value
            self.assertIsNone(guardian_cleanup_facts((json.dumps(changed) + '\n').encode()))

    def test_original_relay_methods_and_normal_instance_remain_unmodified(self):
        original = load_original(); before = {name: getattr(original.Relay, name) for name in ('__init__', 'worker', 'dispatch', 'serve')}
        arm = original.Flow.arm; drop = original.drop_pump
        with patch('subprocess.Popen', side_effect=AssertionError('offline cannot start')):
            normal = construct(original, 'normal', 'a' * 32, 1234)
        self.assertNotIn('spawn', normal.backend.__dict__)
        for name, method in before.items(): self.assertIs(getattr(original.Relay, name), method)
        self.assertIs(original.Flow.arm, arm); self.assertIs(original.drop_pump, drop)
        self.assertEqual(SOURCE_SHA256, hashlib.sha256(REMOTE_SOURCE.encode()).hexdigest())


if __name__ == '__main__': unittest.main()
