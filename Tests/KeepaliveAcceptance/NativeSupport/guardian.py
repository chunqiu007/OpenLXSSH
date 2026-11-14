#!/usr/bin/env python3
"""Blackhole-only owned asynchronous guardian. Import performs no processes or I/O.

One backend instance/token, one exact child and anonymous PIPE pair. Slow exec startup never
runs on the forwarding worker. READY is control-only; ARM/RESULT each use a fresh nonce.
Unknown remote cleanup is failure even if the local Docker CLI was reaped.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import re
import selectors
import subprocess
import threading
import time
import uuid

from guardian_remote import REMOTE_SOURCE
from liveness_protocol import Refused

MAX_FRAME = 1024
QUERY_SECONDS = 0.5  # A tighter rejection bound, not an extension of consumer's existing 3s.
STARTUP_SECONDS = 20.0
CLEANUP_SECONDS = 12.0
REMOTE_KEYS = {'pid', 'startTicks', 'uid', 'token', 'pidfdAlive'}
COMMON_KEYS = {'op', 'token', 'instance', 'sequence', 'guardianPID', 'guardianStartTicks'}
SOURCE_SHA256 = hashlib.sha256(REMOTE_SOURCE.encode()).hexdigest()


def decode(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) < MAX_FRAME or raw.count(b'\n') != 1 or not raw.endswith(b'\n'):
        raise Refused('guardian-frame-bound')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise Refused('guardian-frame-duplicate')
            result[key] = value
        return result
    try: value = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError): raise Refused('guardian-frame-json') from None
    if not isinstance(value, dict): raise Refused('guardian-frame-object')
    return value


def remote_identity(value, token):
    if (not isinstance(value, dict) or set(value) != REMOTE_KEYS or
            type(value['pid']) is not int or value['pid'] <= 1 or type(value['startTicks']) is not int or value['startTicks'] <= 0 or
            type(value['uid']) is not int or value['uid'] != 10000 or value['token'] != token or value['pidfdAlive'] is not True):
        raise Refused('guardian-target-identity')
    return dict(value)


class Request:
    def __init__(self, operation, deadline):
        self.operation = operation; self.deadline = deadline
        self.done = threading.Event(); self.value = None; self.error = None


class OwnedGuardian:
    def __init__(self, backend, token, target_process, relay_deadline, *, popen=subprocess.Popen,
                 clock=time.monotonic, nonce=lambda: uuid.uuid4().hex):
        if not isinstance(token, str) or re.fullmatch('[0-9a-f]{32}', token) is None:
            raise Refused('guardian-token')
        self.backend, self.token, self.target_process = backend, token, target_process
        self.clock, self.popen, self.nonce = clock, popen, nonce
        self.instance = nonce(); self.deadline = relay_deadline
        if not isinstance(self.instance, str) or re.fullmatch('[0-9a-f]{32}', self.instance) is None:
            raise Refused('guardian-instance')
        self.lock = threading.Lock(); self.requests = queue.Queue(maxsize=1)
        self.ready = False; self.busy = False; self.closing = False; self.failed = False
        self.child = None; self.thread = None; self.sequence = 0; self.last_nonce = None
        self.guardian_birth = None; self.actual = None; self.buffer = bytearray()
        self.cleanup_deadline = None
        self.control_ready = False; self.terminal_frame = None; self.last_frame = None; self.sent = {}
        self.close_requested = threading.Event(); self.finished = threading.Event()
        self.cleanup = {'remoteTerminated': False, 'terminationFact': 'unknown', 'localReaped': False,
                        'forcedLocalTermination': False, 'startupJoined': False, 'success': False}

    def start(self):
        self.thread = threading.Thread(target=self._run, name='native-liveness-guardian', daemon=False)
        self.thread.start()

    def query(self):
        with self.lock:
            if self.closing or self.failed or not self.ready or self.child is None or self.child.poll() is not None:
                raise Refused('guardian-not-ready-or-gone')
            if self.busy: raise Refused('guardian-busy')
            if self.sequence not in (0, 1): raise Refused('guardian-query-order')
            if self.target_process.poll() is not None: raise Refused('guardian-target-local-gone')
            self.busy = True
            request = Request('arm' if self.sequence == 0 else 'result', min(self.deadline, self.clock() + QUERY_SECONDS))
            try: self.requests.put_nowait(request)
            except queue.Full:
                self.busy = False; raise Refused('guardian-busy') from None
        if not request.done.wait(max(0, request.deadline - self.clock())):
            with self.lock: self.failed = True
            self.close_requested.set()
            raise Refused('guardian-query-deadline')
        if request.error is not None: raise request.error
        if self.clock() > request.deadline: raise Refused('guardian-late-answer')
        return request.value

    def begin_close(self, deadline):
        with self.lock:
            self.closing = True; self.cleanup_deadline = deadline
        self.close_requested.set()

    def close(self, deadline):
        self.begin_close(deadline)
        if self.thread is not None and self.thread.ident is not None:
            self.thread.join(max(0, deadline - self.clock()))
        self.cleanup['startupJoined'] = self.thread is None or not self.thread.is_alive()
        if not self.cleanup['startupJoined']:
            # Exact local child only. No post-deadline waits and no remote-gone claim.
            child = self.child
            if child is not None and child.poll() is None:
                try: child.kill(); self.cleanup['forcedLocalTermination'] = True
                except ProcessLookupError: pass
            self.cleanup['success'] = False
        return dict(self.cleanup)

    def _read(self, deadline):
        child = self.child
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while self.clock() < deadline:
                if self.close_requested.is_set() and self.cleanup_deadline is not None:
                    deadline = min(deadline, self.cleanup_deadline)
                if b'\n' in self.buffer:
                    end = self.buffer.index(10) + 1; raw = bytes(self.buffer[:end]); del self.buffer[:end]
                    value = decode(raw)
                    if value.get('op') in ('closed', 'ended'): self.terminal_frame = value
                    self.last_frame = value
                    return value
                if not selector.select(min(.01, max(0, deadline - self.clock()))):
                    if child.poll() is not None: raise Refused('guardian-child-ended')
                    continue
                try: raw = os.read(child.stdout.fileno(), MAX_FRAME - len(self.buffer))
                except (BlockingIOError, InterruptedError): continue
                if not raw: raise Refused('guardian-eof-before-frame')
                self.buffer.extend(raw)
                if len(self.buffer) >= MAX_FRAME and b'\n' not in self.buffer: raise Refused('guardian-frame-bound')
        raise Refused('guardian-read-deadline')

    def _frame(self, value, *, op, sequence, nonce=None, extra=()):
        keys = COMMON_KEYS | set(extra) | ({'nonce'} if nonce is not None else set())
        if (set(value) != keys or value['op'] != op or value['token'] != self.token or value['instance'] != self.instance or
                type(value['sequence']) is not int or value['sequence'] != sequence or
                type(value['guardianPID']) is not int or value['guardianPID'] <= 1 or
                type(value['guardianStartTicks']) is not int or value['guardianStartTicks'] <= 0 or
                (nonce is not None and value['nonce'] != nonce)):
            raise Refused('guardian-reply-binding')
        birth = (value['guardianPID'], value['guardianStartTicks'])
        if self.guardian_birth is not None and birth != self.guardian_birth: raise Refused('guardian-birth-changed')
        self.guardian_birth = birth
        return value

    def _send(self, operation, deadline):
        nonce = self.nonce()
        if nonce in self.sent.values() or not isinstance(nonce, str) or re.fullmatch('[0-9a-f]{32}', nonce) is None:
            raise Refused('guardian-nonce')
        self.sequence += 1; self.last_nonce = nonce; self.sent[self.sequence] = nonce
        raw = (json.dumps({'op': operation, 'token': self.token, 'instance': self.instance,
            'sequence': self.sequence, 'nonce': nonce}, separators=(',', ':'), sort_keys=True) + '\n').encode()
        offset = 0
        with selectors.DefaultSelector() as selector:
            selector.register(self.child.stdin, selectors.EVENT_WRITE)
            while offset < len(raw) and self.clock() < deadline:
                if not selector.select(min(.01, max(0, deadline - self.clock()))): continue
                try: count = os.write(self.child.stdin.fileno(), raw[offset:])
                except (BlockingIOError, InterruptedError): continue
                if count <= 0: raise Refused('guardian-write')
                offset += count
        if offset != len(raw): raise Refused('guardian-write-deadline')
        return nonce

    def _terminal(self, value):
        sequence = value.get('sequence')
        if type(sequence) is not int or sequence not in (self.sequence, self.sequence - 1):
            raise Refused('guardian-terminal-sequence')
        expected = self.sent.get(sequence)
        terminal_nonce = value.get('nonce')
        if expected is None:
            self._frame(value, op=value.get('op'), sequence=sequence, extra=('reason',))
            if terminal_nonce is not None: raise Refused('guardian-terminal-nonce')
        else:
            self._frame(value, op=value.get('op'), sequence=sequence, nonce=expected, extra=('reason',))
        if value['op'] not in ('closed', 'ended') or value['reason'] not in ('requested', 'target-gone', 'control-eof'):
            raise Refused('guardian-terminal-fact')
        if value['op'] == 'closed' and value['reason'] != 'requested': raise Refused('guardian-terminal-fact')
        self.cleanup['terminationFact'] = value['reason']

    def _finish_remote(self):
        child = self.child
        if child is None:
            self.cleanup.update(remoteTerminated=True, terminationFact='not-started', localReaped=True,
                                success=True)
            return
        deadline = min(self.deadline, self.clock() + CLEANUP_SECONDS,
                       self.cleanup_deadline if self.cleanup_deadline is not None else float('inf'))
        graceful_deadline = max(self.clock(), deadline - .5)
        terminal = False
        try:
            # A target-gone terminal frame may already be buffered; do not invent a reply.
            if self.terminal_frame is not None:
                self._terminal(self.terminal_frame); terminal = True
            elif self.control_ready and child.poll() is None:
                try: self._send('close', graceful_deadline)
                except (BrokenPipeError, Refused):
                    # Target-gone may have produced its terminal frame concurrently.
                    # Still require a genuine terminal frame, EOF and natural remote exit.
                    pass
                self._terminal(self._read(graceful_deadline)); terminal = True
            child.stdin.close()
            # Require remote terminal record followed by EOF and natural exec exit0.
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                eof = False
                while self.clock() < graceful_deadline and not eof:
                    if self.buffer:
                        if not terminal and b'\n' in self.buffer:
                            end = self.buffer.index(10) + 1; value = decode(bytes(self.buffer[:end])); del self.buffer[:end]
                            self._terminal(value); terminal = True
                        if self.buffer: raise Refused('guardian-extra-terminal-output')
                    if not selector.select(min(.01, max(0, graceful_deadline - self.clock()))): continue
                    block = os.read(child.stdout.fileno(), MAX_FRAME)
                    if not block: eof = True
                    else:
                        self.buffer.extend(block)
                        if not terminal and b'\n' in self.buffer:
                            end = self.buffer.index(10) + 1; value = decode(bytes(self.buffer[:end])); del self.buffer[:end]
                            self._terminal(value); terminal = True
                        if self.buffer: raise Refused('guardian-extra-terminal-output')
                if not eof or self.buffer: raise Refused('guardian-no-clean-eof')
            code = child.wait(timeout=max(.001, graceful_deadline - self.clock()))
            self.cleanup['localReaped'] = True
            self.cleanup['remoteTerminated'] = terminal and code == 0
        except Exception:
            try: child.stdin.close()
            except Exception: pass
        finally:
            if child.poll() is None:
                child.terminate(); self.cleanup['forcedLocalTermination'] = True
                try: child.wait(timeout=max(.001, min(.2, deadline - self.clock())))
                except subprocess.TimeoutExpired:
                    child.kill()
                    try: child.wait(timeout=max(.001, deadline - self.clock()))
                    except subprocess.TimeoutExpired: pass
            self.cleanup['localReaped'] = child.poll() is not None
            for handle in (child.stdin, child.stdout, child.stderr):
                if handle is not None:
                    try: handle.close()
                    except Exception: pass
            self.cleanup['success'] = (self.cleanup['remoteTerminated'] and self.cleanup['localReaped'] and
                                       not self.cleanup['forcedLocalTermination'])

    def _run(self):
        active = None
        try:
            command = list(self.backend.command) + ['exec', '-i', '--user', '10000:10000', self.backend.target.container_id,
                '/usr/bin/python3', '-u', '-c', REMOTE_SOURCE, self.token, self.instance]
            # This call is on the owned background thread, never the original relay worker.
            self.child = self.popen(command, env=self.backend.environment, cwd=str(Path(__file__).absolute().parents[3]),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0, close_fds=True)
            os.set_blocking(self.child.stdin.fileno(), False); os.set_blocking(self.child.stdout.fileno(), False)
            startup_deadline = min(self.deadline, self.clock() + STARTUP_SECONDS)
            self._frame(self._read(startup_deadline), op='ready', sequence=0)
            self.control_ready = True
            with self.lock: self.ready = True
            while not self.close_requested.is_set():
                if self.child.poll() is not None: raise Refused('guardian-child-ended')
                try: active = self.requests.get(timeout=.01)
                except queue.Empty: continue
                nonce = self._send(active.operation, active.deadline)
                value = self._frame(self._read(active.deadline), op='alive', sequence=self.sequence, nonce=nonce, extra=('actual',))
                actual = remote_identity(value['actual'], self.token)
                if self.actual is not None and actual != self.actual: raise Refused('guardian-target-changed')
                if self.clock() > active.deadline: raise Refused('guardian-late-answer')
                self.actual = actual; active.value = actual
                with self.lock: self.busy = False
                active.done.set(); active = None
        except Exception:
            with self.lock: self.failed = True; self.busy = False
            if active is not None:
                active.error = Refused('guardian-query-refused'); active.done.set()
        finally:
            with self.lock: self.ready = False
            self._finish_remote(); self.finished.set()


class GuardianRegistry:
    def __init__(self, backend, relay_deadline, *, factory=OwnedGuardian):
        self.backend, self.deadline, self.factory = backend, relay_deadline, factory
        self.original_spawn = backend.spawn; self.lock = threading.Lock(); self.entries = {}; self.closed = False
        self.launch_failed = False
        self.backend.spawn = self.spawn

    def spawn(self, token):
        # Exact original spawn once; exception identity and returned Popen are unchanged.
        process = self.original_spawn(token)
        with self.lock:
            if self.closed or token in self.entries or len(self.entries) >= 16:
                # Preserve original result; registry failure is only observed as later refusal/cleanup failure.
                self.closed = True; self.launch_failed = True; return process
            try:
                guardian = self.factory(self.backend, token, process, self.deadline)
                self.entries[token] = guardian
                guardian.start()
            except Exception:
                self.launch_failed = True; self.closed = True
        return process

    def remote_alive(self, backend, token):
        with self.lock:
            if backend is not self.backend or self.closed: raise Refused('guardian-backend-owner')
            guardian = self.entries.get(token)
        if guardian is None: raise Refused('guardian-token-owner')
        return guardian.query()

    def close(self):
        with self.lock:
            self.closed = True; owned = list(self.entries.values())
        deadline = min(self.deadline, time.monotonic() + CLEANUP_SECONDS)
        for guardian in owned:
            try: guardian.begin_close(deadline)
            except Exception: self.launch_failed = True
        facts = []
        for guardian in owned:
            try: facts.append(guardian.close(deadline))
            except Exception:
                facts.append({'remoteTerminated': False, 'terminationFact': 'unknown', 'localReaped': False,
                    'forcedLocalTermination': False, 'startupJoined': False, 'success': False})
        self.backend.spawn = self.original_spawn
        return {'sourceSHA256': SOURCE_SHA256, 'count': len(facts), 'owned': facts,
                'success': not self.launch_failed and bool(facts) and all(item.get('success') and item.get('startupJoined') for item in facts)}
