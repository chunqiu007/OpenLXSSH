"""Fixture-only challenge lifetime owner. One bounded, private Unix socket.

The sshd PAM worker holds a lease; kernel EOF, rather than Python finally or
expiry sweeping, ends that lease. Only this owner creates/exports/removes its
challenge files. No response, payload or exception text is logged.
"""
import json
import math
import os
from pathlib import Path
import re
import selectors
import socket
import stat
import struct
import threading
import time

SOCKET = 'challenge-owner.sock'
LIMIT = 4096
MAX_OWNERS = 32
MAX_CLIENTS = 64
SESSION = re.compile(r'^[0-9a-f]{24}$')


class LeaseError(RuntimeError):
    def __init__(self):
        super().__init__('fixture challenge lease refused')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LeaseError()
        result[key] = value
    return result


def _decode(raw):
    if not 0 < len(raw) <= LIMIT:
        raise LeaseError()
    value = json.loads(raw, object_pairs_hook=_pairs)
    if type(value) is not dict:
        raise LeaseError()
    return value


def _encoded(value):
    raw = json.dumps(value, separators=(',', ':'), allow_nan=False).encode('ascii') + b'\n'
    if len(raw) > LIMIT:
        raise LeaseError()
    return raw


def _peer_uid(connection):
    if hasattr(socket, 'SO_PEERCRED'):
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
        return struct.unpack('3i', raw)[1]
    if hasattr(socket, 'LOCAL_PEERCRED'):  # Darwin offline tests; production is Linux.
        raw = connection.getsockopt(0, socket.LOCAL_PEERCRED, 128)
        version, uid = struct.unpack_from('=II', raw)
        if version == 0:
            return uid
    raise LeaseError()


def _identity(value):
    return value.st_dev, value.st_ino, value.st_uid, value.st_mode, value.st_nlink


class _Directory:
    def __init__(self, path, uid, mode):
        self.path = Path(path)
        self.uid, self.mode = uid, mode
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            # Directory link counts change when this owner creates children on
            # APFS. Device/inode/UID/type/mode identify the held directory;
            # regular files below separately require exactly one hard link.
            self.identity = _identity(os.fstat(self.fd))[:4]
            self.validate()
        except BaseException:
            os.close(self.fd)
            raise

    def validate(self):
        held = os.fstat(self.fd)
        named = os.stat(self.path, follow_symlinks=False)
        if (not stat.S_ISDIR(held.st_mode) or held.st_uid != self.uid
                or stat.S_IMODE(held.st_mode) != self.mode
                or _identity(held)[:4] != self.identity or _identity(named)[:4] != self.identity):
            raise LeaseError()

    def close(self):
        os.close(self.fd)


class _OwnedFile:
    def __init__(self, directory, name, payload):
        directory.validate()
        self.directory, self.name, self.payload = directory, name, payload
        self.fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                          0o600, dir_fd=directory.fd)
        self.identity = _identity(os.fstat(self.fd))
        try:
            offset = 0
            while offset < len(payload):
                count = os.write(self.fd, payload[offset:])
                if count <= 0:
                    raise LeaseError()
                offset += count
            os.fsync(self.fd)
            self.validate()
        except BaseException:
            # A failed write may only remove the inode this call created.
            try:
                directory.validate()
                if _identity(os.stat(name, dir_fd=directory.fd, follow_symlinks=False)) == self.identity:
                    os.unlink(name, dir_fd=directory.fd)
            finally:
                os.close(self.fd)
            raise

    def validate(self):
        self.directory.validate()
        held = os.fstat(self.fd)
        named = os.stat(self.name, dir_fd=self.directory.fd, follow_symlinks=False)
        if (not stat.S_ISREG(held.st_mode) or held.st_uid != self.directory.uid
                or stat.S_IMODE(held.st_mode) != 0o600 or held.st_nlink != 1
                or _identity(held) != self.identity or _identity(named) != self.identity
                or held.st_size != len(self.payload)
                or os.pread(self.fd, len(self.payload) + 1, 0) != self.payload):
            raise LeaseError()

    def remove(self):
        try:
            self.validate()
            os.unlink(self.name, dir_fd=self.directory.fd)
        finally:
            os.close(self.fd)
            self.payload = b''


class ChallengeOwner:
    """One selector thread in the existing container supervisor, never a daemon."""
    def __init__(self, root, *, max_owners=MAX_OWNERS):
        if not 1 <= max_owners <= MAX_OWNERS:
            raise LeaseError()
        self.root = Path(root)
        self.uid, self.maximum = os.geteuid(), max_owners
        self.clients, self.owners = {}, {}
        self.failures = 0
        self.thread = None
        self.closed, self.close_failed = False, False
        self.selector = selectors.DefaultSelector()
        self.directories = []
        self.listener = None
        self.wake_read, self.wake_write = socket.socketpair()
        try:
            # Production bootstrap uses 0755 for sshd's authorized_keys traversal.
            mode = stat.S_IMODE(os.stat(self.root, follow_symlinks=False).st_mode)
            if mode not in (0o700, 0o755):
                raise LeaseError()
            self.base = _Directory(self.root, self.uid, mode); self.directories.append(self.base)
            self.sessions = _Directory(self.root / 'sessions', self.uid, 0o700); self.directories.append(self.sessions)
            self.exports = _Directory(self.root / 'export', self.uid, 0o700); self.directories.append(self.exports)
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.listener.bind(str(self.root / SOCKET))  # Existing names are never adopted.
            os.chmod(self.root / SOCKET, 0o600)
            self.socket_identity = _identity(os.stat(self.root / SOCKET, follow_symlinks=False))
            self.listener.listen(MAX_CLIENTS); self.listener.setblocking(False)
            self.selector.register(self.listener, selectors.EVENT_READ, 'listener')
            self.selector.register(self.wake_read, selectors.EVENT_READ, 'stop')
        except BaseException:
            if self.listener is not None:
                self.listener.close()
            for directory in reversed(self.directories): directory.close()
            self.wake_read.close(); self.wake_write.close(); self.selector.close()
            raise

    def start(self):
        self.thread = threading.Thread(target=self._run, name='fixture-challenge-owner')
        self.thread.start()
        return self

    def _reply(self, connection, value):
        connection.settimeout(0.1)
        try: connection.sendall(_encoded(value))
        finally: connection.setblocking(False)

    def _clean(self, record):
        succeeded = True
        for owned in (record.get('export'), record['file']):
            if owned is not None:
                try: owned.remove()
                except Exception: succeeded = False
        record.clear()  # Stop retaining responses even if an unknown replacement is preserved.
        if not succeeded: self.failures += 1
        return succeeded

    def _drop(self, connection):
        state = self.clients.pop(connection, None)
        if state is None: return
        if state['session'] is not None:
            record = self.owners.pop(state['session'], None)
            if record is not None: self._clean(record)
        self.selector.unregister(connection); connection.close()

    def _register(self, connection, state, request):
        if set(request) != {'action', 'session', 'challenge'} or len(self.owners) >= self.maximum:
            raise LeaseError()
        identifier, payload = request['session'], request['challenge']
        if (type(identifier) is not str or not SESSION.fullmatch(identifier) or identifier in self.owners
                or type(payload) is not dict or set(payload) != {'session', 'expires_at', 'scenario', 'responses'}
                or payload['session'] != identifier or payload['scenario'] != 'multi'
                or type(payload['expires_at']) not in (int, float) or not math.isfinite(payload['expires_at'])
                or not 0 < payload['expires_at'] - time.time() <= 76
                or type(payload['responses']) is not list or len(payload['responses']) != 3
                or any(type(answer) is not str or not re.fullmatch(r'[0-9]{8}', answer) for answer in payload['responses'])):
            raise LeaseError()
        owned = _OwnedFile(self.sessions, identifier + '.json', _encoded(payload))
        self.owners[identifier] = {'connection': connection, 'file': owned, 'export': None, 'expiry': payload['expires_at']}
        state['session'] = identifier
        self._reply(connection, {'ok': True})

    def _export(self, identifier):
        if type(identifier) is not str or not SESSION.fullmatch(identifier) or identifier not in self.owners:
            raise LeaseError()
        record = self.owners[identifier]
        # An EOF already pending in the selector cannot be overtaken by export.
        try: pending = record['connection'].recv(1, socket.MSG_PEEK)
        except BlockingIOError: pending = None
        if pending == b'':
            self._drop(record['connection'])
            raise LeaseError()
        if record['expiry'] <= time.time(): raise LeaseError()  # Reject; never sweep/delete on expiry.
        record['file'].validate()
        if record['export'] is None:
            record['export'] = _OwnedFile(self.exports, 'challenge-' + identifier + '.json', record['file'].payload)
        else: record['export'].validate()

    def _request(self, connection, state, request):
        if state['session'] is not None:
            if request != {'action': 'close'}: raise LeaseError()
            record = self.owners.pop(state['session']); state['session'] = None
            self._reply(connection, {'ok': self._clean(record)})
            self._drop(connection)
        elif request.get('action') == 'register':
            self._register(connection, state, request)
        elif set(request) == {'action', 'session'} and request['action'] == 'export':
            self._export(request['session']); self._reply(connection, {'ok': True}); self._drop(connection)
        elif request == {'action': 'health'}:
            self._reply(connection, {'ok': self.failures == 0, 'active': len(self.owners), 'failures': self.failures})
            self._drop(connection)
        else: raise LeaseError()

    def _read(self, connection):
        state = self.clients[connection]
        raw = connection.recv(LIMIT + 1)
        if not raw: self._drop(connection); return
        state['buffer'].extend(raw)
        if len(state['buffer']) > LIMIT: raise LeaseError()
        while b'\n' in state['buffer'] and connection in self.clients:
            line, _, rest = state['buffer'].partition(b'\n'); state['buffer'][:] = rest
            self._request(connection, state, _decode(line))

    def _run(self):
        try:
            while True:
                for key, _ in self.selector.select():
                    if key.data == 'stop': return
                    if key.data == 'listener':
                        connection, _ = self.listener.accept()
                        try: admitted = len(self.clients) < MAX_CLIENTS and _peer_uid(connection) == self.uid
                        except Exception: admitted = False
                        if not admitted:
                            connection.close(); continue
                        connection.setblocking(False)
                        self.clients[connection] = {'buffer': bytearray(), 'session': None}
                        self.selector.register(connection, selectors.EVENT_READ, 'client')
                    elif key.fileobj in self.clients:
                        try: self._read(key.fileobj)
                        except Exception:
                            try: self._reply(key.fileobj, {'ok': False})
                            except Exception: pass
                            self._drop(key.fileobj)
        except Exception:
            self.failures += 1
        finally:
            for connection in list(self.clients): self._drop(connection)

    def check_health(self):
        if self.thread is None or not self.thread.is_alive() or self.failures:
            raise LeaseError()

    def close(self):
        if self.closed:
            if self.close_failed: raise LeaseError()
            return
        if self.thread is not None:
            self.wake_write.sendall(b'x'); self.thread.join(timeout=3)
            if self.thread.is_alive(): raise LeaseError()
            self.thread = None
        self.closed = True
        self.listener.close(); self.wake_read.close(); self.wake_write.close(); self.selector.close()
        try:
            self.base.validate()
            if _identity(os.stat(self.root / SOCKET, follow_symlinks=False)) != self.socket_identity:
                raise LeaseError()
            os.unlink(SOCKET, dir_fd=self.base.fd)
        except BaseException:
            self.close_failed = True
            raise
        finally:
            for directory in reversed(self.directories): directory.close()
        if self.failures:
            self.close_failed = True
            raise LeaseError()


def _connect(root):
    path = Path(root) / SOCKET
    before = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1):
        raise LeaseError()
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(2); connection.connect(str(path))
        if _peer_uid(connection) != os.geteuid() or _identity(os.stat(path, follow_symlinks=False)) != _identity(before):
            raise LeaseError()
        return connection
    except BaseException:
        connection.close(); raise


def _exchange(connection, request):
    connection.sendall(_encoded(request)); raw = bytearray()
    while b'\n' not in raw:
        chunk = connection.recv(LIMIT + 1)
        if not chunk or len(raw) + len(chunk) > LIMIT: raise LeaseError()
        raw.extend(chunk)
    line, _, rest = raw.partition(b'\n')
    if rest: raise LeaseError()
    response = _decode(line)
    if response.get('ok') is not True: raise LeaseError()
    return response


class ChallengeLease:
    def __init__(self, root, identifier, payload):
        self.connection = _connect(root)
        try: _exchange(self.connection, {'action': 'register', 'session': identifier, 'challenge': payload})
        except BaseException:
            self.connection.close(); self.connection = None; raise

    def close(self):
        if self.connection is None: return
        connection, self.connection = self.connection, None
        try: _exchange(connection, {'action': 'close'})
        finally: connection.close()


def export_challenge(root, identifier):
    with _connect(root) as connection:
        _exchange(connection, {'action': 'export', 'session': identifier})


def health(root):
    with _connect(root) as connection:
        return _exchange(connection, {'action': 'health'})
