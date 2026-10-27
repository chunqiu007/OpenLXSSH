"""NEST-MANAGEMENT-ADAPTER-A, source/offline review point; no CLI or import I/O.

Linux-root fixed fixture only. Caller owns a live object/FD ledger; a recovered
receipt is a clue, NEVER permission to adopt a file/lock/case. flock serializes
only cooperating management. /proc checks plus whole-byte hashes are NOT an
atomic CAS against foreign writers/authentication. Keep exclusion externally.
No key generation, SSH transport, private-key read, daemon or broad cleanup here.
"""
import fcntl
import json
import os

import fd_safety as fs
import management_prep as core
from session_metadata import ProcReader, SessionGate


def public_json(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')


class RootAdapter:
    def __init__(self, nonce, *, owned, ssh_tokens):
        self.closed = True  # An incomplete constructor must not unlock a foreign name.
        fs.linux_user(0)
        core.key_plan(nonce)
        self.fixture = self.case = self.proc = self.lock = self.auth = None
        self.receipts = {}
        self.receipt = self.prepared_hash = self.appended_state = None
        self.restored = self.mutation_attempted = self.closed = False
        try:
            self.fixture = fs.Directories((('run', 0, 0o755), ('openlxssh-fixture', 0, 0o755)))
            self.lock = os.open('nested-management.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | fs.NOFOLLOW,
                                0o600, dir_fd=self.fixture.fd)
            fs.regular(os.fstat(self.lock), 0, 0o600)
            self.lock_identity = fs.identity(os.fstat(self.lock))
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.fsync(self.lock)
            os.fsync(self.fixture.fd)
            self.case = fs.Directories((('run', 0, 0o755), ('openlxssh-fixture', 0, 0o755)))
            self.case.create('nested-' + nonce, 0)
            self.auth = os.open('authorized_keys', os.O_RDWR | fs.NOFOLLOW, dir_fd=self.fixture.fd)
            self.proc = ProcReader(self.fixture.fd)
            self.gate = SessionGate(self.proc, owned, ssh_tokens)
            self.nonce = nonce
            self._exclusion()
            self._observed()
        except BaseException:
            self.close()  # No restore unless append was verified and owned.
            raise

    def __enter__(self):
        core.require(not self.closed)
        return self

    def __exit__(self, _kind, _error, _traceback):
        self.close()  # No signal handler/daemon; caller enforces its bounded TTL.

    def _exclusion(self, *, closed=False):
        self.fixture.verify()
        self.case.verify()
        fs.regular(os.fstat(self.lock), 0, 0o600)
        core.require(fs.identity(os.fstat(self.lock)) == self.lock_identity)
        core.require(fs.identity(os.stat('nested-management.lock', dir_fd=self.fixture.fd,
                                       follow_symlinks=False)) == self.lock_identity)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.last_sessions = self.gate.check(closed=closed)  # Not caller booleans/counts.
        return core.Exclusion(True, self.last_sessions['foreign_sessions'])

    def register_owned(self, owned, ssh_tokens):
        """Only explicit, independently ACK-confirmed owned processes may be added."""
        self.fixture.verify()
        self.gate.register(owned, ssh_tokens)
        self._exclusion()

    def _observed(self):
        self.fixture.verify()
        before = fs.version(os.fstat(self.auth))
        data = fs.read_held(self.fixture.fd, 'authorized_keys', self.auth, 0, 0o644, core.LIMIT)
        held = os.fstat(self.auth)
        named = os.stat('authorized_keys', dir_fd=self.fixture.fd, follow_symlinks=False)
        core.require(fs.version(held) == fs.version(named) == before)
        return core.Observation(core.Stamp(*fs.identity(held)), core.Stamp(*fs.identity(named)), True, data)

    def _receipt_hash(self, name):
        self.case.verify()
        return core.digest(fs.read_held(self.case.fd, name, self.receipts[name], 0, 0o600))

    def append(self, new_public_line):
        core.require(self.receipt is None and not self.restored)
        self.receipt = core.prepare(self.nonce, self._observed(), new_public_line, self._exclusion())
        raw = core.public_receipt(self.receipt)  # Only validated original/new public keys.
        fs.durable_public(self.case, 'prepared.json', raw, self.receipts)
        self.prepared_hash = self._receipt_hash('prepared.json')
        exclusion = self._exclusion()
        suffix = core.append_suffix(self.receipt, self._observed(), exclusion, self.prepared_hash)
        self.mutation_attempted = True
        fs.write_all(self.auth, suffix, len(self.receipt.original))
        os.fsync(self.auth)
        after = self._observed()
        core.require(after.held == self.receipt.stamp and after.data == self.receipt.original + suffix)
        # Only a complete, read-back own append may be compensated later.
        self.appended_state = fs.version(os.fstat(self.auth))
        fs.durable_public(self.case, 'appended.json', public_json({
            'schema': 1, 'case': 'NESTrealpublickeyonly', 'prepared_sha256': self.prepared_hash,
            'appended_sha256': core.digest(after.data), 'stamp': after.held._asdict(),
        }), self.receipts)
        return self.prepared_hash

    def restore(self):
        core.require(self.appended_state is not None and not self.restored)
        exclusion = self._exclusion(closed=True)
        current = self._observed()
        core.require(fs.version(os.fstat(self.auth)) == self.appended_state)
        expected = core.restore_original(self.receipt, current, exclusion,
                                         self._receipt_hash('prepared.json'), owned_ssh_closed=True)
        # Durable restore intent first; state/identity are checked again after fsync.
        raw = public_json({'schema': 1, 'case': 'NESTrealpublickeyonly', 'phase': 'restore-intent',
                           'prepared_sha256': self.prepared_hash, 'original_sha256': core.digest(expected)})
        if 'restore-intent.json' not in self.receipts:
            fs.durable_public(self.case, 'restore-intent.json', raw, self.receipts)
        core.require(self._receipt_hash('restore-intent.json') == core.digest(raw))
        exclusion = self._exclusion(closed=True)
        expected = core.restore_original(self.receipt, self._observed(), exclusion,
                                         self._receipt_hash('prepared.json'), owned_ssh_closed=True)
        core.require(fs.version(os.fstat(self.auth)) == self.appended_state)
        # Prefix is unchanged: shrinking removes ONLY the verified own public suffix.
        os.ftruncate(self.auth, len(expected))
        os.fsync(self.auth)
        after = self._observed()
        core.require(after.held == self.receipt.stamp and after.data == expected)
        self.restored = True
        fs.durable_public(self.case, 'restored.json', public_json({
            'schema': 1, 'case': 'NESTrealpublickeyonly', 'phase': 'restored',
            'prepared_sha256': self.prepared_hash, 'original_sha256': core.digest(after.data),
        }), self.receipts)
        return core.digest(after.data)

    def close(self):
        """Compensate only confirmed append; always close FDs, retain unsafe lock."""
        if self.closed:
            return
        safe = not self.mutation_attempted or self.restored
        failure = None
        try:
            if not safe and self.appended_state is not None:
                self.restore()
                safe = True
        except BaseException as error:
            failure = error
        finally:
            if self.proc is not None:
                self.proc.close()
                self.proc = None
            for fd in self.receipts.values():
                os.close(fd)
            self.receipts.clear()
            if self.auth is not None:
                os.close(self.auth)
                self.auth = None
            if self.lock is not None:
                try:
                    self.fixture.verify()
                    named = os.stat('nested-management.lock', dir_fd=self.fixture.fd, follow_symlinks=False)
                    if safe and fs.identity(named) == fs.identity(os.fstat(self.lock)) == getattr(self, 'lock_identity', None):
                        os.unlink('nested-management.lock', dir_fd=self.fixture.fd)
                        os.fsync(self.fixture.fd)
                except BaseException as error:
                    failure = failure or error
                finally:
                    os.close(self.lock)
                    self.lock = None
            for tree in (self.case, self.fixture):
                if tree is not None:
                    tree.close()
            self.closed = True
        if failure is not None:
            raise core.Refused('nested-root-close-refused') from None
        core.require(safe)
        # Public receipts deliberately survive; not a cleanup authority.
