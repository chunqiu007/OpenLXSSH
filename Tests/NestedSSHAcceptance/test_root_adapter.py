"""Tempfile FD tests only: fake root metadata/fixed paths, no Linux services.
No ssh/keygen/Docker, no real fixture paths, no host UID changes or live /proc.
"""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import fd_safety as fs
import management_prep as core
import root_adapter as adapter
from session_metadata import Process, SessionGate, parse_process
from test_management_prep import COMMENT, NONCE, ORIGINAL, public_line

MASTER = Process(1, 0, 10, (0, 0, 0, 0), 'sshd')
OUTER = Process(20, 1, 20, (0, 0, 0, 0), 'sshd')
SHELL = Process(21, 20, 21, (10000, 10000, 10000, 10000), 'bash')


class FakeProc:
    master = MASTER

    def __init__(self):
        self.rows = {item.pid: item for item in (MASTER, OUTER, SHELL)}
        self.scans = 0

    def scan(self):
        self.scans += 1
        return dict(self.rows)

    def close(self):
        pass


class TempOS:
    """Real temp FDs; only UID/GID and the fixed '/' root are simulated."""
    def __init__(self, root):
        self.root, self.synced = str(root), []

    def __getattr__(self, name):
        return getattr(os, name)

    def _path(self, path):
        if path == '/':
            return self.root
        if isinstance(path, str) and path.startswith('/'):
            raise AssertionError('offline test attempted an absolute fixture path')
        return path

    def open(self, path, *args, **kwargs):
        return os.open(self._path(path), *args, **kwargs)

    @staticmethod
    def _root(info):
        values = {name: getattr(info, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
        return SimpleNamespace(st_uid=0, st_gid=0, **values)

    def fstat(self, fd):
        return self._root(os.fstat(fd))

    def stat(self, path, *args, **kwargs):
        return self._root(os.stat(self._path(path), *args, **kwargs))

    def fsync(self, fd):
        self.synced.append(fd)
        return os.fsync(fd)


class RootAdapterOfflineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o755)
        (self.root / 'run').mkdir(mode=0o755)
        self.fixture = self.root / 'run/openlxssh-fixture'
        self.fixture.mkdir(mode=0o755)
        self.auth_path = self.fixture / 'authorized_keys'
        self.auth_path.write_bytes(ORIGINAL)
        self.auth_path.chmod(0o644)
        self.case = self.fixture / ('nested-' + NONCE)
        self.local = TempOS(self.root)
        self.proc = FakeProc()
        for target, name, value in ((fs, 'os', self.local), (adapter, 'os', self.local),
                                    (fs, 'linux_user', lambda uid: None), (adapter, 'ProcReader', lambda fd: self.proc)):
            patcher = patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.owner = None
        self.addCleanup(self.release_fds)
        self.new = public_line('ssh-ed25519', 5, COMMENT)

    def release_fds(self):
        if self.owner is not None:
            try:
                self.owner.close()
            except (core.Refused, OSError):
                pass

    def open(self):
        self.owner = adapter.RootAdapter(NONCE, owned=(OUTER, SHELL), ssh_tokens=(OUTER.token,))
        return self.owner

    def close_owned_ssh(self):
        self.proc.rows = {MASTER.pid: MASTER}

    def test_real_temp_fd_append_restore_and_durable_public_receipts(self):
        owner = self.open()
        prepared_hash = owner.append(self.new)
        self.assertEqual(self.auth_path.read_bytes(), ORIGINAL + self.new)
        prepared = (self.case / 'prepared.json').read_bytes()
        self.assertEqual(prepared_hash, core.digest(prepared))
        self.assertEqual(''.join(json.loads(prepared)['original_public_lines']).encode(), ORIGINAL)
        for name, fd in owner.receipts.items():
            self.assertEqual(os.stat(self.case / name).st_mode & 0o777, 0o600)
            self.assertIn(fd, self.local.synced)
        self.assertIn(owner.case.fd, self.local.synced)
        self.assertIn(owner.auth, self.local.synced)
        self.close_owned_ssh()
        self.assertEqual(owner.restore(), core.digest(ORIGINAL))
        self.assertEqual(self.auth_path.read_bytes(), ORIGINAL)
        self.assertTrue(owner.restored)
        self.assertTrue((self.case / 'restore-intent.json').is_file())
        self.assertTrue((self.case / 'restored.json').is_file())
        owner.close()
        self.assertFalse((self.fixture / 'nested-management.lock').exists())
        self.assertTrue((self.case / 'prepared.json').is_file())  # Receipt retained, not adopted/removed.

    def test_file_and_parent_sync_precede_first_auth_write(self):
        owner = self.open()
        actual = fs.write_all
        def checked(fd, data, offset=0):
            if fd == owner.auth:
                self.assertIn(owner.receipts['prepared.json'], self.local.synced)
                self.assertIn(owner.case.fd, self.local.synced)
                self.assertEqual(self.auth_path.read_bytes(), ORIGINAL)
                self.assertEqual(core.digest((self.case / 'prepared.json').read_bytes()), owner.prepared_hash)
            return actual(fd, data, offset)
        with patch.object(fs, 'write_all', checked):
            owner.append(self.new)
        self.close_owned_ssh()

    def test_existing_lock_or_case_is_not_adopted(self):
        foreign = self.fixture / 'nested-management.lock'
        foreign.write_bytes(b'foreign')
        foreign.chmod(0o600)
        with self.assertRaises(FileExistsError):
            self.open()
        self.assertEqual(foreign.read_bytes(), b'foreign')
        foreign.unlink()
        self.case.mkdir(mode=0o700)
        marker = self.case / 'foreign'
        marker.write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            self.open()
        self.assertEqual(marker.read_bytes(), b'keep')
        self.assertEqual(self.auth_path.read_bytes(), ORIGINAL)

    def test_real_flock_excludes_second_cooperating_owner(self):
        owner = self.open()
        fd = os.open(self.fixture / 'nested-management.lock', os.O_RDWR)
        try:
            with self.assertRaises(BlockingIOError):
                adapter.fcntl.flock(fd, adapter.fcntl.LOCK_EX | adapter.fcntl.LOCK_NB)
        finally:
            os.close(fd)
        self.assertFalse(owner.mutation_attempted)

    def test_authorized_symlink_and_hardlink_refused(self):
        target = self.fixture / 'other'
        self.auth_path.rename(target)
        self.auth_path.symlink_to('other')
        with self.assertRaises(OSError):
            self.open()
        self.auth_path.unlink()
        target.rename(self.auth_path)
        # Constructor's own empty case remains; this is not a reusable/adoptable case.
        self.case.rmdir()
        os.link(self.auth_path, target)
        with self.assertRaises(core.Refused):
            self.open()
        self.assertEqual(target.read_bytes(), ORIGINAL)

    def test_receipt_exclusive_name_and_failed_fsync_prevent_mutation(self):
        owner = self.open()
        (self.case / 'prepared.json').write_bytes(b'foreign')
        with self.assertRaises(FileExistsError):
            owner.append(self.new)
        self.assertEqual(self.auth_path.read_bytes(), ORIGINAL)
        self.assertEqual((self.case / 'prepared.json').read_bytes(), b'foreign')
        self.assertFalse(owner.mutation_attempted)

    def test_identical_bytes_receipt_new_inode_is_not_adopted(self):
        owner = self.open()
        owner.append(self.new)
        self.close_owned_ssh()
        prepared = self.case / 'prepared.json'
        original = prepared.read_bytes()
        prepared.rename(self.case / 'prepared-old.json')
        prepared.write_bytes(original)
        prepared.chmod(0o600)
        with self.assertRaises(core.Refused):
            owner.restore()
        self.assertEqual(self.auth_path.read_bytes(), ORIGINAL + self.new)
        self.assertEqual(prepared.read_bytes(), original)

    def test_partial_fd_reads_and_writes_are_completed(self):
        owner = self.open()
        def small_read(fd, size, offset):
            return os.pread(fd, min(size, 37), offset)
        def small_write(fd, value, offset):
            return os.pwrite(fd, value[:31], offset)
        with patch.object(self.local, 'pread', small_read, create=True), patch.object(self.local, 'pwrite', small_write, create=True):
            owner.append(self.new)
            self.close_owned_ssh()
            owner.restore()
        self.assertEqual(self.auth_path.read_bytes(), ORIGINAL)

    def test_mid_read_auth_change_refuses_before_append(self):
        owner = self.open()
        changed = []
        def edit_after_read(fd, size, offset):
            value = os.pread(fd, size, offset)
            if fd == owner.auth and not changed:
                changed.append(True)
                os.pwrite(fd, b'X', 0)
            return value
        with patch.object(self.local, 'pread', edit_after_read, create=True):
            with self.assertRaises(core.Refused):
                owner.append(self.new)
        self.assertFalse(owner.mutation_attempted)
        self.assertEqual(self.auth_path.read_bytes(), b'X' + ORIGINAL[1:])

    def test_receipt_fsync_failure_prevents_auth_write(self):
        owner = self.open()
        with patch.object(self.local, 'fsync', side_effect=OSError('simulated fsync failure')):
            with self.assertRaises(OSError):
                owner.append(self.new)
        self.assertEqual(self.auth_path.read_bytes(), ORIGINAL)
        self.assertFalse(owner.mutation_attempted)

    def test_receipt_tampering_or_link_replacement_refuses_restore(self):
        owner = self.open()
        owner.append(self.new)
        self.close_owned_ssh()
        (self.case / 'prepared.json').write_bytes(b'{}\n')
        with self.assertRaises(core.Refused):
            owner.restore()
        self.assertEqual(self.auth_path.read_bytes(), ORIGINAL + self.new)
        with self.assertRaises(core.Refused):
            owner.close()
        self.assertTrue((self.fixture / 'nested-management.lock').exists())

    def test_identical_bytes_new_auth_inode_refused_and_preserved(self):
        owner = self.open()
        owner.append(self.new)
        old = self.fixture / 'old'
        self.auth_path.rename(old)
        self.auth_path.write_bytes(ORIGINAL + self.new)
        self.auth_path.chmod(0o644)
        self.close_owned_ssh()
        with self.assertRaises(core.Refused):
            owner.restore()
        self.assertEqual(self.auth_path.read_bytes(), ORIGINAL + self.new)
        self.assertEqual(old.read_bytes(), ORIGINAL + self.new)

    def test_foreign_append_is_never_overwritten_by_finally(self):
        owner = self.open()
        owner.append(self.new)
        foreign = ORIGINAL + self.new + b'# foreign\n'
        self.auth_path.write_bytes(foreign)
        self.close_owned_ssh()
        auth_fd = owner.auth
        with self.assertRaises(core.Refused):
            owner.close()
        self.assertEqual(self.auth_path.read_bytes(), foreign)
        self.assertTrue((self.fixture / 'nested-management.lock').exists())
        with self.assertRaises(OSError):
            os.fstat(auth_fd)

    def test_partial_append_is_not_confirmed_or_auto_compensated(self):
        owner = self.open()
        actual = fs.write_all
        def partial(fd, data, offset=0):
            if fd == owner.auth:
                os.pwrite(fd, data[:7], offset)
                raise OSError('simulated short-write failure')
            return actual(fd, data, offset)
        with patch.object(fs, 'write_all', partial):
            with self.assertRaises(OSError):
                owner.append(self.new)
        self.close_owned_ssh()
        with self.assertRaises(core.Refused):
            owner.close()
        self.assertEqual(self.auth_path.read_bytes(), ORIGINAL + self.new[:7])
        self.assertTrue((self.fixture / 'nested-management.lock').exists())

    def test_exception_context_restores_only_confirmed_closed_ssh_append(self):
        owner = self.open()
        with self.assertRaisesRegex(RuntimeError, 'offline-body-error'):
            with owner:
                owner.append(self.new)
                self.close_owned_ssh()
                raise RuntimeError('offline-body-error')
        self.assertEqual(self.auth_path.read_bytes(), ORIGINAL)
        self.assertTrue(owner.closed and owner.restored)

    def test_compensation_only_confirmed_append_with_closed_owned_ssh(self):
        owner = self.open()
        owner.append(self.new)
        self.close_owned_ssh()
        owner.close()  # Same method used by future explicit exception/TTL finally.
        self.assertEqual(self.auth_path.read_bytes(), ORIGINAL)
        self.assertTrue(owner.restored)

    def test_open_ssh_or_foreign_uid_process_blocks_restore(self):
        owner = self.open()
        owner.append(self.new)
        with self.assertRaises(core.Refused):
            owner.restore()
        self.close_owned_ssh()
        self.proc.rows[90] = Process(90, 1, 90, (10000,) * 4, 'python3')
        with self.assertRaises(core.Refused):
            owner.restore()
        self.assertEqual(self.auth_path.read_bytes(), ORIGINAL + self.new)

    def test_case_parent_replacement_and_restore_receipt_tamper_refused(self):
        owner = self.open()
        owner.append(self.new)
        self.close_owned_ssh()
        actual = fs.durable_public
        def tamper(tree, name, data, ledger):
            result = actual(tree, name, data, ledger)
            if name == 'restore-intent.json':
                os.pwrite(ledger[name], b'X', 0)
            return result
        with patch.object(fs, 'durable_public', tamper):
            with self.assertRaises(core.Refused):
                owner.restore()
        self.assertEqual(self.auth_path.read_bytes(), ORIGINAL + self.new)
        old = self.fixture / 'old-case'
        self.case.rename(old)
        self.case.mkdir(mode=0o700)
        with self.assertRaises(core.Refused):
            owner.restore()
        self.assertTrue((old / 'prepared.json').exists())


class SessionMetadataOfflineTests(unittest.TestCase):
    def test_parse_fixed_public_proc_fields_not_argv(self):
        tail = [b'S', b'1'] + [b'0'] * 17 + [b'123'] + [b'0'] * 4
        raw = b'20 (sshd) ' + b' '.join(tail)
        item = parse_process(20, b'Name:\tsshd\nUid:\t0\t0\t0\t0\n', raw, b'sshd\n')
        self.assertEqual(item, Process(20, 1, 123, (0,) * 4, 'sshd'))
        with self.assertRaises(core.Refused):
            parse_process(21, b'Uid: 0 0 0 0\n', raw, b'sshd\n')
        with self.assertRaises(core.Refused):
            parse_process(20, b'Uid: broken\n', raw, b'sshd\n')

    def test_process_reuse_foreign_sshd_and_scan_churn_refused(self):
        reader = FakeProc()
        gate = SessionGate(reader, (OUTER, SHELL), (OUTER.token,))
        self.assertEqual(gate.check()['foreign_sessions'], 0)
        reader.rows[20] = Process(20, 1, 999, (0,) * 4, 'sshd')
        with self.assertRaises(core.Refused):
            gate.check(closed=True)
        reader.rows = {1: MASTER, 90: Process(90, 1, 90, (0,) * 4, 'sshd')}
        with self.assertRaises(core.Refused):
            gate.check(closed=True)
        reader.rows = {1: MASTER}
        self.assertTrue(gate.check(closed=True)['owned_ssh_closed'])
        actual = reader.scan
        calls = []
        def churn():
            calls.append(1)
            return actual() if len(calls) % 2 else {**actual(), 99: Process(99, 1, 99, (10000,) * 4, 'bash')}
        with patch.object(reader, 'scan', churn), self.assertRaises(core.Refused):
            gate.check()

    def test_explicit_owned_nested_registration_and_parent_chain(self):
        reader = FakeProc()
        gate = SessionGate(reader, (OUTER, SHELL), (OUTER.token,))
        nested = Process(30, SHELL.pid, 30, (10000,) * 4, 'ssh')
        reader.rows[30] = nested
        with self.assertRaises(core.Refused):
            gate.check()
        gate.register((nested,), (nested.token,))
        self.assertIn(nested.token, gate.check()['owned'])
        reader.rows = {1: MASTER}
        self.assertTrue(gate.check(closed=True)['owned_ssh_closed'])
        reader = FakeProc()
        orphan = Process(40, 999, 40, (10000,) * 4, 'ssh')
        reader.rows[40] = orphan
        with self.assertRaises(core.Refused):
            SessionGate(reader, (OUTER, SHELL, orphan), (orphan.token,))

    def test_cannot_omit_owned_ssh_token_to_claim_closed(self):
        reader = FakeProc()
        with self.assertRaises(core.Refused):
            SessionGate(reader, (OUTER, SHELL), ())
        gate = SessionGate(reader, (OUTER, SHELL), (OUTER.token,))
        nested = Process(30, SHELL.pid, 30, (10000,) * 4, 'ssh')
        reader.rows[30] = nested
        with self.assertRaises(core.Refused):
            gate.register((nested,), ())

    def test_non_linux_guard_rejects_before_any_fixture_open(self):
        with patch.object(fs, 'sys', SimpleNamespace(platform='darwin')):
            with patch.object(fs, 'Directories', side_effect=AssertionError('must not open')):
                with self.assertRaises(core.Refused):
                    adapter.RootAdapter(NONCE, owned=(), ssh_tokens=())


if __name__ == '__main__':
    unittest.main()
