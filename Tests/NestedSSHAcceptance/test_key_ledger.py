"""Offline only: fake Popen writes synthetic temp data; never executes keygen.
UID/GID changes are virtual stat metadata, not host setuid/chown operations.
"""
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import fd_safety as fs
import key_ledger as keys
import management_prep as core
import root_adapter as root
from test_management_prep import COMMENT, NONCE, ORIGINAL, public_line
from test_root_adapter import FakeProc, MASTER, OUTER, SHELL, TempOS

PRIVATE_SENTINEL = b'offline-synthetic-private-placeholder-NEVER-READ\n'


class LedgerOS(TempOS):
    def __init__(self, path):
        super().__init__(path)
        self.users, self.opened, self.read_names = {}, [], []
        self.fd_names, self.private_ids = {}, set()

    def _root(self, info):
        result = super()._root(info)
        result.st_uid = result.st_gid = self.users.get((info.st_dev, info.st_ino), 0)
        return result

    def mark(self, path, uid):
        info = os.stat(path, follow_symlinks=False)
        self.users[(info.st_dev, info.st_ino)] = uid

    def fchown(self, fd, uid, gid):
        assert uid == gid == 10000
        info = os.fstat(fd)
        self.users[(info.st_dev, info.st_ino)] = uid

    def open(self, path, *args, **kwargs):
        fd = super().open(path, *args, **kwargs)
        self.opened.append(str(path))
        self.fd_names[fd] = str(path)
        info = os.fstat(fd)
        if path == 'id_ed25519':
            self.private_ids.add((info.st_dev, info.st_ino))
        return fd

    def pread(self, fd, size, offset):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) in self.private_ids:
            raise AssertionError('private bytes must never be read')
        self.read_names.append(self.fd_names.get(fd, '?'))
        return os.pread(fd, size, offset)


class FakeChild:
    def __init__(self, statuses):
        self.statuses, self.events, self.returncode = list(statuses), [], None

    def wait(self, timeout):
        self.events.append(('wait', timeout))
        result = self.statuses.pop(0)
        if result == 'timeout':
            raise subprocess.TimeoutExpired('/usr/bin/ssh-keygen', timeout)
        if result == 'interrupt':
            raise KeyboardInterrupt()
        self.returncode = result
        return result

    def poll(self):
        return self.returncode

    def terminate(self):
        self.events.append(('term',))

    def kill(self):
        self.events.append(('kill',))


class KeyLedgerOfflineTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name)
        self.path.chmod(0o755)
        (self.path / 'run').mkdir(mode=0o755)
        self.fixture = self.path / 'run/openlxssh-fixture'
        self.fixture.mkdir(mode=0o755)
        self.auth = self.fixture / 'authorized_keys'
        self.auth.write_bytes(ORIGINAL)
        self.auth.chmod(0o644)
        (self.path / 'fixture').mkdir(mode=0o755)
        self.home = self.path / 'fixture/home'
        self.home.mkdir(mode=0o700)
        self.local = LedgerOS(self.path)
        self.local.mark(self.home, 10000)
        self.proc = FakeProc()
        self.children, self.calls = [], []
        self.statuses = [0]
        self.maker = self.make_files
        for target, name, value in ((fs, 'os', self.local), (root, 'os', self.local), (keys, 'os', self.local),
                                    (fs, 'linux_user', lambda uid: None), (root, 'ProcReader', lambda fd: self.proc),
                                    (keys, 'subprocess', SimpleNamespace(Popen=self.popen, DEVNULL=subprocess.DEVNULL,
                                                                        TimeoutExpired=subprocess.TimeoutExpired))):
            patcher = patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.owner = root.RootAdapter(NONCE, owned=(OUTER, SHELL), ssh_tokens=(OUTER.token,))
        self.ledger = None
        self.directory = self.home / ('.openlxssh-nested-' + NONCE)
        self.addCleanup(self.release)

    def release(self):
        if self.ledger is not None:
            try:
                self.ledger.close()
            except core.Refused:
                pass
        try:
            self.owner.close()
        except (core.Refused, OSError):
            pass

    def make_files(self):
        for name, data in ((keys.NAMES[0], PRIVATE_SENTINEL), (keys.NAMES[1], public_line('ssh-ed25519', 5, COMMENT))):
            fd = os.open(self.directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
            self.local.mark(self.directory / name, 10000)

    def popen(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        self.maker()
        child = FakeChild(self.statuses)
        self.children.append(child)
        return child

    def generate(self):
        self.ledger = keys.KeyLedger(self.owner)
        return self.ledger.generate()

    def restored(self):
        self.owner.append(self.ledger.receipt.new_public_line)
        self.proc.rows = {MASTER.pid: MASTER}
        self.owner.restore()

    def test_public_export_exact_uid10000_argv_no_private_reads_or_copy(self):
        exported = self.generate()
        self.assertEqual(exported, public_line('ssh-ed25519', 5, COMMENT))
        argv, options = self.calls[0]
        self.assertEqual(argv, core.key_plan(NONCE)['argv'])
        self.assertEqual((options['user'], options['group'], options['extra_groups'], options['umask']), (10000, 10000, (), 0o077))
        self.assertEqual((options['stdin'], options['stdout'], options['stderr']), (subprocess.DEVNULL,) * 3)
        self.assertFalse(options['shell'])
        self.assertTrue(options['close_fds'])
        self.assertEqual(options['env'], {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/fixture/home'})
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        for name in keys.NAMES:
            self.assertEqual((self.directory / name).stat().st_mode & 0o777, 0o600)
        self.assertNotIn('id_ed25519', self.local.read_names)
        self.assertFalse(any('client' in value or 'export' in value or 'known_hosts' in value for value in self.local.opened))
        self.assertNotIn(PRIVATE_SENTINEL.decode(), repr((exported, argv, options, self.ledger.receipt)))
        self.assertEqual(self.children[0].events, [('wait', 4.5)])

    def test_cleanup_same_live_root_receipts_after_restore_and_closed_ssh(self):
        self.generate()
        self.restored()
        self.ledger.cleanup()
        self.assertFalse(self.directory.exists())
        self.assertEqual(self.auth.read_bytes(), ORIGINAL)
        self.assertTrue(self.ledger.closed)
        self.assertTrue((self.fixture / ('nested-' + NONCE) / 'restored.json').exists())

    def test_boolean_restored_flag_alone_never_authorizes_cleanup(self):
        self.generate()
        self.owner.restored = True
        self.proc.rows = {MASTER.pid: MASTER}
        with self.assertRaises(core.Refused):
            self.ledger.cleanup()
        self.assertTrue((self.directory / keys.NAMES[0]).exists())

    def test_actual_restore_receipt_tamper_refuses_cleanup(self):
        self.generate()
        self.restored()
        (self.fixture / ('nested-' + NONCE) / 'restored.json').write_bytes(b'{}\n')
        with self.assertRaises(core.Refused):
            self.ledger.cleanup()
        self.assertEqual(set(os.listdir(self.directory)), set(keys.NAMES))

    def test_open_or_foreign_ssh_and_changed_auth_block_cleanup(self):
        self.generate()
        self.restored()
        self.proc.rows[OUTER.pid] = OUTER
        with self.assertRaises(core.Refused):
            self.ledger.cleanup()
        self.proc.rows = {MASTER.pid: MASTER}
        self.auth.write_bytes(ORIGINAL + b'# foreign\n')
        with self.assertRaises(core.Refused):
            self.ledger.cleanup()
        self.assertTrue((self.directory / keys.NAMES[0]).exists())

    def test_unknown_entry_keeps_all_owned_files(self):
        self.generate()
        self.restored()
        (self.directory / 'unknown').write_bytes(b'foreign')
        with self.assertRaises(core.Refused):
            self.ledger.cleanup()
        self.assertEqual(set(os.listdir(self.directory)), {*keys.NAMES, 'unknown'})

    def test_identical_private_bytes_replacement_inode_is_not_adopted(self):
        self.generate()
        self.restored()
        private = self.directory / keys.NAMES[0]
        private.rename(self.home / 'keep-original-private')
        private.write_bytes(PRIVATE_SENTINEL)
        private.chmod(0o600)
        self.local.mark(private, 10000)
        with self.assertRaises(core.Refused):
            self.ledger.cleanup()
        self.assertTrue(private.exists())
        self.assertTrue((self.directory / keys.NAMES[1]).exists())

    def test_hardlinked_or_symlinked_key_during_generation_refused(self):
        def linked():
            self.make_files()
            private = self.directory / keys.NAMES[0]
            os.link(private, self.home / 'outside-hardlink')
        self.maker = linked
        with self.assertRaises(core.Refused):
            self.generate()
        self.assertTrue((self.home / 'outside-hardlink').exists())
        self.assertTrue((self.directory / keys.NAMES[0]).exists())

    def test_symlink_public_generation_never_reads_target(self):
        target = self.home / 'foreign-public'
        target.write_bytes(public_line('ssh-ed25519', 5, COMMENT))
        def linked():
            self.make_files()
            (self.directory / keys.NAMES[1]).unlink()
            (self.directory / keys.NAMES[1]).symlink_to('../foreign-public')
        self.maker = linked
        with self.assertRaises(OSError):
            self.generate()
        self.assertNotIn('foreign-public', self.local.read_names)
        self.assertTrue(target.exists())

    def test_existing_nonce_directory_refused_before_keygen(self):
        self.directory.mkdir(mode=0o700)
        (self.directory / 'foreign').write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            keys.KeyLedger(self.owner)
        self.assertEqual(self.calls, [])
        self.assertEqual((self.directory / 'foreign').read_bytes(), b'keep')

    def test_generation_public_subject_and_distinctness_checks(self):
        def wrong_public():
            self.make_files()
            (self.directory / keys.NAMES[1]).write_bytes(public_line('ssh-ed25519', 1, COMMENT))
        self.maker = wrong_public
        with self.assertRaises(core.Refused):
            self.generate()
        self.assertIsNone(self.ledger.receipt)
        self.assertTrue((self.directory / keys.NAMES[0]).exists())

    def test_timeout_terms_kills_reaps_only_owned_fake_child(self):
        self.statuses = ['timeout', 'timeout', -9]
        with self.assertRaises(core.Refused):
            self.generate()
        self.assertEqual(self.children[0].events, [('wait', 4.5), ('term',), ('wait', 0.25), ('kill',), ('wait', 0.25)])
        self.assertIsNone(self.ledger.child)
        self.assertTrue((self.directory / keys.NAMES[0]).exists())
        self.assertEqual(len(self.children), 1)

    def test_interrupted_wait_and_nonzero_exit_suppress_tool_errors(self):
        self.statuses = ['interrupt', -15]
        with self.assertRaisesRegex(core.Refused, '^nested-keygen-refused$'):
            self.generate()
        self.assertEqual(self.children[0].events, [('wait', 4.5), ('term',), ('wait', 0.25)])
        self.assertIsNone(self.ledger.child)

    def test_nonzero_keygen_exit_never_exports_or_auto_deletes(self):
        self.statuses = [1]
        with self.assertRaisesRegex(core.Refused, '^nested-keygen-refused$'):
            self.generate()
        self.assertIsNone(self.ledger.receipt)
        self.assertEqual(self.children[0].events, [('wait', 4.5)])
        self.assertTrue((self.directory / keys.NAMES[0]).exists())

    def test_wrong_nonce_public_subject_refused(self):
        def wrong_subject():
            self.make_files()
            (self.directory / keys.NAMES[1]).write_bytes(public_line('ssh-ed25519', 5, 'OpenLXSSH-nested-' + 'a' * 32))
        self.maker = wrong_subject
        with self.assertRaises(core.Refused):
            self.generate()
        self.assertIsNone(self.ledger.receipt)
        self.assertTrue((self.directory / keys.NAMES[0]).exists())

    def test_unknown_directory_replacement_is_not_cleaned(self):
        self.generate()
        self.restored()
        old = self.home / 'old-ledger'
        self.directory.rename(old)
        self.directory.mkdir(mode=0o700)
        self.local.mark(self.directory, 10000)
        marker = self.directory / 'foreign'
        marker.write_bytes(b'keep')
        with self.assertRaises(core.Refused):
            self.ledger.cleanup()
        self.assertEqual(marker.read_bytes(), b'keep')
        self.assertEqual(set(os.listdir(old)), set(keys.NAMES))

    def test_unreaped_child_handle_retained_then_bounded_close_retries(self):
        self.statuses = ['timeout', 'timeout', 'timeout', -9]
        with self.assertRaisesRegex(core.Refused, '^nested-keygen-unreaped$'):
            self.generate()
        self.assertIs(self.ledger.child, self.children[0])
        self.ledger.close()
        self.assertIsNone(self.ledger.child)
        self.assertTrue(self.ledger.closed)
        self.assertTrue(self.directory.exists())

    def test_close_without_cleanup_preserves_files_and_closes_fds(self):
        self.generate()
        fds = [value[0] for value in self.ledger.files.values()]
        self.ledger.close()
        self.assertEqual(set(os.listdir(self.directory)), set(keys.NAMES))
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_cleanup_after_owner_close_or_nonce_mismatch_refused(self):
        self.generate()
        self.restored()
        self.owner.nonce = 'a' * 32
        with self.assertRaises(core.Refused):
            self.ledger.cleanup()
        self.owner.nonce = NONCE
        self.owner.close()
        with self.assertRaises(core.Refused):
            self.ledger.cleanup()
        self.assertTrue(self.directory.exists())


if __name__ == '__main__':
    unittest.main()
