#!/usr/bin/env python3
"""Pure own-file/fake-process/Swift typecheck only. No Docker, SSH, htop, PTY or signing."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest
from unittest import mock
ROOT = Path(__file__).absolute().parent

def probe():
    spec = importlib.util.spec_from_file_location('htop_fixed_offline', ROOT / 'remote_probe.py')
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value

def status():
    return dict(schema=1, stage='initialized', parent=dict(pid=321, startTicks=1000), htop=None, child=None, rows=None, cols=None, failure=None, configPresent=False)

class Tests(unittest.TestCase):
    def test_owned_status_and_known_config_cleanup_without_reading_content(self):
        value = probe()
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw).resolve(); owned = value.OwnedRun('a' * 32, parent)
            owned.publish(status())
            self.assertEqual(json.loads(os.pread(owned.status, 2048, 0)), status())
            self.assertEqual(stat.S_IMODE(owned.path.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((owned.path / 'status.json').stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError): value.OwnedRun('a' * 32, parent)
            (owned.path / 'htoprc').touch(mode=0o600)
            self.assertTrue(owned.config_present()); self.assertTrue(owned.close()); self.assertFalse(owned.path.exists())

    def test_replacement_and_unknown_entries_not_adopted_or_recursively_removed(self):
        value = probe()
        for replacement in ('file', 'symlink', 'unknown'):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as raw:
                owned = value.OwnedRun('b' * 32, Path(raw).resolve())
                if replacement == 'unknown': (owned.path / 'unknown').touch()
                else:
                    (owned.path / 'status.json').rename(owned.path / 'moved')
                    if replacement == 'file': (owned.path / 'status.json').touch(mode=0o600)
                    else: (owned.path / 'status.json').symlink_to(owned.path / 'moved')
                with self.assertRaises(value.Refused): owned.verify()
                self.assertFalse(owned.close()); self.assertTrue(owned.path.exists())

    def test_exact_start_and_closed_failure(self):
        value = probe()
        for data in (b'H\r', b'Q\n', b''):
            with mock.patch.object(value.time, 'monotonic', side_effect=[0, 1]), mock.patch.object(value.select, 'select', return_value=([0], [], [])), mock.patch.object(value.os, 'read', return_value=data):
                with self.assertRaises(value.Refused): value.exact_start()
        with mock.patch.object(value.time, 'monotonic', side_effect=[0, 1]), mock.patch.object(value.select, 'select', return_value=([0], [], [])), mock.patch.object(value.os, 'read', return_value=b'H\n'):
            value.exact_start()
        with mock.patch.object(value.os, 'getuid', return_value=123), mock.patch.object(value.subprocess, 'Popen', side_effect=AssertionError('live')):
            with self.assertRaises(value.Refused): value.run('a' * 32)
        with mock.patch.object(value, 'run', side_effect=RuntimeError('private')), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(value.main(['a' * 32]), 1)
        self.assertIn('preflight,source-error,none', output.getvalue()); self.assertNotIn('private', output.getvalue())

    def test_readiness_requires_exact_own_filtered_foreground_process_and_mode(self):
        value = probe(); process = mock.Mock(pid=322); process.poll.return_value = None
        fields = ['S', str(os.getpid()), '100', '100', '99'] + ['0'] * 15
        identity = dict(pid=322, startTicks=1000)
        def opened(_path, *_args, **_kwargs): return io.BytesIO(b'/usr/bin/htop\0--pid=323\0')
        with mock.patch.object(value, 'process_identity', return_value=(identity, fields)), mock.patch.object(value.Path, 'read_text', return_value='htop\n'), mock.patch.object(value.Path, 'open', opened), mock.patch.object(value.os, 'readlink', return_value='/dev/pts/4'), mock.patch.object(value.os, 'tcgetpgrp', return_value=100):
            with mock.patch.object(value.termios, 'tcgetattr', return_value=[0, 0, 0, value.termios.ICANON | value.termios.ECHO]):
                self.assertIsNone(value.ready_identity(process, 100, 99, '/dev/pts/4', 323))
            with mock.patch.object(value.termios, 'tcgetattr', return_value=[0, 0, 0, 0]):
                self.assertEqual(value.ready_identity(process, 100, 99, '/dev/pts/4', 323), identity)
                self.assertIsNone(value.ready_identity(process, 100, 99, '/dev/pts/4', 999))
            with self.assertRaises(value.Refused): value.ready_identity(process, 101, 99, '/dev/pts/4', 323)
        process.poll.return_value = 0
        with self.assertRaises(value.Refused): value.ready_identity(process, 100, 99, '/dev/pts/4', 323)

    def test_exact_own_reap_ignores_no_other_pid(self):
        value = probe(); process = mock.Mock(); process.poll.return_value = None
        process.wait.side_effect = [value.subprocess.TimeoutExpired('fixed', 2), -9]
        value.reap(process)
        self.assertEqual(process.mock_calls, [mock.call.poll(), mock.call.terminate(), mock.call.wait(timeout=2), mock.call.kill(), mock.call.wait(timeout=1)])
        first, second = mock.Mock(), mock.Mock()
        with mock.patch.object(value, 'reap', side_effect=[value.Deadline(), None]) as reaped:
            with self.assertRaises(value.Deadline): value.reap_owned((first, second))
        self.assertEqual(reaped.call_args_list, [mock.call(first), mock.call(second)])

    def test_readonly_management_is_fixed_bound_and_no_control_or_raw_config(self):
        source = (ROOT / 'StatusQuery.swift').read_text()
        reader = re.search(r'private static let reader = #"""\n(.*?)\n"""#', source, re.S)[1]
        compile(reader, '<readonly-exact-status-reader>', 'exec')
        for required in ('expected_pid', 'expected_start', 'ddev', 'sino', 'LOCK_SH', 'LOCK_NB', 'st_ctime_ns', 'named_after', '/status', '1253a29501483eb71f80e39b9af5c85e10c3a49329d5e93700fecd3f00f334f2'):
            self.assertIn(required, source)
        for forbidden in ('O_WRONLY', 'os.kill', '/cmdline', '/environ', 'htoprc', 'sendInput'):
            self.assertNotIn(forbidden, reader)
        main = (ROOT / 'Main.swift').read_text()
        self.assertLess(main.index('report.readinessVerified = true'), main.index('session.terminal.resize(cols: HPlan.width'))
        self.assertLess(main.index('report.remoteSizeMatched = true'), main.index('enqueue(HPlan.quit'))
        self.assertIn('session.sendInput(data)', main); self.assertIn('HStatusBudget(parent: binding.parent)', main)
        probe_source = (ROOT / 'remote_probe.py').read_text()
        for required in ("'/usr/bin/htop', '--pid='", "'HTOPRC': str(owned.path / 'htoprc')", 'signal.alarm(120)', 'os.pidfd_open', 'termios.tcgetattr(0) != original'):
            self.assertIn(required, probe_source)
        for forbidden in ('F9', 'capture-pane', 'shell=True', 'pkill', 'killall', 'password.txt', 'read_text().splitlines()'):
            self.assertNotIn(forbidden, probe_source)

    def test_management_reader_rejects_replacement_and_unstable_status_in_memory(self):
        source = (ROOT / 'StatusQuery.swift').read_text()
        reader = re.search(r'private static let reader = #"""\n(.*?)\n"""#', source, re.S)[1]
        value = status(); value.update(stage='ready', htop=dict(pid=322, startTicks=1001), child=dict(pid=323, startTicks=1002))
        raw = json.dumps(value).encode()
        def info(device, inode, mode, length=0, tick=1):
            return mock.Mock(st_dev=device, st_ino=inode, st_mode=mode, st_uid=10000, st_nlink=1, st_size=length, st_mtime_ns=tick, st_ctime_ns=tick)
        directory = info(113, 10, stat.S_IFDIR | 0o700)
        before = info(113, 11, stat.S_IFREG | 0o600, len(raw))
        argv = ['reader', 'a' * 32, '321', '1000', '113', '10', '113', '11']
        procstat = '321 (python3) S ' + ' '.join(['0'] * 18 + ['1000'])
        for scenario in ('valid', 'replaced', 'unstable', 'wrong-parent'):
            with self.subTest(scenario=scenario):
                after = info(113, 11, stat.S_IFREG | 0o600, len(raw), 2 if scenario == 'unstable' else 1)
                named = info(113, 12 if scenario == 'replaced' else 11, stat.S_IFREG | 0o600, len(raw))
                payload = dict(value)
                if scenario == 'wrong-parent': payload['parent'] = dict(pid=321, startTicks=999)
                def opened(path, *_args, **_kwargs):
                    return io.StringIO(procstat if str(path).endswith('/stat') else 'Uid:\t10000\t10000\t10000\t10000\n')
                with mock.patch('sys.argv', argv), mock.patch('os.getuid', return_value=10000), mock.patch('os.open', side_effect=[90, 91, 92]), mock.patch('os.close'), mock.patch('os.fstat', side_effect=[directory, before, after]), mock.patch('os.stat', side_effect=[named, named]), mock.patch('os.read', return_value=json.dumps(payload).encode() if scenario == 'wrong-parent' else raw), mock.patch('fcntl.flock'), mock.patch('builtins.open', opened), contextlib.redirect_stdout(io.StringIO()) as output:
                    if scenario == 'valid': exec(compile(reader, '<strict-reader-pure>', 'exec'), {})
                    else:
                        with self.assertRaises(SystemExit): exec(compile(reader, '<strict-reader-pure>', 'exec'), {})
                if scenario == 'valid': self.assertEqual(json.loads(output.getvalue()), value)
                else: self.assertEqual(output.getvalue(), '')

    def test_frozen_nine_objects_and_pure_swift_consumer_typecheck(self):
        manifest = json.loads((ROOT / 'frozen-inputs.json').read_text())
        self.assertEqual(len(manifest['dependencyObjects']), 9)
        for item in manifest['dependencyObjects']: self.assertEqual(hashlib.sha256(Path(item['path']).read_bytes()).hexdigest(), item['sha256'])
        with tempfile.TemporaryDirectory(prefix='htop-core-', dir=ROOT / '.build') as raw:
            work = Path(raw)
            def run(argv):
                result = subprocess.run(list(map(str, argv)), cwd=ROOT, capture_output=True, timeout=120)
                self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
                return result.stdout.decode()
            compiler = run(['/usr/bin/xcrun', '-f', 'swiftc']).strip(); sdk = run(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path']).strip()
            flags = ['-parse-as-library', '-swift-version', '6', '-target', 'arm64-apple-macosx15.0', '-sdk', sdk, '-warnings-as-errors', '-module-cache-path', work / 'module-cache', '-I', manifest['moduleDirectory'], '-I', work]
            base = next(item['path'] for item in manifest['dependencyObjects'] if Path(item['path']).stem == 'RemoteTerminalCore')
            run([compiler, *flags, '-emit-library', '-emit-module', '-module-name', 'HTOPCore', ROOT / 'Core.swift', base, '-emit-module-path', work / 'HTOPCore.swiftmodule', '-o', work / 'libHTOPCore.dylib'])
            run([compiler, *flags, ROOT / 'OfflineMain.swift', base, '-L', work, '-lHTOPCore', '-Xlinker', '-rpath', '-Xlinker', work, '-o', work / 'offline'])
            self.assertIn('HTOP pure core checks passed', run([work / 'offline']))
            location = work / 'BuildLocation.swift'; location.write_text('enum BuildLocation { static let ownRoot="/not/opened"; static let buildRoot="/not/opened"; static let fixtureRoot="/not/opened"; static let team="UNSIGNED00"; static let probeBase64=""; static let probeSHA256="" }\n')
            run([compiler, *flags, '-typecheck', '-I', Path(manifest['parentCheckpoint']) / 'cmodules', ROOT / 'Main.swift', ROOT / 'LiveInput.swift', ROOT / 'StatusQuery.swift', location])

if __name__ == '__main__': unittest.main(verbosity=2)
