"""Offline harness checks only. Temp FD tests and fake Popen/stdin; no fixture tools."""
import ast
import base64
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import fd_safety as fs
import host_case as host
import recovery_public as recovery
import remote_bootstrap as remote
from test_management_prep import NONCE
from test_root_adapter import TempOS


class HostSourceTests(unittest.TestCase):
    def test_fixed_bundle_has_only_eight_public_modules_and_exact_signed_plan(self):
        with patch.object(host.manager_control, 'RootAdapter', side_effect=AssertionError('no root adapter')):
            plan, envelope = host.bundle()
        self.assertEqual(plan['app'], str(host.APP))
        self.assertEqual(host.sha(base64.b64decode(envelope['workplan_base64'])), host.PLAN_SHA256)
        self.assertEqual(set(envelope['modules_base64']), set(remote.NAMES))
        self.assertEqual(len(remote.NAMES), 8)
        self.assertLess(len(json.dumps(envelope)), 196608)
        for name, value in envelope['modules_base64'].items():
            self.assertEqual(host.sha(base64.b64decode(value)), plan['source_sha256'][name + '.py'])

    def test_old_recovery_refuses_rebound_new_bundle(self):
        with self.assertRaises(ValueError):
            recovery.payload()  # Fixed NONCE check before any remote command.

    def test_default_validate_no_files_processes_or_bundle_reads(self):
        with patch.object(host, 'Case', side_effect=AssertionError('no Case')), patch.object(host, 'bundle', side_effect=AssertionError('no read')):
            with patch('sys.stdout', io.StringIO()):
                self.assertEqual(host.main([]), 0)
                self.assertEqual(host.main(['--validate']), 0)
            with self.assertRaises(ValueError):
                host.main(['--authorized-local-fixture'])

    def test_deadlines_keep_thirty_seconds_cleanup_and_clamp_remaining(self):
        case = host.Case.__new__(host.Case)
        case.work_end, case.hard = 330, 360
        with patch.object(host.time, 'monotonic', return_value=329):
            self.assertEqual(case.left(200), 1)
            self.assertEqual(case.left(200, cleanup=True), 31)
        with patch.object(host.time, 'monotonic', return_value=331):
            with self.assertRaises(ValueError):
                case.left(5)
            self.assertEqual(case.left(30, cleanup=True), 29)

    def test_native_closed_requires_report_pid_absent_not_just_flag(self):
        case = host.Case.__new__(host.Case)
        case.save = lambda *args: None
        report = {'closed': True, 'ownedPIDReleased': True, 'ownedPID': 1234,
                  'postAuth': {'lastObservedSession': {'state': 'closed'}}}
        with patch.object(host.os, 'kill', side_effect=ProcessLookupError) as observed:
            self.assertEqual(case.native_closed(json.dumps(report)), report)
            observed.assert_called_once_with(1234, 0)
        with patch.object(host.os, 'kill', return_value=None):
            with self.assertRaises(ValueError):
                case.native_closed(json.dumps(report))

    def test_exact_owned_process_stop_no_pidgroup_and_no_controller_kill(self):
        class Child:
            def __init__(self): self.calls = []
            def poll(self): return None
            def terminate(self): self.calls.append('TERM')
            def kill(self): self.calls.append('KILL')
            def wait(self, timeout):
                self.calls.append(('wait', timeout))
                if len(self.calls) == 2: raise subprocess.TimeoutExpired('fake', timeout)
        case = host.Case.__new__(host.Case)
        case.left = lambda seconds, **kwargs: seconds
        child = Child()
        case.stop(child, 3)
        self.assertEqual(child.calls, ['TERM', ('wait', 3), 'KILL', ('wait', 2)])
        child = Child()
        with self.assertRaises(ValueError):
            case.stop(child, 3, kill=False)
        self.assertNotIn('KILL', child.calls)

    def test_recipe_budgets_and_relay_before_prepare_ready_before_native(self):
        tree = ast.parse(Path(host.__file__).read_text())
        names = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(names & {'rmtree', 'killpg'})
        source = Path(host.__file__).read_text()
        run = ast.get_source_segment(source, next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'run'))
        self.assertLess(run.index('self.relay_start()'), run.index('self.require_mutation_budget()'))
        self.assertLess(run.index('self.require_mutation_budget()'), run.index('self.controller = subprocess.Popen'))
        self.assertLess(run.index("self.save('controller-ready.json'"), run.index('self.consumer = subprocess.Popen'))
        self.assertIn("'--max-duration', '360'", source)
        self.assertIn('self.left(125)', source)
        self.assertIn('self.controller_started + 210', source)
        self.assertIn('self.left(180)', source)
        self.assertIn("'--user', '0:0', CID", source)
        self.assertNotIn('SSH_AUTH_SOCK', host.ENV)
        self.assertEqual(host.ENV['DOCKER_CONTEXT'], 'desktop-linux')

    def test_preappend_budget_requires_full_consumer_manager_cleanup(self):
        case = host.Case.__new__(host.Case)
        case.hard, case.record = 360, {}
        with patch.object(host.time, 'monotonic', return_value=110):
            case.require_mutation_budget()
        with patch.object(host.time, 'monotonic', return_value=110.01):
            with self.assertRaises(ValueError): case.require_mutation_budget()

    def test_relay_or_budget_failure_precedes_any_controller_or_app(self):
        plan, envelope = host.bundle()
        for stage in ('relay', 'budget'):
            case = host.Case.__new__(host.Case)
            case.save = case.no_acl = lambda *args: None
            case.call = lambda *args, **kwargs: b''
            case.fixture = lambda: ({}, {}, 'network')
            case.fresh_contract = lambda *args: Path('/unused/contract')
            case.relay_start = lambda: None
            case.require_mutation_budget = lambda: None
            if stage == 'relay': case.relay_start = lambda: (_ for _ in ()).throw(ValueError('relay'))
            else: case.require_mutation_budget = lambda: (_ for _ in ()).throw(ValueError('budget'))
            with patch.object(host, 'bundle', return_value=(plan, envelope)), patch.object(host.subprocess, 'Popen', side_effect=AssertionError('no controller/app')):
                with self.subTest(stage=stage), self.assertRaises(ValueError): case.run()

    def test_relay_launcher_only_emits_typed_classes_never_error_value(self):
        class FixtureError(Exception): pass
        fake = SimpleNamespace(main=lambda: (_ for _ in ()).throw(FixtureError('SECRET-MUST-NOT-APPEAR')))
        stderr = io.StringIO()
        with patch.dict('sys.modules', {'fixture': fake}), patch.object(host.sys, 'argv', ['launcher', '/unused', 'relay']), patch('sys.stderr', stderr):
            with self.assertRaises(SystemExit) as result:
                exec(compile(host.RELAY_LAUNCHER, '<offline-relay-launcher>', 'exec'), {})
        self.assertEqual(result.exception.code, 2)
        self.assertEqual(json.loads(stderr.getvalue()), {'exceptionClass': 'FixtureError', 'causeClass': 'none'})
        self.assertNotIn('SECRET', stderr.getvalue())

    def test_relay_exit_and_ready_failure_are_kept_as_actual_metadata(self):
        case = host.Case.__new__(host.Case)
        case.record, case.relay_started = {}, 10
        readfd, writefd = os.pipe()
        try:
            os.write(writefd, b'{"exceptionClass":"FixtureError","causeClass":"RelayError"}\n')
            os.close(writefd)
            writefd = None
            with os.fdopen(readfd, 'rb') as stream:
                case.relay = SimpleNamespace(returncode=-15, stderr=stream)
                with patch.object(host.time, 'monotonic', return_value=40): case.relay_metadata()
            self.assertEqual(case.record['relayExitCode'], -15)
            self.assertEqual(case.record['relayElapsedSeconds'], 30)
            self.assertEqual(case.record['relayError']['causeClass'], 'RelayError')
        finally:
            if writefd is not None: os.close(writefd)

    def test_ready_failure_stops_only_owned_relay_before_any_mutation(self):
        class Child:
            def __init__(self): self.calls = []; self.returncode = None
            def poll(self): return self.returncode
            def terminate(self): self.calls.append('TERM'); self.returncode = -15
            def wait(self, timeout): self.calls.append(('wait', timeout)); return self.returncode
        case = host.Case.__new__(host.Case)
        case.consumer = case.controller = case.generation = case.relaylog = None
        case.record = {}; case.relay = Child()
        case.left = lambda seconds, **kwargs: seconds
        case.relay_metadata = lambda: case.record.update(relayExitCode=case.relay.returncode)
        case.save = lambda name, value: None
        case.close()
        self.assertEqual(case.relay.calls, ['TERM', ('wait', 5)])
        self.assertEqual(case.record['relayExitCode'], -15)

    def test_consumed_d801_nonce_cannot_run_again(self):
        with patch.object(host, 'BUILD', host.HERE / '.build/host-d8015521-49ed-47b3-baeb-b9f4e7320a36'), \
                patch.object(host, 'Case', side_effect=AssertionError('must not create run')):
            with self.assertRaises(ValueError): host.main(['--live', '--authorized-local-fixture', '--engine-ready'])

    def test_host_generation_fourteen_files_cleaned_without_reading_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            directory = root / 'credentials-123456789abc'
            directory.mkdir(mode=0o700)
            for name in host.GENERATION_NAMES:
                path = directory / name
                path.write_bytes(b'offline-disposable-placeholder')
                path.chmod(0o600)
            owner = host.Generation(directory)
            try:
                self.assertEqual(len(owner.files), 14)
                with patch.object(host.os, 'pread', side_effect=AssertionError('must not read private values')):
                    owner.cleanup()
                self.assertFalse(directory.exists())
            finally:
                owner.close()

    def test_generation_unknown_or_replaced_file_kept(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve() / 'credentials-123456789abc'
            directory.mkdir(mode=0o700)
            for name in host.GENERATION_NAMES:
                path = directory / name
                path.write_bytes(b'offline')
                path.chmod(0o600)
            owner = host.Generation(directory)
            try:
                unknown = directory / 'unknown'
                unknown.write_bytes(b'keep')
                with self.assertRaises(ValueError): owner.cleanup()
                self.assertEqual(len(list(directory.iterdir())), 15)
                unknown.unlink()
                original = directory / 'id_ed25519'
                original.rename(directory.parent / 'original-private')
                original.write_bytes(b'offline')
                original.chmod(0o600)
                with self.assertRaises(ValueError): owner.cleanup()
                self.assertEqual(len(list(directory.iterdir())), 14)
            finally:
                owner.close()

    def test_receipt_ack_occurs_only_after_exact_public_export_is_saved(self):
        case = host.Case.__new__(host.Case)
        events = []
        case.save = lambda name, value: events.append(('save', name))
        case.send = lambda value: events.append(('send', value))
        payload = {'event': 'PUBLIC-RECEIPTS', 'workplan_sha256': host.PLAN_SHA256,
                   'manager_exit': 0, 'receipts_base64': {'prepared.json': base64.b64encode(b'{"public":true}\n').decode()}}
        receipt_hash = host.sha(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode())
        case.export_receipts(dict(payload, receipt_export_sha256=receipt_hash))
        self.assertEqual(events[-1], ('send', 'receipt-ack ' + receipt_hash + '\n'))
        with self.assertRaises(ValueError):
            case.export_receipts(dict(payload, receipt_export_sha256='0' * 64))


class BootstrapStagingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)
        self.path.chmod(0o755)
        (self.path / 'run').mkdir(mode=0o755)
        self.fixture = self.path / 'run/openlxssh-fixture'
        self.fixture.mkdir(mode=0o755)
        self.local = TempOS(self.path)
        patcher = patch.object(remote, 'os', self.local)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(fs, 'os', self.local)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.owner = remote.Stage(NONCE)
        self.addCleanup(self.owner.close)
        self.directory = self.fixture / self.owner.name

    def test_stage_exclusive_public0600_readback_cleanup(self):
        self.owner.put('manager_control.py', b'# fixed public source\n')
        self.owner.put('workplan.json', b'{"public":true}\n')
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.directory / 'manager_control.py').stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError): self.owner.put('id_ed25519', b'no-secret')
        with self.assertRaises(FileExistsError): remote.Stage(NONCE)
        self.owner.cleanup()
        self.assertFalse(self.directory.exists())

    def test_stage_unknown_entry_and_replacement_never_removed(self):
        self.owner.put('workplan.json', b'{}\n')
        unknown = self.directory / 'unknown'
        unknown.write_bytes(b'keep')
        with self.assertRaises(ValueError): self.owner.cleanup()
        unknown.unlink()
        plan = self.directory / 'workplan.json'
        plan.rename(self.fixture / 'old-plan')
        plan.write_bytes(b'{}\n')
        plan.chmod(0o600)
        with self.assertRaises(ValueError): self.owner.cleanup()
        self.assertTrue(plan.exists())
        self.assertTrue((self.fixture / 'old-plan').exists())

    def test_receipts_held_before_manager_close_export_then_cleanup(self):
        tree = fs.Directories((('run', 0, 0o755), ('openlxssh-fixture', 0, 0o755)))
        tree.create('nested-' + NONCE, 0)
        receipt_owner = remote.PublicReceipts(fs)
        ledger = {}
        try:
            for name in remote.RECEIPTS:
                receipt_owner.capture(tree, name, b'{"public":true}\n', ledger)
            for fd in ledger.values(): os.close(fd)
            tree.close()  # Simulate actual RootAdapter.close before export.
            values = receipt_owner.export()
            self.assertEqual(set(values), remote.RECEIPTS)
            self.assertTrue(all(base64.b64decode(value) == b'{"public":true}\n' for value in values.values()))
            receipt_owner.cleanup()
            self.assertFalse((self.fixture / ('nested-' + NONCE)).exists())
        finally:
            if tree.nodes: tree.close()
            receipt_owner.close()

    def test_no_receipt_adoption_or_unknown_cleanup(self):
        tree = fs.Directories((('run', 0, 0o755), ('openlxssh-fixture', 0, 0o755)))
        tree.create('nested-' + NONCE, 0)
        receipt_owner = remote.PublicReceipts(fs)
        ledger = {}
        try:
            receipt_owner.capture(tree, 'prepared.json', b'{}\n', ledger)
            (self.fixture / ('nested-' + NONCE) / 'foreign').write_bytes(b'keep')
            with self.assertRaises(ValueError): receipt_owner.cleanup()
            self.assertTrue((self.fixture / ('nested-' + NONCE) / 'foreign').exists())
        finally:
            for fd in ledger.values(): os.close(fd)
            tree.close()
            receipt_owner.close()


class PublicRecoveryTests(unittest.TestCase):
    def setUp(self):
        # Exercise the frozen old recovery against its exact original public bundle.
        # Production binding has moved on and MUST refuse feeding it the new nonce.
        old_build = host.HERE / '.build/host-d8015521-49ed-47b3-baeb-b9f4e7320a36'
        with patch.object(host, 'BUILD', old_build), patch.object(host, 'APP', old_build / 'OpenLXSSHRemoteTerminal.app'), \
                patch.object(host, 'BIN', old_build / 'OpenLXSSHRemoteTerminal.app/Contents/MacOS/OpenLXSSHRemoteTerminal'), \
                patch.object(host, 'PLAN_SHA256', '1b5268b49cfa8864de1e673faa3e29dc8c90b227dc3172dfb30982e0c660959f'):
            self.value = recovery.payload()
        patcher = patch.object(remote, 'PLAN_SHA256', '1b5268b49cfa8864de1e673faa3e29dc8c90b227dc3172dfb30982e0c660959f')
        patcher.start()
        self.addCleanup(patcher.stop)
        self.expected = recovery.expected_files(self.value)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)
        self.path.chmod(0o755)
        (self.path / 'run').mkdir(mode=0o755)
        self.fixture = self.path / 'run/openlxssh-fixture'
        self.fixture.mkdir(mode=0o755)
        for directory, contents in self.expected:
            folder = self.fixture / directory
            folder.mkdir(mode=0o700)
            for name, data in contents.items():
                path = folder / name
                path.write_bytes(data)
                path.chmod(0o600)
        local = TempOS(self.path)
        for target, name, value in ((recovery, 'os', local), (fs, 'os', local), (fs, 'linux_user', lambda uid: None),
                                    (recovery, 'baseline', lambda fixture: None)):
            patcher = patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_exact14_public_values_deleted_only_after_all_checked(self):
        checks = []
        with patch.object(recovery, 'baseline', lambda fixture: checks.append('verified')):
            result = recovery.recover(self.value)
        self.assertEqual(result['removedFiles'], 14)
        self.assertEqual(checks, ['verified', 'verified', 'verified'])
        self.assertEqual(list(self.fixture.iterdir()), [])

    def test_unknown_late_receipt_keeps_all_fourteen(self):
        directory = self.fixture / self.expected[-1][0]
        (directory / 'unknown').write_bytes(b'keep')
        with self.assertRaises(ValueError): recovery.recover(self.value)
        self.assertEqual(sum(len(list((self.fixture / name).iterdir())) for name, _contents in self.expected), 15)

    def test_corrupted_last_receipt_prevents_any_unlink(self):
        directory = self.fixture / self.expected[-1][0]
        (directory / 'restored.json').write_bytes(b'foreign')
        with self.assertRaises(ValueError): recovery.recover(self.value)
        self.assertEqual(sum(len(list((self.fixture / name).iterdir())) for name, _contents in self.expected), 14)

    def test_symlink_or_hardlink_is_never_adopted(self):
        path = self.fixture / self.expected[0][0] / 'workplan.json'
        path.rename(self.fixture / 'foreign-target')
        path.symlink_to('../foreign-target')
        with self.assertRaises(OSError): recovery.recover(self.value)
        self.assertTrue(path.is_symlink())
        path.unlink()
        os.link(self.fixture / 'foreign-target', path)
        with self.assertRaises(ValueError): recovery.recover(self.value)
        self.assertTrue(path.exists())

    def test_changed_baseline_blocks_before_delete(self):
        with patch.object(recovery, 'baseline', side_effect=ValueError('master/auth changed')):
            with self.assertRaises(ValueError): recovery.recover(self.value)
        self.assertEqual(sum(len(list((self.fixture / name).iterdir())) for name, _contents in self.expected), 14)

    def test_payload_hash_tamper_and_remote_loader_syntax(self):
        changed = json.loads(json.dumps(self.value))
        changed['receipts']['restored.json'] = base64.b64encode(b'{}\n').decode()
        with self.assertRaises(ValueError): recovery.expected_files(changed)
        ast.parse(recovery.remote_code())  # Compile/parse only, never execute remote code.
        with patch.object(recovery, 'apply', side_effect=AssertionError('no apply')), patch.object(recovery, 'payload', side_effect=AssertionError('no files')):
            with patch('sys.stdout', io.StringIO()): self.assertEqual(recovery.main([]), 0)


if __name__ == '__main__':
    unittest.main()
