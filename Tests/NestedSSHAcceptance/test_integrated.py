"""Source/offline integration tests: fake execv, in-memory controls, no tools/services."""
import ast
import base64
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import build_integrated as build
import fd_safety as fs
import key_ledger as keys
import management_prep as core
import manager_control as manager
import nested_probe
import root_adapter as root
from test_key_ledger import FakeChild, LedgerOS, PRIVATE_SENTINEL
from test_management_prep import NONCE, ORIGINAL, STAMP, public_line
from test_root_adapter import FakeProc, MASTER, OUTER


class ExecCaptured(Exception):
    pass


class IntegratedPrepTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inner = (build.PARENT / 'inputs/Tests/RemoteTerminalAcceptance/remote_probe.py').read_bytes()

    def plan(self):
        source = nested_probe.wrapper(self.inner, NONCE)
        hashes = dict(nested_probe.FROZEN)
        hashes.update({name: core.digest((build.HERE / name).read_bytes()) for name in manager.LOCAL})
        return build.workplan(NONCE, source, b'generated-location-offline',
                              build.HERE / '.build/host-00000000-0000-0000-0000-000000000000/OpenLXSSHRemoteTerminal.app',
                              'a' * 64, hashes)

    def test_exact_frozen_parent_nine_objects_without_running_recipe(self):
        with patch.object(build.importlib.util, 'spec_from_file_location', side_effect=AssertionError('must not import builder')):
            sources, objects, team, helper, plist, readonly = build.inspect_parent()
        self.assertEqual(len(objects), 9)
        self.assertEqual({Path(item['path']).stem for item in objects}, {*build.MODULES, 'RemoteTerminalCore'})
        self.assertEqual(team, '74Q9ARM7JJ')
        self.assertIn(helper, readonly)
        self.assertIn(plist, readonly)
        self.assertEqual(set(sources), set(nested_probe.FROZEN))
        self.assertTrue(any(path.name == 'RealIntegrationPOSIX.h' for path in readonly))

    def test_wrapper_execv_fixed_ssh_argv_and_inner_exact_hash(self):
        source = nested_probe.wrapper(self.inner, NONCE)
        self.assertLessEqual(len(source), 32768)
        captured = []
        def execv(path, argv):
            captured.append((path, argv))
            raise ExecCaptured()
        fake_os = SimpleNamespace(getuid=lambda: 10000, isatty=lambda fd: True, environ={'SSH_TTY': '/dev/pts/offline'}, execv=execv)
        with patch.dict('sys.modules', {'os': fake_os, 'sys': SimpleNamespace(argv=['<probe>', NONCE])}):
            with self.assertRaises(ExecCaptured):
                exec(compile(source, '<offline-generated-wrapper>', 'exec'), {})
        path, argv = captured[0]
        self.assertEqual(path, '/usr/bin/ssh')
        self.assertEqual(argv[:10], ['/usr/bin/ssh', '-F', '/dev/null', '-tt', '-p', '2222', '-l', 'fixture', '-i',
                                    '/fixture/home/.openlxssh-nested-' + NONCE + '/id_ed25519'])
        self.assertEqual(argv[-3:-1], ['--', '127.0.0.1'])
        options = argv[10:-3]
        parsed = {options[index + 1] for index in range(0, len(options), 2) if options[index] == '-o'}
        self.assertTrue({'BatchMode=yes', 'StrictHostKeyChecking=yes', 'IdentityAgent=none', 'PasswordAuthentication=no',
                         'KbdInteractiveAuthentication=no', 'UserKnownHostsFile=/fixture/home/.ssh/known_hosts', 'EscapeChar=none'} <= parsed)
        command = shlex.split(argv[-1])
        self.assertEqual((command[0], command[1], command[-1]), ('/usr/bin/python3', '-c', NONCE))
        tree = ast.parse(command[2])
        source_call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                           and node.func.attr == 'b64decode')
        self.assertEqual(base64.b64decode(ast.literal_eval(source_call.args[0]), validate=True), self.inner)
        self.assertNotIn(b'returned', source)
        inner_tree = ast.parse(self.inner)
        events = [node.args[1].value for node in ast.walk(inner_tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                  and node.func.id == 'emit' and len(node.args) > 1 and isinstance(node.args[1], ast.Constant)]
        self.assertIn('done', events)
        self.assertNotIn('returned', events)

    def test_frozen_outer_shell_alone_emits_returned_and_keeps_twelve_gates(self):
        source = (build.PARENT / 'inputs/Tests/RemoteTerminalAcceptance/Core.swift').read_text()
        self.assertIn('; r=$?; printf', source)
        self.assertIn(r'\\122\\1241|', source)
        self.assertIn('exec(compile(source', source)
        expected = '"load-ready", "hello", "input-ready", "input", "interrupt-ready", "interrupt", "resize-ready", "size", "vim-ready", "vim", "done", "returned"'
        self.assertIn(expected, source)
        self.assertIn('case "returned": guard fields == ["0"]', source)
        self.assertIn('case "hello":', source)
        self.assertIn('remotePID = pid', source)

    def test_wrapper_hash_and_nonce_refuse_before_exec(self):
        for nonce, inner in ((NONCE + ';id', self.inner), (NONCE, self.inner + b'\n')):
            with self.assertRaises(ValueError):
                nested_probe.wrapper(inner, nonce)
        source = nested_probe.wrapper(self.inner, NONCE)
        fake_os = SimpleNamespace(getuid=lambda: 10000, isatty=lambda fd: True, environ={'SSH_TTY': 'offline'},
                                  execv=lambda *args: self.fail('must not exec'))
        with patch.dict('sys.modules', {'os': fake_os, 'sys': SimpleNamespace(argv=['<probe>', 'bad;command'])}):
            with self.assertRaises(SystemExit):
                exec(compile(source, '<offline-generated-wrapper>', 'exec'), {})

    def test_workplan_public_bindings_and_tamper_refusal(self):
        plan = self.plan()
        raw = manager.public_json(plan)
        self.assertEqual(manager.validate_plan(raw, core.digest(raw)), plan)
        self.assertEqual(plan['key_directory'], '/fixture/home/.openlxssh-nested-' + NONCE)
        for change in ({'container_id': '0' * 64}, {'fingerprint': 'foreign'}, {'key_directory': '/arbitrary/key'},
                       {'wrapper_bytes': 32769}, {'app_sha256': 'not-a-hash'}, {'exclusion': 'flag=true'}):
            edited = dict(plan, **change)
            raw = manager.public_json(edited)
            with self.subTest(change=change), self.assertRaises(core.Refused):
                manager.validate_plan(raw, core.digest(raw))
        with self.assertRaises(core.Refused):
            manager.validate_plan(manager.public_json(plan), '0' * 64)

    def test_build_recipe_only_compiles_frozen_consumer_and_reuses_nine(self):
        tree = ast.parse(Path(build.__file__).read_text())
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
        compiles = [node for node in calls if node.func.attr == 'swift_compile']
        self.assertEqual(len(compiles), 1)
        self.assertEqual(ast.literal_eval(compiles[0].args[0]), 'OpenLXSSHRemoteTerminal')
        self.assertFalse(any(node.func.attr == 'c_module' for node in calls))
        self.assertFalse(any(node.func.attr == 'run' and len(node.args) > 1 and any(isinstance(part, ast.Name) and part.id == 'app'
                              for part in ast.walk(node.args[1])) for node in calls))

    def test_repeated_build_labels_use_exclusive_numbered_logs_and_redact_private(self):
        class FakeBuilder:
            def __init__(self, work):
                self.work, self.commands = work, []
        accepted = SimpleNamespace(Builder=FakeBuilder, environment=lambda work: {}, Refusal=ValueError)
        result = SimpleNamespace(returncode=0, stdout=b'public-output', stderr=b'')
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / 'logs').mkdir()
            owner = build.build_builder(accepted)(work)
            with patch.object(build.subprocess, 'run', return_value=result):
                owner.run('signature', ['fixed-tool'])
                owner.run('signature', ['fixed-tool'])
                owner.run('signature', ['private-signing-identifier'], private=True)
                self.assertEqual([item['label'] for item in owner.commands], ['001-signature', '002-signature', '003-signature'])
                self.assertEqual({path.name for path in (work / 'logs').iterdir()}, {'001-signature.log', '002-signature.log'})
                self.assertNotIn('private-signing-identifier', repr(owner.commands))
                owner.commands.clear()
                with self.assertRaises(FileExistsError):
                    owner.run('signature', ['fixed-tool'])
                self.assertEqual((work / 'logs/001-signature.log').read_bytes(), b'public-output')

    def test_default_and_validate_are_inert(self):
        with patch.object(build, 'inspect_parent', side_effect=AssertionError('no parent read')), patch.object(build, 'build', side_effect=AssertionError('no build')):
            with patch('sys.stdout', io.StringIO()):
                build.main([])
                build.main(['validate'])
        with patch.object(manager, 'serve', side_effect=AssertionError('no serve')):
            with patch('sys.stdout', io.StringIO()):
                self.assertEqual(manager.main([]), 0)
                self.assertEqual(manager.main(['validate']), 0)

    def test_controller_order_ready_after_appended_receipt_finish_globalidle(self):
        events, owner, key = self.fake_controls()
        with patch.object(manager, 'RootAdapter', lambda nonce, **kwargs: (events.append(('owner', kwargs)) or owner)), \
                patch.object(manager, 'KeyLedger', lambda candidate: key), patch.object(manager.fs, 'durable_public', lambda *args: events.append('plan-fsynced')):
            control = manager.Control(self.plan(), 'a' * 64)
            ready = control.prepare()
            self.assertEqual(ready['event'], 'READY')
            self.assertLess(events.index('append'), events.index('read-appended.json'))
            self.assertEqual(events[0], ('owner', {'owned': (), 'ssh_tokens': ()}))
            control.finish()
        self.assertEqual(events[-5:], [('idle', True), 'restore', 'cleanup', 'key-close', 'owner-close'])

    def fake_controls(self):
        events = []
        public = public_line('ssh-ed25519', 5, 'OpenLXSSH-nested-' + NONCE)
        prepared = 'a' * 64
        receipt = SimpleNamespace(original=ORIGINAL, new_public_line=public, stamp=STAMP)
        appended = manager.public_json({'schema': 1, 'case': 'NESTrealpublickeyonly', 'prepared_sha256': prepared,
                                       'appended_sha256': core.digest(ORIGINAL + public), 'stamp': STAMP._asdict()})
        owner = SimpleNamespace(case=object(), receipts={}, receipt=receipt, appended_state=('own',), restored=False)
        def append(value):
            self.assertEqual(value, public)
            events.append('append')
            return prepared
        def idle(*, closed=False):
            events.append(('idle', closed))
        def restore():
            events.append('restore')
            owner.restored = True
        owner.append, owner._exclusion, owner.restore = append, idle, restore
        owner._receipt_hash = lambda name: (events.append('read-' + name) or core.digest(appended))
        owner.close = lambda: events.append('owner-close')
        key = SimpleNamespace(generate=lambda: (events.append('generate') or public), cleanup=lambda: events.append('cleanup'),
                              close=lambda: events.append('key-close'))
        return events, owner, key

    def test_abort_only_restores_when_globalidle_and_never_kills(self):
        events, owner, key = self.fake_controls()
        control = manager.Control(self.plan(), 'a' * 64)
        control.owner, control.keys = owner, key
        self.assertTrue(control.abort())
        self.assertEqual(events, [('idle', True), 'restore', 'cleanup', 'key-close', 'owner-close'])
        events, owner, key = self.fake_controls()
        owner._exclusion = lambda **kwargs: (_ for _ in ()).throw(core.Refused('foreign'))
        control = manager.Control(self.plan(), 'a' * 64)
        control.owner, control.keys = owner, key
        self.assertFalse(control.abort())
        self.assertEqual(events, ['key-close', 'owner-close'])

    def test_real_control_root_keyledger_tempfile_globalidle_finish(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            path.chmod(0o755)
            (path / 'run').mkdir(mode=0o755)
            fixture = path / 'run/openlxssh-fixture'
            fixture.mkdir(mode=0o755)
            auth = fixture / 'authorized_keys'
            auth.write_bytes(ORIGINAL)
            auth.chmod(0o644)
            (path / 'fixture').mkdir(mode=0o755)
            home = path / 'fixture/home'
            home.mkdir(mode=0o700)
            local = LedgerOS(path)
            local.mark(home, 10000)
            reader = FakeProc()
            reader.rows = {MASTER.pid: MASTER}  # Empty-owned global-idle strategy.
            directory = home / ('.openlxssh-nested-' + NONCE)
            def fake_popen(argv, **options):
                self.assertEqual((options['user'], options['group']), (10000, 10000))
                for name, data in ((keys.NAMES[0], PRIVATE_SENTINEL),
                                   (keys.NAMES[1], public_line('ssh-ed25519', 5, 'OpenLXSSH-nested-' + NONCE))):
                    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    try:
                        os.write(fd, data)
                    finally:
                        os.close(fd)
                    local.mark(directory / name, 10000)
                return FakeChild([0])
            with patch.object(fs, 'os', local), patch.object(root, 'os', local), patch.object(keys, 'os', local), \
                    patch.object(fs, 'linux_user', lambda uid: None), patch.object(root, 'ProcReader', lambda fd: reader), \
                    patch.object(keys, 'subprocess', SimpleNamespace(Popen=fake_popen, DEVNULL=subprocess.DEVNULL,
                                                                   TimeoutExpired=subprocess.TimeoutExpired)):
                control = manager.Control(self.plan(), 'a' * 64)
                try:
                    self.assertEqual(control.prepare()['event'], 'READY')
                    self.assertEqual(len(control.owner.gate.owned), 0)
                    self.assertEqual(auth.read_bytes(), ORIGINAL + control.keys.receipt.new_public_line)
                    reader.rows[OUTER.pid] = OUTER  # Running outer/inner is NOT registered or touched.
                    with self.assertRaises(core.Refused):
                        control.finish()
                    self.assertTrue(directory.exists())
                    reader.rows = {MASTER.pid: MASTER}  # Host closes all sessions before finish.
                    self.assertEqual(control.finish()['event'], 'FINISHED')
                    self.assertEqual(auth.read_bytes(), ORIGINAL)
                    self.assertFalse(directory.exists())
                    self.assertFalse((fixture / 'nested-management.lock').exists())
                    self.assertNotIn('id_ed25519', local.read_names)
                finally:
                    control.abort()

    def test_prepare_failure_never_prints_ready_and_eof_aborts(self):
        plan = self.plan()
        raw = manager.public_json(plan)
        plan_hash = core.digest(raw)
        envelope = json.dumps({'workplan_base64': base64.b64encode(raw).decode()}) + '\n'
        events = []
        control = SimpleNamespace(prepare=lambda: (_ for _ in ()).throw(core.Refused('not-ready')),
                                  abort=lambda: events.append('abort'))
        with patch.object(manager, 'Control', lambda *args: control), patch.object(manager.fs, 'linux_user', lambda uid: None), \
                patch.object(manager.signal, 'signal', lambda *args: None), patch.object(manager.signal, 'alarm', lambda *args: None), patch('sys.stderr', io.StringIO()):
            output = io.StringIO()
            self.assertEqual(manager.serve(plan_hash, io.StringIO(envelope), output), 2)
            self.assertEqual(output.getvalue(), '')
            self.assertEqual(events, ['abort'])
            control.prepare = lambda: {'event': 'READY'}
            self.assertEqual(manager.serve(plan_hash, io.StringIO(envelope), output), 2)
            self.assertNotIn('FINISHED', output.getvalue())
            self.assertEqual(events, ['abort', 'abort'])


if __name__ == '__main__':
    unittest.main()
