#!/usr/bin/env python3
"""Pure source/file/Swift tests. No Docker, SSH, tmux, htop, signing or interactive execution."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).absolute().parent

def probe():
    spec = importlib.util.spec_from_file_location('fixed_tmux_offline', ROOT / 'remote_probe.py')
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value

def pane_functions():
    tree = ast.parse(probe().PANE_SOURCE)
    nodes = [node for node in tree.body if isinstance(node, (ast.Import, ast.FunctionDef, ast.ClassDef))]
    namespace = {'__name__': '_pure_pane_functions'}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<fixed-pane-functions>', 'exec'), namespace)
    return namespace

class Tests(unittest.TestCase):
    def test_source_fixed_single_pane_and_no_payload_capture(self):
        source = (ROOT / 'remote_probe.py').read_text()
        tree = ast.parse(source)
        value = probe(); compile(value.PANE_SOURCE, '<fixed-pane>', 'exec')
        for required in ("'/usr/bin/tmux'", "'-S'", "'-f', '/dev/null'", "'new-session'", "'kill-server'", "'status', 'off'", 'signal.alarm(95)', 'signal.alarm(85)', 'os.pidfd_open', 'wait_gone(handle)', 'termios.tcgetattr(0) != initial', 'O_EXCL', 'O_NOFOLLOW'):
            self.assertIn(required, source)
        for forbidden in ('split-window', 'send-keys', 'detach-client', 'capture-pane', 'shell=True', 'password.txt', 'key-passphrase', 'sudo', 'killall', 'pkill', 'get-server', 'socket.create_connection'):
            self.assertNotIn(forbidden, source)
        run = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
        actions = next(node for node in run.body if isinstance(node, ast.Try)).body
        hello = next(i for i, node in enumerate(actions) if isinstance(node, ast.Expr) and ast.unparse(node).startswith("emit(nonce, 'hello'"))
        self.assertEqual(ast.unparse(actions[hello + 1]), "require_ack(b'T\\n')")
        main = (ROOT / 'Main.swift').read_text()
        self.assertIn('session.sendInput(data)', main)
        self.assertIn('session.terminal.resize(cols: TmuxPlan.width', main)
        self.assertIn('enqueue(TmuxPlan.detach', main)
        self.assertIn('catch { report.recordProbe(budget); throw error }', main)
        self.assertNotIn('session.respond(', main)
        self.assertNotIn('startProbe(', main)
        self.assertNotIn('terminal.text.suffix', main)

    def test_closed_frames_and_failures(self):
        value = probe()
        with contextlib.redirect_stdout(io.StringIO()) as output: value.emit('a' * 32, 'hello', 10000, 321)
        self.assertEqual(output.getvalue(), '\r\nRT1|' + 'a' * 32 + '|hello|10000,321|END\r\n')
        for fields in [('private-stage', 'refused', 'none'), ('input', 'private-error', 'none'), ('input', 'refused', '/private/path')]:
            with self.assertRaises(value.Refused): value.emit('a' * 32, 'failed', *fields)
        self.assertEqual(value.failure_fields('cleanup', PermissionError(13, 'private', '/private/path')), ('cleanup', 'os-error', 'eacces'))
        with mock.patch.object(value, 'run', side_effect=RuntimeError('private')), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(value.main(['a' * 32]), 1)
        self.assertNotIn('private', output.getvalue())
        self.assertIn('preflight,source-error,none', output.getvalue())

    def test_ack_exact_timeout_and_no_start_side_effects(self):
        value = probe()
        for actual in (b'bad', b'T\r', b''):
            with mock.patch.object(value, 'bounded_read', return_value=actual), mock.patch.object(value.subprocess, 'Popen', side_effect=AssertionError('child')):
                with self.assertRaises(value.Refused): value.require_ack(b'T\n')
        with mock.patch.object(value, 'bounded_read', return_value=b'T\n') as read:
            value.require_ack(b'T\n'); read.assert_called_once_with(0, 2, 12)
        with mock.patch.object(value, 'bounded_read', side_effect=value.Deadline):
            with self.assertRaises(value.Deadline): value.require_ack(b'T\n')
        with mock.patch.object(value.os, 'getuid', return_value=123), mock.patch.object(value.subprocess, 'Popen', side_effect=AssertionError('live child')):
            with self.assertRaises(value.Refused): value.run('a' * 32)

    def test_owned_client_reap_escalates_ignored_term_and_never_claims_clean(self):
        value = probe()
        timeout = lambda seconds: value.subprocess.TimeoutExpired('fixed-own-client', seconds)
        natural = mock.Mock()
        natural.wait.return_value = 0
        value.reap_client(natural)
        natural.wait.assert_called_once_with(timeout=3)
        natural.terminate.assert_not_called(); natural.kill.assert_not_called()
        terminated = mock.Mock()
        terminated.wait.side_effect = [timeout(3), -15]
        with self.assertRaises(value.Refused): value.reap_client(terminated)
        self.assertEqual(terminated.mock_calls, [mock.call.wait(timeout=3), mock.call.terminate(), mock.call.wait(timeout=2)])
        ignored_term = mock.Mock()
        ignored_term.wait.side_effect = [timeout(3), timeout(2), -9]
        with self.assertRaises(value.Refused): value.reap_client(ignored_term)
        self.assertEqual(ignored_term.mock_calls, [mock.call.wait(timeout=3), mock.call.terminate(), mock.call.wait(timeout=2), mock.call.kill(), mock.call.wait(timeout=1)])
        unreaped = mock.Mock()
        unreaped.wait.side_effect = [timeout(3), timeout(2), timeout(1)]
        with self.assertRaises(value.subprocess.TimeoutExpired): value.reap_client(unreaped)
        unreaped.kill.assert_called_once_with()
        self.assertEqual(value.failure_fields('cleanup', timeout(1)), ('cleanup', 'deadline', 'none'))

    def test_owned_files_exclusive_cleanup_and_no_replace_adoption(self):
        value = probe()
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw).resolve()
            run = value.OwnedRun('a' * 32, parent)
            self.assertEqual(stat.S_IMODE(run.path.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((run.path / 'pane.py').stat().st_mode), 0o600)
            self.assertEqual((run.path / 'pane.py').read_text(), value.PANE_SOURCE)
            with self.assertRaises(FileExistsError): value.OwnedRun('a' * 32, parent)
            run.verify(); self.assertTrue(run.close()); self.assertFalse(run.path.exists())
        for replacement in ('file', 'symlink'):
            with tempfile.TemporaryDirectory() as raw:
                run = value.OwnedRun('b' * 32, Path(raw).resolve())
                original = run.path / 'pane.py'; moved = run.path / 'moved'; original.rename(moved)
                if replacement == 'file': original.write_text('public bystander'); original.chmod(0o600)
                else: original.symlink_to(moved)
                with self.assertRaises(value.Refused): run.verify()
                self.assertFalse(run.close()); self.assertTrue(original.exists()); self.assertTrue(moved.exists())

    def test_socket_gate_is_uid_owned_with_private_parent_and_closed_modes(self):
        value = probe()
        with tempfile.TemporaryDirectory() as raw:
            run = value.OwnedRun('c' * 32, Path(raw).resolve())
            try:
                for mode in (0o600, 0o660):
                    info = mock.Mock(st_mode=stat.S_IFSOCK | mode, st_uid=os.getuid(), st_dev=1, st_ino=2)
                    with mock.patch.object(run, 'verify'), mock.patch.object(value.os, 'stat', return_value=info):
                        run.confirm_socket(); self.assertEqual(run.socket_identity, (1, 2))
                for mode, uid in ((0o666, os.getuid()), (0o600, os.getuid() + 1)):
                    info = mock.Mock(st_mode=stat.S_IFSOCK | mode, st_uid=uid, st_dev=1, st_ino=2)
                    with mock.patch.object(run, 'verify'), mock.patch.object(value.os, 'stat', return_value=info):
                        with self.assertRaises(value.Refused): run.confirm_socket()
            finally: self.assertTrue(run.close())

    def test_pane_fixed_input_hash_resize_and_detach_handshake_in_memory(self):
        value = probe()
        namespace = {'__name__': '_pure_pane'}
        tree = ast.parse(value.PANE_SOURCE)
        definitions = [node for node in tree.body if isinstance(node, (ast.Import, ast.FunctionDef, ast.ClassDef))]
        exec(compile(ast.Module(body=definitions, type_ignores=[]), '<fixed-pane-functions>', 'exec'), namespace)
        outputs = []
        # Execute only the fixed pane try-body with fake file descriptors/terminal state.
        body = next(node.body for node in tree.body if isinstance(node, ast.Try))
        namespace.update(nonce='a' * 32, sample=value.SAMPLE, emit=lambda *fields: outputs.append(fields),
                         read=mock.Mock(side_effect=[value.SAMPLE, b'C', b'R', b'D']))
        class Done(Exception): pass
        with mock.patch.object(value.os, 'getuid', return_value=10000), mock.patch.object(value.os, 'isatty', return_value=True), mock.patch.object(value.os, 'getpid', return_value=321), mock.patch.object(value.tty, 'setraw'), mock.patch.object(value.fcntl, 'ioctl', return_value=value.struct.pack('HHHH', 31, 93, 0, 0)), mock.patch.object(value.signal, 'pause', side_effect=Done), mock.patch.object(value.signal, 'signal'), contextlib.redirect_stdout(io.StringIO()) as screen:
            with self.assertRaises(Done): exec(compile(ast.Module(body=body, type_ignores=[]), '<fixed-pane-body>', 'exec'), namespace)
        self.assertEqual(outputs, [('tmux-ready', 10000, 321, len(value.SAMPLE)),
                                   ('input', len(value.SAMPLE), hashlib.sha256(value.SAMPLE).hexdigest()),
                                   ('resize-ready',), ('size', 31, 93), ('detach-ready',)])
        namespace['read'].assert_has_calls([mock.call(len(value.SAMPLE)), mock.call(1), mock.call(1), mock.call(1)])
        self.assertEqual(screen.getvalue(), '\x1b[2J\x1b[3J\x1b[H')

    def test_prepare_resize_requires_C_before_clear_and_ready(self):
        namespace = pane_functions()
        for response in (b'R', b'', b'c'):
            namespace.update(read=mock.Mock(return_value=response), emit=mock.Mock())
            with contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaises(RuntimeError): namespace['prepare_resize']()
            self.assertEqual(output.getvalue(), '')
            namespace['emit'].assert_not_called()
        events = []
        namespace.update(read=mock.Mock(return_value=b'C'), emit=lambda *fields: events.append(fields))
        with contextlib.redirect_stdout(io.StringIO()) as output: namespace['prepare_resize']()
        self.assertEqual(output.getvalue(), '\x1b[2J\x1b[3J\x1b[H')
        self.assertEqual(events, [('resize-ready',)])
        main = (ROOT / 'Main.swift').read_text()
        branch = main[main.index('case .prepareResize:'):main.index('case .resize:')]
        self.assertIn('enqueue(TmuxPlan.prepareResize', branch)
        self.assertNotIn('terminal.resize', branch)
        self.assertNotIn('sleep', branch)

    def test_resize_wait_uses_WINCH_or_ioctl_until_exact_deadline(self):
        value = probe()
        for event, sizes, clocks, expected in [
            (True, [(24, 80), (31, 93)], [0, 0, 1], (31, 93)),
            (False, [(24, 80), (31, 93)], [0, 0, 1], (31, 93)),
            (False, [(24, 80), (30, 93)], [0, 0, 12], None),
            (True, [(24, 80), (31, 93)], [0, 0, 12], None)]:
            with self.subTest(event=event, sizes=sizes, clocks=clocks):
                namespace = pane_functions(); registered = {}; closed = []
                def install(number, handler):
                    previous = registered.get(number, value.signal.SIG_DFL)
                    registered[number] = handler
                    return previous
                def selected(reads, _writes, _errors, timeout):
                    self.assertGreater(timeout, 0)
                    if event: registered[value.signal.SIGWINCH]()
                    return (reads if event else [], [], [])
                payloads = [value.struct.pack('HHHH', *size, 0, 0) for size in sizes]
                with mock.patch.object(value.os, 'pipe', return_value=(90, 91)), mock.patch.object(value.os, 'set_blocking'), mock.patch.object(value.os, 'close', side_effect=closed.append), mock.patch.object(value.os, 'write', return_value=1) as wake, mock.patch.object(value.os, 'read', return_value=b'W'), mock.patch.object(value.signal, 'signal', side_effect=install), mock.patch.object(value.fcntl, 'ioctl', side_effect=payloads), mock.patch.object(value.time, 'monotonic', side_effect=clocks), mock.patch.object(value.select, 'select', side_effect=selected), mock.patch.object(value.time, 'sleep', side_effect=AssertionError('not a synchronization mechanism')):
                    if expected is None:
                        with self.assertRaises(namespace['ResizeDeadline']) as failure: namespace['wait_size']()
                        self.assertEqual((failure.exception.rows, failure.exception.cols), sizes[-1])
                    else: self.assertEqual(namespace['wait_size'](), expected)
                    if event: wake.assert_called_once_with(91, b'W')
                self.assertEqual(closed, [90, 91])
                self.assertEqual(registered[value.signal.SIGWINCH], value.signal.SIG_DFL)

    def test_status_first_pane_error_survives_later_no_session_failure(self):
        value = probe(); namespace = pane_functions()
        with tempfile.TemporaryDirectory() as raw:
            run = value.OwnedRun('d' * 32, Path(raw).resolve())
            fd, identity = run.files['pane-status']
            try:
                namespace.update(status_path=str(run.path / 'pane-status'), status_identity=identity, status_fd=fd)
                self.assertIsNone(run.pane_failure())
                original_fstat = os.fstat
                with mock.patch.object(value.os, 'getuid', return_value=10000), mock.patch.object(value.os, 'fstat') as real_info:
                    # File belongs to the local test UID; fake only the expected disposable UID field.
                    def info(number):
                        original = original_fstat(number)
                        return type('Info', (), {**{name: getattr(original, name) for name in ('st_mode', 'st_dev', 'st_ino', 'st_nlink', 'st_size')}, 'st_uid': 10000})()
                    real_info.side_effect = info
                    namespace['record_failure'](('resize', 'deadline', 'none', 24, 80))
                self.assertEqual(run.pane_failure(), ('resize', 'deadline', 'none', 24, 80))
                path = run.path / 'pane-status'; moved = run.path / 'moved-status'; path.rename(moved); path.touch(mode=0o600)
                with self.assertRaises(value.Refused): run.pane_failure()
                path.unlink(); moved.rename(path)
                os.ftruncate(fd, 0); os.pwrite(fd, b'resize,deadline,none,24,80', 0)
                with self.assertRaises(RuntimeError):
                    with mock.patch.object(value.os, 'getuid', return_value=10000): namespace['record_failure'](('detach', 'refused', 'none'))
                self.assertEqual(run.pane_failure(), ('resize', 'deadline', 'none', 24, 80))
                for bad in (b'resize,deadline,none,65536,80', b'resize,deadline,none,0,80', b'resize,deadline,none,-1,80', b'private,refused,none', b'input,refused,none,24,80'):
                    os.ftruncate(fd, 0); os.pwrite(fd, bad, 0)
                    with self.assertRaises(value.Refused): run.pane_failure()
                os.ftruncate(fd, 0); os.pwrite(fd, b'resize,deadline,none,24,80', 0)
                fake = mock.Mock(); fake.pane_failure.return_value = ('resize', 'deadline', 'none', 24, 80)
                tree = ast.parse((ROOT / 'remote_probe.py').read_text())
                function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
                keeper = next(node for node in function.body if isinstance(node, ast.FunctionDef) and node.name == 'preserve_pane_error')
                keeper_body = [node for node in keeper.body if not isinstance(node, ast.Nonlocal)]
                scope = {**vars(value), 'owned': fake, 'failure': ('detach', 'process-exit', 'none')}
                exec(compile(ast.Module(body=keeper_body, type_ignores=[]), '<preserve-first-pane-error>', 'exec'), scope)
                self.assertEqual(scope['failure'], ('resize', 'deadline', 'none', 24, 80))
            finally: self.assertTrue(run.close())

    def test_frozen_nine_objects_readonly(self):
        manifest = json.loads((ROOT / 'frozen-inputs.json').read_text())
        self.assertEqual(len(manifest['dependencyObjects']), 9)
        self.assertEqual(len({item['path'] for item in manifest['dependencyObjects']}), 9)
        for item in manifest['dependencyObjects']:
            self.assertEqual(hashlib.sha256(Path(item['path']).read_bytes()).hexdigest(), item['sha256'])
        self.assertEqual(hashlib.sha256((Path(manifest['parentCheckpoint']) / 'result.json').read_bytes()).hexdigest(), manifest['parentManifestSHA256'])
        for path, digest in manifest['moduleSHA256'].items():
            self.assertEqual(hashlib.sha256(Path(path).read_bytes()).hexdigest(), digest)
        self.assertFalse(manifest['fullDependencyBuildRequired'])

    def test_reject_metadata_is_closed_and_existing_strict_gate_remains(self):
        core = (ROOT / 'Core.swift').read_text()
        for field in ('rejectReason: TUIRejectReason?', 'rejectFieldCount: TUIFieldCount?', 'inputLengthMatch: Bool?', 'inputHashMatch: Bool?'):
            self.assertIn(field, core)
        for text in ('if consumed.contains(frame) { continue }', 'parts[0] == expected[events]',
                     'rendered.utf8.count <= 65536', 'frame.utf8.count <= 256',
                     '["load-ready", "hello", "tmux-ready", "input", "resize-ready", "size", "detach-ready", "detached", "done", "returned"]'):
            self.assertIn(text, core)
        self.assertNotIn('var rejectedText', core)
        self.assertNotIn('var rejectedHash', core)
        self.assertNotIn('var actualFields', core)
        self.assertIn('catch { report.recordProbe(budget); throw error }', (ROOT / 'Main.swift').read_text())

    def test_pure_swift_and_consumer_typecheck_without_linking_product(self):
        manifest = json.loads((ROOT / 'frozen-inputs.json').read_text())
        with tempfile.TemporaryDirectory(prefix='tui-core-', dir=ROOT / '.build') as raw:
            work = Path(raw)
            def run(argv):
                result = subprocess.run(list(map(str, argv)), cwd=ROOT, capture_output=True, timeout=120)
                self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode())
                return result.stdout.decode()
            compiler = run(['/usr/bin/xcrun', '-f', 'swiftc']).strip()
            sdk = run(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path']).strip()
            modules = manifest['moduleDirectory']
            flags = ['-parse-as-library', '-swift-version', '6', '-target', 'arm64-apple-macosx15.0', '-sdk', sdk, '-warnings-as-errors', '-module-cache-path', work / 'module-cache', '-I', modules, '-I', work]
            core_object = next(item['path'] for item in manifest['dependencyObjects'] if Path(item['path']).stem == 'RemoteTerminalCore')
            run([compiler, *flags, '-emit-library', '-emit-module', '-module-name', 'TUIToolsCore', ROOT / 'Core.swift', core_object,
                 '-emit-module-path', work / 'TUIToolsCore.swiftmodule', '-o', work / 'libTUIToolsCore.dylib'])
            run([compiler, *flags, ROOT / 'OfflineMain.swift', core_object, '-L', work, '-lTUIToolsCore', '-Xlinker', '-rpath', '-Xlinker', work, '-o', work / 'offline'])
            self.assertIn('pure core checks passed', run([work / 'offline']))
            location = work / 'BuildLocation.swift'
            location.write_text('enum BuildLocation { static let ownRoot="/not/opened"; static let buildRoot="/not/opened"; static let fixtureRoot="/not/opened"; static let team="UNSIGNED00"; static let probeBase64=""; static let probeSHA256="" }\n')
            run([compiler, *flags, '-typecheck', '-I', Path(manifest['parentCheckpoint']) / 'cmodules',
                 ROOT / 'Main.swift', ROOT / 'LiveInput.swift', location])

if __name__ == '__main__': unittest.main(verbosity=2)
