#!/usr/bin/env python3
"""Offline source/owned-file and pure Swift checks. No SSH, Docker, PTY/socket, signing or live probe."""
import ast
import contextlib
import errno
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).absolute().parent


def probe():
    spec = importlib.util.spec_from_file_location('fixed_remote_probe_offline', ROOT / 'remote_probe.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class SafetyTests(unittest.TestCase):
    def test_fixed_source_syntax_and_commands(self):
        for path in ROOT.glob('*.py'):
            ast.parse(path.read_text(), filename=str(path))
        source = (ROOT / 'remote_probe.py').read_text()
        for required in ("'/usr/bin/vim.tiny'", "'/usr/bin/sleep'", "'/usr/bin/stty'", 'os.O_EXCL', 'os.O_NOFOLLOW', 'finally:', 'termios.tcsetattr', 'signal.alarm(110)', 'pass_fds=(ready_fd,)'):
            self.assertIn(required, source)
        for forbidden in ('shell=True', 'docker', 'socket.', 'paramiko', 'sshpass', 'PAM_', 'password.txt', 'key-passphrase', 'authorized_keys'):
            self.assertNotIn(forbidden, source)
        self.assertNotIn('subprocess', (ROOT / 'Core.swift').read_text())

    def test_frames_exact_nonce_and_no_terminal_dump(self):
        value = probe()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            value.emit('a' * 32, 'input', 20, 'b' * 64)
        self.assertEqual(output.getvalue(), '\r\nRT1|' + 'a' * 32 + '|input|20,' + 'b' * 64 + '|END\r\n')
        for nonce in ('a' * 31, 'A' * 32, 'a' * 32 + ';id'):
            with self.assertRaises(value.Refused): value.emit(nonce, 'done', 1)
        main = (ROOT / 'Main.swift').read_text()
        self.assertNotIn('session.respond(', main)
        self.assertNotIn('terminal.text)', main.replace('budget.inspect(session.terminal.text,', ''))
        self.assertNotIn('terminal.text.suffix', main)
        self.assertNotIn('savedPassword:', main)
        self.assertIn('keyboardInteractive: false', main)
        self.assertIn('authenticationRequests += 1', main)

    def test_fixed_vim_ready_argv_uses_core_ex_without_executing_vim(self):
        source = (ROOT / 'remote_probe.py').read_text()
        tree = ast.parse(source)
        command = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == 'ready_command' for target in node.targets))
        expression = ast.Expression(command.value)
        self.assertEqual(eval(compile(expression, '<fixed-ready-command>', 'eval'), {'__builtins__': {}, 'str': str}, {'ready_fd': 7}),
                         'write! /proc/self/fd/7')
        self.assertNotIn('call writefile', source)
        self.assertLess(source.index('ready_fd = document.arm_vim_ready()'), source.index("child = subprocess.Popen(['/usr/bin/vim.tiny'"))
        self.assertIn('if document.vim_ready():', source)
        self.assertIn('if child.poll() is not None or not document.vim_ready():', source)
        call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == 'Popen' and isinstance(node.args[0], ast.List)
                    and isinstance(node.args[0].elts[0], ast.Constant) and node.args[0].elts[0].value == '/usr/bin/vim.tiny')
        self.assertEqual([ast.literal_eval(node) for node in call.args[0].elts[:-3]],
                         ['/usr/bin/vim.tiny', '-Nu', 'NONE', '-U', 'NONE', '-i', 'NONE', '-n', '--noplugin',
                          '-c', 'set nobackup nowritebackup noswapfile backupcopy=yes encoding=utf-8 fileencoding=utf-8', '-c'])
        self.assertEqual(ast.unparse(call.args[0].elts[-3]), 'ready_command')
        self.assertEqual(ast.literal_eval(call.args[0].elts[-2]), '--')
        self.assertEqual(ast.unparse(call.args[0].elts[-1]), 'document.document_path')

    def test_vim_ready_requires_armed_sentinel_then_same_inode_empty_write(self):
        value = probe()
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw).resolve(); parent.chmod(0o700)
            document = value.OwnedDocument('e' * 32, parent)
            try:
                with self.assertRaises(value.Refused): document.vim_ready()  # Fresh empty file is not proof.
                with mock.patch.object(value.os, 'fsync', wraps=os.fsync) as synced:
                    ready_fd = document.arm_vim_ready()
                    synced.assert_called_once_with(ready_fd)
                self.assertEqual(os.pread(ready_fd, len(value.READY_SENTINEL) + 1, 0), value.READY_SENTINEL)
                self.assertGreater(os.fstat(ready_fd).st_size, 0)
                self.assertFalse(document.vim_ready())
                with self.assertRaises(value.Refused): document.arm_vim_ready()
                ready_path = Path(document.document_path).with_name('vim-ready')
                other_fd = os.open(ready_path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
                os.close(other_fd)  # Simulate Ex's empty-buffer write, not a host Vim invocation.
                self.assertEqual(value.file_info(ready_fd), document.files['vim-ready'][1])
                self.assertEqual(os.fstat(ready_fd).st_size, 0)
                self.assertEqual(os.pread(ready_fd, 1, 0), b'')
                self.assertTrue(document.vim_ready())
                os.write(document.files['document.txt'][0], value.VIM_SAMPLE)
                self.assertEqual(document.contents(), value.VIM_SAMPLE)
            finally:
                self.assertTrue(document.close())

    def test_vim_ready_failed_sentinel_write_never_arms(self):
        value = probe()
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw).resolve(); parent.chmod(0o700)
            document = value.OwnedDocument('f' * 32, parent)
            try:
                with mock.patch.object(value.os, 'pwrite', return_value=0), mock.patch.object(value.os, 'fsync') as synced:
                    with self.assertRaises(value.Refused): document.arm_vim_ready()
                    synced.assert_not_called()
                with self.assertRaises(value.Refused): document.vim_ready()
                fd = document.files['vim-ready'][0]
                os.write(fd, b'unexpected')
                with self.assertRaises(value.Refused): document.arm_vim_ready()
            finally:
                self.assertTrue(document.close())

    def test_vim_ready_checks_exact_size_and_read_count_after_identity(self):
        value = probe()
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw).resolve(); parent.chmod(0o700)
            document = value.OwnedDocument('1' * 32, parent)
            try:
                fd = document.arm_vim_ready()
                with mock.patch.object(value.os, 'pread', return_value=b''):
                    self.assertFalse(document.vim_ready())  # Nonempty held inode is not ready.
                os.ftruncate(fd, 0)
                with mock.patch.object(value.os, 'pread', return_value=b'x'):
                    self.assertFalse(document.vim_ready())  # Size alone is not enough.
                with mock.patch.object(document, 'verify', side_effect=value.Refused), mock.patch.object(value.os, 'pread') as read:
                    with self.assertRaises(value.Refused): document.vim_ready()
                    read.assert_not_called()
            finally:
                self.assertTrue(document.close())

    def test_vim_ready_refuses_replaced_file_or_symlink_even_if_held_fd_is_empty(self):
        value = probe()
        for replacement in ('file', 'symlink'):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as raw:
                parent = Path(raw).resolve(); parent.chmod(0o700)
                document = value.OwnedDocument('2' * 32, parent)
                fd = document.arm_vim_ready()
                path = Path(document.document_path).with_name('vim-ready'); moved = path.with_name('moved-ready')
                path.rename(moved)
                if replacement == 'file': path.touch(mode=0o600)
                else: path.symlink_to(moved)
                os.ftruncate(fd, 0)
                with self.assertRaises(value.Refused): document.vim_ready()
                self.assertFalse(document.close())
                self.assertTrue(path.exists()); self.assertTrue(moved.exists())

    def test_vim_start_blocks_until_exact_fixed_ack_without_children_or_sleep(self):
        value = probe()
        for response, error in [(b'V\n', None), (b'S\n', value.Refused), (b'V\r', value.Refused),
                                (b'v\n', value.Refused), (b'', value.Refused), (None, value.Deadline)]:
            with self.subTest(response=response):
                reader = mock.Mock(side_effect=error() if response is None else None, return_value=response)
                with mock.patch.object(value, 'bounded_read', reader), mock.patch.object(value.subprocess, 'Popen', side_effect=AssertionError('child before ACK')), mock.patch.object(value.time, 'sleep', side_effect=AssertionError('sleep is not synchronization')):
                    if error is None: value.wait_vim_start()
                    else:
                        with self.assertRaises(error): value.wait_vim_start()
                reader.assert_called_once_with(0, 2, 12)
        tree = ast.parse((ROOT / 'remote_probe.py').read_text())
        run = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
        steps = next(node for node in run.body if isinstance(node, ast.Try)).body
        size_index = next(index for index, node in enumerate(steps) if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                          and isinstance(node.value.func, ast.Name) and node.value.func.id == 'emit'
                          and isinstance(node.value.args[1], ast.Constant) and node.value.args[1].value == 'size')
        self.assertEqual(ast.unparse(steps[size_index + 1]), 'wait_vim_start()')
        self.assertEqual(ast.unparse(steps[size_index + 2]), "stage = 'document-create'")
        self.assertEqual(ast.unparse(steps[size_index + 3]), 'document = OwnedDocument(nonce)')
        main = (ROOT / 'Main.swift').read_text()
        branch = main[main.index('case .vimStart:'):main.index('case .vimKeys:')]
        self.assertIn('enqueue(ProbePlan.vimStart, stage: .vimStartEnqueue, event: .vimStartEnqueued', branch)
        self.assertNotIn('sleep', branch)
        self.assertNotIn('remoteSizeMatched =', branch)

    def test_remote_failure_metadata_is_closed_and_never_error_text(self):
        value = probe()
        cases = [(value.Refused('private text'), ('refused', 'none')),
                 (value.Deadline(), ('deadline', 'none')),
                 (OSError(errno.ENOENT, 'private text', '/private/nonexistent'), ('os-error', 'enoent')),
                 (PermissionError(errno.EACCES, 'private text'), ('os-error', 'eacces')),
                 (OSError(98765, 'private text'), ('os-error', 'other')),
                 (value.subprocess.TimeoutExpired(['/private/tool'], 12), ('process-timeout', 'none')),
                 (value.subprocess.CalledProcessError(7, ['/private/tool']), ('process-exit', 'none')),
                 (RuntimeError('private text'), ('source-error', 'none'))]
        for error, expected in cases:
            with self.subTest(expected=expected):
                fields = value.failure_fields('vim-launch', error)
                self.assertEqual(fields, ('vim-launch', *expected))
                with mock.patch.object(value, 'run', side_effect=value.ProbeFailure(fields)), contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(value.main(['a' * 32]), 1)
                self.assertEqual(output.getvalue(), '\r\nRT1|' + 'a' * 32 + '|failed|' + ','.join(fields) + '|END\r\n')
                self.assertNotIn('private', output.getvalue())
        self.assertEqual(value.failure_fields('/private/stage', RuntimeError('private text')), ('unknown', 'source-error', 'none'))
        for fields in [('vim-ready', 'refused', '/private/path'), ('private-stage', 'refused', 'none'), ('vim-ready', 'private-error', 'none'), (1,)]:
            with self.assertRaises(value.Refused): value.emit('a' * 32, 'failed', *fields)
        with mock.patch.object(value, 'run', side_effect=RuntimeError('private text')), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(value.main(['a' * 32]), 1)
        self.assertIn('|failed|preflight,source-error,none|END', output.getvalue())

    def test_probe_progress_is_recorded_even_when_inspection_throws(self):
        main = (ROOT / 'Main.swift').read_text()
        core = (ROOT / 'Core.swift').read_text()
        self.assertIn('catch { report.recordProbe(budget); throw error }', main)
        self.assertNotIn('report.remoteSizeMatched = true', main)
        self.assertIn('remoteSizeMatched = budget.remoteSizeMatched', core)
        self.assertIn('unexpectedProbeFrame = budget.unexpectedFrame', core)
        self.assertIn('remoteProbeFailure = budget.remoteFailure', core)
        self.assertIn('next == expected.count, events == expected.count, remotePID != nil', core)

    def test_pure_swift_baseline_and_vim_failure_boundary(self):
        with tempfile.TemporaryDirectory(prefix='vim-frame-offline-', dir=ROOT / '.build') as raw:
            work = Path(raw)
            def run(args):
                result = subprocess.run([str(arg) for arg in args], cwd=ROOT, capture_output=True, text=True, timeout=120)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return result.stdout
            compiler = run(['/usr/bin/xcrun', '--find', 'swiftc']).strip()
            sdk = run(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path']).strip()
            flags = ['-parse-as-library', '-swift-version', '6', '-target', 'arm64-apple-macosx15.0', '-sdk', sdk,
                     '-module-cache-path', work / 'module-cache', '-warnings-as-errors']
            run([compiler, *flags, '-emit-library', '-emit-module', '-module-name', 'RemoteTerminalCore',
                 ROOT / 'Core.swift', '-emit-module-path', work / 'RemoteTerminalCore.swiftmodule', '-o', work / 'libRemoteTerminalCore.dylib'])
            regression = work / 'VimFailureBoundary.swift'
            regression.write_text(r'''
import Foundation
import RemoteTerminalCore

@main enum VimFailureBoundary {
    static func main() throws {
        func check(_ value: Bool) throws { if !value { throw TerminalCheckError.integrity } }
        let nonce = String(repeating: "a", count: 32), hash = String(repeating: "c", count: 64)
        func frame(_ name: String, _ fields: String = "") -> String { "RT1|" + nonce + "|" + name + "|" + fields + "|END" }
        let prefix = [frame("load-ready", "10," + hash), frame("hello", "10000,321"),
                      frame("input-ready", String(ProbePlan.input.count)), frame("input", String(ProbePlan.input.count) + "," + Syntax.hash(ProbePlan.input)),
                      frame("interrupt-ready"), frame("interrupt", "1"), frame("resize-ready")]
        func seeded() throws -> ProbeBudget {
            var budget = try ProbeBudget(nonce: nonce, sourceCount: 10, sourceSHA256: hash, start: 100)
            for text in prefix { _ = try budget.inspect(text, now: 101) }
            try check(budget.events == 7 && !budget.remoteSizeMatched)
            return budget
        }
        for (fields, expectedKind, expectedErrno): (String, RemoteFailureKind, RemoteFailureErrno) in [
            ("vim-launch,os-error,enoent", .osError, .enoent), ("vim-ready,refused,none", .refused, .none),
            ("document-create,os-error,eacces", .osError, .eacces), ("vim-ready,source-error,none", .sourceError, .none)] {
            var budget = try seeded()
            do {
                _ = try budget.inspect(frame("size", "31,93") + frame("failed", fields), now: 102)
                throw TerminalCheckError.integrity
            } catch let error as TerminalCheckError { try check(error == .remoteFailure) }
            try check(budget.events == 8 && budget.remoteSizeMatched && !budget.cleanupAcknowledged)
            try check(budget.unexpectedFrame == .failed)
            try check(budget.remoteFailure?.kind == expectedKind && budget.remoteFailure?.errno == expectedErrno)
            try check(budget.remoteFailure?.stage.rawValue == String(fields.split(separator: ",")[0]))
            do { try budget.requireComplete(); throw TerminalCheckError.integrity }
            catch let error as TerminalCheckError { try check(error == .unexpectedFrame) }
            var report = TerminalReport()
            report.recordProbe(budget)
            let encoded = try JSONEncoder().encode(report)
            let object = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
            try check(object["remoteSizeMatched"] as? Bool == true && object["probeEvents"] as? Int == 8)
            try check(object["unexpectedProbeFrame"] as? String == "failed")
            try check((object["remoteProbeFailure"] as? [String: String])?["errno"] == expectedErrno.rawValue)
            try check(!report.returnedToOuter && !report.remoteCleanup && !report.vimBytesHashMatched)
        }
        for (name, fields, allowed): (String, String, ProbeFrameName) in [
            ("failed", "1", .failed), ("failed", "vim-ready,refused,/private/path", .failed),
            ("failed", "arbitrary-stage,refused,none", .failed), ("failed", "vim-ready,arbitrary-error,none", .failed),
            ("failed", "vim-ready,refused,none,extra", .failed), ("/private/frame-name", "private-value", .unrecognized),
            ("", "", .unrecognized), ("vim-ready", "private-value|extra", .vimReady),
            ("vim", "0,wrong-hash", .vim)] {
            var budget = try seeded()
            _ = try budget.inspect(frame("size", "31,93"), now: 102)
            do { _ = try budget.inspect(frame(name, fields), now: 103); throw TerminalCheckError.integrity }
            catch let error as TerminalCheckError { try check(error == .unexpectedFrame) }
            try check(budget.unexpectedFrame == allowed && budget.remoteFailure == nil && budget.events == 8)
            var report = TerminalReport(); report.recordProbe(budget)
            let text = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
            try check(!text.contains("private") && !text.contains("arbitrary") && !text.contains("wrong-hash"))
        }
        var wrongSize = try seeded()
        do { _ = try wrongSize.inspect(frame("size", "31,94"), now: 102); throw TerminalCheckError.unexpectedFrame }
        catch let error as TerminalCheckError { try check(error == .integrity) }
        try check(!wrongSize.remoteSizeMatched && wrongSize.events == 7)
        var tooEarly = try ProbeBudget(nonce: nonce, sourceCount: 10, sourceSHA256: hash, start: 100)
        do { _ = try tooEarly.inspect(frame("size", "31,93"), now: 102); throw TerminalCheckError.integrity }
        catch let error as TerminalCheckError { try check(error == .unexpectedFrame) }
        try check(!tooEarly.remoteSizeMatched && tooEarly.events == 0)
        var valid = try seeded()
        _ = try valid.inspect(frame("size", "31,93"), now: 102)
        try check(valid.inspect(frame("vim-ready"), now: 103) == .vimKeys && valid.unexpectedFrame == nil)
        try check(ProbeFrameName(rawValue: "/private/unknown") == nil)
        print("Vim boundary pure Swift checks passed; strict failure/order/size and closed report metadata.")
    }
}
''')
            for source in (ROOT / 'OfflineMain.swift', regression):
                binary = work / source.stem
                run([compiler, *flags, '-I', work, '-L', work, '-lRemoteTerminalCore', '-Xlinker', '-rpath', '-Xlinker', work,
                     source, '-o', binary])
                output = run([binary])
                self.assertIn('checks passed', output)
                if source.name == 'OfflineMain.swift':
                    self.assertIn('original 128-check baseline passed', output)
                    self.assertIn('original128 retained', output)

    def test_owned_document_exclusive_and_safe_cleanup(self):
        value = probe()
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw).resolve(); parent.chmod(0o700)
            document = value.OwnedDocument('a' * 32, parent)
            self.assertEqual(stat.S_IMODE(Path(document.document_path).stat().st_mode), 0o600)
            fd = document.files['document.txt'][0]
            os.write(fd, value.VIM_SAMPLE)
            self.assertEqual(document.contents(), value.VIM_SAMPLE)
            with self.assertRaises(FileExistsError): value.OwnedDocument('a' * 32, parent)
            self.assertTrue(document.close())
            self.assertEqual(list(parent.iterdir()), [])

    def test_owned_document_never_removes_replacement_or_symlink(self):
        value = probe()
        for replacement in ('file', 'symlink'):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as raw:
                parent = Path(raw).resolve(); parent.chmod(0o700)
                document = value.OwnedDocument('b' * 32, parent)
                path = Path(document.document_path); moved = path.with_name('moved-original')
                path.rename(moved)
                if replacement == 'file': path.write_bytes(b'public-bystander'); path.chmod(0o600)
                else: path.symlink_to(moved)
                with self.assertRaises(value.Refused): document.verify()
                self.assertFalse(document.close())
                self.assertTrue(path.exists()); self.assertTrue(moved.exists())

    def test_owned_document_refuses_parent_alias_and_unknown_entry(self):
        value = probe()
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw).resolve(); parent.chmod(0o700)
            alias = parent / 'alias'; alias.symlink_to(parent)
            with self.assertRaises(OSError): value.OwnedDocument('c' * 32, alias)
            document = value.OwnedDocument('d' * 32, parent)
            extra = Path(document.document_path).with_name('unowned')
            extra.write_bytes(b'nonsecret'); extra.chmod(0o600)
            with self.assertRaises(value.Refused): document.verify()
            self.assertFalse(document.close()); self.assertTrue(extra.exists())

    def test_remote_run_offline_guard_has_no_children(self):
        value = probe()
        with mock.patch.object(value.os, 'getuid', return_value=123), mock.patch.object(value.subprocess, 'Popen', side_effect=AssertionError('live process')):
            with self.assertRaises(value.Refused): value.run('e' * 32)

    def test_named_volume_gate_is_exact_and_full_cid_contract_remains(self):
        core = (ROOT / 'Core.swift').read_text()
        live = (ROOT / 'LiveInput.swift').read_text()
        for required in ('validateMounts', 'mounts.count == 1', '"Type"] as? String == "volume"', '"Destination"] as? String == "/fixture"', 'CFBooleanGetTypeID()', 'Syntax.hex(containerID, 64)'):
            self.assertIn(required, core)
        self.assertIn('try Syntax.validateMounts(binds: host["Binds"], mounts: item["Mounts"], project: contract.project)', live)
        self.assertNotIn('host["Binds"] is NSNull', live)
        self.assertIn('"Source"] as? String == "/var/lib/docker/volumes/" + volume + "/_data"', core)

    def test_short_ack_precedes_loader_and_preserves_typed_failure(self):
        main = (ROOT / 'Main.swift').read_text()
        core = (ROOT / 'Core.swift').read_text()
        self.assertLess(main.index('shortACK.requireAcknowledged()'), main.index('ProbePlan.command(source:'))
        self.assertLess(main.index('shortACK.command()'), main.index('shortACK.inspect(rendered:'))
        self.assertIn('failureSession = observation()', main)
        self.assertLess(main.index('preCloseSession = observation()'), main.index('session.cancel(); session.closeTab()'))
        for value in ('session.lastExitCode', 'session.pendingInputBytes', 'session.inputError', 'terminalFailure = reason',
                      'stopRequested = stop.requested', 'remoteStarted = true', 'report.recordProbe(budget)',
                      'mark(.firstInputAttempt', 'mark(.firstInputReturned', 'mark(.sessionEnded'):
            self.assertIn(value, main)
        self.assertIn('postAuth?.remotePID = budget.remotePID', core)
        self.assertIn('bytes.count <= 256', core)
        self.assertIn('remotePIDConfirmed: Bool { remotePID != nil }', core)
        self.assertIn('case .launchFailed: reason = .launchFailed', main)
        self.assertNotIn('error.localizedDescription', main)
        self.assertNotIn('String(describing: error)', main)
        self.assertNotIn('case 255:', main)
        self.assertIn('["load-ready", "hello", "input-ready", "input", "interrupt-ready", "interrupt", "resize-ready", "size", "vim-ready", "vim", "done", "returned"]', core)

    def test_diagnostic_schema_never_records_freeform_terminal_or_error(self):
        core = (ROOT / 'Core.swift').read_text()
        start = core.index('public struct PostAuthDiagnostics:')
        end = core.index('public struct ShortShellACK:', start)
        diagnostics = core[start:end]
        for forbidden in ('var terminalText', 'var prompt', 'var inputData', 'var errorDescription', 'Any', 'Data'):
            self.assertNotIn(forbidden, diagnostics)
        self.assertIn('case stage, failureStage', diagnostics)
        self.assertIn('try values.encode(remotePID, forKey: .remotePID)', diagnostics)

    def test_build_default_is_inert_and_own_outputs(self):
        source = (ROOT / 'build_host.py').read_text()
        self.assertIn("base = HERE / '.build'", source)
        self.assertIn("work = base / ('host-' + str(uuid.uuid4()))", source)
        self.assertNotIn('authorized-download', source)
        self.assertNotIn('apt-get', source)
        self.assertNotIn('subprocess.run([str(app)', source)
        self.assertIn("builder.sign(app)", source)
        self.assertIn("'OpenLXSSHRemoteTerminalTestOnly': True", source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
