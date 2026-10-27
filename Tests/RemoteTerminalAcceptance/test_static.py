#!/usr/bin/env python3
"""Offline AST/owned-file checks only. No SSH, Docker, PTY/socket, signing or live probe."""
import ast
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import stat
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
                      'stopRequested = stop.requested', 'remoteStarted = true', 'remotePID = budget.remotePID',
                      'mark(.firstInputAttempt', 'mark(.firstInputReturned', 'mark(.sessionEnded'):
            self.assertIn(value, main)
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
