#!/usr/bin/env python3
"""Source-only regressions: never invoke Docker, compiler, credentials or network."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('remote_file_build', HERE / 'build_host.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class OfflinePolicyTests(unittest.TestCase):
    def test_default_help_validate_do_not_touch_files_or_children(self):
        with patch.object(build, 'build', side_effect=AssertionError('build not authorized')), \
             patch.object(build.subprocess, 'run', side_effect=AssertionError('child not authorized')), \
             patch.object(Path, 'read_bytes', side_effect=AssertionError('read not authorized')), \
             patch.object(Path, 'mkdir', side_effect=AssertionError('write not authorized')), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(build.main([]), 0)
            self.assertEqual(build.main(['help']), 0)
            self.assertEqual(build.main(['validate']), 0)
            with self.assertRaises(SystemExit) as caught:
                build.main(['--help'])
            self.assertEqual(caught.exception.code, 0)

    def test_builder_has_no_live_or_shared_cache_commands(self):
        source = (HERE / 'build_host.py').read_text()
        for forbidden in ("'docker'", "'ssh'", "'sftp'", "'curl'", "'swift', 'build'", "'swift', 'test'", "'security'", 'sign-development'):
            self.assertNotIn(forbidden, source)
        self.assertIn("'host-' + str(uuid.uuid4())", source)
        self.assertIn('b.unchanged()', source)
        self.assertIn("'HOME': str(work / 'home')", source)
        self.assertIn('nativeOutputMismatch', source)

    def test_driver_uses_only_production_capability_probe(self):
        source = (HERE / 'Campaign.swift').read_text()
        self.assertIn('ServerCommitProbe.run(', source)
        self.assertIn('LibSSH2FileService.connect(', source)
        self.assertIn('SafeTransferEngine(', source)
        self.assertIn('TransferManager(', source)
        self.assertNotIn('ServerCommitConfirmation(', source)
        self.assertNotIn('Process(', source)
        self.assertNotIn('/bin/sh', source)
        self.assertNotIn('SSHSession', source)
        self.assertEqual(source.count('"/id_ed25519"'), 1)
        self.assertNotIn('password.txt', source)
        self.assertIn('privateKey: privateKey', source)
        self.assertNotIn('String(data: privateKey', source)
        self.assertIn('actual-readdir-bytes-match', source)

    def test_sources_have_exact_binding_and_no_reduced_mode(self):
        source = (HERE / 'Core.swift').read_text()
        for value in ('127.0.0.1:22221', 'keyonly/credentials-', 'small_file_count == 1000', 'large_bytes == Fixed.largeBytes',
                      '2 * 1024 * 1024 * 1024', 'oCBbJaAjOZMzrKEnj+Z4iHSn74Qc+0tTu9bOzfpwJ5w'):
            self.assertIn(value, source)
        self.assertNotIn('case small', source)
        self.assertNotIn('defaultHost', source)
        self.assertEqual((HERE / '.gitignore').read_text(), '.runtime/\n__pycache__/\n')

    def test_native_macho_parser_fails_closed(self):
        class Fake:
            def read_bytes(self):
                return b'not-a-mach-o'
        with self.assertRaises(build.Refusal):
            build.macho(Fake(), 2)


if __name__ == '__main__':
    unittest.main()
