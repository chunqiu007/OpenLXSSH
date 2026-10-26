#!/usr/bin/env python3
"""Offline-only fixed-peer safety checks; never opens any socket."""
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode=True
HERE=Path(__file__).absolute().parent


class Tests(unittest.TestCase):
    def test_python_syntax_and_inert_builder(self):
        for path in HERE.glob('*.py'):compile(path.read_bytes(),str(path),'exec')
        spec=importlib.util.spec_from_file_location('timeout_builder',HERE/'build_host.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        for args in ([],['--help'],['validate']):
            with mock.patch.object(module.os,'open',side_effect=AssertionError('I/O')),mock.patch.object(module.subprocess,'Popen',side_effect=AssertionError('child')),mock.patch('sys.stdout',io.StringIO()):
                try:result=module.main(args)
                except SystemExit as error:result=error.code
                self.assertEqual(result,0)

    def test_fixed_silent_peer_only_no_wire_io_or_reuse(self):
        source=(HERE/'SilentPeer.swift').read_text()
        self.assertIn('inet_pton(AF_INET,TimeoutFixed.host',source)
        self.assertIn('address.sin_port=TimeoutFixed.port.bigEndian',source)
        self.assertIn('Darwin.listen(fd,1)',source)
        self.assertIn('descriptors.closeListener() // exactly one accept',source)
        for forbidden in ('Darwin.read(','Darwin.recv(','Darwin.write(','Darwin.send(','SO_REUSEADDR','SO_REUSEPORT','Process()'):
            self.assertNotIn(forbidden,source)
        self.assertIn('TimeoutFixed.peerSeconds',source)
        self.assertIn('await pending.value',source)

    def test_public_connection_no_secrets_or_mock_timeout(self):
        source=(HERE/'TimeoutCase.swift').read_text()
        self.assertIn('LibSSH2FileService.connect(',source)
        self.assertIn('operationTimeout:TimeoutFixed.operationSeconds',source)
        self.assertIn('authentication:[.keyboardInteractive(',source)
        self.assertIn('failure=TimeoutFacts(error)',source)
        for forbidden in ('FileServiceError(.timeout','connectedSocket:','.runtime/keyonly','id_ed25519','passphrase','Keychain','docker','ssh-keyscan'):
            self.assertNotIn(forbidden,source)
        self.assertIn('gate.outerTimeout()',source)
        self.assertIn('watchdog.cancel();await watchdog.value',source)

    def test_default_and_validate_before_any_runtime(self):
        source=(HERE/'Main.swift').read_text()
        validate=source.index('options.action == .validate')
        self.assertLess(validate,source.index('PrivateInput.read'))
        self.assertLess(validate,source.index('TimeoutRun.execute'))
        self.assertNotIn('prepare',source)

    def test_exact_shared_core_closure(self):
        source=(HERE/'build_host.py').read_text()
        self.assertIn("('Contract.swift','PrivateInput.swift')",source)
        self.assertNotIn("b.sources(accepted.CORE/'RealIntegrationCore')",source)
        self.assertNotIn('IntegrationEnvironment/relay.py',source)


if __name__=='__main__':unittest.main(verbosity=2)
