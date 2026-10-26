#!/usr/bin/env python3
"""Offline syntax/policy tests; no generation, SSH, Docker or credentials."""
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
        spec=importlib.util.spec_from_file_location('builder',HERE/'build_host.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        for args in ([],['--help'],['validate']):
            with mock.patch.object(module.os,'open',side_effect=AssertionError('I/O')),mock.patch.object(module.subprocess,'Popen',side_effect=AssertionError('child')),mock.patch('sys.stdout',io.StringIO()):
                try:result=module.main(args)
                except SystemExit as value:result=value.code
                self.assertEqual(result,0)

    def test_closed_cases_and_no_secret_transport(self):
        core=(HERE/'AuthCore.swift').read_text();case=(HERE/'AuthCase.swift').read_text();main=(HERE/'Main.swift').read_text()
        self.assertIn('bad-key-passphrase',core);self.assertIn('known-host-mismatch',core)
        self.assertNotIn('.keyboardInteractive(',case)
        self.assertNotIn('.password(',case)
        self.assertNotIn('Keychain',case.split('let authBoundaries=')[0])
        self.assertIn('authentication:[.publicKey(',case)
        self.assertIn('mutatePassphraseOnce',case)
        self.assertIn('expectedCurrentFingerprint:old',case)
        self.assertIn('displayedFingerprint:AuthFixed.fingerprint',case)
        callback=case[case.index('func callback'):case.index('func snapshot')]
        self.assertIn('reply.resolve(.reject)',callback)
        self.assertNotIn('prepareReplacement',callback);self.assertNotIn('.confirm',callback)
        self.assertIn('options.action == .runNegative',main)
        for forbidden in ('secretSHA256','passphraseSHA256','passwordSHA256','String(describing:error)','localizedDescription'):
            self.assertNotIn(forbidden,core+case+main)

    def test_no_remote_writes_and_failed_connection_not_reclassified(self):
        text=(HERE/'AuthCase.swift').read_text()
        for forbidden in ('service.write(', 'service.mkdir(', 'service.remove(', 'service.rename(', 'SafeTransferEngine', 'sendInput'):
            self.assertNotIn(forbidden,text)
        self.assertIn('catch let error as FileServiceError {failure=FailureFacts(error)}',text)
        self.assertIn('await service.close()',text)
        self.assertIn('remote_file_fixture_sockets()',text)
        self.assertIn('if positive,let service',text)
        self.assertIn('service.list(RemotePath("/fixture/home")',text)

    def test_bounded_mature_public_key_generation_and_exact_cleanup(self):
        text=(HERE/'OwnedFiles.swift').read_text()
        self.assertIn('"/usr/bin/ssh-keygen"',text)
        self.assertIn('process.standardOutput=FileHandle.nullDevice',text)
        self.assertIn('O_NOFOLLOW',text)
        self.assertIn('unlinkat(parent,name,0)',text)
        self.assertIn('owned[name]?.0==UInt64(info.st_dev)',text)
        self.assertNotIn('FileManager.default.removeItem',text)
        self.assertNotIn('shell',text)
        self.assertIn('mismatch-public.txt',text)

    def test_exact_core_closure_excludes_parallel_auth_sources(self):
        text=(HERE/'build_host.py').read_text()
        self.assertIn("('Contract.swift','PrivateInput.swift')",text)
        self.assertNotIn("b.sources(accepted.CORE/'RealIntegrationCore')",text)
        self.assertNotIn('Tests/IntegrationEnvironment/relay.py',text)


if __name__=='__main__':unittest.main(verbosity=2)
