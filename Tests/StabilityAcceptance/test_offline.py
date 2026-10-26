#!/usr/bin/env python3
"""Offline-only black-box refusals, static safety checks and existing-module typecheck.

Requires the small offline SwiftPM tests to have been run already. Never compiles
or links the real driver, resolves dependencies, signs, queries identities, opens
.runtime, launches the wrapper, starts fixtures, sleeps for a soak or connects.
"""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parent.parent
BUILD = HERE / '.build'
OFFLINE = BUILD / 'offline' / 'arm64-apple-macosx' / 'debug'
BINARY = OFFLINE / 'stability-preflight'


def tree_snapshot():
    # Deliberately only this task's directory, never official fixture runtime.
    return sorted(str(path.relative_to(HERE)) for path in HERE.rglob('*'))


class OfflineChecks(unittest.TestCase):
    def test_offline_build_plan_has_no_implicit_codesign_step(self):
        plan = (BUILD / 'offline' / 'debug.yaml').read_text()
        self.assertNotIn('codesign', plan)
        self.assertNotIn('Applying debug entitlements', plan)
        entry = (HERE / 'verify_offline.py').read_text()
        self.assertIn("'--disable-get-task-allow-entitlement'", entry)
        self.assertIn("'--print-manifest-job-graph'", entry)
        self.assertLess(entry.index("if 'codesign' in plan"), entry.index("run(['swift', 'test']"))

    def run_cli(self, arguments, expected):
        result = subprocess.run([str(BINARY)] + arguments, cwd=HERE, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def test_default_help_and_validate_are_readonly(self):
        before = tree_snapshot()
        self.assertIn('no network by default', self.run_cli([], 0))
        self.assertIn('no network or output files', self.run_cli(['validate'], 0))
        self.assertEqual(tree_snapshot(), before)

    def test_missing_flag_refuses_and_offline_binary_never_runs_transport(self):
        before = tree_snapshot()
        marker = 'MUST-NOT-BE-PRINTED-OR-OPENED'
        output = self.run_cli(['run', '--credentials', '/' + marker, '--output-parent', '/' + marker], 2)
        self.assertIn('authorizationRequired', output)
        self.assertNotIn(marker, output)
        output = self.run_cli(['run', '--authorized-isolated-run'], 2)
        self.assertIn('signedAppRequired', output)
        self.assertEqual(tree_snapshot(), before)
        # Structural proof: the preflight package imports no network/Transport.
        manifest = (HERE / 'Package.swift').read_text()
        self.assertNotIn('.package(', manifest)
        source = (HERE / 'Sources' / 'StabilityPreflight' / 'Main.swift').read_text()
        for forbidden in ('DirectSSHSession(', 'Process()', 'URLSession', 'socket(', 'connect('):
            self.assertNotIn(forbidden, source)

    def test_invalid_endpoints_and_duration_rejected_without_io(self):
        before = tree_snapshot()
        for host in ('localhost', '127.1', '127.0.0.2', '::1', '::ffff:127.0.0.1', '192.0.2.1'):
            self.assertIn('unsafeEndpoint', self.run_cli(['validate', '--host', host], 2))
        for duration in ('1', '86399', '604801'):
            self.assertIn('invalidArguments', self.run_cli(['validate', '--duration-seconds', duration], 2))
        self.assertEqual(tree_snapshot(), before)

    def test_driver_consumes_public_product_api_without_backdoors(self):
        driver = (HERE / 'SignedDriver' / 'Main.swift').read_text()
        self.assertIn('DirectSSHSession(trustStore:', driver)
        self.assertIn('case .connected:', driver)
        self.assertIn('NSApp.run()', driver)
        self.assertIn('BundledAskpassHelper.discover()', driver)
        self.assertIn('var cancellationEligible: Bool', driver)
        self.assertIn('guard failure == nil, !authenticated else { return false }', driver)
        self.assertIn('switch session.state', driver)
        self.assertIn('case .preparing, .connectionPending: return true', driver)
        self.assertIn('guard try sampler.observedChildrenStillAlive().isEmpty', driver)
        self.assertIn('metricsIncomplete = true // Unknown is not an empty/already-clean resource set.', driver)
        self.assertIn('anchor apple generic and identifier', driver)
        self.assertIn('try await store.confirm(decision, displayedFingerprint: fixture.hostFingerprint)', driver)
        for forbidden in ('acceptTrust(', 'probeStore:', 'startProbe(', 'TRANSPORT_HOST_PROBE',
                          'sendInput(', 'terminal.text', 'getBufferAsData', 'SecItemCopyMatching',
                          'StrictHostKeyChecking no', 'StrictHostKeyChecking accept-new',
                          'ssh-keyscan -', 'kill(', 'pkill', 'Process()', 'UserDefaults'):
            self.assertNotIn(forbidden, driver)
        # Only the reviewed product scanner observes network keys; source has no
        # embedded system ssh command line or remote shell command generation.
        self.assertNotIn('executableURL', driver)
        c_source = (HERE / 'Sources' / 'StabilityPOSIX' / 'StabilityPOSIX.c').read_text()
        self.assertIn('PROC_PPID_ONLY', c_source)
        for forbidden in ('PROC_ALL_PIDS', 'kill(', 'system(', 'popen(', 'execve(', 'socket('):
            self.assertNotIn(forbidden, c_source)

    def test_wrapper_defaults_refusals_and_metadata_validation_no_packaging(self):
        spec = importlib.util.spec_from_file_location('stability_prepare_wrapper', HERE / 'prepare_wrapper.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(module.main([]), 0)
        before = tree_snapshot()
        with self.assertRaises(ValueError):
            module.main(['prepare', '--driver', '/not-read', '--helper', '/not-read'])
        with tempfile.TemporaryDirectory(prefix='wrapper-unit-', dir=BUILD) as value:
            directory = Path(value)
            for name in ('driver', 'helper'):
                path = directory / name
                path.write_text('OFFLINE METADATA SENTINEL, NOT EXECUTABLE CODE\n')
                path.chmod(0o700)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(module.main(['validate', '--driver', str(directory / 'driver'), '--helper', str(directory / 'helper'),
                                              '--revision', 'c' * 40]), 0)
            alias = directory / 'alias'
            alias.symlink_to(directory / 'driver')
            with self.assertRaises(ValueError):
                module.main(['validate', '--driver', str(alias), '--helper', str(directory / 'helper'), '--revision', 'c' * 40])
        self.assertEqual(tree_snapshot(), before)
        self.assertFalse(module.DESTINATION.exists())
        text = (HERE / 'prepare_wrapper.py').read_text()
        self.assertNotIn('subprocess', text)
        self.assertNotIn('codesign', text)


def typecheck_existing_modules():
    transport = WORKSPACE / 'Packages' / 'OpenLXSSHTransport' / '.build' / 'macos26' / 'arm64-apple-macosx' / 'release'
    required = (transport / 'Modules' / 'OpenLXSSHTransport.swiftmodule',
                transport / 'Modules' / 'OpenLXSSHTrust.swiftmodule', OFFLINE / 'Modules' / 'StabilityCore.swiftmodule')
    if not all(path.exists() for path in required):
        raise RuntimeError('Existing modules unavailable; not building or fetching them. Typecheck NOT performed.')
    command = ['xcrun', 'swiftc', '-typecheck', '-parse-as-library', '-swift-version', '6', '-warnings-as-errors',
               '-target', 'arm64-apple-macosx26.0', '-module-cache-path', str(BUILD / 'module-cache'),
               '-I', str(OFFLINE / 'Modules'), '-I', str(OFFLINE / 'StabilityPOSIX.build'),
               '-I', str(transport / 'Modules'), '-I', str(transport / 'COpenLXSSHAskpass.build'),
               str(HERE / 'SignedDriver' / 'Main.swift')]
    completed = subprocess.run(command, cwd=HERE, timeout=60)
    print(json.dumps({'check': 'real-public-API-typecheck-only-not-build-or-run', 'cwd': str(HERE),
                      'command': command, 'exitCode': completed.returncode}), flush=True)
    return completed.returncode


if __name__ == '__main__':
    # Python compilation in memory: no pycache, fixture import, or Docker invocation.
    for name in ('test_offline.py', 'prepare_wrapper.py', 'verify_offline.py'):
        compile((HERE / name).read_text(), str(HERE / name), 'exec')
    if not BINARY.is_file():
        sys.stderr.write('Run the documented no-dependency offline SwiftPM tests first.\n')
        sys.exit(2)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(OfflineChecks)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        sys.exit(1)
    try:
        sys.exit(typecheck_existing_modules())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        sys.stderr.write(str(error) + '\n')
        sys.exit(2)
