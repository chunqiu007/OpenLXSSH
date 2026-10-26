#!/usr/bin/env python3
"""Offline source/wrapper boundaries, never a live integration assertion."""
import importlib.util
import json
from pathlib import Path
import plistlib
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('host_build', HERE / 'build_host.py')
host_build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host_build)


class StaticTests(unittest.TestCase):
    def test_help_validate_never_open_inputs_query_signers_or_spawn(self):
        with mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('fileIO')), \
             mock.patch.object(Path, 'mkdir', side_effect=AssertionError('write')), \
             mock.patch.object(host_build.subprocess, 'run', side_effect=AssertionError('spawn')):
            self.assertEqual(host_build.main(['validate']), 0)
            self.assertEqual(host_build.main(['help']), 0)

    def test_consumer_only_calls_public_production_entrypoints(self):
        body = (HERE / 'Consumer/ProductionConsumer.swift').read_text()
        self.assertIn('session = DirectSSHSession(trustStore:', body)
        self.assertIn('try session.connect(configuration)', body)
        self.assertIn('LibSSH2FileService.connect(configuration:', body)
        self.assertIn('trustStore: trust', body)
        self.assertIn('await service.close()', body)
        self.assertIn('session.state != .closed || session.ownedProcessID != nil', body)
        self.assertNotIn('session.startProbe(', body)
        self.assertNotIn('probeStore:', body)
        self.assertNotIn('session.terminal.text', body)
        self.assertNotIn('savedPassword:', body)
        self.assertNotIn('sendInput(', body)
        self.assertIn('throw SmokeError.negativeUnclassified', body)

    def test_no_fixture_or_product_edits_in_build_recipe(self):
        source = (HERE / 'build_host.py').read_text()
        self.assertNotIn("'docker'", source)
        self.assertNotIn('swift package', source)
        self.assertIn("'OPENLXSSH_TRANSPORT_HOST_PROBE': '1'", source)
        self.assertEqual(host_build.TARGET, 'arm64-apple-macosx15.0')
        self.assertNotEqual(host_build.APP_ID, host_build.HELPER_ID)
        self.assertIn("'--timestamp=none'", source)
        self.assertIn("'--options', 'runtime'", source)
        self.assertIn("('helper', app / 'Contents/Helpers/openlxssh-askpass', HELPER_ID), ('app', app, APP_ID)", source)

    def test_native_manifest_and_sources_are_snapshotted_before_link(self):
        source = (HERE / 'build_host.py').read_text()
        self.assertIn("sha(NATIVE / relative, native_export=True) != expected", source)
        self.assertIn('builder.unchanged()', source)
        self.assertIn("minimum(output, 2)", source)
        self.assertIn("consumer-public-api-symbols", source)
        self.assertIn("'liveExecuted': False", source)

    def test_output_metadata_has_no_secret_surface(self):
        body = (HERE / 'Sources/RealIntegrationCore/Limits.swift').read_text().split('public struct SmokeReport:', 1)[1]
        for name in ('password:', 'privateKey:', 'prompt:', 'terminal:', 'credentialDirectory:', 'hostKeyLine:'):
            self.assertNotIn(name, body)


if __name__ == '__main__':
    unittest.main()
