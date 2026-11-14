#!/usr/bin/env python3
"""Offline source-shape security checks; never runs native binaries or fixtures."""
from pathlib import Path
import unittest

ROOT = Path(__file__).absolute().parents[3]
PROBE = ROOT / 'Experiments/UXNativeShellProbe'


class NativeLivenessSourceTests(unittest.TestCase):
    def test_fault_validation_failure_keeps_sanitized_report(self):
        text = (PROBE / 'Fixture/LiveConsumer.swift').read_text()
        self.assertIn('final.validationFailure = validationStage', text)
        self.assertIn('final.result = "failed-validation"', text)
        self.assertIn('let data = try JSONEncoder().encode(final)', text)
        self.assertIn('return final.failure == nil ? 0 : 1', text)
        self.assertIn('native.pendingInteractionTasks == 0', text)
        self.assertIn('final.serverSessionFileRemoved', text)
        self.assertNotIn('String(describing: error)', text)

    def test_maxsessions_instrumentation_is_separate_build_and_public_apis_only(self):
        build = (PROBE / 'build_liveness.py').read_text()
        shim = (PROBE / 'LivenessTestSupport/MaxSessions.c').read_text()
        self.assertIn("if instrumented:", build)
        self.assertIn('-Dlibssh2_channel_open_ex=ns_test_channel_open_ex', build)
        self.assertIn("'normalAndDropUninstrumented': not instrumented", build)
        self.assertIn('while(next_slot < 7)', shim)
        self.assertIn('libssh2_channel_open_ex(session, "session", 7, 1024, 1024, NULL, 0)', shim)
        self.assertIn('libssh2_session_free(session)', shim)
        for forbidden in ('libssh2_priv.h', 'channel_process_startup', 'channel_request_pty', 'system(', 'exec('):
            self.assertNotIn(forbidden, shim)

    def test_supervisor_never_loads_secret_material_or_writes_server_configuration(self):
        text = (Path(__file__).parent / 'supervise_native.py').read_text()
        self.assertNotIn("'id_ed25519'", text)
        self.assertNotIn("'password.txt'", text)
        self.assertNotIn("'key-passphrase.txt'", text)
        self.assertIn('lsof_connection(result.stdout, consumer.pid)', text)
        self.assertIn("'remoteBridgeAtResult'", (Path(__file__).parent / 'liveness_protocol.py').read_text())
        self.assertNotIn('killall', text)
        self.assertNotIn('pkill', text)


if __name__ == '__main__': unittest.main()
