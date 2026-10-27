#!/usr/bin/env python3
"""Offline source-boundary checks only. No compiler, process launch or live I/O."""
import hashlib
from pathlib import Path
import unittest

HERE = Path(__file__).absolute().parent
ROOT = HERE.parent.parent
PARENT = ROOT / 'Tests/RealIntegration/.build/host-f20119c1-8514-4545-b4d0-eb9562da4d0d'


class SourceContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = (HERE / 'Core.swift').read_text()
        cls.case = (HERE / 'ConcurrentCase.swift').read_text()
        cls.main = (HERE / 'Main.swift').read_text()
        cls.all = cls.core + cls.case + cls.main

    def test_inert_modes_before_signature_appkit_or_load(self):
        for action in ('.help', '.validate', '.offline'):
            self.assertLess(self.main.index('if action == ' + action), self.main.index('try SignatureGuard.validate()'))
        parser = self.core.split('static func parse', 1)[1].split('static func check', 1)[0]
        self.assertIn('args.count == 4', parser)
        self.assertIn('args[1] == "--primary-release"', parser)
        for bad in ('FileManager', 'PrivateInput.read', 'Bundle.', 'NSApp', 'Process(', 'primarySecret('):
            self.assertNotIn(bad, parser)

    def test_primary_template_not_observed_or_literal_hash(self):
        self.assertIn('"fixture@" + "[127.0.0.1]:22224" + "\'s password: "', self.core)
        self.assertIn('c.primaryPromptSHA256 == primaryHash', self.core)
        self.assertNotIn('OpenSSHObservation', self.all)
        self.assertIn('OpenSSHAnswerBudget(service:', self.case)
        self.assertIn('budget.claim(id: request.id, prompt: request.prompt', self.case)

    def test_two_real_sessions_and_pending_pid_barrier(self):
        self.assertIn('DirectSSHSession(trustStore:', self.case)
        self.assertIn('try a.start(configuration); try b.start(configuration)', self.case)
        self.assertIn('withThrowingTaskGroup', self.case)
        for fact in ('old.token.sessionID != other.token.sessionID', 'old.requestID != other.requestID', 'ca != cb',
                     'pa != pb', 'kill(pa, 0) == 0, kill(pb, 0) == 0', 'a.handler == nil, b.handler == nil'):
            self.assertIn(fact, self.case)
        self.assertLess(self.case.index('a.beginClose(); try await a.drain()'), self.case.index('try b.releaseB()'))

    def test_typed_late_cancel_after_drained_no_a_otp(self):
        self.assertIn('session.state != .closed || session.ownedProcessID != nil || handler != nil', self.case)
        late = 'try a.session.respond(.cancel, requestID: old.requestID, token: old.token)'
        self.assertLess(self.case.index('a.beginClose(); try await a.drain()'), self.case.index(late))
        self.assertIn('catch let error as TransportError where error == .stale', self.case)
        for fact in ('a.successfulSubmissions == submissions', 'a.otpReads == 0', 'b.otpReads == 3', 'b.successfulSubmissions == 4'):
            self.assertIn(fact, self.case)
        self.assertEqual(self.case.count('.releaseB()'), 1)

    def test_no_terminal_or_keychain_secret_automation(self):
        for forbidden in ('sendInput(', 'onOutput =', 'terminal.text', 'SavedPasswordAuthorization', 'CredentialStore(',
                          'SecItem', 'startProbe', 'configureProbe', 'OpenSSHObservation', 'print(answer', 'print(request'):
            self.assertNotIn(forbidden, self.all)
        self.assertIn('answer.resetBytes(in: 0..<answer.count)', self.case)
        self.assertIn('guard released, identifier == budget.sessionID', self.case)
        self.assertEqual(self.main.count('try ma.verify()'), 1)

    def test_current_connected_terminal_and_exact_run_receipt(self):
        self.assertIn('!stop.requested, !ended, !closing, session.token == token', self.case)
        self.assertIn('connectedEvents == 1, session.state == .connected', self.case)
        self.assertIn('try Task.checkCancellation(); guard', self.case)
        self.assertIn('report.runID = runID; report.runDirectory = run', self.main)
        receipt = 'try PrivateInput.writeExclusive(receipt + Data([10]), to: run + "/run-receipt.json")'
        self.assertIn(receipt, self.main)
        self.assertLess(self.main.index(receipt), self.main.index('mkdir(run + "/trust"'))
        self.assertIn('print(String(decoding: receipt, as: UTF8.self)); fflush(stdout)', self.main)

    def test_offline_typed_negative_checks_and_completion_exist(self):
        for error in ('.unknownRequest', '.staleRequest', '.wrongRound', '.invalidContract'):
            self.assertIn('rejects(' + error, self.core)
        self.assertIn('try survivor.requireComplete()', self.core)
        self.assertIn('a.closed, a.otpAnswers == 0', self.core)

    def test_incremental_builder_keeps_exact_compile_and_offline_boundary(self):
        source = (HERE / 'build_host.py').read_text()
        self.assertIn("PARENT_SHA = '1130bd88aae8c286f2271cff2cee7c67caa3f915c508d17dc4187ea1cd93225c'", source)
        self.assertEqual(source.count('b.swift_compile('), 1)
        for forbidden in ('b.c_module(', 'accepted.build(', 'swift build', 'xcodebuild'):
            self.assertNotIn(forbidden, source)
        self.assertIn("for name in ('Core.swift', 'ConcurrentCase.swift', 'Main.swift')", source)
        self.assertIn('unchanged()', source)
        self.assertIn("with log.open('xb')", source)

    def test_reviewed_parent_identity_and_reused_sources(self):
        pins = [(PARENT / 'result.json', '1130bd88aae8c286f2271cff2cee7c67caa3f915c508d17dc4187ea1cd93225c'),
                (PARENT / 'modules/RealIntegrationCore.swiftmodule', 'c2169b89eefed705f970ea0fc8c8c8158762bf44ecedc0612ed37288baabc302'),
                (ROOT / 'Tests/RealIntegration/Consumer/OpenSSHManagement.swift', '7121febf2d2218e1a79948ed9e50c4de7603abc61af003877e07cc07628cd309'),
                (ROOT / 'Tests/RealIntegration/Consumer/ProductionConsumer.swift', '550779213a80b9aba1d00ab0377cb5645c885281967fe1293919e61d09126aed')]
        for path, digest in pins:
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest, path.name)


if __name__ == '__main__':
    unittest.main()
