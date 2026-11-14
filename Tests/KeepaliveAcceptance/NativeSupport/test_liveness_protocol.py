#!/usr/bin/env python3
"""Native liveness R2 offline security contracts. Synthetic facts test refusal, never live proof."""
import copy
import json
import unittest
from unittest.mock import patch
from liveness_protocol import ConsumerSequence, Refused, proof, validate_contract, verdict, arm_age_bounds
from supervise_native import stop_owned


class NativeLivenessProtocolTests(unittest.TestCase):
    def contract(self):
        return {'schema': 1, 'taskID': 'NATIVE-LIVENESS-SUPERVISOR-R2', 'run': 'a' * 32, 'role': 'blackhole',
                'materialContractPath': '/offline/.build/sftp-auth-case-012345abcdef/sftp-auth.json', 'issuedAt': 1000, 'collectedAt': 999}

    def settled(self):
        return {'started': 3, 'confirmed': 3, 'rejected': 0, 'freed': 3, 'helpers': 0, 'pending': False}

    def evidence(self):
        contract = self.contract(); binding = {'session': '01234567-89ab-cdef-0123-456789abcdef', 'sourcePort': 42001, 'token': 'b' * 32}
        pre = {'taskID': 'NATIVE-LIVENESS-SUPERVISOR-R2', 'run': contract['run'], 'role': contract['role'], 'instrumented': False,
               'session': binding['session'], 'sourcePort': binding['sourcePort'], 'prepareSeconds': 4, 'quietSeconds': 12.1,
               'quietOutputBytes': 0, 'shellACK': True, 'freshACK': True, 'sourceGateVerified': True, 'contractFresh': True,
               'preArm': self.settled(), 'final': {**self.settled(), 'started': 4}, 'nativeKind': 'timeout',
               'nativeOperation': 'ssh-round-trip', 'naturalResultAt': 109, 'dropToResultSeconds': 6,
               'clock': {'offset': 3, 'disagreement': .01, 'elapsedAtACK': .1}, 'naturalResultBeforeCancel': True,
               'cancelBeforeResult': False, 'deadlineBeforeResult': False, 'ownerLostBeforeResult': False, 'stoppedBeforeResult': False,
               'closed': False, 'interactionsDrained': False, 'fdReturnedToBaseline': False, 'extraChannelsAtProof': 0,
               'extraChannelsAfterClose': 0, 'instrumentedRealOpenCode': 0, 'instrumentedRejections': 0,
               'instrumentedSessionFreed': False, 'instrumentedThreadViolation': False,
               'proofLower': 102.8, 'proofUpper': 102.81, 'armReadySent': 102.82, 'dropACKReceived': 103.2,
               'armAge': arm_age_bounds(102.8, 102.81, 102.82, 103.2, 100, 100.1)}
        closed = copy.deepcopy(pre); closed.update(closed=True, interactionsDrained=True, fdReturnedToBaseline=True)
        remote = {'pidfdAlive': True, 'pid': 77, 'startTicks': 33}
        relay = {'token': binding['token'], 'sourcePort': binding['sourcePort'], 'failure': None, 'cleanupFailed': False,
                 'cancelBeforeResult': False, 'deadlineBeforeResult': False, 'mode': 'drop', 'firstEOFDirection': None,
                 'clientResultAt': 106, 'armedAt': 100, 'relayNow': 100.1, 'establishedAtArm': True, 'bridgeAliveAtArm': True, 'halfClosedByDirection': [False, False],
                 'forwardedBytes': [512, 900], 'discardedAtArm': [12, 5], 'droppedBytes': [32, 24], 'tcpSnapshotCount': 3,
                 'remoteBridgeAtArm': remote, 'remoteBridgeAtResult': dict(remote)}
        return contract, pre, closed, copy.deepcopy(relay), relay, copy.deepcopy(relay), binding, {'armRequestToResult': 6.1, 'armAfterReady': .2}

    def test_contract_fixed_generation_freshness_and_types(self):
        value = self.contract(); path = '/offline/.build/native-liveness-case-012345abcdef/liveness.json'
        validate_contract(value, path, '/offline/.build', 1001)
        for key, changed in [('schema', True), ('issuedAt', 1200), ('collectedAt', 800), ('run', 'bad'),
                             ('role', 'production'), ('materialContractPath', '/etc/passwd')]:
            invalid = dict(value); invalid[key] = changed
            with self.assertRaises(Refused): validate_contract(invalid, path, '/offline/.build', 1001)
        invalid = dict(value); invalid['password'] = 'forbidden'
        with self.assertRaises(Refused): validate_contract(invalid, path, '/offline/.build', 1001)

    def test_proof_requires_two_completed_actual_helper_results_and_all_freed(self):
        proof(self.settled())
        for key, value in [('started', 1), ('pending', True), ('helpers', 1), ('freed', 2), ('confirmed', 2)]:
            changed = self.settled(); changed[key] = value
            with self.assertRaises(Refused): proof(changed)

    def test_pipe_replay_wrong_session_clock_and_order(self):
        run = 'a' * 32; session = '01234567-89ab-cdef-0123-456789abcdef'
        frame = {'op': 'native-ready', 'sequence': 0, 'run': run, 'role': 'blackhole', 'session': session,
                 'stamp': 100, 'sourcePort': 42001, 'pid': 1234, 'proof': self.settled(), 'freshACK': True}
        state = ConsumerSequence(run, 'blackhole'); state.accept(frame)
        with self.assertRaises(Refused): state.accept(frame)
        arm = {key: value for key, value in frame.items() if key != 'pid'}
        arm.update(op='arm-ready', sequence=1, stamp=101, proofLower=100.8, proofUpper=100.9)
        for key, value in [('session', '11234567-89ab-cdef-0123-456789abcdef'), ('stamp', 99), ('sequence', True), ('run', 'b' * 32)]:
            state = ConsumerSequence(run, 'blackhole'); state.accept(frame)
            changed = copy.deepcopy(arm); changed[key] = value
            with self.assertRaises(Refused): state.accept(changed)

    def test_native_timeout_and_strict_drop_gate(self):
        evidence = self.evidence(); self.assertTrue(verdict(*evidence))
        for key, value in [('sourcePort', 42002), ('nativeOperation', 'read'), ('nativeKind', 'transport'),
                           ('cancelBeforeResult', True), ('deadlineBeforeResult', True), ('ownerLostBeforeResult', True),
                           ('naturalResultBeforeCancel', False), ('dropToResultSeconds', 3.9), ('dropToResultSeconds', 7.1),
                           ('freshACK', False), ('quietOutputBytes', 1), ('fdReturnedToBaseline', False)]:
            changed = list(copy.deepcopy(evidence)); changed[2][key] = value
            self.assertFalse(verdict(*changed), key)
        for key, value in [('firstEOFDirection', 'backend'), ('halfClosedByDirection', [False, True]),
                           ('forwardedBytes', [513, 900]), ('bridgeAliveAtArm', False), ('droppedBytes', [0, 0]),
                           ('remoteBridgeAtResult', {'pidfdAlive': False})]:
            changed = list(copy.deepcopy(evidence)); changed[4][key] = value
            self.assertFalse(verdict(*changed), key)

    def test_old_keepalive_green_cannot_be_native_result(self):
        evidence = list(self.evidence()); evidence[1] = {'lastExitCode': 255, 'serverAliveCountMax': 2, 'naturalState': 'failed-launchFailed'}
        self.assertFalse(verdict(*evidence))
        evidence = list(self.evidence()); evidence[2]['serverAliveCountMax'] = 2
        self.assertFalse(verdict(*evidence))

    def test_maxsessions_is_separate_instrumented_gate_not_normal_or_drop(self):
        evidence = list(copy.deepcopy(self.evidence())); evidence[0]['role'] = 'maxsessions'
        for report in (evidence[1], evidence[2]):
            report.update(role='maxsessions', instrumented=True, naturalExit=7, extraChannelsAtProof=7,
                          instrumentedRealOpenCode=-21, instrumentedRejections=3, instrumentedSessionFreed=True)
            report.pop('nativeKind'); report.pop('nativeOperation'); report.pop('dropToResultSeconds'); report.pop('clock')
            report['preArm'] = {'started': 3, 'confirmed': 0, 'rejected': 3, 'freed': 0, 'helpers': 0, 'pending': False}
            report['final'] = dict(report['preArm'])
        for relay in (evidence[4], evidence[5]):
            relay.update(mode='forward', pumpImplementation='frozen-normal', reason='complete', finished=True, armedAt=None)
        self.assertTrue(verdict(*evidence))
        evidence[2]['instrumentedRealOpenCode'] = 0
        self.assertFalse(verdict(*evidence))
        evidence[2]['instrumentedRealOpenCode'] = -21; evidence[2]['instrumented'] = False
        self.assertFalse(verdict(*evidence))

    def test_stop_only_exact_owned_process_and_reports_forced_drain(self):
        class Child:
            pid = 12345; stdin = None; stdout = None
            terminated = False; killed = False
            def poll(self): return None if not self.terminated else 143
            def terminate(self): self.terminated = True
            def kill(self): self.killed = True
            def wait(self, timeout=None): return 143
        child = Child()
        with patch('os.kill') as broad_kill:
            result = stop_owned(child)
        self.assertEqual(result['pid'], 12345); self.assertTrue(result['terminated']); self.assertFalse(result['killed'])
        broad_kill.assert_not_called()


if __name__ == '__main__': unittest.main()
