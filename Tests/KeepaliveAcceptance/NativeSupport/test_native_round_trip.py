#!/usr/bin/env python3
"""Pure offline contract regressions. No fixture, socket, Docker, build or credential access."""
from __future__ import annotations
import copy
import unittest
from native_round_trip import Flow, Refused, verdict


class NativeRoundTripContractTests(unittest.TestCase):
    def binding(self):
        return {'run': 'a' * 32, 'role': 'blackhole', 'token': 'b' * 32, 'sourcePort': 42001,
                'session': '01234567-89ab-cdef-0123-456789abcdef', 'generation': 1,
                'ssh': {'pid': 1234, 'ppid': 1233, 'uid': 501, 'startSeconds': 12345, 'startMicroseconds': 1}}

    def evidence(self):
        binding = self.binding()
        report = {'taskID': 'NATIVE-READINESS-R1-LIVENESS', 'role': 'blackhole', 'interval': 2,
                  'maxUnresponsivePeriods': 2, 'session': binding['session'], 'sourcePort': binding['sourcePort'],
                  'shellACK': True, 'freshACK': True, 'quietSeconds': 12, 'pendingAtArm': False,
                  'probesStartedBeforeArm': 3, 'confirmationsBeforeArm': 2, 'rejectionsBeforeArm': 1,
                  'probesStartedAfterArm': 4, 'helpersAfterClose': 0, 'pendingAfterClose': False,
                  'nativeKind': 'timeout', 'nativeOperation': 'ssh-round-trip', 'naturalResultBeforeCancel': True,
                  'closed': True, 'interactionsDrained': True, 'fdReturnedToBaseline': True,
                  'contractFresh': True, 'sourceGateVerified': True, 'deadlineBeforeResult': False,
                  'cancelBeforeResult': False, 'dropToResultSeconds': 6}
        birth = {'pidfdAlive': True, 'pid': 2222, 'uid': 10000, 'startTicks': 44, 'token': binding['token']}
        relay = {'token': binding['token'], 'sourcePort': binding['sourcePort'], 'failure': None,
                 'cleanupFailed': False, 'cancelBeforeResult': False, 'deadlineBeforeResult': False,
                 'mode': 'drop', 'firstEOFDirection': None, 'clientResultAt': 200, 'establishedAtArm': True,
                 'bridgeAliveAtArm': True, 'halfClosedByDirection': [False, False],
                 'remoteBridgeAtArm': birth, 'remoteBridgeAtResult': dict(birth), 'tcpSnapshotCount': 3,
                 'droppedBytes': [24, 0]}
        return report, relay, binding

    def test_strict_native_facts_and_real_rejection_policy(self):
        report, relay, binding = self.evidence()
        self.assertTrue(verdict(report, relay, binding))
        report['confirmationsBeforeArm'] = 0
        report['rejectionsBeforeArm'] = 3  # MaxSessions rejections are proof of alive, not failure.
        self.assertTrue(verdict(report, relay, binding))

    def test_all_failure_shortcuts_refuse(self):
        report, relay, binding = self.evidence()
        for key, value in [('sourceGateVerified', False), ('contractFresh', False), ('freshACK', False),
                           ('pendingAtArm', True), ('pendingAfterClose', True), ('helpersAfterClose', 1),
                           ('interactionsDrained', False), ('cancelBeforeResult', True), ('deadlineBeforeResult', True),
                           ('nativeKind', 'transport'), ('nativeOperation', 'read'), ('naturalResultBeforeCancel', False),
                           ('probesStartedAfterArm', 5), ('dropToResultSeconds', 3), ('dropToResultSeconds', 9)]:
            altered = dict(report); altered[key] = value
            self.assertFalse(verdict(altered, relay, binding), key)
        altered = dict(report); altered['serverAliveCountMax'] = 2
        self.assertFalse(verdict(altered, relay, binding))

    def test_backend_eof_halfclose_wrong_tuple_and_lost_bridge_refuse(self):
        report, relay, binding = self.evidence()
        for key, value in [('firstEOFDirection', 'backend'), ('halfClosedByDirection', [False, True]),
                           ('bridgeAliveAtArm', False), ('establishedAtArm', False), ('droppedBytes', [0, 0]),
                           ('sourcePort', 42002), ('token', 'c' * 32), ('cancelBeforeResult', True),
                           ('remoteBridgeAtResult', {'pidfdAlive': False})]:
            altered = copy.deepcopy(relay); altered[key] = value
            self.assertFalse(verdict(report, altered, binding), key)

    def test_existing_drop_flow_remains_tuple_bound_and_never_forwards_or_fin(self):
        binding = self.binding(); flow = Flow(); flow.bound = binding
        flow.receive(0, b'opaque-public-test-bytes', 10)
        flow.arm(binding, lambda: 11, tcp_established=True, bridge_alive=True, safe_remaining=35)
        self.assertEqual(flow.queues, [bytearray(), bytearray()])
        flow.receive(0, b'opaque-public-test-bytes', 12)
        with self.assertRaises(Refused): flow.wrote(0, 1)
        flow.eof('client', 13)
        flow.drain_eof((lambda: self.fail('no halfclose in DROP'), lambda: self.fail('no FIN in DROP')))
        self.assertEqual(flow.half_closed, [False, False])
        stale = dict(binding); stale['sourcePort'] += 1
        with self.assertRaises(Refused): flow.arm(stale, lambda: 14, tcp_established=True, bridge_alive=True, safe_remaining=35)


if __name__ == '__main__':
    unittest.main()
