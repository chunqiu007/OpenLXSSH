#!/usr/bin/env python3
"""Native liveness R2 closed public contracts and verdicts. Import performs no I/O."""
from __future__ import annotations
import math
import re
import uuid
from native_round_trip import Refused

CONTRACT_KEYS = {'schema', 'taskID', 'run', 'role', 'materialContractPath', 'issuedAt', 'collectedAt'}
PROOF_KEYS = {'started', 'confirmed', 'rejected', 'freed', 'helpers', 'pending'}


def number(value):
    return type(value) in (float, int) and math.isfinite(value)


def validate_contract(value, path, build_root, now):
    if not isinstance(value, dict) or set(value) != CONTRACT_KEYS:
        raise Refused('native-contract-schema')
    prefix, suffix = build_root + '/native-liveness-case-', '/liveness.json'
    if (not isinstance(path, str) or not path.startswith(prefix) or not path.endswith(suffix) or
            not re.fullmatch('[0-9a-f]{12}', path[len(prefix):-len(suffix)])):
        raise Refused('native-contract-path')
    material = value['materialContractPath']
    mp, ms = build_root + '/sftp-auth-case-', '/sftp-auth.json'
    if (not isinstance(material, str) or not material.startswith(mp) or not material.endswith(ms) or
            not re.fullmatch('[0-9a-f]{12}', material[len(mp):-len(ms)])):
        raise Refused('native-material-path')
    if (type(value['schema']) is not int or value['schema'] != 1 or value['taskID'] != 'NATIVE-LIVENESS-SUPERVISOR-R2' or
            not isinstance(value['run'], str) or not re.fullmatch('[0-9a-f]{32}', value['run']) or
            value['role'] not in ('normal', 'blackhole', 'maxsessions') or
            not all(number(x) for x in (now, value['issuedAt'], value['collectedAt'])) or
            not 0 < value['collectedAt'] <= value['issuedAt'] <= now or
            now - value['issuedAt'] > 120 or now - value['collectedAt'] > 120):
        raise Refused('native-contract-freshness')
    return value


def proof(value, minimum=2):
    if not isinstance(value, dict) or set(value) != PROOF_KEYS:
        raise Refused('native-proof-schema')
    if (any(type(value[k]) is not int or value[k] < 0 for k in PROOF_KEYS - {'pending'}) or
            value['started'] < minimum or value['confirmed'] + value['rejected'] != value['started'] or
            value['freed'] != value['confirmed'] or value['helpers'] != 0 or value['pending'] is not False):
        raise Refused('native-proof-not-settled')
    return value


def arm_age_bounds(proof_lower, proof_upper, consumer_sent, consumer_ack, relay_armed, relay_reply):
    values = (proof_lower, proof_upper, consumer_sent, consumer_ack, relay_armed, relay_reply)
    if (not all(number(value) and value > 0 for value in values) or
            not proof_lower <= proof_upper <= consumer_sent <= consumer_ack or relay_armed > relay_reply):
        raise Refused('actual-arm-age-clock')
    low, high = relay_reply - consumer_ack, relay_armed - consumer_sent
    minimum = relay_armed - (proof_upper + high)
    maximum = relay_armed - (proof_lower + low)
    if not low <= high or not 0 <= minimum <= maximum <= 1.5:
        raise Refused('actual-arm-age-bound')
    return {'offsetLower': low, 'offsetUpper': high, 'minimumAge': minimum, 'maximumAge': maximum}


class ConsumerSequence:
    def __init__(self, run, role):
        self.run, self.role, self.session, self.next, self.stamp = run, role, None, 0, 0

    def accept(self, frame):
        ops = ('native-ready', 'arm-ready', 'case-result', 'closed')
        if self.next >= len(ops):
            raise Refused('native-control-replay')
        common = {'op', 'sequence', 'run', 'role', 'session', 'stamp'}
        extra = ({'sourcePort', 'pid', 'proof', 'freshACK'} if self.next == 0 else
                 {'sourcePort', 'proof', 'freshACK'} if self.next == 1 else {'report'})
        if self.next == 1 and self.role == 'blackhole': extra |= {'proofLower', 'proofUpper'}
        if not isinstance(frame, dict) or set(frame) != common | extra:
            raise Refused('native-control-schema')
        if (frame['op'] != ops[self.next] or type(frame['sequence']) is not int or frame['sequence'] != self.next or
                frame['run'] != self.run or frame['role'] != self.role or not number(frame['stamp']) or frame['stamp'] <= self.stamp):
            raise Refused('native-control-order')
        try:
            canonical = str(uuid.UUID(frame['session'])) == frame['session']
        except (ValueError, TypeError, AttributeError):
            canonical = False
        if not canonical or (self.session is not None and frame['session'] != self.session):
            raise Refused('native-control-session')
        if self.next in (0, 1):
            proof(frame['proof'])
            if type(frame['sourcePort']) is not int or not 1024 <= frame['sourcePort'] <= 65535 or frame['freshACK'] is not True:
                raise Refused('native-control-tuple-or-ack')
        if self.next == 1 and self.role == 'blackhole':
            if (not number(frame['proofLower']) or not number(frame['proofUpper']) or
                    not 0 < frame['proofLower'] <= frame['proofUpper'] <= frame['stamp']):
                raise Refused('native-proof-interval')
        if self.next == 0 and (type(frame['pid']) is not int or frame['pid'] <= 1):
            raise Refused('native-control-pid')
        self.session = frame['session']; self.stamp = frame['stamp']; self.next += 1
        return frame


def base_report(report, contract, exact_binding):
    required = {'taskID', 'run', 'role', 'instrumented', 'session', 'sourcePort', 'prepareSeconds', 'quietSeconds',
                'quietOutputBytes', 'shellACK', 'freshACK', 'sourceGateVerified', 'contractFresh', 'preArm', 'final',
                'naturalResultBeforeCancel', 'cancelBeforeResult', 'deadlineBeforeResult', 'ownerLostBeforeResult',
                'stoppedBeforeResult', 'closed', 'interactionsDrained', 'fdReturnedToBaseline', 'extraChannelsAtProof',
                'extraChannelsAfterClose', 'instrumentedRealOpenCode', 'instrumentedRejections',
                'instrumentedSessionFreed', 'instrumentedThreadViolation', 'naturalResultAt'}
    optional = {'nativeKind', 'nativeOperation', 'dropToResultSeconds', 'clock', 'naturalExit', 'failure',
                'proofLower', 'proofUpper', 'armReadySent', 'dropACKReceived', 'armAge'}
    if not isinstance(report, dict) or not required <= set(report) or set(report) - required - optional:
        raise Refused('native-report-schema')
    if (report['taskID'] != 'NATIVE-LIVENESS-SUPERVISOR-R2' or report['run'] != contract['run'] or
            report['role'] != contract['role'] or report['session'] != exact_binding['session'] or
            type(report['sourcePort']) is not int or report['sourcePort'] != exact_binding['sourcePort'] or report.get('failure') is not None):
        raise Refused('native-report-binding')
    for key in ('shellACK', 'freshACK', 'sourceGateVerified', 'contractFresh', 'naturalResultBeforeCancel'):
        if report[key] is not True: raise Refused('native-report-evidence')
    for key in ('cancelBeforeResult', 'deadlineBeforeResult', 'ownerLostBeforeResult', 'stoppedBeforeResult', 'instrumentedThreadViolation'):
        if report[key] is not False: raise Refused('native-report-owner-or-cancel')
    if (not number(report['prepareSeconds']) or not 0 <= report['prepareSeconds'] <= 30 or
            not number(report['quietSeconds']) or report['quietSeconds'] < 12 or report['quietOutputBytes'] != 0 or
                type(report['quietOutputBytes']) is not int or report['quietOutputBytes'] != 0 or
                not number(report['naturalResultAt'])):
        raise Refused('native-report-budget')
    if any(type(report[key]) is not int for key in ('extraChannelsAtProof', 'extraChannelsAfterClose',
                                                   'instrumentedRealOpenCode', 'instrumentedRejections')):
        raise Refused('native-report-counter-type')
    proof(report['preArm'])
    return report


def verdict(contract, pre, closed, relay_at_arm, relay_result, relay_finished, exact_binding, timing):
    """No old OpenSSH green, mock result, raw recv, external stop or early FIN can satisfy this."""
    try:
        base_report(pre, contract, exact_binding); base_report(closed, contract, exact_binding)
        if any(closed[key] is not True for key in ('closed', 'interactionsDrained', 'fdReturnedToBaseline')):
            return False
        if (closed['extraChannelsAfterClose'] != 0 or pre['naturalResultAt'] != closed['naturalResultAt'] or
                pre['preArm'] != closed['preArm'] or pre['final'] != closed['final']):
            return False
        role = contract['role']
        if closed['instrumented'] is not (role == 'maxsessions'):
            return False
        for relay in (relay_result, relay_finished):
            if (relay.get('token') != exact_binding['token'] or relay.get('sourcePort') != exact_binding['sourcePort'] or
                    relay.get('failure') is not None or relay.get('cleanupFailed') is not False or
                    relay.get('cancelBeforeResult') is not False or relay.get('deadlineBeforeResult') is not False):
                return False
        if role != 'blackhole':
            if (closed.get('naturalExit') != 7 or closed.get('nativeKind') is not None or
                    relay_finished.get('mode') != 'forward' or relay_finished.get('pumpImplementation') != 'frozen-normal' or
                    relay_finished.get('reason') != 'complete' or relay_finished.get('finished') is not True or relay_finished.get('armedAt') is not None):
                return False
            if role == 'maxsessions':
                return (closed['extraChannelsAtProof'] == 7 and closed['preArm']['rejected'] >= 2 and
                        closed['preArm']['confirmed'] == 0 and closed['instrumentedRealOpenCode'] == -21 and
                        closed['instrumentedRejections'] >= 2 and closed['instrumentedSessionFreed'] is True)
            return closed['extraChannelsAtProof'] == 0 and closed['instrumentedRejections'] == 0
        for key in ('proofLower', 'proofUpper', 'armReadySent', 'dropACKReceived', 'armAge'):
            if key not in closed or closed[key] != pre.get(key): return False
        actual_age = arm_age_bounds(closed['proofLower'], closed['proofUpper'], closed['armReadySent'],
            closed['dropACKReceived'], relay_at_arm['armedAt'], relay_at_arm['relayNow'])
        if (not isinstance(closed['armAge'], dict) or set(closed['armAge']) != set(actual_age) or
                any(not number(closed['armAge'][key]) or abs(closed['armAge'][key] - value) > 1e-7 for key, value in actual_age.items())):
            return False
        elapsed = closed.get('dropToResultSeconds'); clock = closed.get('clock')
        if (not number(elapsed) or not 4 <= elapsed <= 7 or closed.get('nativeKind') != 'timeout' or
                closed.get('nativeOperation') != 'ssh-round-trip' or not isinstance(clock, dict) or
                set(clock) != {'offset', 'disagreement', 'elapsedAtACK'} or
                not all(number(x) for x in clock.values()) or not 0 <= clock['disagreement'] < .2 or
                not 0 <= clock['elapsedAtACK'] < 2 or not 4 <= timing['armRequestToResult'] <= 7 or
                not 0 <= timing['armAfterReady'] < 1.5):
            return False
        arm_elapsed = timing['armRequestToResult']
        if (not number(arm_elapsed) or not number(timing['armAfterReady']) or
                abs(elapsed - arm_elapsed) > 0.5 or not 4 <= arm_elapsed <= 7):
            return False
        projected = relay_at_arm.get('armedAt')
        if not number(projected) or abs((closed['naturalResultAt'] - clock['offset'] - projected) - elapsed) > 0.2:
            return False
        if (not isinstance(closed['final'], dict) or closed['final'].get('started') != closed['preArm']['started'] + 1 or
                closed['final'].get('confirmed') != closed['preArm']['confirmed'] or
                closed['final'].get('rejected') != closed['preArm']['rejected'] or
                closed['final'].get('helpers') != 0 or closed['final'].get('pending') is not False):
            return False
        dropped = relay_result.get('droppedBytes')
        forwarded = relay_result.get('forwardedBytes')
        discarded = relay_result.get('discardedAtArm')
        if not all(isinstance(values, list) and len(values) == 2 and all(type(x) is int and x >= 0 for x in values)
                   for values in (dropped, forwarded, discarded)):
            return False
        return (relay_result.get('mode') == 'drop' and relay_result.get('firstEOFDirection') in (None, 'client') and
                relay_result.get('clientResultAt') is not None and relay_result.get('establishedAtArm') is True and
                relay_result.get('bridgeAliveAtArm') is True and relay_result.get('halfClosedByDirection') == [False, False] and
                relay_result.get('forwardedBytes') == relay_at_arm.get('forwardedBytes') and
                relay_result.get('discardedAtArm') == relay_at_arm.get('discardedAtArm') and
                isinstance(relay_result.get('droppedBytes'), list) and sum(relay_result['droppedBytes']) > 0 and
                relay_result.get('tcpSnapshotCount', 0) >= 2 and
                isinstance(relay_result.get('remoteBridgeAtArm'), dict) and relay_result['remoteBridgeAtArm'].get('pidfdAlive') is True and
                relay_result.get('remoteBridgeAtResult') == relay_result.get('remoteBridgeAtArm'))
    except (Refused, KeyError, TypeError, ValueError):
        return False
