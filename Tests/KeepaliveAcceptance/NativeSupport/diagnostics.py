#!/usr/bin/env python3
"""Bounded public diagnostics only. No I/O on import; no relaxed relay/verdict behavior."""
import math
from liveness_protocol import Refused

RELAY_OPERATIONS = frozenset(('lookup', 'bind', 'arm', 'inspect', 'result', 'finish', 'stop'))
RELAY_FAILURES = frozenset(('worker-control-refused', 'closed-management-refusal'))
FAILURE_FRAME_KEYS = frozenset(('op', 'sequence', 'run', 'role', 'session', 'stamp', 'report'))


REPORT_STRING_FIELDS = frozenset(('taskID', 'run', 'role', 'session', 'nativeKind', 'nativeOperation', 'failure'))
REPORT_BOOL_FIELDS = frozenset(('instrumented', 'shellACK', 'freshACK', 'sourceGateVerified', 'contractFresh',
    'naturalResultBeforeCancel', 'cancelBeforeResult', 'deadlineBeforeResult', 'ownerLostBeforeResult',
    'stoppedBeforeResult', 'closed', 'interactionsDrained', 'fdReturnedToBaseline',
    'instrumentedSessionFreed', 'instrumentedThreadViolation'))
REPORT_INT_FIELDS = frozenset(('sourcePort', 'quietOutputBytes', 'naturalExit', 'extraChannelsAtProof',
    'extraChannelsAfterClose', 'instrumentedRealOpenCode', 'instrumentedRejections'))
REPORT_NUMBER_FIELDS = frozenset(('prepareSeconds', 'quietSeconds', 'naturalResultAt', 'dropToResultSeconds',
    'proofLower', 'proofUpper', 'armReadySent', 'dropACKReceived'))
REPORT_NESTED_FIELDS = frozenset(('preArm', 'final', 'clock', 'armAge'))


def diagnostic_report(value):
    if not isinstance(value, dict) or set(value) - (REPORT_STRING_FIELDS | REPORT_BOOL_FIELDS |
            REPORT_INT_FIELDS | REPORT_NUMBER_FIELDS | REPORT_NESTED_FIELDS): return False
    if value.get('taskID') != 'NATIVE-LIVENESS-SUPERVISOR-R2': return False
    for name, item in value.items():
        if name in REPORT_STRING_FIELDS:
            if not isinstance(item, str) or len(item) > 128: return False
            if name == 'failure' and item not in ('arguments', 'schema', 'replay', 'order', 'clock', 'cancelled',
                    'deadline', 'owner', 'evidence', 'native-or-evidence-failure', 'prepare-or-control-failure'): return False
            if name == 'nativeKind' and item not in ('invalidConfiguration', 'resourceLimit', 'busy', 'cancelled',
                    'timeout', 'untrusted', 'authentication', 'transport', 'closed', 'protocolFailure', 'unsupported'): return False
            if name == 'nativeOperation' and item not in ('ssh-round-trip', 'ssh-probe', 'ssh-probe-cleanup',
                    'read', 'write', 'poll', 'control', 'cancel', 'close', 'shell-not-ready'): return False
        elif name in REPORT_BOOL_FIELDS:
            if type(item) is not bool: return False
        elif name in REPORT_INT_FIELDS:
            if type(item) is not int: return False
        elif name in REPORT_NUMBER_FIELDS:
            if type(item) not in (int, float) or not math.isfinite(item): return False
        elif not isinstance(item, dict): return False
        elif name in ('clock', 'armAge'):
            expected = {'offset', 'disagreement', 'elapsedAtACK'} if name == 'clock' else {'offsetLower', 'offsetUpper', 'minimumAge', 'maximumAge'}
            if set(item) != expected or any(
                    type(x) not in (int, float) or not math.isfinite(x) for x in item.values()): return False
        elif (set(item) != {'started', 'confirmed', 'rejected', 'freed', 'helpers', 'pending'} or
              type(item['pending']) is not bool or any(type(item[key]) is not int for key in set(item) - {'pending'})): return False
    return True


class RelayCommandRefused(Refused):
    def __init__(self, *, operation, response, sent, received):
        super().__init__('relay-command-refused')
        self.observation = {'operation': operation if isinstance(operation, str) and operation in RELAY_OPERATIONS else 'unknown',
                            'sentAt': sent, 'receivedAt': received,
                            'response': safe_refusal(response)}


def safe_refusal(response):
    # Original refusal frames are two static scalars, not arbitrary exception/prompt text.
    # Unknown/extra fields remain a refusal and are not copied into diagnostic output.
    if (isinstance(response, dict) and set(response) == {'ok', 'failure'} and
            response['ok'] is False and isinstance(response['failure'], str) and response['failure'] in RELAY_FAILURES):
        return dict(response)
    return {'ok': False, 'failure': 'unrecognized-safe-response-schema'}


def classify_relay_observations(raw):
    """Classify only fixed observations, never infer that an SSH timeout happened before arm."""
    from relay_observations import MAX_RECORDS, STAGES, TAG
    import json
    if not isinstance(raw, bytes) or len(raw) > MAX_RECORDS * 512 + 16384: return 'unknown'
    records = raw.splitlines()
    records = [line for line in records if b'"tag":"native-guardian-cleanup-v1"' not in line]
    if len(records) > MAX_RECORDS: return 'unknown'
    last = None
    for index, line in enumerate(records):
        try:
            def pairs(items):
                value = {}
                for key, item in items:
                    if key in value: raise ValueError('duplicate-observation')
                    value[key] = item
                return value
            event = json.loads(line, object_pairs_hook=pairs)
        except (ValueError, UnicodeError): return 'unknown'
        if (not isinstance(event, dict) or set(event) != {'tag', 'sequence', 'stage', 'event', 'at', 'elapsed'} or
                event['tag'] != TAG or type(event['sequence']) is not int or event['sequence'] != index or
                not isinstance(event['stage'], str) or event['stage'] not in STAGES.values() or
                not isinstance(event['event'], str) or event['event'] not in ('begin', 'end', 'error') or
                any(type(event[key]) not in (int, float) or not math.isfinite(event[key]) for key in ('at', 'elapsed')) or
                event['elapsed'] < 0): return 'unknown'
        last = event
    if last is None: return 'unknown'
    if last['event'] == 'error': return last['stage'] + '-error'
    if last['event'] == 'begin': return last['stage'] + '-incomplete'
    # A later Flow.arm/peer/budget/arm_ack refusal remains unknown, not guessed from an end.
    return 'unknown-after-' + last['stage']


def guardian_cleanup_facts(raw):
    import json
    if not isinstance(raw, bytes) or len(raw) > 128 * 512 + 16384: return None
    found = []
    for line in raw.splitlines():
        try: value = json.loads(line)
        except (ValueError, UnicodeError): return None
        if isinstance(value, dict) and value.get('tag') == 'native-guardian-cleanup-v1': found.append(value)
    if len(found) != 1: return None
    value = found[0]
    if (set(value) != {'tag', 'sourceSHA256', 'count', 'owned', 'success'} or type(value['success']) is not bool or
            not isinstance(value['sourceSHA256'], str) or len(value['sourceSHA256']) != 64 or
            any(ch not in '0123456789abcdef' for ch in value['sourceSHA256'])):
        return None
    if type(value['count']) is not int or not 1 <= value['count'] <= 16 or not isinstance(value['owned'], list) or len(value['owned']) != value['count']:
        return None
    keys = {'remoteTerminated', 'terminationFact', 'localReaped', 'forcedLocalTermination', 'startupJoined', 'success'}
    for item in value['owned']:
        if (not isinstance(item, dict) or set(item) != keys or not isinstance(item['terminationFact'], str) or
                item['terminationFact'] not in ('unknown', 'not-started', 'requested', 'target-gone', 'control-eof') or
                any(type(item[key]) is not bool for key in keys - {'terminationFact'})):
            return None
    if value['success'] and not all(item['success'] and item['remoteTerminated'] and item['localReaped'] and
            item['startupJoined'] and not item['forcedLocalTermination'] and item['terminationFact'] != 'unknown' for item in value['owned']):
        return None
    return value


def collect_failed_close(reader, *, run, role, session, result, seconds=15, clock):
    """Read at most three public frames under the EXISTING 15s total failure-drain budget.

    Does not request arm/result/finish, invent ACKs, cancel the connection, or alter its verdict.
    The caller retains ownership cleanup. Failed/preclose and later closed are both preserved.
    """
    deadline = clock() + seconds
    last_stamp = 0.0
    initial = result.get('consumerFailureFrame')
    if isinstance(initial, dict) and type(initial.get('stamp')) in (int, float):
        last_stamp = initial['stamp']
    observations = []
    seen = {'failed'} if isinstance(initial, dict) and initial.get('op') == 'failed' else set()
    if 'preCloseReport' in result: seen.add('case-result')
    for _ in range(3):
        remaining = deadline - clock()
        if remaining <= 0:
            result['failureDrainStage'] = 'deadline'
            break
        try:
            frame = reader.read(remaining)
        except Exception:
            result['failureDrainStage'] = 'read-refused-or-eof'
            break
        if clock() > deadline:
            result['failureDrainStage'] = 'deadline'
            break
        if (not isinstance(frame, dict) or set(frame) != FAILURE_FRAME_KEYS or
                not isinstance(frame['op'], str) or frame['op'] not in ('failed', 'case-result', 'closed') or frame['op'] in seen or
                (frame['op'] == 'case-result' and 'failed' in seen) or
                frame['run'] != run or frame['role'] != role or frame['session'] != session or
                type(frame['sequence']) is not int or frame['sequence'] != {'failed': -1, 'case-result': 2, 'closed': 3}[frame['op']] or
                type(frame['stamp']) not in (int, float) or not math.isfinite(frame['stamp']) or frame['stamp'] <= last_stamp or
                not diagnostic_report(frame['report']) or frame['report'].get('run') != run or
                frame['report'].get('role') != role or frame['report'].get('session') != session):
            result['failureDrainStage'] = 'frame-binding-or-order-refused'
            break
        last_stamp = frame['stamp']; seen.add(frame['op'])
        # The report uses the existing consumer's structured public facts; nothing from SSH output.
        observations.append(frame)
        if frame['op'] == 'failed':
            result['consumerFailureFrame'] = frame
        elif frame['op'] == 'case-result':
            result.setdefault('preCloseReport', frame['report'])
        else:
            result['closedReport'] = frame['report']
            result['failureDrainStage'] = 'closed-observed'
            break
    else:
        result['failureDrainStage'] = 'frame-count-bound'
    result['failureDrainFrames'] = observations
