#!/usr/bin/env python3
"""Independent offline verdict for native SSH round-trip candidate. Import is inert.

Reuses the original approved byte relay Flow/binding model, never edits it or interprets
OpenSSH's old green report as NativeShell evidence. A future live supervisor must retain
private PIPE ownership, frozen source/contract freshness, exact TCP tuple and no-FIN gates.
"""
from __future__ import annotations
import math
import sys
from pathlib import Path

# Import existing safety primitives only; core.py has no process/socket/file side effects.
PARENT = Path(__file__).absolute().parent.parent
if str(PARENT) not in sys.path:
    sys.path.insert(0, str(PARENT))
from core import Flow, Refused, binding

REPORT_KEYS = {
    'taskID', 'role', 'interval', 'maxUnresponsivePeriods', 'session', 'sourcePort',
    'shellACK', 'freshACK', 'quietSeconds', 'pendingAtArm', 'probesStartedBeforeArm',
    'confirmationsBeforeArm', 'rejectionsBeforeArm', 'probesStartedAfterArm',
    'helpersAfterClose', 'pendingAfterClose', 'nativeKind', 'nativeOperation',
    'naturalResultBeforeCancel', 'closed', 'interactionsDrained', 'fdReturnedToBaseline',
    'contractFresh', 'sourceGateVerified', 'deadlineBeforeResult', 'cancelBeforeResult',
    'dropToResultSeconds',
}


def finite_number(value):
    return type(value) in (int, float) and math.isfinite(value)


def verdict(report, relay, exact_binding):
    """False unless all independent native facts and unchanged original safety gates agree."""
    try:
        binding(exact_binding)
    except Refused:
        return False
    if not isinstance(report, dict) or set(report) != REPORT_KEYS:
        return False
    role = exact_binding['role']
    if (report['taskID'] != 'NATIVE-READINESS-R1-LIVENESS' or report['role'] != role or
            report['session'] != exact_binding['session'] or report['sourcePort'] != exact_binding['sourcePort'] or
            type(report['interval']) not in (int, float) or report['interval'] != 2 or
            type(report['maxUnresponsivePeriods']) is not int or report['maxUnresponsivePeriods'] != 2):
        return False
    for key in ('shellACK', 'freshACK', 'naturalResultBeforeCancel', 'closed', 'interactionsDrained',
                'fdReturnedToBaseline', 'contractFresh', 'sourceGateVerified'):
        if report[key] is not True:
            return False
    for key in ('pendingAtArm', 'pendingAfterClose', 'deadlineBeforeResult', 'cancelBeforeResult'):
        if report[key] is not False:
            return False
    if (type(report['helpersAfterClose']) is not int or report['helpersAfterClose'] != 0 or
            not finite_number(report['quietSeconds']) or report['quietSeconds'] < 12):
        return False
    for key in ('probesStartedBeforeArm', 'confirmationsBeforeArm', 'rejectionsBeforeArm', 'probesStartedAfterArm'):
        if type(report[key]) is not int or report[key] < 0:
            return False
    proofs = report['confirmationsBeforeArm'] + report['rejectionsBeforeArm']
    if report['probesStartedBeforeArm'] < 2 or proofs != report['probesStartedBeforeArm']:
        return False
    # Same original byte-relay constraints; never count TCP ACK/raw recv as an SSH reply.
    if (relay.get('token') != exact_binding['token'] or relay.get('sourcePort') != exact_binding['sourcePort'] or
            relay.get('failure') is not None or relay.get('cleanupFailed') is not False or
            relay.get('cancelBeforeResult') is not False or relay.get('deadlineBeforeResult') is not False):
        return False
    if role == 'normal':
        return (report['nativeKind'] is None and report['nativeOperation'] is None and
                relay.get('mode') == 'forward' and relay.get('pumpImplementation') == 'frozen-normal' and
                relay.get('reason') == 'complete' and relay.get('finished') is True and relay.get('armedAt') is None)
    elapsed = report['dropToResultSeconds']
    budget = report['interval'] * report['maxUnresponsivePeriods']
    if (not finite_number(elapsed) or not budget <= elapsed <= budget + report['interval'] + 1 or
            report['nativeKind'] != 'timeout' or report['nativeOperation'] != 'ssh-round-trip' or
            report['probesStartedAfterArm'] != report['probesStartedBeforeArm'] + 1):
        return False
    dropped = relay.get('droppedBytes')
    return (relay.get('mode') == 'drop' and relay.get('firstEOFDirection') in (None, 'client') and
            relay.get('clientResultAt') is not None and relay.get('establishedAtArm') is True and
            relay.get('bridgeAliveAtArm') is True and relay.get('halfClosedByDirection') == [False, False] and
            isinstance(relay.get('remoteBridgeAtArm'), dict) and
            relay['remoteBridgeAtArm'].get('pidfdAlive') is True and
            relay.get('remoteBridgeAtResult') == relay.get('remoteBridgeAtArm') and
            type(relay.get('tcpSnapshotCount')) is int and relay['tcpSnapshotCount'] >= 2 and
            isinstance(dropped, list) and len(dropped) == 2 and
            all(type(value) is int and value >= 0 for value in dropped) and sum(dropped) > 0)
