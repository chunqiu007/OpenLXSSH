#!/usr/bin/env python3
"""Closed keepalive metadata, exact TCP identity parsing and bounded opaque queue model. No I/O on import."""
from __future__ import annotations
from dataclasses import dataclass, field
import json
import math
import re
import uuid

LIMIT = 65536
CONTROL_LIMIT = 2048
NORMAL_SECONDS = 12.0
BLACKHOLE_SECONDS = 15.0
DROP_SAFETY_SECONDS = 35.0


class Refused(Exception):
    pass


def exact_json(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) < CONTROL_LIMIT or not raw.endswith(b'\n'):
        raise Refused('control-bounds')
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result: raise Refused('duplicate-field')
            result[key] = value
        return result
    try: result = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError): raise Refused('control-json') from None
    if not isinstance(result, dict): raise Refused('control-object')
    return result


def encoded(value):
    data = (json.dumps(value, separators=(',', ':'), sort_keys=True) + '\n').encode()
    if len(data) >= CONTROL_LIMIT: raise Refused('control-bounds')
    return data


def identity(value):
    keys = {'pid', 'ppid', 'uid', 'startSeconds', 'startMicroseconds'}
    if not isinstance(value, dict) or set(value) != keys or any(type(value[k]) is not int for k in keys):
        raise Refused('identity-schema')
    if min(value['pid'], value['ppid'], value['startSeconds']) <= 0 or value['uid'] < 0 or not 0 <= value['startMicroseconds'] < 1000000:
        raise Refused('identity-bounds')
    return value


def binding(value):
    keys = {'run', 'role', 'token', 'sourcePort', 'session', 'generation', 'ssh'}
    if not isinstance(value, dict) or set(value) != keys: raise Refused('binding-schema')
    if any(not isinstance(value[k], str) for k in ('run','role','token','session')): raise Refused('binding-string-types')
    if not re.fullmatch('[0-9a-f]{32}', value['run']) or value['role'] not in ('normal', 'blackhole'):
        raise Refused('binding-run-role')
    try: canonical_session = str(uuid.UUID(value['session'])) == value['session']
    except ValueError: canonical_session = False
    if not re.fullmatch('[0-9a-f]{32}', value['token']) or not canonical_session:
        raise Refused('binding-token')
    if type(value['sourcePort']) is not int or not 1024 <= value['sourcePort'] <= 65535 or type(value['generation']) is not int or value['generation'] != 1:
        raise Refused('binding-generation-port')
    identity(value['ssh'])
    return value


def lsof_connection(raw, pid, *, fd=None, server=False):
    """Strict lsof -F pufnPT record; accepts exactly one matching own TCP/ESTABLISHED FD."""
    if not isinstance(raw, bytes) or len(raw) > 65536: raise Refused('tcp-metadata-bounds')
    try: lines = raw.decode('ascii').splitlines()
    except UnicodeError: raise Refused('tcp-metadata-encoding') from None
    records = []; process = {}; current = None
    for line in lines:
        if not line: continue
        key, text = line[0], line[1:]
        if key in ('p', 'u'):
            if not text.isdecimal(): raise Refused('tcp-process')
            process[key] = int(text)
        elif key == 'f':
            if current is not None: records.append(current)
            if not re.fullmatch('[0-9]+', text): raise Refused('tcp-fd')
            current = {'fd': int(text), **process}
        elif current is not None and key in ('n', 'P'):
            if key in current: raise Refused('tcp-duplicate')
            current[key] = text
        elif current is not None and key == 'T':
            if text.startswith('ST='):
                if 'state' in current: raise Refused('tcp-state-duplicate')
                current['state'] = text[3:]
        else: raise Refused('tcp-unknown-field')
    if current is not None: records.append(current)
    candidates = []
    for row in records:
        if row.get('p') != pid or row.get('P') != 'TCP' or row.get('state') != 'ESTABLISHED' or (fd is not None and row['fd'] != fd):
            continue
        match = re.fullmatch(r'127\.0\.0\.1:([0-9]+)->127\.0\.0\.1:([0-9]+)', row.get('n', ''))
        if not match: continue
        local, remote = map(int, match.groups())
        source = remote if server else local
        if (local if server else remote) != 22221 or not 1024 <= source <= 65535: continue
        candidates.append({'pid': pid, 'fd': row['fd'], 'uid': row.get('u'), 'sourcePort': source,
                           'state': 'ESTABLISHED', 'tuple': row['n']})
    if len(candidates) != 1: raise Refused('tcp-not-exactly-one-established')
    return candidates[0]


@dataclass
class Flow:
    """Single-worker queue owner. Payload is never returned in metadata or exceptions."""
    queues: list = field(default_factory=lambda: [bytearray(), bytearray()])
    read_bytes: list = field(default_factory=lambda: [0, 0])
    forwarded: list = field(default_factory=lambda: [0, 0])
    dropped: list = field(default_factory=lambda: [0, 0])
    discarded_at_arm: list = field(default_factory=lambda: [0, 0])
    peaks: list = field(default_factory=lambda: [0, 0])
    mode: str = 'forward'
    bound: dict | None = None
    armed_at: float | None = None
    first_eof: str | None = None
    first_eof_at: float | None = None
    eof_times: list = field(default_factory=lambda: [None, None])
    half_closed: list = field(default_factory=lambda: [False, False])
    refused: str | None = None
    client_result_at: float | None = None

    def receive(self, direction, data, now):
        if direction not in (0, 1) or not isinstance(data, bytes) or len(data) > LIMIT: raise Refused('read-bound')
        if not data:
            self.eof('client' if direction == 0 else 'backend', now); return
        self.read_bytes[direction] += len(data)
        if self.mode == 'drop': self.dropped[direction] += len(data)
        else:
            if len(self.queues[direction]) + len(data) > LIMIT: raise Refused('queue-bound')
            self.queues[direction].extend(data)
            self.peaks[direction] = max(self.peaks[direction], len(self.queues[direction]))

    def wrote(self, direction, size):
        if self.mode != 'forward' or not 0 < size <= len(self.queues[direction]): raise Refused('write-after-drop-or-bound')
        del self.queues[direction][:size]; self.forwarded[direction] += size

    def arm(self, requested, clock, *, tcp_established, bridge_alive, safe_remaining):
        binding(requested)
        if self.mode != 'forward' or self.armed_at is not None or self.first_eof is not None or self.refused or self.bound != requested:
            raise Refused('arm-stale-or-not-bound')
        if not tcp_established or not bridge_alive or safe_remaining < DROP_SAFETY_SECONDS:
            raise Refused('arm-not-live')
        # Single worker owns queues; callback clock is sampled only AFTER atomic mode switch.
        self.discarded_at_arm = [len(q) for q in self.queues]
        for queue in self.queues: queue.clear()
        self.mode = 'drop'; self.armed_at = clock()
        if not math.isfinite(self.armed_at): self.refused = 'arm-clock'; raise Refused('arm-clock')
        return self.metadata()

    def eof(self, direction, now):
        index = 0 if direction == 'client' else 1
        if self.eof_times[index] is None: self.eof_times[index] = now
        if self.first_eof is None: self.first_eof = direction; self.first_eof_at = now
        if self.mode == 'drop' and self.first_eof != 'client' and self.client_result_at is None:
            self.refused = self.refused or 'proxy-eof-before-client'

    def drain_eof(self, callbacks):
        if self.mode == 'drop': return
        for index in (0, 1):
            if self.eof_times[index] is not None and not self.queues[index] and not self.half_closed[index]:
                callbacks[index](); self.half_closed[index] = True

    def result(self, now):
        if self.client_result_at is not None: raise Refused('result-replay')
        if self.refused or (self.mode == 'drop' and self.first_eof not in (None, 'client')): raise Refused('proxy-ended-first')
        self.client_result_at = now

    def metadata(self):
        return {'mode': self.mode, 'readBytes': list(self.read_bytes), 'forwardedBytes': list(self.forwarded),
                'droppedBytes': list(self.dropped), 'discardedAtArm': list(self.discarded_at_arm), 'bufferPeaks': list(self.peaks),
                'armedAt': self.armed_at, 'firstEOFDirection': self.first_eof, 'firstEOFAt': self.first_eof_at,
                'failure': self.refused, 'clientResultAt': self.client_result_at, 'EOFAtByDirection': list(self.eof_times),
                'halfClosedByDirection': list(self.half_closed)}


def verdict(role, report, relay):
    """Never classifies EOF/cancel/deadline/early backend failure as keepalive success."""
    if role not in ('normal', 'blackhole') or report.get('role') != role or report.get('serverAliveInterval') != 2 or report.get('serverAliveCountMax') != 2:
        return False
    if report.get('failure') is not None or report.get('pidGone') is not True or report.get('closed') is not True or report.get('fdReturnedToBaseline') is not True:
        return False
    if relay.get('failure') is not None or relay.get('cleanupFailed') is not False or relay.get('cancelBeforeResult') is not False or relay.get('deadlineBeforeResult') is not False:
        return False
    if not report.get('shellACK') or report.get('authenticationRequests') != 0 or report.get('trustRequests') != 0:
        return False
    if any(report.get(key) for key in ('stopBeforeResult', 'cancelBeforeResult', 'deadlineBeforeResult')):
        return False
    if role == 'normal':
        return (report.get('quietSeconds', 0) >= NORMAL_SECONDS and report.get('quietSamples', 0) >= 2 and report.get('sameTokenPIDDuringQuiet') is True and report.get('freshACK') is True and report.get('lastExitCode') == 0 and report.get('naturalState') == 'disconnected0' and report.get('quietApplicationOutputEvents') == 0 and relay.get('mode') == 'forward' and relay.get('pumpImplementation') == 'frozen-normal'
                and relay.get('reason') == 'complete' and relay.get('finished') is True and relay.get('armedAt') is None)
    elapsed = report.get('dropToExitSeconds')
    return (isinstance(elapsed, (float, int)) and not isinstance(elapsed, bool) and 0 < elapsed <= BLACKHOLE_SECONDS
            and report.get('lastExitCode') == 255 and report.get('naturalState') == 'failed-launchFailed'
            and relay.get('mode') == 'drop' and relay.get('failure') is None
            and relay.get('firstEOFDirection') in (None, 'client') and relay.get('clientResultAt') is not None
            and relay.get('establishedAtArm') is True and relay.get('bridgeAliveAtArm') is True
            and isinstance(relay.get('remoteBridgeAtArm'),dict) and relay['remoteBridgeAtArm'].get('pidfdAlive') is True
            and relay.get('remoteBridgeAtResult') == relay.get('remoteBridgeAtArm')
            and relay.get('tcpSnapshotCount', 0) >= 2 and sum(relay.get('droppedBytes', [])) > 0
            and relay.get('cancelBeforeResult') is False and relay.get('deadlineBeforeResult') is False)
