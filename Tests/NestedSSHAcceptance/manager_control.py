#!/usr/bin/env python3
"""Fixed single-container root controller; default/help/validate are inert.
Later host must exec this inside the exact workplan CID, keep stdin/process owned,
then wait for native closed/PID nil + relay no connections BEFORE sending finish.
No running-session registry: prepare and restoration require globally idle UID10000
and sshd children. EOF/TTL/errors never kill SSH; non-idle/foreign states are retained.
"""
import argparse
import base64
import json
from pathlib import Path
import re
import signal
import sys

import fd_safety as fs
import management_prep as core
from key_ledger import KeyLedger
from nested_probe import FROZEN, INNER_SHA256
from root_adapter import RootAdapter, public_json

LOCAL = ('management_prep.py', 'fd_safety.py', 'session_metadata.py', 'root_adapter.py',
         'key_ledger.py', 'nested_probe.py', 'build_integrated.py', 'manager_control.py')
EXCLUSION = 'global-idle-before-prepare-and-after-native-SSH-closed; no-running-registry'


def validate_plan(raw, expected_sha256):
    core.require(type(raw) is bytes and 0 < len(raw) <= 32768 and core.digest(raw) == expected_sha256)
    plan = json.loads(raw)
    core.require(plan['schema'] == 1 and plan['taskID'] == 'NEST-INTEGRATED-PREP-A' and plan['case'] == 'NESTrealpublickeyonly')
    path = core.key_plan(plan['nonce'])['argv'][-1]
    core.require(plan['key_directory'] == path.rsplit('/', 1)[0])
    core.require(plan['container_id'] == core.CONTAINER_ID and plan['fingerprint'] == core.HOST_FINGERPRINT)
    core.require(plan['inner_sha256'] == INNER_SHA256 and 0 < plan['wrapper_bytes'] <= 32768)
    core.require(plan['exclusion'] == EXCLUSION and plan['finish_precondition'] == 'native-closed-ownedPID-nil-and-host-relay-no-connections')
    core.require(re.fullmatch(r'/[^\r\n]+/Tests/NestedSSHAcceptance/\.build/host-[0-9a-f-]{36}/OpenLXSSHRemoteTerminal\.app', plan['app']) is not None)
    for name in ('app_sha256', 'wrapper_sha256', 'build_location_sha256', 'parent_manifest_sha256'):
        core.require(re.fullmatch('[0-9a-f]{64}', plan[name]) is not None)
    for name, expected in FROZEN.items():
        core.require(plan['source_sha256'][name] == expected)
    for name in LOCAL:  # Only fixed public source files, never credentials.
        core.require(core.digest((Path(__file__).absolute().parent / name).read_bytes()) == plan['source_sha256'][name])
    return plan


class Control:
    def __init__(self, plan, plan_sha256):
        self.plan, self.plan_sha256 = plan, plan_sha256
        self.owner = self.keys = None
        self.ready = self.closed = False

    def prepare(self):
        core.require(not self.ready and self.owner is None)
        self.owner = RootAdapter(self.plan['nonce'], owned=(), ssh_tokens=())
        # Public receipt binds this exact build/nonce before generation; recovery clue only.
        fs.durable_public(self.owner.case, 'integrated-plan.json', public_json({
            'workplan': self.plan, 'workplan_sha256': self.plan_sha256,
            'exclusion': EXCLUSION, 'atomic_against_foreign_writers': False,
        }), self.owner.receipts)
        self.keys = KeyLedger(self.owner)
        public = self.keys.generate()
        prepared = self.owner.append(public)
        appended = public_json({'schema': 1, 'case': 'NESTrealpublickeyonly', 'prepared_sha256': prepared,
                               'appended_sha256': core.digest(self.owner.receipt.original + public),
                               'stamp': self.owner.receipt.stamp._asdict()})
        core.require(self.owner._receipt_hash('appended.json') == core.digest(appended))
        self.owner._exclusion()  # Still globally idle; no READY on a competing connection.
        self.ready = True
        return {'event': 'READY', 'case': 'NESTrealpublickeyonly', 'nonce': self.plan['nonce'],
                'workplan_sha256': self.plan_sha256, 'prepared_sha256': prepared,
                'new_public_sha256': core.digest(public), 'exclusion': EXCLUSION}

    def finish(self):
        core.require(self.ready and not self.closed)
        self.owner._exclusion(closed=True)  # Independent global-idle observation, not host flags.
        self.owner.restore()
        self.keys.cleanup()  # Requires same live owner, restored receipt and current original.
        self.keys.close()
        self.owner.close()
        self.closed = True
        return {'event': 'FINISHED', 'nonce': self.plan['nonce'], 'workplan_sha256': self.plan_sha256,
                'original_sha256': core.digest(self.owner.receipt.original), 'key_directory_removed': True}

    def abort(self):
        """Best effort only when independently idle; no broad kill/unlink or adoption."""
        if self.closed:
            return True
        clean = True
        try:
            if self.owner is not None:
                self.owner._exclusion(closed=True)
                if self.owner.appended_state is not None and not self.owner.restored:
                    self.owner.restore()
                if self.keys is not None and self.owner.restored:
                    self.keys.cleanup()
        except BaseException:
            clean = False
        finally:
            if self.keys is not None:
                try:
                    self.keys.close()  # Partial/unknown key names survive.
                except BaseException:
                    clean = False
            if self.owner is not None:
                try:
                    self.owner.close()  # Existing adapter also checks closed/global-idle before compensation.
                except BaseException:
                    clean = False
            self.closed = True
        return clean


def serve(expected_sha256, incoming, outgoing):
    # A finite foreground owner, not a daemon. Timers/signals only affect this process.
    def stopped(*_args):
        raise core.Refused('nested-controller-stopped')
    prior = {number: signal.signal(number, stopped) for number in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT)}
    signal.alarm(240)
    control = None
    try:
        line = incoming.readline(49153)
        core.require(0 < len(line) <= 49152 and line.endswith('\n'))
        envelope = json.loads(line)
        core.require(set(envelope) == {'workplan_base64'})
        raw = base64.b64decode(envelope['workplan_base64'], validate=True)
        plan = validate_plan(raw, expected_sha256)
        fs.linux_user(0)
        control = Control(plan, expected_sha256)
        outgoing.write(public_json(control.prepare()).decode('ascii'))
        outgoing.flush()
        command = incoming.readline(257)
        core.require(command == 'finish ' + expected_sha256 + '\n')
        outgoing.write(public_json(control.finish()).decode('ascii'))
        outgoing.flush()
        return 0
    except BaseException:
        # Do not let a pending TTL/TERM interrupt the existing bounded compensation.
        signal.alarm(0)
        for number in prior:
            signal.signal(number, signal.SIG_IGN)
        if control is not None:
            control.abort()
        sys.stderr.write('Nested controller refused/retained; no private details.\n')
        return 2
    finally:
        signal.alarm(0)
        for number, handler in prior.items():
            signal.signal(number, handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='help', choices=('help', 'validate', 'serve'))
    parser.add_argument('--workplan-sha256')
    parser.add_argument('--authorized-local-fixture', action='store_true')
    args = parser.parse_args(argv)
    if args.action != 'serve':
        if args.workplan_sha256 or args.authorized_local_fixture:
            parser.error('serve-only flags')
        if args.action == 'help':
            parser.print_help()
        else:
            print('Syntax only; no plan/fixture/process access.')
        return 0
    if not args.authorized_local_fixture or not args.workplan_sha256 or re.fullmatch('[0-9a-f]{64}', args.workplan_sha256) is None:
        parser.error('explicit local fixture and exact build workplan digest required')
    return serve(args.workplan_sha256, sys.stdin, sys.stdout)


if __name__ == '__main__':
    sys.exit(main())
