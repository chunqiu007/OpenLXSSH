#!/usr/bin/env python3
"""Explicit native normal/DROP/MaxSessions supervisor. Default/help/validate are inert.

Only `run --primary-reviewed-live ...` may start the unchanged approved relay and exactly
one native consumer. No collect, new container, server mutation, pf, production or Keychain.
Secret material is opened solely by the consumer's mature selected stable reader.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
OLD = HERE.parent
ROOT = OLD.parent.parent
PROBE = ROOT / 'Experiments/UXNativeShellProbe'
BUILD = PROBE / '.build'
if str(OLD) not in sys.path: sys.path.insert(0, str(OLD))
from core import Refused, binding, encoded, exact_json, identity, lsof_connection
from liveness_protocol import ConsumerSequence, validate_contract, verdict, arm_age_bounds
from fixture_identity import CONTAINER, CONTEXT, ENDPOINT, FINGERPRINT, IMAGE, NETWORK, PROJECT
from public_files import contract_object, material_object
from diagnostics import RelayCommandRefused, collect_failed_close, classify_relay_observations, guardian_cleanup_facts


def public_read(path, limit=131072, mode=None, exported=False):
    path = Path(path)
    if path.resolve() != path: raise Refused('public-symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or
                before.st_mode & (0o002 if exported else 0o022) or before.st_size > limit or (mode is not None and stat.S_IMODE(before.st_mode) != mode)):
            raise Refused('public-owner-mode-bound')
        data = bytearray()
        while len(data) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(data)))
            if not block: break
            data.extend(block)
        after = os.fstat(fd)
        fields = lambda x: (x.st_dev, x.st_ino, x.st_mode, x.st_uid, x.st_gid, x.st_nlink, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        if fields(before) != fields(after) or len(data) != before.st_size: raise Refused('public-changed')
        return bytes(data)
    finally: os.close(fd)


def directory(path):
    path = Path(path)
    if path.resolve() != path: raise Refused('private-directory-symlink')
    value = path.stat()
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.getuid() or stat.S_IMODE(value.st_mode) != 0o700:
        raise Refused('private-directory-owner-mode')


def save(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'w') as handle: json.dump(value, handle, indent=2, sort_keys=True); handle.write('\n')


def load_contract(path):
    path = Path(path)
    directory(BUILD); directory(path.parent)
    if public_read(path.parent / '.native-liveness-case-owner', mode=0o600) != b'NATIVE-LIVENESS-SUPERVISOR-R2\n':
        raise Refused('native-case-marker')
    value = contract_object(public_read(path, 4096, 0o600))
    validate_contract(value, str(path), str(BUILD), time.time())
    material_path = Path(value['materialContractPath'])
    directory(material_path.parent)
    if public_read(material_path.parent / '.native-shell-case-owner', mode=0o600) != b'U0-NATIVE-SHELL-LIVE-A\n':
        raise Refused('material-case-marker')
    # Public references only. Never open private key/passphrase/password or fingerprint hashes.
    material_object(public_read(material_path, 8192, 0o600))
    return value


def build_receipt(folder, role):
    folder = Path(folder)
    if folder.parent != BUILD or not folder.name.startswith('liveness-'): raise Refused('build-path')
    record = json.loads(public_read(folder / 'result.json', 1024 * 1024))
    if (record.get('status') != 'linked-not-live-run' or record.get('taskID') != 'NATIVE-LIVENESS-SUPERVISOR-R2-BUILD' or
            record.get('instrumented') is not (role == 'maxsessions') or record.get('frozenReadinessInputCount') != 228 or
            record.get('frozenReadinessBinary') != '1808b3bd411e30384be31fbd5d645967981bb8aa951b152ed2c251000a392818'):
        raise Refused('build-receipt')
    for item in record['inputs']:
        original, snapshot = Path(item['path']), Path(item['snapshot'])
        limit = 128 * 1024 * 1024 if original.suffix in ('.a', '.gz') else 2 * 1024 * 1024
        exported = str(original).startswith(str(ROOT / 'Packages/OpenLXSSHFiles/.build/native/install') + '/')
        if hashlib.sha256(public_read(original, limit, exported=exported)).hexdigest() != item['sha256'] or hashlib.sha256(public_read(snapshot, limit)).hexdigest() != item['sha256']:
            raise Refused('build-public-input-changed')
    item = record['binary']
    if item.get('metadata') != {'architecture': 'arm64', 'minimumOS': '26.0', 'kind': 2}:
        raise Refused('native-consumer-minimum-os')
    for key in ('binary', 'identityTool'):
        path = Path(record[key]['path'])
        if path.parent != folder / 'artifacts' or hashlib.sha256(public_read(path, 128 * 1024 * 1024)).hexdigest() != record[key]['sha256']:
            raise Refused('build-artifact-changed')
    # Existing relay itself verifies every immutable frozen relay source when it starts.
    return record


class FrameReader:
    def __init__(self, process, limit=4096):
        self.process, self.limit = process, limit
        self.buffer = bytearray()
        os.set_blocking(process.stdout.fileno(), False)

    def read(self, seconds):
        deadline = time.monotonic() + seconds; data = self.buffer
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                if b'\n' in data:
                    end = data.index(10) + 1
                    raw = bytes(data[:end]); del data[:end]
                    if len(raw) >= self.limit: raise Refused('private-pipe-bound')
                    if self.limit == 2048: return exact_json(raw)
                    def pairs(items):
                        result = {}
                        for key, value in items:
                            if key in result: raise Refused('private-pipe-duplicate')
                            result[key] = value
                        return result
                    value = json.loads(raw, object_pairs_hook=pairs)
                    if not isinstance(value, dict): raise Refused('private-pipe-object')
                    return value
                if not selector.select(min(.025, max(0, deadline - time.monotonic()))):
                    if self.process.poll() is not None: raise Refused('owned-child-ended-before-frame')
                    continue
                try: block = os.read(self.process.stdout.fileno(), self.limit - len(data))
                except (BlockingIOError, InterruptedError): continue
                if not block: raise Refused('private-pipe-eof')
                data.extend(block)
                if len(data) >= self.limit and b'\n' not in data: raise Refused('private-pipe-bound')
        raise Refused('private-pipe-deadline')


def send(process, value, limit=2048):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if len(raw) >= limit or process.poll() is not None: raise Refused('private-pipe-send')
    process.stdin.write(raw); process.stdin.flush()


def relay_query(relay, reader, value):
    sent = time.monotonic(); send(relay, value); result = reader.read(10)
    received = time.monotonic()
    if result.get('ok') is not True:
        raise RelayCommandRefused(operation=value.get('op'), response=result, sent=sent, received=received)
    return result, sent, received


def process_birth(tool, pid):
    result = subprocess.run([str(tool), str(pid)], stdin=subprocess.DEVNULL, capture_output=True, timeout=2)
    if result.returncode: raise Refused('native-process-birth')
    return identity(exact_json(result.stdout))


def exact_tcp(tool, consumer, birth):
    if birth['pid'] != consumer.pid or birth['ppid'] != os.getpid() or birth['uid'] != os.getuid(): raise Refused('native-process-owner')
    if consumer.poll() is not None or process_birth(tool, consumer.pid) != birth: raise Refused('native-process-reused')
    result = subprocess.run(['/usr/sbin/lsof', '-nP', '-a', '-p', str(consumer.pid), '-iTCP:22221', '-sTCP:ESTABLISHED', '-F', 'pufnPT'],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=2)
    if result.returncode: raise Refused('native-owned-tcp')
    row = lsof_connection(result.stdout, consumer.pid)
    if row['uid'] != os.getuid() or process_birth(tool, consumer.pid) != birth: raise Refused('native-tcp-birth')
    return row


def stop_owned(child, seconds=12):
    if child is None: return None
    result = {'pid': child.pid, 'terminated': False, 'killed': False}
    if child.poll() is None:
        child.terminate(); result['terminated'] = True
        try: child.wait(timeout=seconds)
        except subprocess.TimeoutExpired: child.kill(); result['killed'] = True; child.wait(timeout=3)
    result['exitCode'] = child.wait()
    for handle in (child.stdin, child.stdout):
        if handle is not None: handle.close()
    return result


def run_case(record, contract, contract_path, work):
    run, role = contract['run'], contract['role']; relay_role = 'blackhole' if role == 'blackhole' else 'normal'
    relay = consumer = None; acknowledged = False
    stage = 'relay-start'
    result = {'taskID': 'NATIVE-LIVENESS-SUPERVISOR-R2', 'run': run, 'role': role, 'status': 'running',
              'startedAt': time.monotonic(), 'secretReadBySupervisor': False, 'instrumented': record['instrumented']}
    environment = {'PATH': '/Applications/Docker.app/Contents/Resources/bin:/usr/bin:/bin:/usr/sbin:/sbin',
                   'HOME': str(Path.home()), 'LANG': 'C', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
    stderr = (work / 'stderr.log').open('xb')
    relay_stderr = (work / 'relay-diagnostics.log').open('xb')
    try:
        relay = subprocess.Popen([sys.executable, '-B', str(HERE / 'relay_native.py'), '--live-test-only', '--role', relay_role,
            '--run', run, '--owner-pid', str(os.getpid())], cwd=OLD, env=environment, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=relay_stderr, bufsize=0, close_fds=True)
        relay_reader = FrameReader(relay, 2048)
        if relay_reader.read(60) != {'event': 'ready', 'run': run, 'role': relay_role, 'pid': relay.pid, 'port': 22221}:
            raise Refused('relay-ready')
        # Freshness rechecked after relay preflight, before consumer can read any secret.
        validate_contract(contract, str(contract_path), str(BUILD), time.time())
        stage = 'consumer-start'
        consumer = subprocess.Popen([record['binary']['path'], '--live-native-liveness', '--authorized-local-fixture',
            '--primary-reviewed', '--contract', str(contract_path), '--owner-pid', str(os.getpid()), '--private-pipes'],
            cwd=PROBE, env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, bufsize=0, close_fds=True)
        frames = FrameReader(consumer); state = ConsumerSequence(run, role)
        def receive(seconds):
            frame = frames.read(seconds)
            if frame.get('op') == 'failed':
                result['consumerFailureFrame'] = frame
                raise Refused('native-consumer-explicit-failure')
            return state.accept(frame)
        stage = 'native-ready'
        ready = receive(73); result['ready'] = ready
        stage = 'native-tuple'
        birth = process_birth(record['identityTool']['path'], consumer.pid)
        row = exact_tcp(record['identityTool']['path'], consumer, birth)
        if row['sourcePort'] != ready['sourcePort'] or ready['pid'] != consumer.pid: raise Refused('consumer-tuple-mismatch')
        stage = 'relay-lookup'
        found, _, _ = relay_query(relay, relay_reader, {'op': 'lookup', 'run': run, 'role': relay_role, 'sourcePort': row['sourcePort']})
        bound = binding({'run': run, 'role': relay_role, 'token': found['token'], 'sourcePort': row['sourcePort'],
                         'session': ready['session'], 'generation': 1, 'ssh': birth})
        result['binding'] = bound; result['tcpBeforeArm'] = row
        stage = 'relay-bind'
        result['bound'], _, _ = relay_query(relay, relay_reader, {'op': 'bind', 'run': run, 'role': relay_role, 'binding': bound})
        send(consumer, {'op': 'binding-confirmed', 'sequence': 1, 'run': run, 'role': role, 'session': ready['session'], 'stamp': time.monotonic(), 'ok': True})
        stage = 'arm-ready'
        arm_ready = receive(7); arm_ready_received = time.monotonic(); result['armReady'] = arm_ready
        if arm_ready['sourcePort'] != row['sourcePort'] or exact_tcp(record['identityTool']['path'], consumer, birth) != row:
            raise Refused('native-tuple-changed-before-arm')
        if arm_ready['proof']['started'] <= ready['proof']['started']: raise Refused('fresh-proof-boundary')
        timing = {'armAfterReady': 0.0, 'armRequestToResult': 0.0}
        arm = {}
        if role == 'blackhole':
            stage = 'relay-arm'
            arm, arm_sent, arm_received = relay_query(relay, relay_reader, {'op': 'arm', 'run': run, 'role': relay_role, 'binding': bound})
            timing['armAfterReady'] = arm_sent - arm_ready_received
            if not 0 <= timing['armAfterReady'] < 1.5 or arm.get('mode') != 'drop': raise Refused('arm-too-late-or-not-drop')
            result['arm'] = arm; result['armRequestSentAt'] = arm_sent; result['armACKReceivedAt'] = arm_received
            send(consumer, {'op': 'drop-confirmed', 'sequence': 2, 'run': run, 'role': role, 'session': ready['session'],
                'stamp': time.monotonic(), 'ok': True, **{key: arm[key] for key in ('armedAt', 'armedWall', 'relayNow', 'relayWall')}})
        else:
            send(consumer, {'op': 'normal-ready', 'sequence': 2, 'run': run, 'role': role, 'session': ready['session'], 'stamp': time.monotonic(), 'ok': True})
        stage = 'native-result'
        outcome = receive(9); observed = time.monotonic(); result['resultObservedAt'] = observed
        result['preCloseReport'] = outcome['report']
        if role == 'blackhole':
            report = outcome['report']
            if (report.get('proofLower') != arm_ready['proofLower'] or report.get('proofUpper') != arm_ready['proofUpper'] or
                    report.get('armReadySent') != arm_ready['stamp']): raise Refused('proof-interval-report-binding')
            result['actualArmAge'] = arm_age_bounds(report['proofLower'], report['proofUpper'], report['armReadySent'],
                report['dropACKReceived'], arm['armedAt'], arm['relayNow'])
            timing['armRequestToResult'] = observed - arm_sent
        result['timing'] = timing
        stage = 'relay-result'
        relay_result, _, _ = relay_query(relay, relay_reader, {'op': 'result', 'run': run, 'role': relay_role, 'binding': bound})
        result['relayAtResult'] = relay_result
        send(consumer, {'op': 'result-recorded', 'sequence': 3, 'run': run, 'role': role, 'session': ready['session'], 'stamp': time.monotonic(), 'ok': True})
        acknowledged = True
        stage = 'native-close'
        closed = receive(15); result['closedReport'] = closed['report']
        result['consumerExitCode'] = consumer.wait(timeout=3)
        stage = 'relay-finish'
        finished, _, _ = relay_query(relay, relay_reader, {'op': 'finish', 'run': run, 'role': relay_role, 'binding': bound})
        result['relayAfterFinish'] = finished
        stage = 'combined-verdict'
        result['verdict'] = verdict(contract, outcome['report'], closed['report'], arm, relay_result, finished, bound, timing)
        if not result['verdict'] or result['consumerExitCode'] != 0: raise Refused('native-combined-verdict')
        stage = 'relay-stop'
        relay_query(relay, relay_reader, {'op': 'stop', 'run': run, 'role': relay_role})
        result['relayExitCode'] = relay.wait(timeout=30)
        if result['relayExitCode'] != 0: raise Refused('relay-owned-cleanup')
        result['status'] = 'passed-native-limited-case'
    except Exception as error:
        result['status'] = 'failed-retain-no-retry'
        result['failureStage'] = stage
        if isinstance(error, RelayCommandRefused): result['relayRefusal'] = error.observation
        result['failure'] = str(error) if isinstance(error, Refused) else type(error).__name__
        # A genuine result may still be awaiting ACK. Cleanup never changes failure to success.
        if consumer is not None and 'preCloseReport' in result and not acknowledged:
            try:
                send(consumer, {'op': 'result-recorded', 'sequence': 3, 'run': run, 'role': role,
                    'session': result['preCloseReport']['session'], 'stamp': time.monotonic(), 'ok': True})
                result['cleanupACKSent'] = True
            except Exception: result['cleanupACKSent'] = False
        if consumer is not None:
            try:
                if 'frames' in locals() and 'ready' in result:
                    collect_failed_close(frames, run=run, role=role, session=result['ready']['session'],
                                         result=result, seconds=15, clock=time.monotonic)
                consumer.wait(timeout=15)
            except Exception: pass
    finally:
        result['consumerDrain'] = stop_owned(consumer); result['relayDrain'] = stop_owned(relay, 30)
        if result['status'] == 'passed-native-limited-case' and any(
                item and (item['terminated'] or item['killed']) for item in (result['consumerDrain'], result['relayDrain'])):
            result['status'] = 'failed-retain-no-retry'; result['failure'] = 'forced-owner-drain'
        stderr.close(); relay_stderr.close()
        try:
            diagnostic_bytes = public_read(work / 'relay-diagnostics.log', 128 * 512 + 16384, 0o600)
            result['relayDiagnosticStage'] = classify_relay_observations(diagnostic_bytes)
            if role == 'blackhole':
                cleanup = guardian_cleanup_facts(diagnostic_bytes)
                result['guardianCleanup'] = cleanup
                from guardian import SOURCE_SHA256
                if result['status'] == 'passed-native-limited-case' and (cleanup is None or cleanup['success'] is not True or
                        cleanup['sourceSHA256'] != SOURCE_SHA256):
                    result['status'] = 'failed-retain-no-retry'; result['failure'] = 'guardian-cleanup-unproven'
        except Exception:
            result['relayDiagnosticStage'] = 'unknown-diagnostic-read-refused'
            if role == 'blackhole' and result['status'] == 'passed-native-limited-case':
                result['status'] = 'failed-retain-no-retry'; result['failure'] = 'guardian-cleanup-unproven'
        result['endedAt'] = time.monotonic(); save(work / 'result.json', result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='help', choices=['help', 'validate', 'run'])
    parser.add_argument('--build', type=Path); parser.add_argument('--contract', type=Path)
    parser.add_argument('--primary-reviewed-live', action='store_true')
    args = parser.parse_args(argv)
    if args.action == 'help': parser.print_help(); return 0
    if args.action == 'validate': print('Syntax only; no files, descriptors, credentials, relay or processes.'); return 0
    if not args.primary_reviewed_live or args.build is None or args.contract is None: return 64
    os.umask(0o077)
    contract = load_contract(args.contract); record = build_receipt(args.build, contract['role'])
    work = BUILD / ('native-liveness-supervisor-' + uuid.uuid4().hex); work.mkdir(mode=0o700)
    save(work / 'source-binding.json', {'build': str(args.build), 'binary': record['binary'], 'contract': str(args.contract),
         'contractSHA256': hashlib.sha256(public_read(args.contract, 4096, 0o600)).hexdigest(), 'sourceInputs': record['inputs']})
    result = run_case(record, contract, args.contract, work)
    return 0 if result['status'] == 'passed-native-limited-case' else 1


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception:
        sys.stderr.write('Native liveness supervisor refused; no private details.\n'); raise SystemExit(2)
