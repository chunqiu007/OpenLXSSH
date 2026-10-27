#!/usr/bin/env python3
"""One frozen NEST case. Default/validate are inert; --live is a later review gate.
No private values read/exported by this runner. Only the existing authorized outer
freshcollect may populate its private generation; inner keys are generated remotely.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time
import uuid

import manager_control
import remote_bootstrap as remote

HERE = Path(__file__).absolute().parent
ROOT = HERE.parent.parent
FIX = ROOT / 'Tests/IntegrationEnvironment'
BUILD = HERE / '.build/host-a4e5f93e-87d3-4402-b270-036873a5a753'
APP = BUILD / 'OpenLXSSHRemoteTerminal.app'
BIN = APP / 'Contents/MacOS/OpenLXSSHRemoteTerminal'
PLAN_SHA256 = remote.PLAN_SHA256
CID = '1253a29501483eb71f80e39b9af5c85e10c3a49329d5e93700fecd3f00f334f2'
FP = 'SHA256:MHUel445tN/gQtcvZikLZVE1mlWZf7U38C0zZTTru+Q'
EP = 'unix://' + str(Path.home() / '.docker/run/docker.sock')
DOCKER = ['/Applications/Docker.app/Contents/Resources/bin/docker', '--host', EP]
ENV = {'PATH': '/Applications/Docker.app/Contents/Resources/bin:/usr/bin:/bin:/usr/sbin:/sbin',
       'HOME': str(Path.home()), 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1', 'DOCKER_CONTEXT': 'desktop-linux'}
# Only closed exception classes cross stderr; no exception strings, traceback or wire.
RELAY_LAUNCHER = '''import json,sys,contextlib,os
sys.path.insert(0,sys.argv.pop(1))
import fixture
classes={'FixtureError','RelayError','TimeoutExpired','OSError','FileNotFoundError','PermissionError','ValueError','KeyError','TypeError','KeyboardInterrupt'}
def kind(error):return type(error).__name__ if type(error).__name__ in classes else 'other'
try:
 with open(os.devnull,'w') as sink,contextlib.redirect_stderr(sink):result=fixture.main()
except BaseException as error:
 sys.stderr.write(json.dumps({'exceptionClass':kind(error),'causeClass':kind(error.__cause__) if error.__cause__ is not None else 'none'})+'\\n')
 result=2
sys.exit(result)
'''
GENERATION_NAMES = {'password.txt', 'key-passphrase.txt', 'known_hosts', 'fingerprint.txt', 'packages.txt', 'provenance.json'} | {
    name + suffix for name in ('id_ed25519', 'id_ed25519_encrypted', 'id_rsa', 'id_rsa_encrypted') for suffix in ('', '.pub')}


def require(value):
    if not value:
        raise ValueError('nested-host-case-refused')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink)


def safe(path, mode=None):
    require(path.is_absolute() and path.resolve() == path)
    info = path.lstat()
    require(info.st_uid == os.getuid() and not info.st_mode & 0o022)
    if mode is not None:
        require(stat.S_IMODE(info.st_mode) == mode)
    return info


def public(path, mode=None):
    before = safe(path, mode)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 1048576)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(stamp(os.fstat(fd)) == stamp(before))
        value = os.pread(fd, before.st_size + 1, 0)
        require(len(value) == before.st_size and stamp(path.lstat()) == stamp(before))
        return value
    finally:
        os.close(fd)


def bundle():
    raw = public(BUILD / 'workplan.json', 0o600)
    require(sha(raw) == PLAN_SHA256)
    plan = manager_control.validate_plan(raw, PLAN_SHA256)  # Public only, no RootAdapter.
    require(plan['app'] == str(APP) and sha(BIN.read_bytes()) == plan['app_sha256'])
    manifest = json.loads(public(BUILD / 'result.json', 0o600))
    require(sha((APP / 'Contents/Helpers/openlxssh-askpass').read_bytes()) == manifest['helperSHA256'])
    modules = {}
    for name in remote.NAMES:
        source = public(HERE / (name + '.py'))
        require(sha(source) == plan['source_sha256'][name + '.py'])
        modules[name] = base64.b64encode(source).decode('ascii')
    envelope = {'workplan_base64': base64.b64encode(raw).decode('ascii'), 'modules_base64': modules}
    return plan, envelope


class Generation:
    """Exact14 names/FDs only. No secret reads; no recursive host cleanup."""
    def __init__(self, path):
        safe(path, 0o700)
        self.path, self.fd, self.files = path, os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW), {}
        self.identity = stamp(os.fstat(self.fd))[:5]
        self.parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.parent_identity = stamp(os.fstat(self.parent))[:5]
        try:
            require(set(os.listdir(self.fd)) == GENERATION_NAMES)
            for name in sorted(GENERATION_NAMES):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.fd)
                self.files[name] = (fd, stamp(os.fstat(fd)))
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1)
                require(stamp(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) == self.files[name][1])
        except BaseException:
            self.close()
            raise

    def cleanup(self):
        require(stamp(self.path.parent.lstat())[:5] == self.parent_identity == stamp(os.fstat(self.parent))[:5])
        require(stamp(os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False))[:5] == self.identity == stamp(os.fstat(self.fd))[:5])
        require(set(os.listdir(self.fd)) == GENERATION_NAMES)
        for name, (fd, identity) in self.files.items():
            require(stamp(os.fstat(fd)) == identity == stamp(os.stat(name, dir_fd=self.fd, follow_symlinks=False)))
        for name in self.files:
            os.unlink(name, dir_fd=self.fd)
        require(not os.listdir(self.fd))
        os.rmdir(self.path.name, dir_fd=self.parent)
        os.fsync(self.parent)

    def close(self):
        for fd, _identity in self.files.values():
            os.close(fd)
        self.files.clear()
        os.close(self.fd)
        os.close(self.parent)


class Case:
    def __init__(self):
        self.started = time.monotonic()
        self.hard, self.work_end = self.started + 360, self.started + 330
        self.controller = self.consumer = self.relay = self.generation = self.relaylog = None
        self.ready = self.native_released = False
        self.pending, self.record = bytearray(), {'taskID': 'NEST-RELAY-READY-R1', 'case': 'NESTrealpublickeyonly', 'commands': [], 'live_passed': False,
            'budgets': {'total': 360, 'cleanupReserve': 30, 'relayReady': 125, 'relayMax': 360,
                        'consumer': 180, 'managerPrepareFinish': 40, 'managerTTL': 240}}
        self.stage = 'preflight'
        self.out = HERE / '.runtime' / ('live-' + uuid.uuid4().hex)
        self.out.parent.mkdir(mode=0o700, exist_ok=True)
        safe(self.out.parent, 0o700)
        self.out.mkdir(mode=0o700)

    def left(self, seconds, *, cleanup=False):
        remaining = (self.hard if cleanup else self.work_end) - time.monotonic()
        require(remaining > 0)
        return min(seconds, remaining)

    def save(self, name, value):
        with (self.out / name).open('xb') as stream:
            stream.write(value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, indent=2).encode() + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        fd = os.open(self.out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def call(self, argv, seconds=15, ok=(0,), cleanup=False):
        result = subprocess.run(list(map(str, argv)), cwd=HERE, env=ENV, capture_output=True, timeout=self.left(seconds, cleanup=cleanup))
        self.record['commands'].append({'argv': list(map(str, argv)), 'exitCode': result.returncode})
        require(result.returncode in ok)
        return result.stdout

    def no_acl(self, paths):
        for path in paths:
            output = self.call(['/bin/ls', '-lde', path], 3)
            require(b'+' not in output.split(None, 1)[0])

    def line(self, seconds, cleanup=False):
        end = time.monotonic() + self.left(seconds, cleanup=cleanup)
        while b'\n' not in self.pending:
            require(time.monotonic() < end and len(self.pending) <= 196608)
            with selectors.DefaultSelector() as selector:
                selector.register(self.controller.stdout, selectors.EVENT_READ)
                require(selector.select(max(0.001, end - time.monotonic())))
            part = os.read(self.controller.stdout.fileno(), 8192)
            require(part)
            self.pending.extend(part)
        raw, _, self.pending = self.pending.partition(b'\n')
        return json.loads(raw)

    def send(self, value):
        fd = self.controller.stdin.fileno()
        os.set_blocking(fd, False)
        pending = memoryview(value.encode('ascii'))
        end = time.monotonic() + self.left(8, cleanup=True)
        while pending:
            require(time.monotonic() < end)
            with selectors.DefaultSelector() as selector:
                selector.register(fd, selectors.EVENT_WRITE)
                require(selector.select(max(0.001, end - time.monotonic())))
            count = os.write(fd, pending)
            require(count > 0)
            pending = pending[count:]

    def stop(self, process, seconds, *, kill=True):
        if process is None:
            return
        if process.poll() is None:
            process.terminate()  # Exact Popen only; never report-derived/global PID/PGID kills.
        try:
            process.wait(timeout=self.left(seconds, cleanup=True))
        except subprocess.TimeoutExpired:
            require(kill)
            process.kill()
            process.wait(timeout=self.left(2, cleanup=True))

    def require_mutation_budget(self):
        # Reserve the full consumer+manager budgets AND the final 30s before append.
        remaining = self.hard - time.monotonic()
        self.record['preAppendRemainingSeconds'] = round(remaining, 3)
        require(remaining >= 180 + 40 + 30)

    def relay_start(self):
        self.stage = 'relay-startup'
        self.relaylog = (self.out / 'relay-events.log').open('xb')
        self.relay_started = time.monotonic()
        argv = [sys.executable, '-B', '-c', RELAY_LAUNCHER, str(FIX), 'relay', '--authorized-run', '--max-duration', '360']
        self.relay = subprocess.Popen(argv, cwd=HERE, env=ENV, stdout=self.relaylog, stderr=subprocess.PIPE)
        end = time.monotonic() + self.left(125)
        while b'"event": "relay-ready"' not in (self.out / 'relay-events.log').read_bytes():
            require(self.relay.poll() is None and time.monotonic() < end)
            time.sleep(0.1)
        self.record['relayReadySeconds'] = round(time.monotonic() - self.relay_started, 3)
        require(self.relay.poll() is None)

    def relay_metadata(self):
        if self.record.get('relayMetadataRecorded'):
            return
        self.record['relayExitCode'] = self.relay.returncode
        self.record['relayElapsedSeconds'] = round(time.monotonic() - self.relay_started, 3)
        # The launcher permits exactly one <4KiB typed line; unknown output is discarded.
        fd = self.relay.stderr.fileno()
        os.set_blocking(fd, False)
        try:
            raw = os.read(fd, 4097)
        except BlockingIOError:
            raw = b''
        if raw:
            require(len(raw) <= 4096)
            value = json.loads(raw)
            allowed = {'FixtureError', 'RelayError', 'TimeoutExpired', 'OSError', 'FileNotFoundError',
                       'PermissionError', 'ValueError', 'KeyError', 'TypeError', 'KeyboardInterrupt', 'other', 'none'}
            require(set(value) == {'exceptionClass', 'causeClass'} and set(value.values()) <= allowed)
            self.record['relayError'] = value
        self.record['relayMetadataRecorded'] = True

    def fixture(self):
        state = json.loads(public(FIX / '.runtime/state.json', 0o600))
        context = json.loads(self.call([DOCKER[0], 'context', 'inspect', 'desktop-linux']))
        require(len(context) == 1 and context[0]['Endpoints']['docker']['Host'] == EP)
        container = json.loads(self.call(DOCKER + ['inspect', CID]))[0]
        host, labels = container['HostConfig'], container['Config']['Labels']
        require(container['Id'] == CID and container['State']['Running'] and container['State']['Health']['Status'] == 'healthy')
        require(labels['com.docker.compose.service'] == 'keyonly' and labels['org.openlxssh.fixture'] == 'env-fixture-a' and labels['com.docker.compose.project'] == state['project'])
        caps = sorted(value[4:] if value.startswith('CAP_') else value for value in host['CapAdd'])
        require(host['ReadonlyRootfs'] and not host['Privileged'] and host['CapDrop'] == ['ALL'] and caps == ['AUDIT_WRITE', 'CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'KILL', 'SETGID', 'SETUID', 'SYS_CHROOT'])
        require(host['SecurityOpt'] == ['no-new-privileges:true'] and host['LogConfig']['Type'] == 'none')
        volume = state['project'] + '_key-data'
        require(host['Binds'] == [volume + ':/fixture:rw'] and len(container['Mounts']) == 1 and container['Mounts'][0]['Name'] == volume)
        require(container['Mounts'][0]['Destination'] == '/fixture' and container['Mounts'][0]['Type'] == 'volume' and container['Mounts'][0]['RW'] is True)
        require(host['PortBindings'] == {'2222/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '22221'}]})
        networks = container['NetworkSettings']['Networks']
        require(len(networks) == 1)
        network_id = next(iter(networks.values()))['NetworkID']
        network = json.loads(self.call(DOCKER + ['network', 'inspect', network_id]))[0]
        image = json.loads(self.call(DOCKER + ['image', 'inspect', container['Image']]))[0]
        require(network['Internal'] and network['Driver'] == 'bridge' and CID in network['Containers'] and network['Labels']['com.docker.compose.project'] == state['project'])
        require(image['Architecture'] == 'arm64' and image['Os'] == 'linux' and image['Config']['Labels']['org.openlxssh.fixture.base'] == state['image'])
        self.save('fixture-baseline.json', {'state': state, 'container': container, 'image': image, 'network': network})
        return state, container, network_id

    def fresh_contract(self, state, container, network):
        parent = FIX / '.runtime/keyonly'
        before = set(parent.glob('credentials-*'))
        self.call([FIX / 'fixture.sh', 'collect', '--authorized-run', '--service', 'keyonly'], 80)
        fresh = set(parent.glob('credentials-*')) - before
        require(len(fresh) == 1)
        self.generation = Generation(fresh.pop())
        self.no_acl([self.generation.path] + [self.generation.path / name for name in GENERATION_NAMES])
        provenance = json.loads(public(self.generation.path / 'provenance.json', 0o600))
        require(public(self.generation.path / 'fingerprint.txt', 0o600).split()[1].decode() == FP)
        require(provenance['built_image_id'] == container['Image'] and 0 <= time.time() - provenance['collected_at'] < 120)
        case = HERE / '.runtime' / ('case-' + uuid.uuid4().hex[:12])
        case.mkdir(mode=0o700)
        contract = case / 'remote-terminal.json'
        value = dict(schema=1, taskID='REAL-OUTER-PTY-TUI-PREP-A', service='keyonly', host='127.0.0.1', port=22221,
                     user='fixture', key='edplain', credentialDirectory=str(self.generation.path), expectedFingerprint=FP,
                     baseImage=state['image'], imageID=container['Image'], containerID=CID, project=state['project'],
                     networkID=network, context='desktop-linux', endpoint=EP, collectedAt=provenance['collected_at'], expiresAt=provenance['collected_at'] + 1800)
        with contract.open('x') as stream:
            json.dump(value, stream)
        safe(contract, 0o600)
        self.no_acl([case, contract])
        self.save('contract-public.json', value)
        return contract

    def export_receipts(self, value):
        require(value['event'] == 'PUBLIC-RECEIPTS' and value['workplan_sha256'] == PLAN_SHA256)
        candidate = dict(value)
        expected = candidate.pop('receipt_export_sha256')
        require(sha(json.dumps(candidate, sort_keys=True, separators=(',', ':')).encode()) == expected)
        require(set(value['receipts_base64']) <= remote.RECEIPTS)
        for name, encoded in value['receipts_base64'].items():
            self.save('remote-' + name, base64.b64decode(encoded, validate=True))
        self.save('receipt-export.json', value)
        self.send('receipt-ack ' + expected + '\n')

    def native_closed(self, raw):
        report = json.loads(raw)
        self.save('native-closed-metadata.json', report.get('postAuth', {}).get('lastObservedSession', {}))
        closed = report.get('postAuth', {}).get('lastObservedSession', {})
        require(report['closed'] and report['ownedPIDReleased'] and closed.get('state') == 'closed' and closed.get('ownedPID') is None)
        pid = report.get('ownedPID')
        require(type(pid) is int and pid > 0)
        try:
            os.kill(pid, 0)  # Observe only; never signal a report-selected PID.
        except ProcessLookupError:
            self.native_released = True
            return report
        raise ValueError('native-ssh-still-present')

    def relay_closed(self):
        self.stop(self.relay, 15)
        self.relay_metadata()
        if self.relaylog is not None:
            self.relaylog.close()
            self.relaylog = None
        events = [json.loads(line) for line in (self.out / 'relay-events.log').read_bytes().splitlines()]
        stopped = next(item for item in reversed(events) if item['event'] == 'relay-stopped')
        counts = stopped['counters']
        require(counts['accepted'] == counts['finished'] and counts['cleanup_failed'] == 0)
        require(not self.call(['/usr/sbin/lsof', '-nP', '-iTCP:22221-22224', '-Fpn'], ok=(0, 1), cleanup=True))

    def finish(self, baseline):
        self.send('finish ' + PLAN_SHA256 + '\n')
        finished = self.line(12, cleanup=True)
        require(finished['event'] == 'FINISHED' and finished['original_sha256'] == baseline['snapshot']['authorized_keys_sha256'] and finished['key_directory_removed'])
        self.save('controller-finished.json', finished)
        self.export_receipts(self.line(5, cleanup=True))
        cleaned = self.line(8, cleanup=True)
        require(cleaned['event'] == 'STAGING-CLEANED' and cleaned['snapshot'] == baseline['snapshot'])
        self.save('remote-staging-cleaned.json', cleaned)
        require(self.controller.wait(timeout=self.left(5, cleanup=True)) == 0)

    def run(self):
        plan, envelope = bundle()
        self.save('runner-binding.json', {'workplan_sha256': PLAN_SHA256,
                  'host_case_sha256': sha(public(HERE / 'host_case.py')),
                  'remote_bootstrap_sha256': sha(public(HERE / 'remote_bootstrap.py'))})
        self.no_acl([HERE, BUILD / 'workplan.json'] + [HERE / (name + '.py') for name in remote.NAMES])
        require(not self.call(['/usr/sbin/lsof', '-nP', '-iTCP:22221-22224', '-sTCP:LISTEN', '-Fpn'], ok=(0, 1)))
        self.stage = 'fixture-and-freshcollect'
        state, container, network = self.fixture()
        contract = self.fresh_contract(state, container, network)
        self.relay_start()  # LISTEN/metadata only; no SSH client before manager READY.
        self.stage = 'pre-append-budget'
        self.require_mutation_budget()
        self.stage = 'controller-prepare'
        loader = public(HERE / 'remote_bootstrap.py').decode('utf-8')
        launch = DOCKER + ['exec', '-i', '--user', '0:0', CID, '/usr/bin/python3', '-B', '-c', loader]
        self.controller_started = time.monotonic()
        self.controller = subprocess.Popen(launch, cwd=HERE, env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        self.send(json.dumps(envelope, separators=(',', ':')) + '\n')
        self.send(json.dumps({'workplan_base64': envelope['workplan_base64']}) + '\n')
        baseline = self.line(25)
        require(baseline['event'] == 'BASELINE' and baseline['workplan_sha256'] == PLAN_SHA256)
        self.save('remote-baseline.json', baseline)
        ready = self.line(20)
        require(ready['event'] == 'READY' and ready['nonce'] == plan['nonce'] and ready['workplan_sha256'] == PLAN_SHA256)
        self.save('controller-ready.json', ready)
        self.ready, self.baseline = True, baseline
        self.stage = 'native-consumer'
        require(self.relay.poll() is None)
        self.consumer = subprocess.Popen([str(BIN), '--live', '--authorized-local-fixture', '--engine-ready', '--contract', str(contract)], cwd=HERE, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        limit = min(self.left(180), self.controller_started + 210 - time.monotonic())
        require(limit > 0)
        self.consumer_started = time.monotonic()
        raw, errors = self.consumer.communicate(timeout=limit)
        self.save('consumer-result.raw.json', raw)
        self.record['consumer_stderr_bytes'] = len(errors)  # Never persist stderr/terminal content.
        report = self.native_closed(raw)
        self.stage = 'relay-close'
        self.relay_closed()
        self.stage = 'controller-finish'
        self.finish(baseline)
        required = ('shellACK', 'probeProcessACK', 'inputByteHashMatched', 'interruptObserved', 'remoteSizeMatched', 'vimBytesHashMatched',
                    'remoteCleanup', 'returnedToOuter', 'remoteProcessReleased', 'ownedPIDReleased', 'closed', 'fdReturnedToBaseline')
        require(self.consumer.returncode == 0 and report.get('failure') is None and all(report[name] is True for name in required))
        require(report['probeEvents'] == 12 and report['connectedEvents'] == 1 and report['authenticationRequests'] == report['postConnectedAuthenticationRequests'] == 0)
        self.record.update(live_passed=True, case='NESTrealpublickeyonly', not_covered=plan['not_covered'])

    def close(self):
        try:
            if self.consumer is not None and self.consumer.poll() is None:
                self.consumer.terminate()
                try:
                    raw, errors = self.consumer.communicate(timeout=self.left(18, cleanup=True))
                    self.save('consumer-failure.raw.json', raw)
                    self.record['consumer_failure_stderr_bytes'] = len(errors)
                    self.native_closed(raw)
                except Exception:
                    self.stop(self.consumer, 1)
            self.stop(self.relay, 5)
            if self.relay is not None:
                self.relay_metadata()
            if self.relaylog is not None:
                self.relaylog.close()
                self.relaylog = None
            if self.controller is not None and self.controller.poll() is None:
                self.controller.stdin.close()  # EOF triggers only idle-checked compensation.
                try:
                    while True:
                        value = self.line(5, cleanup=True)
                        if value.get('event') == 'PUBLIC-RECEIPTS':
                            self.save('aborted-receipt-export.json', value)
                            break
                except Exception:
                    pass
                self.stop(self.controller, 2, kill=False)  # Never KILL a privileged remote owner.
        except Exception:
            self.record['cleanup_refused'] = True
        finally:
            if self.generation is not None:
                try:
                    require(self.consumer is None or (self.consumer.poll() is not None and self.native_released))
                    self.generation.cleanup()
                except Exception:
                    self.record['generation_cleanup_refused'] = True
                finally:
                    self.generation.close()
            self.save('case-result.json', self.record)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--authorized-local-fixture', action='store_true')
    parser.add_argument('--engine-ready', action='store_true')
    parser.add_argument('--validate', action='store_true')
    args = parser.parse_args(argv)
    if not args.live:
        require(not args.authorized_local_fixture and not args.engine_ready)
        print('Nested harness source/validate only; no files/tools/fixture/runtime.')
        return 0
    require(args.authorized_local_fixture and args.engine_ready and not args.validate)
    # The consumed d801 build remains unusable even when public recovery succeeds.
    require(BUILD.name != 'host-d8015521-49ed-47b3-baeb-b9f4e7320a36')
    os.umask(0o077)
    owner = Case()
    try:
        owner.run()
        return 0
    except BaseException as error:
        owner.record.update(refused=True, failureStage=owner.stage,
                            failureClass=type(error).__name__ if type(error).__name__ in
                            {'ValueError', 'TimeoutExpired', 'OSError', 'FileNotFoundError', 'BrokenPipeError',
                             'JSONDecodeError', 'KeyError', 'KeyboardInterrupt'} else 'other')
        return 2
    finally:
        owner.close()


if __name__ == '__main__':
    sys.exit(main())
