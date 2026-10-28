#!/usr/bin/env python3
"""Private pipe-controlled, keyonly-only finite test relay. Default/import is inert. No SSH decoding."""
from __future__ import annotations
import argparse
from dataclasses import dataclass, field
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import queue
import selectors
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid

from core import Flow, LIMIT, Refused, binding, encoded, exact_json, lsof_connection, DROP_SAFETY_SECONDS

HERE = Path(__file__).absolute().parent
FROZEN = HERE / 'frozen-inputs.json'


def load_bridge():
    record = json.loads(FROZEN.read_bytes())
    for name, expected in record['frozenRelaySHA256'].items():
        path = Path(name)
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected: raise Refused('frozen-relay-changed')
    # Only immutable copied modules, never the mutable fixture helper or a patched old pump.
    folder = record['frozenRelayDirectory']
    sys.path.insert(0, folder)
    spec = importlib.util.spec_from_file_location('keepalive_frozen_bridge', Path(folder) / 'relay.py')
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    return module


def tcp_state(connection, source):
    args = ['/usr/sbin/lsof', '-nP', '-a', '-p', str(os.getpid()), '-d', str(connection.fileno()), '-iTCP', '-F', 'pufnPT']
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=2)
    if result.returncode != 0: raise Refused('own-tcp-metadata')
    row = lsof_connection(result.stdout, os.getpid(), fd=connection.fileno(), server=True)
    if row['sourcePort'] != source or row['uid'] != os.getuid(): raise Refused('own-tcp-binding')
    return {'at': time.monotonic(), 'state': row['state'], 'sourcePort': source, 'fd': row['fd']}


def remote_bridge_alive(backend, token):
    # Read only this bridge's exact owner receipt and /proc identity; no cmdline/environment/payload.
    reader = """import json,os,pathlib,re,select,stat,sys
n=sys.argv[1]
if os.getuid()!=10000 or re.fullmatch('[0-9a-f]{32}',n) is None:raise SystemExit(64)
d=os.open('/tmp/openlxssh-relay-'+n,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
f=os.open('owner.json',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=d)
s=os.fstat(f)
if s.st_uid!=10000 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1:raise SystemExit(65)
v=json.loads(os.read(f,1025));os.close(f);os.close(d)
if set(v)!={'pid','uid','token'} or v['token']!=n or v['uid']!=10000:raise SystemExit(65)
p=v['pid'];h=os.pidfd_open(p,0);q=select.poll();q.register(h,select.POLLIN)
if q.poll(0):raise SystemExit(66)
x=pathlib.Path('/proc')/str(p);a=(x/'stat').read_text();z=a[a.rfind(')')+2:].split();u=(x/'status').read_text().split('Uid:',1)[1].splitlines()[0].split()
if [int(i) for i in u]!=[10000]*4 or z[0]=='Z' or q.poll(0):raise SystemExit(66)
print(json.dumps({'pid':p,'startTicks':int(z[19]),'uid':10000,'token':n,'pidfdAlive':True}));os.close(h)
"""
    result=backend.metadata(['exec','--user','10000:10000',backend.target.container_id,'/usr/bin/python3','-c',reader,token],
        time.monotonic()+5,threading.Event())
    if result.get('token')!=token or result.get('pidfdAlive') is not True:raise Refused('remote-bridge-not-alive')
    return result


def drain_pending_arm(flow, sources, read=os.read, clock=time.monotonic):
    for direction, source in enumerate(sources):
        room = LIMIT-len(flow.queues[direction])
        if room:
            try: data=read(source,room)
            except (BlockingIOError,InterruptedError): data=None
            if data is not None: flow.receive(direction,data,clock())


def forward_step(flow, directions, ready, read=os.read, write=os.write, now=time.monotonic):
    """One selector batch. DROP never calls write, even for stale WRITE readiness."""
    for fd, events in ready:
        for index, (source, sink) in enumerate(directions):
            if fd == source and events & selectors.EVENT_READ:
                if flow.eof_times[index] is not None: continue
                room = LIMIT if flow.mode == 'drop' else LIMIT - len(flow.queues[index])
                if room:
                    try: data = read(fd, min(LIMIT, room))
                    except (BlockingIOError, InterruptedError): continue
                    flow.receive(index, data, now())
            if fd == sink and events & selectors.EVENT_WRITE and flow.mode == 'forward' and flow.queues[index]:
                try: size = write(fd, flow.queues[index])
                except (BlockingIOError, InterruptedError): continue
                if size <= 0: raise Refused('write-zero')
                flow.wrote(index, size)


@dataclass
class Connection:
    token: str
    source_port: int
    socket: object
    commands: object = field(default_factory=queue.Queue)
    flow: object = field(default_factory=Flow)
    backend: object = None
    process: object = None
    ready: bool = False
    ended: bool = False
    finished: bool = False
    snapshots: list = field(default_factory=list)
    reason: str | None = None
    cleanup_failed: bool = False
    snapshot_count: int = 0
    pump_implementation: str = 'bounded-local'
    cancel_before_result: bool = False
    deadline_before_result: bool = False
    established_at_arm: bool = False
    bridge_alive_at_arm: bool = False
    armed_wall: float | None = None
    remote_bridge_at_arm: dict | None = None
    remote_bridge_at_result: dict | None = None

    def metadata(self):
        counters = self.flow.metadata()
        if self.pump_implementation == 'frozen-normal':
            for name in ('readBytes','forwardedBytes','droppedBytes','discardedAtArm','bufferPeaks','EOFAtByDirection','halfClosedByDirection'):
                counters[name] = None # Frozen pump exposes no wire counters; never fabricate zeros.
        return {'token': self.token, 'sourcePort': self.source_port, 'bridgePID': self.process.pid if self.process else None,
                'pumpImplementation': self.pump_implementation,
                'bridgeAlive': self.process is not None and self.process.poll() is None, 'ready': self.ready,
                'ended': self.ended, 'finished': self.finished, 'reason': self.reason, 'cleanupFailed': self.cleanup_failed,
                'tcpSnapshots': self.snapshots[-8:], 'tcpSnapshotCount': self.snapshot_count,
                'armedWall': self.armed_wall, 'remoteBridgeAtArm':self.remote_bridge_at_arm,'remoteBridgeAtResult':self.remote_bridge_at_result,
                'establishedAtArm': self.established_at_arm, 'bridgeAliveAtArm': self.bridge_alive_at_arm,
                'cancelBeforeResult': self.cancel_before_result, 'deadlineBeforeResult': self.deadline_before_result,
                **counters}


def arm_ack(item):
    # Both times are sampled in the relay worker, the SAME origin as Flow.armed_at.
    return {'ok': True, **item.metadata(), 'relayNow':time.monotonic(), 'relayWall':time.time()}


def drop_pump(item, cancelled, deadline):
    process, connection, flow = item.process, item.socket, item.flow
    directions = [(connection.fileno(), process.stdin.fileno()), (process.stdout.fileno(), connection.fileno())]
    for fd in {number for pair in directions for number in pair}: os.set_blocking(fd, False)
    last_snapshot = 0.0
    with selectors.DefaultSelector() as selector:
        registered = set()
        while True:
            now = time.monotonic()
            if cancelled.is_set() or now >= deadline:
                item.cancel_before_result = flow.client_result_at is None and cancelled.is_set()
                item.deadline_before_result = flow.client_result_at is None and now >= deadline
                flow.refused = flow.refused or 'relay-cancel-or-deadline'; return
            # A backend/process failure before client natural result is not a keepalive pass.
            if flow.bound is not None and flow.client_result_at is None and flow.first_eof != 'client' and process.poll() is not None:
                flow.refused = 'bridge-exited-first'; return
            try: request, reply = item.commands.get_nowait()
            except queue.Empty: request = reply = None
            if request is not None:
                try:
                    if request['op'] == 'arm':
                        # Drain a bounded single read from each already-readable endpoint at the arm boundary.
                        # Any pending EOF prevents arming; no writes occur in this step.
                        item.remote_bridge_at_arm=remote_bridge_alive(item.backend,item.token)
                        drain_pending_arm(flow,(connection.fileno(),process.stdout.fileno()))
                        snap = tcp_state(connection, item.source_port)
                        if flow.first_eof is not None or process.poll() is not None: raise Refused('arm-peer-ended')
                        flow.arm(request['binding'], time.monotonic, tcp_established=snap['state'] == 'ESTABLISHED',
                                 bridge_alive=process.poll() is None, safe_remaining=deadline - time.monotonic())
                        item.armed_wall = time.time()
                        # No more FORWARD writes can occur once Flow.arm has returned.
                        item.snapshots.append(snap); item.snapshot_count += 1
                        item.snapshots.append(tcp_state(connection, item.source_port)); item.snapshot_count += 1
                        item.established_at_arm = True; item.bridge_alive_at_arm = True
                        reply.put(arm_ack(item))
                    elif request['op'] == 'result':
                        flow.result(now)
                        item.remote_bridge_at_result=remote_bridge_alive(item.backend,item.token)
                        if item.remote_bridge_at_result!=item.remote_bridge_at_arm:raise Refused('remote-bridge-identity-changed')
                        # Clear any outstanding client EOF / final in-flight encrypted bytes BEFORE the result snapshot.
                        try: final_data = os.read(connection.fileno(), LIMIT)
                        except (BlockingIOError, InterruptedError): final_data = None
                        if final_data is not None: flow.receive(0, final_data, time.monotonic())
                        reply.put({'ok': True, **item.metadata()})
                    elif request['op'] == 'finish':
                        if flow.client_result_at is None: raise Refused('finish-before-result')
                        reply.put({'ok': True, **item.metadata()}); return
                    else: raise Refused('worker-op')
                except Exception:
                    reply.put({'ok': False, 'failure': 'worker-control-refused'})
                    flow.refused = flow.refused or 'worker-control-refused'; return
            if flow.mode == 'drop' and flow.first_eof != 'client' and now - last_snapshot >= .5:
                try:
                    item.snapshots.append(tcp_state(connection, item.source_port)); item.snapshot_count += 1
                    item.snapshots = item.snapshots[-8:]; last_snapshot = now
                except Exception:
                    # Read any already-arrived client EOF before treating metadata disappearance as proxy failure.
                    try: data = os.read(connection.fileno(), LIMIT)
                    except (BlockingIOError, InterruptedError): data = None
                    if data is not None: flow.receive(0, data, time.monotonic())
                    if data != b'':
                        flow.refused = 'tcp-state-query-failed-without-client-eof'; return
            desired = {}
            for index, (source, sink) in enumerate(directions):
                side = 'client' if index == 0 else 'backend'
                if flow.eof_times[index] is None and (flow.mode == 'drop' or len(flow.queues[index]) < LIMIT): desired[source] = desired.get(source, 0) | selectors.EVENT_READ
                if flow.mode == 'forward' and flow.queues[index]: desired[sink] = desired.get(sink, 0) | selectors.EVENT_WRITE
            for fd in registered - desired.keys(): selector.unregister(fd)
            for fd, events in desired.items():
                if fd in registered: selector.modify(fd, events)
                else: selector.register(fd, events)
            registered = set(desired)
            ready = [(key.fd, events) for key, events in selector.select(.025)]
            try:
                forward_step(flow, directions, ready)
                flow.drain_eof((lambda: process.stdin.close(), lambda: connection.shutdown(socket.SHUT_WR)))
            except OSError: flow.refused = 'io-before-result'; return
            if flow.refused: return
            if flow.mode == 'forward' and all(flow.half_closed): return
            if flow.bound is not None and flow.first_eof is not None and flow.mode == 'forward':
                flow.refused = 'bound-forward-ended-before-arm'; return
            # In DROP, client EOF is evidence only. Keep pipes/socket owned until supervisor confirms its actual SSH result.


class Relay:
    def __init__(self, role, run, parent):
        self.role, self.run, self.parent = role, run, parent
        self.bridge = load_bridge()
        self.target = self.bridge.FrozenDockerTarget('desktop-linux', 'unix:///Users/liuwenshuo/.docker/run/docker.sock',
            '1253a29501483eb71f80e39b9af5c85e10c3a49329d5e93700fecd3f00f334f2',
            'sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363',
            'openlxssh-fixture-61ed25328c13', 'keyonly', 'env-fixture-a',
            'b949645e158058f7484e21b758459f8d0e6a284f0d2bb641879faf67f2b50ed1', 22221)
        self.backend = self.bridge.DockerTarget(self.target)
        self.cancelled = threading.Event(); self.lock = threading.Lock(); self.items = {}; self.workers = []
        self.deadline = time.monotonic() + 240

    def worker(self, item):
        try:
            item.backend=self.backend
            startup = min(self.deadline, time.monotonic() + 20)
            self.backend.validate(startup, self.cancelled)
            item.process = self.backend.spawn(item.token)
            if not self.bridge.wait_ready(item.process, self.cancelled, startup): raise Refused('bridge-not-ready')
            item.ready = True
            if self.role == 'normal':
                item.pump_implementation = 'frozen-normal'
                def close_input():
                    item.flow.eof('client', time.monotonic()); item.process.stdin.close()
                def half_close_client():
                    item.flow.eof('backend', time.monotonic()); item.socket.shutdown(socket.SHUT_WR)
                item.reason = self.bridge.pump(item.socket.fileno(), item.socket.fileno(), item.process.stdout.fileno(), item.process.stdin.fileno(),
                    close_input, half_close_client, self.cancelled, deadline=self.deadline)
                if item.reason != 'complete':
                    item.cancel_before_result = item.flow.client_result_at is None and item.reason == 'cancelled'
                    item.deadline_before_result = item.flow.client_result_at is None and item.reason in ('duration-timeout','idle-timeout')
                    item.flow.refused = 'normal-proxy-aborted'
            else:
                drop_pump(item, self.cancelled, self.deadline)
                item.reason = item.flow.refused or ('client-result' if item.flow.client_result_at is not None else 'unbound-scan-ended')
        except Exception:
            item.reason = 'worker-refused'; item.flow.refused = item.flow.refused or 'worker-refused'
        finally:
            item.ended = True
            if item.process is not None:
                try:
                    try: natural = item.process.wait(timeout=.1) == 0
                    except subprocess.TimeoutExpired: natural = False
                    if not natural: self.backend.cleanup(item.token)
                except Exception: item.cleanup_failed = True
                finally:
                    try: self.bridge.reap_owned(item.process)
                    except Exception: item.cleanup_failed = True
            item.socket.close(); item.finished = True

    def dispatch(self, request):
        if request.get('run') != self.run or request.get('role') != self.role: raise Refused('control-campaign')
        op = request.get('op')
        if op == 'lookup' and set(request) == {'op','run','role','sourcePort'}:
            candidates = [item for item in self.items.values() if item.source_port == request['sourcePort'] and item.ready and not item.ended]
            if len(candidates) != 1: raise Refused('connection-not-unique')
            return {'ok': True, 'token': candidates[0].token, 'sourcePort': candidates[0].source_port}
        if op == 'stop' and set(request) == {'op','run','role'}:
            if any(item.flow.bound and item.flow.client_result_at is None for item in self.items.values()): raise Refused('stop-before-result')
            self.cancelled.set(); return {'ok': True}
        if set(request) != {'op','run','role','binding'} or op not in ('bind','arm','inspect','result','finish'):
            raise Refused('control-schema')
        value = binding(request['binding'])
        if value['run'] != self.run or value['role'] != self.role: raise Refused('binding-campaign')
        item = self.items.get(value['token'])
        if item is None or item.source_port != value['sourcePort']: raise Refused('binding-peer')
        if op == 'bind':
            if item.flow.bound is not None or item.ended: raise Refused('binding-replay')
            snap = tcp_state(item.socket, item.source_port)
            if item.process.poll() is not None: raise Refused('binding-bridge-ended')
            item.flow.bound = value; item.snapshots.append(snap); item.snapshot_count += 1
            return {'ok': True, **item.metadata()}
        if item.flow.bound != value: raise Refused('binding-changed')
        if op == 'inspect': return {'ok': True, **item.metadata()}
        if self.role == 'normal':
            if op == 'arm': raise Refused('normal-cannot-drop')
            if op == 'result': item.flow.result(time.monotonic()); return {'ok': True, **item.metadata()}
            if op == 'finish':
                if item.flow.client_result_at is None: raise Refused('finish-before-result')
                deadline = time.monotonic() + 10
                while not item.finished and time.monotonic() < deadline: time.sleep(.02)
                if not item.finished: raise Refused('normal-cleanup-not-finished')
                return {'ok': True, **item.metadata()}
        if item.ended: raise Refused('worker-ended-before-command')
        reply = queue.Queue(maxsize=1); item.commands.put((request, reply))
        return reply.get(timeout=9)

    def serve(self):
        if os.getppid() != self.parent: raise Refused('management-parent')
        for fd in (0, 1):
            if not stat.S_ISFIFO(os.fstat(fd).st_mode): raise Refused('private-management-pipes-required')
            os.set_inheritable(fd, False)
        if os.fstat(0).st_uid!=os.getuid() or os.fstat(1).st_uid!=os.getuid():raise Refused('management-pipe-owner')
        # Verify the declared owner is this process's actual current parent and same UID without reading argv.
        meta=subprocess.run(['/bin/ps','-p',str(self.parent),'-o','pid=,uid='],stdin=subprocess.DEVNULL,capture_output=True,timeout=2)
        fields=meta.stdout.decode().split()
        if meta.returncode or fields!=[str(self.parent),str(os.getuid())]:raise Refused('management-parent-uid')
        self.backend.validate(min(self.deadline,time.monotonic()+40),self.cancelled)
        listener = self.bridge._listen_loopback(22221); os.set_blocking(0,False)
        buf = bytearray()
        try:
            os.write(1,encoded({'event':'ready','run':self.run,'role':self.role,'pid':os.getpid(),'port':22221}))
            with selectors.DefaultSelector() as selector:
                selector.register(listener,selectors.EVENT_READ); selector.register(0,selectors.EVENT_READ)
                while not self.cancelled.is_set() and time.monotonic()<self.deadline:
                    for key,_ in selector.select(.05):
                        if key.fileobj is listener:
                            client,peer=listener.accept()
                            if peer[0]!='127.0.0.1' or sum(not x.finished for x in self.items.values())>=8 or len(self.items)>=16:
                                client.close(); raise Refused('admission')
                            item=Connection(uuid.uuid4().hex,peer[1],client);self.items[item.token]=item
                            worker=threading.Thread(target=self.worker,args=(item,),daemon=False);worker.start();self.workers.append(worker)
                        else:
                            data=os.read(0,2048)
                            if not data: raise Refused('management-eof')
                            buf.extend(data)
                            if len(buf)>=2048: raise Refused('management-bounds')
                            if b'\n' in buf:
                                if buf.count(10)!=1 or not buf.endswith(b'\n'): raise Refused('one-management-frame')
                                try: answer=self.dispatch(exact_json(bytes(buf)))
                                except Exception: answer={'ok':False,'failure':'closed-management-refusal'}
                                buf.clear();os.write(1,encoded(answer))
        finally:
            self.cancelled.set();listener.close()
            for worker in self.workers:worker.join(timeout=30)
            if any(worker.is_alive() for worker in self.workers) or any(x.cleanup_failed for x in self.items.values()):raise Refused('owned-cleanup-incomplete')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live-test-only',action='store_true');parser.add_argument('--role',choices=('normal','blackhole'))
    parser.add_argument('--run');parser.add_argument('--owner-pid',type=int)
    args=parser.parse_args(argv)
    if not args.live_test_only: return 64
    if args.role is None or args.run is None or len(args.run)!=32 or args.owner_pid!=os.getppid(): return 64
    try:
        relay = Relay(args.role,args.run,args.owner_pid)
        prior = {number:signal.signal(number,lambda *_:relay.cancelled.set()) for number in (signal.SIGINT,signal.SIGTERM)}
        try: relay.serve();return 0
        finally:
            for number,handler in prior.items():signal.signal(number,handler)
    except Exception:return 1


if __name__=='__main__':sys.exit(main())
