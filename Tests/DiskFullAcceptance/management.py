#!/usr/bin/env python3
"""Private pipe owner for ONE fixed ENOSPC case; defaults/help/validate do no I/O."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid

CID = '2db5bbb3cb75a3253d9b02af5ca52cbdc8095230464f82c18d37eca9ac1fc837'
IMAGE = 'sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363'
PROJECT = 'openlxssh-fixture-61ed25328c13'
ENDPOINT = 'unix:///Users/liuwenshuo/.docker/run/docker.sock'
DOCKER = '/Applications/Docker.app/Contents/Resources/bin/docker'
OWN = '/Users/liuwenshuo/Desktop/OpenLXSSH/Tests/DiskFullAcceptance'
MAX_LINES = 8


def syntax(path):
    prefix, suffix = OWN+'/.runtime/enospc-', '/case.json'
    if not isinstance(path, str) or not path.startswith(prefix) or not path.endswith(suffix):
        raise ValueError('casePath')
    value = path[len(prefix):-len(suffix)]
    if str(uuid.UUID(value)) != value:
        raise ValueError('caseID')
    return value


def read_private(path, limit):
    path = Path(path)
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = following
        parent = os.fstat(directory)
        if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise ValueError('privateParent')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > limit):
                raise ValueError('privateInput')
            data = os.read(fd, limit+1)
            # Reading can legitimately advance atime. Compare stable identity
            # and nanosecond mutation fields explicitly; stat_result's tuple
            # includes atime but loses the separate *_ns precision.
            stable = lambda info: (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if len(data)>limit or stable(os.fstat(fd))!=stable(before):
                raise ValueError('changedInput')
            return data
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def line(fd, deadline, maximum):
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(min(.1, max(0, deadline-time.monotonic()))):
                continue
            part = os.read(fd, 1)
            if not part:
                raise EOFError('pipeEOF')
            data.extend(part)
            if len(data)>maximum:
                raise ValueError('pipeLimit')
            if part==b'\n':
                return bytes(data)
    raise TimeoutError('pipeDeadline')


def emit(raw):
    if len(raw)>4096 or not raw.endswith(b'\n'):
        raise ValueError('eventLimit')
    view=memoryview(raw)
    while view:
        count=os.write(1,view)
        if count<=0: raise OSError('outputPipe')
        view=view[count:]


def live(path):
    case_id=syntax(path)
    contract=json.loads(read_private(path,8192))
    if (contract.get('id')!=case_id or contract.get('container')!=CID or contract.get('image')!=IMAGE
            or contract.get('project')!=PROJECT or contract.get('schema')!=1):
        raise ValueError('caseBinding')
    claim=Path(path).with_name('management.claim')
    fd=os.open(claim,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    os.close(fd)
    # Fixed source snapshot, not operator-supplied Python/path/command.
    helper=Path(__file__).with_name('management_helper.py')
    info=helper.lstat()
    if (helper.resolve()!=helper or not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid()
            or info.st_nlink!=1 or info.st_mode&0o022):
        raise ValueError('helperSource')
    code=helper.read_text()
    os.environ['PATH']='/Applications/Docker.app/Contents/Resources/bin:/usr/bin:/bin:/usr/sbin:/sbin'
    environment={key:value for key,value in os.environ.items()
                 if not key.startswith(('DOCKER_','BUILDX_','BUILDKIT_','COMPOSE_'))}
    # Under the built driver __file__ is the read-only input snapshot; use its
    # sibling reviewed root helpers, never whichever live source later changed.
    root=Path(__file__).absolute().parent.parent/'IntegrationEnvironment'
    sys.path.insert(0,str(root))
    import relay
    frozen=relay.FrozenDockerTarget('desktop-linux',ENDPOINT,CID,IMAGE,PROJECT,'keyonly','env-fixture-a',
        'b949645e158058f7484e21b758459f8d0e6a284f0d2bb641879faf67f2b50ed1',22221)
    target=relay.DockerTarget(frozen)
    target.validate(time.monotonic()+8, __import__('threading').Event())
    inspected=json.loads(relay._bounded_stdout([DOCKER,'--host',ENDPOINT,'inspect',CID],environment,
        time.monotonic()+8,__import__('threading').Event()))[0]
    if (inspected['HostConfig']['IpcMode']!='private' or inspected['HostConfig']['ShmSize']!=67108864
            or inspected['HostConfig']['Memory']!=402653184):
        raise ValueError('privateShm')
    process=subprocess.Popen([DOCKER,'--host',ENDPOINT,'exec','-i','--user','10000:10000',CID,
        '/usr/bin/python3','-u','-c',code,'--container-owned-case',case_id],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=environment,bufsize=0)
    deadline=time.monotonic()+120
    actions=set()
    try:
        flags = os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC
        # Record the fixed helper snapshot hash as non-secret provenance.
        record_path=Path(path).with_name('helper-source-sha256.txt')
        record=os.open(record_path,flags,0o600)
        try: os.write(record,(hashlib.sha256(code.encode()).hexdigest()+'\n').encode())
        finally: os.close(record)
        ready=line(process.stdout.fileno(),min(deadline,time.monotonic()+12),4096)
        value=json.loads(ready)
        if value.get('caseID')!=case_id or value.get('event')!='ready': raise ValueError('notReady')
        emit(ready)
        for _ in range(MAX_LINES):
            raw=line(0,deadline,1024)
            command=json.loads(raw)
            if (set(command)!={'caseID','action'} or command['caseID']!=case_id
                    or command['action'] not in ('fill','sample','release','stop')):
                raise ValueError('command')
            if command['action'] in actions:
                raise ValueError('actionOnceOnly')
            actions.add(command['action'])
            process.stdin.write(raw)
            process.stdin.flush()
            answer=line(process.stdout.fileno(),min(deadline,time.monotonic()+15),4096)
            result=json.loads(answer)
            if result.get('caseID')!=case_id: raise ValueError('eventBinding')
            emit(answer)
            if command['action']=='stop':
                process.stdin.close()
                if process.wait(timeout=5)!=0: raise ValueError('helperExit')
                return
        raise ValueError('commandBudget')
    finally:
        # EOF causes the pre-held helper to release; no new exec/relay needed.
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Do NOT kill the Docker CLI and pretend the exec was reaped. The
            # fixed container helper independently releases by absolute TTL.
            try: process.wait(timeout=max(1,deadline-time.monotonic()+3))
            except subprocess.TimeoutExpired:
                process.terminate()
                try: process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill();process.wait(timeout=1)
        process.stdout.close()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',nargs='?',default='help',choices=('help','validate','live'))
    parser.add_argument('--case')
    parser.add_argument('--primary-reviewed',action='store_true')
    args=parser.parse_args(argv)
    if args.action=='help': parser.print_help();return 0
    if not args.case: parser.error('exact case required')
    syntax(args.case)
    if args.action=='validate': return 0
    if not args.primary_reviewed: parser.error('primary live release required')
    def interrupted(*_args):
        raise InterruptedError('ownedManagementCancelled')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    os.umask(0o077)
    live(args.case)
    return 0


if __name__=='__main__':
    try: sys.exit(main())
    except Exception:
        os.write(2,b'ENOSPC management refused/stopped; no private details.\n')
        raise SystemExit(2)
