#!/usr/bin/env python3
"""Fixed read-only remote guardian program; importing this module performs no I/O.

Only public token/nonces cross argv/PIPE. READY does not inspect or cache bridge liveness.
The source string is a build-receipt-bound public input, not caller-provided code.
"""
REMOTE_SOURCE = r'''
import json,os,re,select,stat,sys,time

LIFETIME_SECONDS=85.0
FRAME_LIMIT=1024

def decode(raw):
    if not isinstance(raw,bytes) or not 0<len(raw)<FRAME_LIMIT or not raw.endswith(b'\n') or raw.count(b'\n')!=1:
        raise ValueError('frame')
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('duplicate')
            result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=pairs)
    if not isinstance(value,dict):raise ValueError('object')
    return value

def birth(pid,api=os):
    statfd=api.open('/proc/'+str(pid)+'/stat',api.O_RDONLY|api.O_NOFOLLOW)
    try:raw=api.read(statfd,4097)
    finally:api.close(statfd)
    if len(raw)>4096:raise ValueError('proc-bound')
    text=raw.decode('utf-8');fields=text[text.rfind(')')+2:].split()
    statusfd=api.open('/proc/'+str(pid)+'/status',api.O_RDONLY|api.O_NOFOLLOW)
    try:status=api.read(statusfd,65537)
    finally:api.close(statusfd)
    if len(status)>65536:raise ValueError('uid-bound')
    uids=status.decode('ascii').split('Uid:',1)[1].splitlines()[0].split()
    if [int(value) for value in uids]!=[10000]*4 or fields[0]=='Z':raise ValueError('uid-or-zombie')
    return int(fields[19])

class Target:
    def __init__(self,token,api=os,poll_factory=select.poll):
        self.token=token;self.api=api;self.poll_factory=poll_factory
        self.pid=None;self.start=None;self.handle=None;self.poller=None
    def inspect(self):
        api=self.api
        if api.getuid()!=10000 or re.fullmatch('[0-9a-f]{32}',self.token) is None:raise ValueError('identity')
        directory=api.open('/tmp/openlxssh-relay-'+self.token,api.O_RDONLY|api.O_DIRECTORY|api.O_NOFOLLOW)
        try:
            d=api.fstat(directory)
            if not stat.S_ISDIR(d.st_mode) or d.st_uid!=10000 or stat.S_IMODE(d.st_mode)!=0o700:raise ValueError('directory')
            descriptor=api.open('owner.json',api.O_RDONLY|api.O_NOFOLLOW,dir_fd=directory)
            try:
                before=api.fstat(descriptor);raw=api.read(descriptor,1025);after=api.fstat(descriptor)
                fields=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid!=10000 or stat.S_IMODE(before.st_mode)!=0o600 or
                    before.st_nlink!=1 or len(raw)>1024 or fields(before)!=fields(after) or len(raw)!=before.st_size):raise ValueError('receipt')
            finally:api.close(descriptor)
        finally:api.close(directory)
        def pairs(items):
            result={}
            for key,value in items:
                if key in result:raise ValueError('duplicate')
                result[key]=value
            return result
        value=json.loads(raw,object_pairs_hook=pairs)
        if (not isinstance(value,dict) or set(value)!={'pid','uid','token'} or value['token']!=self.token or
            type(value['uid']) is not int or value['uid']!=10000 or type(value['pid']) is not int or value['pid']<=1):raise ValueError('receipt-identity')
        pid=value['pid']
        if self.pid is not None and pid!=self.pid:raise ValueError('target-changed')
        new=self.handle is None
        handle=api.pidfd_open(pid,0) if new else self.handle
        poller=self.poll_factory() if new else self.poller
        if new:poller.register(handle,select.POLLIN)
        try:
            if poller.poll(0):raise ValueError('target-gone')
            ticks=birth(pid,api)
            if self.start is not None and ticks!=self.start:raise ValueError('birth-changed')
            if poller.poll(0):raise ValueError('target-gone')
        except BaseException:
            if new:api.close(handle)
            raise
        self.pid=pid;self.start=ticks;self.handle=handle;self.poller=poller
        return {'pid':pid,'startTicks':ticks,'uid':10000,'token':self.token,'pidfdAlive':True}
    def gone(self):return self.poller is not None and bool(self.poller.poll(0))
    def close(self):
        if self.handle is not None:self.api.close(self.handle);self.handle=None

def run():
    if len(sys.argv)!=3:raise SystemExit(64)
    token,instance=sys.argv[1:]
    if os.getuid()!=10000 or any(re.fullmatch('[0-9a-f]{32}',x) is None for x in (token,instance)):raise SystemExit(64)
    for fd in (0,1):
        if not stat.S_ISFIFO(os.fstat(fd).st_mode):raise SystemExit(65)
        os.set_inheritable(fd,False)
    os.set_blocking(0,False)
    pid=os.getpid();ticks=birth(pid)
    target=Target(token);started=time.monotonic();sequence=0;last_nonce=None;seen_nonces=set();terminal=False
    def emit(op,nonce=None,**extra):
        value={'op':op,'token':token,'instance':instance,'sequence':sequence,'guardianPID':pid,'guardianStartTicks':ticks}
        if nonce is not None:value['nonce']=nonce
        value.update(extra);raw=(json.dumps(value,separators=(',',':'),sort_keys=True)+'\n').encode()
        if len(raw)>=FRAME_LIMIT:raise ValueError('output-bound')
        sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
    emit('ready') # Control ready ONLY; no owner receipt or target liveness was read.
    buffer=bytearray()
    try:
        while time.monotonic()-started<LIFETIME_SECONDS:
            if target.gone():
                target.close();emit('ended',last_nonce,reason='target-gone');terminal=True;return 0
            ready,_,_=select.select([0],[],[],0.05)
            if not ready:continue
            block=os.read(0,FRAME_LIMIT-len(buffer))
            if not block:
                target.close();emit('ended',last_nonce,reason='control-eof');terminal=True;return 0
            buffer.extend(block)
            if len(buffer)>=FRAME_LIMIT:raise ValueError('input-bound')
            if b'\n' not in buffer:continue
            request=decode(bytes(buffer));buffer.clear()
            if (set(request)!={'op','token','instance','sequence','nonce'} or request['token']!=token or request['instance']!=instance or
                type(request['sequence']) is not int or request['sequence']!=sequence+1 or
                not isinstance(request['nonce'],str) or re.fullmatch('[0-9a-f]{32}',request['nonce']) is None or
                request['nonce'] in seen_nonces):raise ValueError('request-binding')
            op=request['op'];nonce=request['nonce']
            if op not in ('arm','result','close') or (op=='arm' and sequence!=0) or (op=='result' and sequence!=1):raise ValueError('order')
            sequence+=1;last_nonce=nonce;seen_nonces.add(nonce)
            if op=='close':
                target.close();emit('closed',nonce,reason='requested');terminal=True;return 0
            # Every ARM/RESULT fresh nonce performs all original receipt/UID/pidfd/start checks.
            actual=target.inspect();emit('alive',nonce,actual=actual)
        target.close();emit('ended',last_nonce,reason='lifetime');terminal=True;return 1
    finally:
        target.close()

if __name__=='__main__':
    try:raise SystemExit(run())
    except Exception:raise SystemExit(1)
'''
