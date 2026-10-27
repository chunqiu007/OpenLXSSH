#!/usr/bin/env python3
"""Fixed Linux container client diagnostic; import/help inert, no server/config changes."""
import hashlib,json,os,re,selectors,signal,stat,subprocess,sys,time
from pathlib import Path
BASE='/run/openlxssh-fixture'
LIMIT=65536
STAGES={'sent-pty':rb'^debug[123]: (?:channel [0-9]+: request pty-req confirm 1|Requesting pseudo-terminal.*)$',
 'pty-accepted':rb'^debug[123]: PTY allocation request accepted on channel [0-9]+$',
 'pty-rejected':rb'^PTY allocation request failed on channel [0-9]+$',
 'exec-sent':rb'^debug[123]: Sending command:.*$',
 'exec-accepted':rb'^debug[123]: exec request accepted on channel [0-9]+$',
 'exec-rejected':rb'^exec request failed on channel [0-9]+$',
 'channel-close':rb'^debug[123]: channel [0-9]+: (?:rcvd|send) close.*$',
 'keepalive-failed':rb'^Timeout, server .* not responding\.$',
 'exit-status':rb'^debug[123]: Exit status [0-9]+$'}

def argv(token):
    if not re.fullmatch(r'[0-9a-f]{32}',token):raise ValueError('token')
    args=['/usr/bin/ssh','-F','/dev/null','-vv','-tt','-p','2222','-l','fixture','-i',BASE+'/client/id_ed25519']
    options=['BatchMode=yes','StrictHostKeyChecking=yes','UserKnownHostsFile='+BASE+'/host_known_hosts','HostKeyAlias=[127.0.0.1]:22221','GlobalKnownHostsFile=/dev/null','HostKeyAlgorithms=ssh-ed25519','KnownHostsCommand=none','UpdateHostKeys=no','IdentityAgent=none','IdentitiesOnly=yes','PreferredAuthentications=publickey','PasswordAuthentication=no','KbdInteractiveAuthentication=no','GSSAPIAuthentication=no','HostbasedAuthentication=no','CertificateFile=none','PKCS11Provider=none','AddKeysToAgent=no','ForwardAgent=no','ForwardX11=no','ClearAllForwardings=yes','Tunnel=no','ProxyCommand=none','ProxyJump=none','ControlMaster=no','ControlPath=none','ControlPersist=no','PermitLocalCommand=no','LocalCommand=none','RemoteCommand=none','EscapeChar=none','ConnectTimeout=5','ConnectionAttempts=1','ServerAliveInterval=5','ServerAliveCountMax=1']
    for item in options:args+=['-o',item]
    return args+['--','127.0.0.1',"printf 'OPENLXSSH_INTERNAL_"+token+"\\n'"]

def gate():
    if sys.platform!='linux' or os.getuid()!=0:raise ValueError('containerUID0')
    for name in ('client/id_ed25519','host_known_hosts'):
        fd=os.open(BASE+'/'+name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('fileMetadata')
        finally:os.close(fd)

def run_owned(args,deadline):
    process=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':'/nonexistent'})
    handle=None;data=[bytearray(),bytearray()];failure=None
    try:
        handle=os.pidfd_open(process.pid,0)
        with selectors.DefaultSelector() as selector:
            for index,stream in enumerate((process.stdout,process.stderr)):
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,index)
            while selector.get_map():
                if time.monotonic()>=deadline:failure='execution-deadline';break
                for key,_ in selector.select(min(.1,max(0,deadline-time.monotonic()))):
                    part=os.read(key.fd,min(4096,LIMIT+1-sum(map(len,data))))
                    if not part:selector.unregister(key.fileobj);continue
                    data[key.data].extend(part)
                    if sum(map(len,data))>LIMIT:failure='combined-output-limit';break
                if failure:break
        try:process.wait(timeout=max(.001,deadline-time.monotonic()))
        except subprocess.TimeoutExpired:failure=failure or 'execution-deadline'
    finally:
        try:
            if process.poll() is None:
                def send(sig):
                    try:
                        if handle is None:process.send_signal(sig)
                        else:signal.pidfd_send_signal(handle,sig)
                    except ProcessLookupError:pass
                send(signal.SIGTERM)
                try:process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    send(signal.SIGKILL);process.wait(timeout=3)
        finally:
            try:
                if handle is not None:os.close(handle)
            finally:
                try:process.stdout.close()
                finally:process.stderr.close()
    return process.returncode,bytes(data[0]),bytes(data[1]),failure

def execute(token):
    gate();start=time.monotonic();signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('total25s')));signal.setitimer(signal.ITIMER_REAL,25)
    try:code,out,err,failure=run_owned(argv(token),start+20)
    finally:signal.setitimer(signal.ITIMER_REAL,0)
    expected=('OPENLXSSH_INTERNAL_'+token+'\n').encode()
    stages=[name for name,pattern in STAGES.items() if any(re.fullmatch(pattern,line) for line in err.splitlines())]
    value={'schema':1,'token':token,'exit':code,'signal':-code if code<0 else None,'seconds':time.monotonic()-start,'boundedFailure':failure,'stdoutBytes':len(out),'stdoutSHA256':hashlib.sha256(out).hexdigest(),'stderrBytes':len(err),'stderrSHA256':hashlib.sha256(err).hexdigest(),'ackLF':out==expected,'ackCRLF':out==expected.replace(b'\n',b'\r\n'),'stages':stages,'unclassifiedLines':sum(not any(re.fullmatch(p,line) for p in STAGES.values()) for line in err.splitlines()),'rawLogged':False,'childReaped':True,'pipesClosed':True}
    print(json.dumps(value,sort_keys=True));return 0

def main(args=None):
    args=sys.argv[1:] if args is None else args
    if args in ([],['--help']):print('Container-only fixed direct PTY client; default/help inert. Runtime requires primary authorization plus --authorized-container-case <32hex>.');return 0
    if len(args)!=2 or args[0]!='--authorized-container-case' or not re.fullmatch(r'[0-9a-f]{32}',args[1]):raise ValueError('arguments')
    return execute(args[1])

if __name__=='__main__':
    try:sys.exit(main())
    except Exception:os.write(2,b'Fixed PTY client diagnostic refused; no raw output.\n');sys.exit(2)
