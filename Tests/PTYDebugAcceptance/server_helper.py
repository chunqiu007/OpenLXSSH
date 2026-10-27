#!/usr/bin/env python3
"""One disposable container-local debug sshd; default/help inert. Raw logs stay in memory."""
import ctypes,json,os,re,selectors,signal,stat,subprocess,sys,time
from pathlib import Path
import client_helper as client
LIMIT=65536
ENV={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':'/nonexistent'}
READY=rb'^(?:debug[123]: )?Server listening on 127\.0\.0\.1 port 2223\.$'
RULES={'pty-owner-stat':rb'stat\(.*\) failed:', 'pty-owner-chown':rb'chown\(.*\) failed:', 'pty-owner-chmod':rb'chmod\(.*\) failed:',
 'monitor-fdpass':rb'mm_(?:send|receive|recv)_fd|send fds failed|receive fd failed', 'session-dup':rb'dup #[12]:|dup2(?: stdin| stdout| stderr)?[(: ]',
 'session-fork':rb'fork:|fork failed', 'login-accounting':rb'login_write|utmp|wtmp|lastlog', 'audit':rb'audit[_ (]|audit event',
 'pty-allocated':rb'session_pty_req: session [0-9]+ alloc /dev/', 'audit-fatal':rb'linux_audit_write_entry failed:', 'fatal':rb'(?i)fatal:', 'disconnected':rb'(?i)disconnected|connection (?:closed|reset)'}
ERRNOS={b'Operation not permitted':1,b'Permission denied':13,b'Read-only file system':30,b'Too many open files':24,b'Resource temporarily unavailable':11,b'No space left on device':28}

def classify(raw):
    return {'classes':sorted(name for name,pattern in RULES.items() if re.search(pattern,raw)),
            'errnos':sorted(value for text,value in ERRNOS.items() if text in raw),
            'permissionDeniedOrReadonly':any(text in raw for text in (b'Operation not permitted',b'Permission denied',b'Read-only file system'))}

def configuration(raw,folder):
    expected={'Port':'2222','ListenAddress':'0.0.0.0','PidFile':'/run/openlxssh-fixture/sshd.pid','LogLevel':'ERROR'}
    changed={'Port':'2223','ListenAddress':'127.0.0.1','PidFile':folder+'/sshd.pid','LogLevel':'DEBUG3'}
    seen=set();output=[]
    for line in raw.splitlines(keepends=True):
        parts=line.strip().split(None,1)
        if parts and parts[0] in expected:
            key=parts[0]
            if key in seen or len(parts)!=2 or parts[1]!=expected[key]:raise ValueError('originalConfig')
            seen.add(key);line=key+' '+changed[key]+'\n'
        output.append(line)
    if seen!=set(expected):raise ValueError('missingOriginalDirective')
    return ''.join(output)

class Workspace:
    def __init__(self,token,raw):
        if not re.fullmatch(r'[0-9a-f]{32}',token):raise ValueError('token')
        self.path='/tmp/openlxssh-server-pty-'+token;os.mkdir(self.path,0o700)
        self.directory=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        self.fd=None;self.identity=os.fstat(self.directory);self.server_pid=None
        try:
            self.fd=os.open('sshd_config',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.directory)
            data=configuration(raw,self.path).encode();offset=0
            while offset<len(data):
                written=os.write(self.fd,data[offset:])
                if written<=0:raise OSError('configWrite')
                offset+=written
        except BaseException:self.close();raise
    def close(self):
        try:
            if self.fd is not None:
                held=os.fstat(self.fd)
                try:now=os.stat('sshd_config',dir_fd=self.directory,follow_symlinks=False)
                except FileNotFoundError:now=None
                if now and (held.st_dev,held.st_ino)==(now.st_dev,now.st_ino):os.unlink('sshd_config',dir_fd=self.directory)
                os.close(self.fd);self.fd=None
            # -ddd does not normally write a pidfile. Only an exact own-PID
            # regular file may be captured and removed; never original pidfile.
            try:pidfd=os.open('sshd.pid',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.directory)
            except FileNotFoundError:pidfd=None
            if pidfd is not None:
                try:
                    info=os.fstat(pidfd);value=os.read(pidfd,32)
                    if stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and value.strip()==str(self.server_pid).encode():
                        now=os.stat('sshd.pid',dir_fd=self.directory,follow_symlinks=False)
                        if (now.st_dev,now.st_ino)==(info.st_dev,info.st_ino):os.unlink('sshd.pid',dir_fd=self.directory)
                finally:os.close(pidfd)
            now=os.lstat(self.path)
            if (now.st_dev,now.st_ino)==(self.identity.st_dev,self.identity.st_ino) and not os.listdir(self.directory):os.rmdir(self.path)
        finally:os.close(self.directory)

class OwnedTree:
    """Only this fresh standalone supervisor's new children and their descendants."""
    def __init__(self):
        self.roots={};self.owned={};self.libc=ctypes.CDLL(None,use_errno=True)
        previous=ctypes.c_int()
        if self.libc.prctl(37,ctypes.byref(previous),0,0,0)!=0 or self.children(os.getpid()):raise ValueError('subreaperPrecondition')
        self.previous=previous.value
        if self.libc.prctl(36,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),'subreaper')
    def children(self,pid):
        try:return [int(value) for value in Path('/proc/'+str(pid)+'/task/'+str(pid)+'/children').read_text().split()]
        except FileNotFoundError:return []
    def metadata(self,pid):
        text=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()
        uid=Path('/proc/'+str(pid)+'/status').read_text().split('Uid:',1)[1].splitlines()[0].split()[0]
        return int(text[1]),int(text[19]),int(uid)
    def capture(self,pid,parent):
        if pid in self.owned:return
        handle=os.pidfd_open(pid,0)
        try:
            first=self.metadata(pid)
            if first[0]!=parent or self.metadata(pid)!=first:raise ValueError('childIdentity')
            self.owned[pid]=(handle,first[1],first[2])
        except BaseException:os.close(handle);raise
    def add(self,process):
        self.roots[process.pid]=process
        self.capture(process.pid,os.getpid())
    def discover(self):
        for parent in [os.getpid()]+list(self.owned):
            for pid in self.children(parent):
                try:self.capture(pid,parent)
                except (ProcessLookupError,FileNotFoundError):pass
    def send(self,pid,sig):
        handle,start,uid=self.owned[pid]
        try:
            now=self.metadata(pid)
            if now[1:]!=(start,uid):raise ValueError('PIDChanged')
            signal.pidfd_send_signal(handle,sig)
        except (FileNotFoundError,ProcessLookupError):pass
    def close(self):
        end=time.monotonic()+5;clean=True
        def discover():
            nonlocal clean
            try:self.discover()
            except Exception:clean=False # still release every previously owned child
        try:
            for sig in (signal.SIGTERM,signal.SIGKILL):
                discover()
                for pid in reversed(list(self.owned)):
                    try:self.send(pid,sig)
                    except Exception:clean=False
                for pid,process in self.roots.items():
                    if process.poll() is None and pid not in self.owned:
                        try:process.send_signal(sig) # exact unreaped Popen fallback
                        except ProcessLookupError:pass
                until=min(end,time.monotonic()+(0.25 if sig==signal.SIGTERM else 3.5))
                while time.monotonic()<until:
                    discover()
                    for pid in list(self.owned):
                        if pid in self.roots:self.roots[pid].poll()
                        else:
                            try:os.waitpid(pid,os.WNOHANG)
                            except ChildProcessError:pass
                    if not self.children(os.getpid()):break
                    time.sleep(.01)
            clean=clean and not self.children(os.getpid())
            for process in self.roots.values():
                try:process.wait(timeout=max(.001,end-time.monotonic()))
                except subprocess.TimeoutExpired:clean=False
            return clean
        finally:
            try:
                for process in self.roots.values():
                    try:process.stdout.close()
                    finally:process.stderr.close()
            finally:
                try:
                    for handle,_,_ in self.owned.values():os.close(handle)
                finally:self.libc.prctl(36,self.previous,0,0,0)

def capture(tree,server,client_args,deadline):
    data=[bytearray(),bytearray(),bytearray(),bytearray()];peer=None;failure=None
    with selectors.DefaultSelector() as selector:
        def register(process,index):
            for offset,stream in enumerate((process.stdout,process.stderr)):
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,index+offset)
        register(server,0)
        while selector.get_map():
            tree.discover()
            if time.monotonic()>=deadline:failure='execution-deadline';break
            for key,_ in selector.select(min(.05,max(0,deadline-time.monotonic()))):
                part=os.read(key.fd,min(4096,LIMIT+1-sum(map(len,data))))
                if not part:selector.unregister(key.fileobj);continue
                data[key.data].extend(part)
                if sum(map(len,data))>LIMIT:failure='combined-output-limit';break
            if failure:break
            if peer is None and any(re.fullmatch(READY,line) for line in bytes(data[1]).splitlines()):
                peer=subprocess.Popen(client_args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,env=ENV);tree.add(peer);register(peer,2)
    return peer,data,failure

def execute(token):
    client.gate();start=time.monotonic();tree=OwnedTree();workspace=None;server=None;peer=None;clean=False
    try:
        fd=os.open(client.BASE+'/sshd_config',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd)
            if info.st_uid!=0 or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>16384:raise ValueError('configMetadata')
            raw=os.read(fd,16385).decode()
        finally:os.close(fd)
        workspace=Workspace(token,raw)
        server=subprocess.Popen(['/usr/sbin/sshd','-D','-ddd','-e','-f',workspace.path+'/sshd_config'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,env=ENV);workspace.server_pid=server.pid;tree.add(server)
        args=client.argv(token);args[args.index('-p')+1]='2223'
        peer,data,failure=capture(tree,server,args,start+20)
    finally:
        try:clean=tree.close()
        finally:
            if workspace is not None:workspace.close()
    expected=('OPENLXSSH_INTERNAL_'+token+'\n').encode();out=bytes(data[2])
    value={'schema':1,'token':token,'serverExit':server.returncode,'clientExit':peer.returncode if peer else None,'seconds':time.monotonic()-start,'boundedFailure':failure,'ready':peer is not None,'ackLF':out==expected,'ackCRLF':out==expected.replace(b'\n',b'\r\n'),'capturedBytes':sum(map(len,data)),'server':classify(bytes(data[0]+data[1])),'client':classify(bytes(data[3])),'ownedProcessesReaped':clean,'workspaceAbsent':not Path(workspace.path).exists(),'rawLogged':False,'stagesAreUnordered':True}
    print(json.dumps(value,sort_keys=True));return 0 if clean else 2

def main(args=None):
    args=sys.argv[1:] if args is None else args
    if args in ([],['--help']):print('Container-local single debug diagnostic; default/help inert; primary must authorize --authorized-server-case <32hex>.');return 0
    if len(args)!=2 or args[0]!='--authorized-server-case' or not re.fullmatch(r'[0-9a-f]{32}',args[1]):raise ValueError('arguments')
    return execute(args[1])

if __name__=='__main__':
    try:sys.exit(main())
    except Exception:os.write(2,b'Single server PTY diagnostic refused; no raw logs.\n');sys.exit(2)
