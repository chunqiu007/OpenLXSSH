#!/usr/bin/env python3
"""Fixed single-pane tmux probe. Imported only by pure tests; live requires a real outer PTY."""
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import struct
import subprocess
import sys
import termios
import time
import tty
import fcntl

SAMPLE = 'TMUX ASCII 中文 e\u0301'.encode('utf-8')
STAGES = ('preflight', 'start', 'input', 'resize', 'detach', 'cleanup')
KINDS = ('refused', 'deadline', 'os-error', 'process-exit', 'source-error')
ERRNOS = {errno.ENOENT: 'enoent', errno.EACCES: 'eacces', errno.EPERM: 'eperm', errno.EBADF: 'ebadf', errno.EIO: 'eio'}
EVENTS = ('hello', 'tmux-ready', 'input', 'resize-ready', 'size', 'detach-ready', 'detached', 'done', 'failed')

class Refused(Exception): pass
class Deadline(Exception): pass
class ProbeFailure(Exception):
    def __init__(self, fields): self.fields = fields

def valid_nonce(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{32}', value) is not None

def failure_fields(stage, error):
    kind, code = 'source-error', 'none'
    if isinstance(error, Refused): kind = 'refused'
    elif isinstance(error, (Deadline, subprocess.TimeoutExpired)): kind = 'deadline'
    elif isinstance(error, subprocess.CalledProcessError): kind = 'process-exit'
    elif isinstance(error, OSError): kind, code = 'os-error', ERRNOS.get(error.errno, 'other')
    return (stage if stage in STAGES else 'preflight', kind, code)

def emit(nonce, event, *fields):
    if not valid_nonce(nonce) or event not in EVENTS: raise Refused()
    text = ','.join(str(field) for field in fields)
    if not re.fullmatch('[A-Za-z0-9,.-]*', text): raise Refused()
    if event == 'failed':
        if len(fields) not in (3, 5) or fields[0] not in STAGES or fields[1] not in KINDS or fields[2] not in ('none', 'other', *ERRNOS.values()): raise Refused()
        if len(fields) == 5 and (fields[0] != 'resize' or any(type(value) is not int or not 1 <= value <= 65535 for value in fields[3:])): raise Refused()
    sys.stdout.write('\r\nRT1|' + nonce + '|' + event + '|' + text + '|END\r\n'); sys.stdout.flush()

def bounded_read(fd, count, seconds=12):
    end = time.monotonic() + seconds
    data = bytearray()
    while len(data) < count:
        left = end - time.monotonic()
        if left <= 0: raise Deadline()
        if select.select([fd], [], [], min(left, .1))[0]:
            part = os.read(fd, count - len(data))
            if not part: raise Refused()
            data.extend(part)
    return bytes(data)

def require_ack(expected):
    if bounded_read(0, len(expected), 12) != expected: raise Refused()

def same_file(fd):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1: raise Refused()
    return info.st_dev, info.st_ino

class OwnedRun:
    def __init__(self, nonce, parent=Path('/tmp')):
        if not valid_nonce(nonce): raise Refused()
        self.path = Path(parent) / ('openlxssh-tmux-' + nonce)
        self.parent = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.directory = None; self.identity = None; self.files = {}; self.socket_identity = None; self.socket_released = False
        try:
            os.mkdir(self.path.name, 0o700, dir_fd=self.parent)
            self.directory = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent)
            info = os.fstat(self.directory); self.identity = (info.st_dev, info.st_ino)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700: raise Refused()
            for name, payload in (('pane.py', PANE_SOURCE.encode()), ('pane-status', b'')):
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.directory)
                self.files[name] = (fd, same_file(fd))
                if payload and os.write(fd, payload) != len(payload): raise Refused()
                os.fsync(fd)
        except BaseException:
            self.close(); raise

    @property
    def socket_path(self): return str(self.path / 'server')

    def verify(self):
        info = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != self.identity or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700: raise Refused()
        if set(os.listdir(self.directory)) - {'pane.py', 'pane-status', 'server'}: raise Refused()
        for name, (fd, identity) in self.files.items():
            named = os.stat(name, dir_fd=self.directory, follow_symlinks=False)
            if not stat.S_ISREG(named.st_mode) or (named.st_dev, named.st_ino) != identity or same_file(fd) != identity: raise Refused()

    def confirm_socket(self):
        self.verify()
        info = os.stat('server', dir_fd=self.directory, follow_symlinks=False)
        # tmux may create an owner/group socket; the verified parent stays UID-owned 0700.
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) not in (0o600, 0o660): raise Refused()
        self.socket_identity = info.st_dev, info.st_ino

    def pane_failure(self):
        self.verify()
        fd = self.files['pane-status'][0]
        raw = os.pread(fd, 161, 0)
        if len(raw) > 160: raise Refused()
        if not raw: return None
        try: fields = raw.decode('ascii').strip().split(',')
        except UnicodeError: raise Refused() from None
        if len(fields) not in (3, 5) or fields[0] not in STAGES or fields[1] not in KINDS or fields[2] not in ('none', 'other', *ERRNOS.values()): raise Refused()
        if len(fields) == 5:
            if fields[0] != 'resize' or any(re.fullmatch('[0-9]{1,5}', value) is None or not 1 <= int(value) <= 65535 for value in fields[3:]): raise Refused()
            return (*fields[:3], int(fields[3]), int(fields[4]))
        return tuple(fields)

    def close(self):
        if self.parent is None: return True
        clean = True
        try:
            if self.directory is not None:
                for name, (fd, identity) in self.files.items():
                    try:
                        info = os.stat(name, dir_fd=self.directory, follow_symlinks=False)
                        if stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == identity and same_file(fd) == identity: os.unlink(name, dir_fd=self.directory)
                        else: clean = False
                    except FileNotFoundError: clean = False
                try:
                    info = os.stat('server', dir_fd=self.directory, follow_symlinks=False)
                    if self.socket_released and stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == self.socket_identity and info.st_uid == os.getuid(): os.unlink('server', dir_fd=self.directory)
                    else: clean = False
                except FileNotFoundError: pass
                named = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
                if not os.listdir(self.directory) and (named.st_dev, named.st_ino) == self.identity: os.rmdir(self.path.name, dir_fd=self.parent)
                else: clean = False
        finally:
            for fd, _ in self.files.values(): os.close(fd)
            self.files.clear()
            if self.directory is not None: os.close(self.directory); self.directory = None
            os.close(self.parent); self.parent = None
        return clean

# Fixed pane helper. No credential/prompt parsing or arbitrary file paths.
# tmux 3.4 input.c INPUT_CSI_ED: ED2 calls screen_write_clearscreen;
# ED3 calls screen_write_clearhistory. Explicit CUP homes after clearing.
# https://github.com/tmux/tmux/blob/3.4/input.c (single reviewed upstream source)
PANE_SOURCE = r'''
import fcntl,hashlib,os,select,signal,stat,struct,sys,termios,time,tty
nonce,status_path,status_dev,status_ino=sys.argv[1:]
status_identity=int(status_dev),int(status_ino)
status_fd=os.open(status_path,os.O_WRONLY|os.O_NOFOLLOW)
status_info=os.fstat(status_fd)
if not stat.S_ISREG(status_info.st_mode) or (status_info.st_dev,status_info.st_ino)!=status_identity or status_info.st_uid!=10000 or stat.S_IMODE(status_info.st_mode)!=0o600 or status_info.st_nlink!=1 or status_info.st_size!=0:
 os.close(status_fd);raise SystemExit(65)
def emit(event,*fields): print('\r\nRT1|'+nonce+'|'+event+'|'+','.join(str(v) for v in fields)+'|END\r\n',flush=True)
def read(count):
 end=time.monotonic()+12;data=bytearray()
 while len(data)<count:
  left=end-time.monotonic()
  if left<=0:raise RuntimeError()
  if select.select([0],[],[],min(left,.1))[0]:
   part=os.read(0,count-len(data))
   if not part:raise RuntimeError()
   data.extend(part)
 return bytes(data)
def prepare_resize():
 if read(1)!=b'C':raise RuntimeError()
 # Clear only the public, already-validated frames in this isolated pane.
 sys.stdout.write('\x1b[2J\x1b[3J\x1b[H');sys.stdout.flush()
 emit('resize-ready')
class ResizeDeadline(Exception):
 def __init__(self,rows,cols):self.rows=rows;self.cols=cols
def wait_size():
 wake_read,wake_write=os.pipe();previous=None
 def changed(*_):
  try:os.write(wake_write,b'W')
  except BlockingIOError:pass
 try:
  os.set_blocking(wake_read,False);os.set_blocking(wake_write,False)
  previous=signal.signal(signal.SIGWINCH,changed)
  end=time.monotonic()+12
  while True:
   rows,cols,_,_=struct.unpack('HHHH',fcntl.ioctl(0,termios.TIOCGWINSZ,bytes(8)))
   left=end-time.monotonic()
   if left<=0:raise ResizeDeadline(rows,cols)
   if (rows,cols)==(31,93):return rows,cols
   # Short selector timeouts also re-check ioctl if a platform coalesces WINCH.
   # Time alone never passes the gate; only an in-budget exact ioctl does.
   if select.select([wake_read],[],[],min(left,.1))[0]:
    try:os.read(wake_read,4096)
    except BlockingIOError:pass
 finally:
  try:
   if previous is not None:signal.signal(signal.SIGWINCH,previous)
  finally:os.close(wake_read);os.close(wake_write)
def record_failure(fields):
 info=os.fstat(status_fd)
 if not stat.S_ISREG(info.st_mode) or (info.st_dev,info.st_ino)!=status_identity or info.st_uid!=10000 or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size!=0:raise RuntimeError()
 payload=','.join(str(value) for value in fields).encode('ascii')
 if os.pwrite(status_fd,payload,0)!=len(payload):raise RuntimeError()
 os.fsync(status_fd)
sample='TMUX ASCII 中文 e\u0301'.encode()
initial=termios.tcgetattr(0);stage='start'
def abort(*_): raise RuntimeError()
signal.signal(signal.SIGALRM,abort);signal.alarm(85)
try:
 if os.getuid()!=10000 or not os.isatty(0):raise RuntimeError()
 tty.setraw(0,termios.TCSANOW)
 emit('tmux-ready',10000,os.getpid(),len(sample))
 stage='input'
 data=read(len(sample))
 if data!=sample:raise RuntimeError()
 emit('input',len(data),hashlib.sha256(data).hexdigest())
 stage='resize'
 prepare_resize()
 if read(1)!=b'R':raise RuntimeError()
 rows,cols=wait_size()
 emit('size',rows,cols)
 stage='detach'
 if read(1)!=b'D':raise RuntimeError()
 emit('detach-ready')
 # Keep pane alive until actual Ctrl-b d, then only the own server is killed.
 while True:signal.pause()
except BaseException as error:
 fields=(stage,'deadline' if isinstance(error,ResizeDeadline) else 'refused','none')
 if isinstance(error,ResizeDeadline) and error.rows>0 and error.cols>0:fields+=error.rows,error.cols
 record_failure(fields)
 emit('failed',*fields)
 raise SystemExit(1)
finally:
 signal.alarm(0)
 try:termios.tcsetattr(0,termios.TCSANOW,initial)
 finally:os.close(status_fd)
'''

def tmux(run, *args, check=True):
    run.verify()
    if run.socket_identity is not None:
        info = os.stat('server', dir_fd=run.directory, follow_symlinks=False)
        if not stat.S_ISSOCK(info.st_mode) or (info.st_dev, info.st_ino) != run.socket_identity: raise Refused()
    result = subprocess.run(['/usr/bin/tmux', '-S', run.socket_path, '-f', '/dev/null', *args], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3, check=check)
    if len(result.stdout) > 512: raise Refused()
    return result.stdout

def owned_pid(pid):
    if pid <= 1: raise Refused()
    handle = os.pidfd_open(pid, 0)
    try:
        uids = (Path('/proc') / str(pid) / 'status').read_text().split('Uid:', 1)[1].splitlines()[0].split()
        if uids != ['10000'] * 4: raise Refused()
    except BaseException:
        os.close(handle); raise
    return handle

def wait_gone(handle):
    poller = select.poll(); poller.register(handle, select.POLLIN)
    if not poller.poll(3000): raise Refused()

def reap_client(client):
    try:
        client.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        client.terminate()
    try:
        client.wait(timeout=2)
    except subprocess.TimeoutExpired:
        client.kill()
        client.wait(timeout=1)
    raise Refused()  # Forced termination was reaped, but is never a successful detach/cleanup.


def run(nonce):
    if not valid_nonce(nonce) or os.getuid() != 10000 or not os.isatty(0) or not os.environ.get('SSH_TTY'): raise Refused()
    initial = termios.tcgetattr(0); owned = client = None; handles = []; stage = 'preflight'; failure = None; cleaned = False; server = pane = None
    old = {}
    def abort(*_): raise Deadline()
    def preserve_pane_error():
        nonlocal failure
        if owned is not None:
            try:
                pane_error = owned.pane_failure()
                if pane_error is not None: failure = pane_error
            except BaseException:
                pass  # Invalid/replaced status never hides the original failure.
    try:
        for number in (signal.SIGALRM, signal.SIGTERM, signal.SIGHUP): old[number] = signal.signal(number, abort)
        signal.alarm(95)
        owned = OwnedRun(nonce)
        emit(nonce, 'hello', 10000, os.getpid())
        require_ack(b'T\n')  # Do not enter fullscreen before consumer has validated the remote ACK.
        stage = 'start'
        status_identity = owned.files['pane-status'][1]
        command = '/usr/bin/python3 ' + str(owned.path / 'pane.py') + ' ' + nonce + ' ' + str(owned.path / 'pane-status') + ' ' + ' '.join(str(value) for value in status_identity)
        # Socket path is nonce-exclusive; fixed alphabet paths/command, one session and exactly one pane.
        client = subprocess.Popen(['/usr/bin/tmux', '-S', owned.socket_path, '-f', '/dev/null', 'new-session', '-s', 'probe', command,
                                   ';', 'set-option', '-g', 'status', 'off'],
                                  env={'PATH': '/usr/bin:/bin', 'HOME': str(owned.path), 'TERM': os.environ.get('TERM', 'xterm-256color'),
                                       'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TMUX': ''})
        client.wait(timeout=70)  # Only App's actual Ctrl-b d detaches this foreground client.
        pane_error = owned.pane_failure()
        if pane_error is not None: raise ProbeFailure(pane_error)
        if client.returncode != 0: raise Refused()
        stage = 'detach'; owned.confirm_socket()
        fields = tmux(owned, 'display-message', '-p', '-t', 'probe:0.0', '#{pid},#{pane_pid},#{session_attached},#{window_panes}').decode('ascii').strip().split(',')
        if len(fields) != 4 or fields[2:] != ['0', '1'] or not all(v.isdigit() for v in fields[:2]): raise Refused()
        server, pane = map(int, fields[:2])
        clients = tmux(owned, 'list-clients', '-F', '#{client_pid}')
        if clients.strip(): raise Refused()
        handles.append(owned_pid(server)); handles.append(owned_pid(pane))
        stage = 'detach'
    except BaseException as error:
        failure = error.fields if isinstance(error, ProbeFailure) else failure_fields(stage, error)
        # The held, identity-checked status file survives tmux teardown/redraw and
        # preserves the first pane failure instead of a later no-session error.
        preserve_pane_error()
    finally:
        try:
            if owned is not None:
                if owned.socket_identity is None:
                    try: owned.confirm_socket()
                    except FileNotFoundError: pass
                if owned.socket_identity is not None:
                    if not handles:
                        ids = tmux(owned, 'display-message', '-p', '-t', 'probe:0.0', '#{pid},#{pane_pid}').decode('ascii').strip().split(',')
                        if len(ids) != 2 or not all(item.isdigit() for item in ids): raise Refused()
                        for item in ids: handles.append(owned_pid(int(item)))
                    tmux(owned, 'kill-server')
            if client is not None: reap_client(client)
            preserve_pane_error()
            for handle in handles: wait_gone(handle)
            if owned is not None and owned.socket_identity is not None: owned.socket_released = True
            termios.tcsetattr(0, termios.TCSANOW, initial)
            if termios.tcgetattr(0) != initial: raise Refused()
            if owned is not None:
                cleaned = owned.close(); owned = None
                if not cleaned: raise Refused()
        except BaseException as error:
            if failure is None: failure = failure_fields('cleanup', error)
        finally:
            preserve_pane_error()
            for handle in handles: os.close(handle)
            if owned is not None:
                try: owned.close()
                except BaseException: pass
            termios.tcsetattr(0, termios.TCSANOW, initial)
            signal.alarm(0)
            for number, handler in old.items(): signal.signal(number, handler)
    if failure is not None: raise ProbeFailure(failure) from None
    emit(nonce, 'detached', 1, server)  # After tmux exit/reset; stable outer-screen frames cannot race its teardown.
    emit(nonce, 'done', 1 if cleaned else 0)

def main(argv=None):
    args = sys.argv[1:] if argv is None else argv; nonce = args[0] if len(args) == 1 else ''
    try: run(nonce)
    except BaseException as error:
        if valid_nonce(nonce): emit(nonce, 'failed', *(error.fields if isinstance(error, ProbeFailure) else failure_fields('preflight', error)))
        return 1
    return 0

if __name__ == '__main__': sys.exit(main())
