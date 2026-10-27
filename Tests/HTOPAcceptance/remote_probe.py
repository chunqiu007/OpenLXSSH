#!/usr/bin/env python3
"""Fixed htop own-child probe. No live activity on import; no screen capture or kill UI."""
import errno
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
import fcntl

STAGES = ('preflight', 'launch', 'readiness', 'resize', 'exit', 'cleanup')
KINDS = ('refused', 'deadline', 'os-error', 'source-error')
CODES = {errno.ENOENT: 'enoent', errno.EACCES: 'eacces', errno.EPERM: 'eperm', errno.EIO: 'eio'}
class Refused(Exception): pass
class Deadline(Exception): pass

def nonce_ok(value): return type(value) is str and re.fullmatch('[0-9a-f]{32}', value) is not None

def classification(stage, error):
    return {'stage': stage if stage in STAGES else 'preflight', 'kind': 'deadline' if isinstance(error, (Deadline, subprocess.TimeoutExpired)) else 'os-error' if isinstance(error, OSError) else 'refused' if isinstance(error, Refused) else 'source-error', 'errno': CODES.get(error.errno, 'other') if isinstance(error, OSError) else 'none'}

def emit(nonce, event, *values):
    if not nonce_ok(nonce) or event not in ('hello', 'exited', 'done', 'failed'): raise Refused()
    text = ','.join(str(value) for value in values)
    if not re.fullmatch('[a-z0-9,.-]*', text): raise Refused()
    if event == 'failed' and (len(values) != 3 or values[0] not in STAGES or values[1] not in KINDS or values[2] not in ('none', 'other', *CODES.values())): raise Refused()
    sys.stdout.write('\r\nRT1|' + nonce + '|' + event + '|' + text + '|END\r\n'); sys.stdout.flush()

def exact_start():
    end = time.monotonic() + 12; data = bytearray()
    while len(data) < 2:
        left = end - time.monotonic()
        if left <= 0: raise Deadline()
        if select.select([0], [], [], left)[0]:
            part = os.read(0, 2 - len(data))
            if not part: raise Refused()
            data.extend(part)
    if data != b'H\n': raise Refused()

def file_id(fd):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1: raise Refused()
    return info.st_dev, info.st_ino

class OwnedRun:
    def __init__(self, nonce, parent=Path('/tmp')):
        if not nonce_ok(nonce): raise Refused()
        self.path = Path(parent) / ('openlxssh-htop-' + nonce)
        self.parent = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.directory = self.status = None; self.identity = self.status_identity = None
        try:
            os.mkdir(self.path.name, 0o700, dir_fd=self.parent)
            self.directory = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent)
            info = os.fstat(self.directory); self.identity = info.st_dev, info.st_ino
            self.status = os.open('status.json', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.directory)
            self.status_identity = file_id(self.status); self.verify()
        except BaseException:
            self.close(); raise

    def verify(self):
        info = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != self.identity or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700: raise Refused()
        if set(os.listdir(self.directory)) - {'status.json', 'htoprc'}: raise Refused()
        info = os.stat('status.json', dir_fd=self.directory, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != self.status_identity or file_id(self.status) != self.status_identity: raise Refused()

    def publish(self, value):
        self.verify(); payload = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')
        if len(payload) > 2048: raise Refused()
        # Reader takes the matching shared lock; no partial JSON or adopted pathname.
        fcntl.flock(self.status, fcntl.LOCK_EX)
        try:
            if os.pwrite(self.status, payload, 0) != len(payload): raise Refused()
            os.ftruncate(self.status, len(payload)); os.fsync(self.status)
        finally: fcntl.flock(self.status, fcntl.LOCK_UN)

    def config_present(self):
        try: info = os.stat('htoprc', dir_fd=self.directory, follow_symlinks=False)
        except FileNotFoundError: return False
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1: raise Refused()
        return True

    def close(self):
        if self.parent is None: return True
        clean = True
        try:
            if self.directory is not None:
                # Only fixed documented HTOPRC and our held status file; never recursive removal.
                if self.config_present():
                    fd = os.open('htoprc', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.directory)
                    try:
                        identity = file_id(fd); info = os.stat('htoprc', dir_fd=self.directory, follow_symlinks=False)
                        if (info.st_dev, info.st_ino) != identity: raise Refused()
                        os.unlink('htoprc', dir_fd=self.directory)
                    finally: os.close(fd)
                if self.status is not None:
                    info = os.stat('status.json', dir_fd=self.directory, follow_symlinks=False)
                    if (info.st_dev, info.st_ino) == self.status_identity and file_id(self.status) == self.status_identity: os.unlink('status.json', dir_fd=self.directory)
                    else: clean = False
                info = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
                if os.listdir(self.directory) or (info.st_dev, info.st_ino) != self.identity: clean = False
                else: os.rmdir(self.path.name, dir_fd=self.parent)
        finally:
            if self.status is not None: os.close(self.status); self.status = None
            if self.directory is not None: os.close(self.directory); self.directory = None
            os.close(self.parent); self.parent = None
        return clean

def process_identity(pid):
    path = Path('/proc') / str(pid)
    fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
    if (path / 'status').read_text().split('Uid:', 1)[1].splitlines()[0].split() != ['10000'] * 4: raise Refused()
    return {'pid': pid, 'startTicks': int(fields[19])}, fields

def ready_identity(process, parent_sid, tty_number, tty_name, child_pid):
    if process.poll() is not None: raise Refused()
    identity, fields = process_identity(process.pid)
    if int(fields[1]) != os.getpid() or int(fields[3]) != parent_sid or int(fields[4]) != tty_number: raise Refused()
    path = Path('/proc') / str(process.pid)
    if (path / 'comm').read_text().strip() != 'htop' or os.readlink(path / 'fd/0') != tty_name: return None
    with (path / 'cmdline').open('rb') as stream: args = stream.read(257).split(b'\0')
    if args != [b'/usr/bin/htop', ('--pid=' + str(child_pid)).encode('ascii'), b'']: return None
    mode = termios.tcgetattr(0)
    if mode[3] & (termios.ICANON | termios.ECHO) or os.tcgetpgrp(0) != int(fields[2]): return None
    return identity

def reap(process):
    if process is None: return
    if process.poll() is None:
        process.terminate()
        try: process.wait(timeout=2)
        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=1)
    else: process.wait(timeout=1)

def reap_owned(processes):
    first = None
    for process in processes:
        try: reap(process)
        except BaseException as error:
            if first is None: first = error
    if first is not None: raise first


def gone(handle):
    poller = select.poll(); poller.register(handle, select.POLLIN)
    if not poller.poll(3000): raise Refused()

def run(nonce):
    if not nonce_ok(nonce) or os.getuid() != 10000 or not os.isatty(0) or not os.environ.get('SSH_TTY'): raise Refused()
    original = termios.tcgetattr(0); owned = child = htop = None; handles = []; failure = None; stage = 'preflight'; old = {}; value = None
    def abort(*_): raise Deadline()
    try:
        for number in (signal.SIGALRM, signal.SIGTERM, signal.SIGHUP): old[number] = signal.signal(number, abort)
        signal.alarm(120); os.umask(0o077)
        owned = OwnedRun(nonce); parent, parent_stat = process_identity(os.getpid())
        value = dict(schema=1, stage='initialized', parent=parent, htop=None, child=None, rows=None, cols=None, failure=None, configPresent=False)
        owned.publish(value); emit(nonce, 'hello', 10000, os.getpid(), parent['startTicks'], *owned.identity, *owned.status_identity); exact_start()
        stage = 'launch'
        child = subprocess.Popen(['/usr/bin/sleep', '110'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        handles.append(os.pidfd_open(child.pid, 0)); child_identity, _ = process_identity(child.pid)
        htop = subprocess.Popen(['/usr/bin/htop', '--pid=' + str(child.pid)], env={'PATH': '/usr/bin:/bin', 'HOME': str(owned.path),
            'XDG_CONFIG_HOME': str(owned.path), 'HTOPRC': str(owned.path / 'htoprc'), 'TERM': os.environ.get('TERM', 'xterm-256color'), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'})
        handles.append(os.pidfd_open(htop.pid, 0)); stage = 'readiness'; end = time.monotonic() + 12
        while True:
            identity = ready_identity(htop, int(parent_stat[3]), int(parent_stat[4]), os.ttyname(0), child.pid)
            if time.monotonic() >= end: raise Deadline()
            if identity is not None: break
            select.select([], [], [], .02)  # Poll only; readiness requires observed process and actual terminal mode.
        value.update(stage='ready', htop=identity, child=child_identity); owned.publish(value)
        stage = 'resize'; end = time.monotonic() + 12
        while True:
            if child.poll() is not None or ready_identity(htop, int(parent_stat[3]), int(parent_stat[4]), os.ttyname(0), child.pid) != identity: raise Refused()
            rows, cols, _, _ = struct.unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ, bytes(8)))
            if time.monotonic() >= end: raise Deadline()
            if (rows, cols) == (31, 93): break
            select.select([], [], [], .02)
        value.update(stage='sized', rows=rows, cols=cols); owned.publish(value)
        stage = 'exit'
        if htop.wait(timeout=15) != 0: raise Refused()  # Only App's q can satisfy normal exit.
        gone(handles[1]); stage = 'cleanup'; reap(child); gone(handles[0])
        termios.tcsetattr(0, termios.TCSANOW, original)
        if termios.tcgetattr(0) != original: raise Refused()
        owned.config_present()  # Validate only its fixed path/type; never inspect configuration contents.
        if not owned.close(): raise Refused()
        owned = None
    except BaseException as error:
        failure = classification(stage, error)
        if owned is not None and value is not None:
            try: value.update(stage='failed', failure=failure); owned.publish(value)
            except BaseException: pass
            # Keep the typed failure receipt boundedly readable while the App observes it;
            # never count this wait as successful cleanup or leave a live TUI running.
            reap_owned((htop, child))
            until = time.monotonic() + 6
            while True:
                left = until - time.monotonic()
                if left <= 0: break
                select.select([], [], [], min(.1, left))
    finally:
        try:
            reap_owned((htop, child))
            for handle in handles: gone(handle)
        except BaseException as error:
            if failure is None: failure = classification('cleanup', error)
        finally:
            for handle in handles: os.close(handle)
            if owned is not None:
                try:
                    if not owned.close() and failure is None: failure = classification('cleanup', Refused())
                except BaseException as error:
                    if failure is None: failure = classification('cleanup', error)
            termios.tcsetattr(0, termios.TCSANOW, original); signal.alarm(0)
            for number, handler in old.items(): signal.signal(number, handler)
    if failure is not None:
        emit(nonce, 'failed', failure['stage'], failure['kind'], failure['errno']); return 1
    emit(nonce, 'exited', 0); emit(nonce, 'done', 1); return 0

def main(argv=None):
    args = sys.argv[1:] if argv is None else argv; nonce = args[0] if len(args) == 1 else ''
    try: return run(nonce)
    except BaseException as error:
        if nonce_ok(nonce):
            value = classification('preflight', error); emit(nonce, 'failed', value['stage'], value['kind'], value['errno'])
        return 1

if __name__ == '__main__': sys.exit(main())
