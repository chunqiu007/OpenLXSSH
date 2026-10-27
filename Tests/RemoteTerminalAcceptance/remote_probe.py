#!/usr/bin/env python3
"""Fixed non-secret remote PTY probe. Not installed or executed by offline builds."""
import base64
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

HOME = Path('/fixture/home')
SAMPLE = 'ASCII / 中文 / e\u0301'.encode('utf-8')
VIM_SAMPLE = 'VIM ASCII 中文 e\u0301\n'.encode('utf-8')
RESIZE = (31, 93)


class Refused(Exception):
    pass


class Deadline(Exception):
    pass


def nonce_ok(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{32}', value) is not None


def emit(nonce, event, *values):
    if not nonce_ok(nonce) or event not in ('hello', 'input-ready', 'input', 'interrupt-ready', 'interrupt', 'resize-ready', 'size', 'vim-ready', 'vim', 'done', 'failed'):
        raise Refused()
    text = ','.join(str(value) for value in values)
    if not re.fullmatch(r'[A-Za-z0-9,.-]*', text):
        raise Refused()
    sys.stdout.write('\r\nRT1|' + nonce + '|' + event + '|' + text + '|END\r\n')
    sys.stdout.flush()


def file_info(fd):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise Refused()
    return (info.st_dev, info.st_ino)


class OwnedDocument:
    def __init__(self, nonce, parent=HOME):
        if not nonce_ok(nonce):
            raise Refused()
        self.name = '.openlxssh-terminal-' + nonce
        self.parent = Path(parent)
        self.parent_fd = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.directory_fd = None
        self.files = {}
        self.directory_identity = None
        self.created = False
        try:
            info = os.fstat(self.parent_fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise Refused()
            os.mkdir(self.name, 0o700, dir_fd=self.parent_fd)  # Exclusive ownership; never adopt.
            self.created = True
            self.directory_fd = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent_fd)
            info = os.fstat(self.directory_fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise Refused()
            self.directory_identity = (info.st_dev, info.st_ino)
            for name in ('document.txt', 'vim-ready'):
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.directory_fd)
                self.files[name] = (fd, file_info(fd))
        except BaseException:
            self.close()
            raise

    @property
    def document_path(self):
        return str(self.parent / self.name / 'document.txt')

    def verify(self):
        if self.directory_fd is None or set(os.listdir(self.directory_fd)) != set(self.files):
            raise Refused()
        info = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != self.directory_identity:
            raise Refused()
        for name, (fd, identity) in self.files.items():
            if file_info(fd) != identity:
                raise Refused()
            info = os.stat(name, dir_fd=self.directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != identity:
                raise Refused()

    def contents(self):
        self.verify()
        fd = self.files['document.txt'][0]
        data = os.pread(fd, 4097, 0)
        if len(data) > 4096:
            raise Refused()
        return data

    def close(self):
        clean = True
        try:
            if self.directory_fd is not None:
                for name, (fd, identity) in self.files.items():
                    try:
                        info = os.stat(name, dir_fd=self.directory_fd, follow_symlinks=False)
                        if stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == identity and file_info(fd) == identity:
                            os.unlink(name, dir_fd=self.directory_fd)
                        else:
                            clean = False
                    except FileNotFoundError:
                        clean = False
                try:
                    info = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
                    if (info.st_dev, info.st_ino) != self.directory_identity or os.listdir(self.directory_fd):
                        clean = False
                    elif self.created:
                        os.rmdir(self.name, dir_fd=self.parent_fd)
                except FileNotFoundError:
                    clean = False
        finally:
            for fd, _identity in self.files.values():
                os.close(fd)
            self.files.clear()
            if self.directory_fd is not None:
                os.close(self.directory_fd)
                self.directory_fd = None
            if self.parent_fd is not None:
                os.close(self.parent_fd)
                self.parent_fd = None
        return clean


def reap(process):
    if process is not None:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
        process.wait(timeout=1)


def bounded_read(fd, count, seconds):
    end = time.monotonic() + seconds
    data = bytearray()
    while len(data) < count:
        left = end - time.monotonic()
        if left <= 0:
            raise Deadline()
        if select.select([fd], [], [], min(left, 0.1))[0]:
            part = os.read(fd, count - len(data))
            if not part:
                raise Refused()
            data.extend(part)
    return bytes(data)


def run(nonce):
    if not nonce_ok(nonce) or os.getuid() != 10000 or not os.isatty(0) or os.environ.get('SSH_TTY') is None:
        raise Refused()
    initial = termios.tcgetattr(0)
    prior = {}
    document = None
    child = None
    interrupted = False
    cleaned = False
    def abort(*_args):
        raise Deadline()
    def interrupt(*_args):
        nonlocal interrupted
        interrupted = True
    try:
        for number in (signal.SIGALRM, signal.SIGHUP, signal.SIGTERM):
            prior[number] = signal.signal(number, abort)
        prior[signal.SIGINT] = signal.signal(signal.SIGINT, interrupt)
        signal.alarm(110)
        emit(nonce, 'hello', 10000, os.getpid())  # ACK comes from this actual remote process, not shell echo.
        try:
            tty.setraw(0, termios.TCSANOW)
            emit(nonce, 'input-ready', len(SAMPLE))
            data = bounded_read(0, len(SAMPLE), 12)
            if data != SAMPLE:
                raise Refused()
            emit(nonce, 'input', len(data), hashlib.sha256(data).hexdigest())
        finally:
            termios.tcsetattr(0, termios.TCSANOW, initial)
        if interrupted:
            raise Refused()  # No pre-ready control character can satisfy the signal test.
        child = subprocess.Popen(['/usr/bin/sleep', '30'], stdin=None, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        emit(nonce, 'interrupt-ready')
        end = time.monotonic() + 12
        while child.poll() is None and time.monotonic() < end:
            time.sleep(0.02)
        if not interrupted or child.poll() != -signal.SIGINT:
            raise Refused()
        child.wait(timeout=1)
        child = None
        emit(nonce, 'interrupt', 1)
        emit(nonce, 'resize-ready')
        if bounded_read(0, 2, 12) != b'S\n':
            raise Refused()
        end = time.monotonic() + 5
        while time.monotonic() < end:
            rows, cols, _x, _y = struct.unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ, bytes(8)))
            if (rows, cols) == RESIZE:
                break
            time.sleep(0.02)
        if (rows, cols) != RESIZE:
            raise Refused()
        # Mature system stty is used as a second view of the actual remote PTY.
        size = subprocess.run(['/usr/bin/stty', 'size'], stdin=0, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2, check=True)
        if size.stdout.split() != [b'31', b'93']:
            raise Refused()
        emit(nonce, 'size', rows, cols)
        document = OwnedDocument(nonce)
        ready_fd = document.files['vim-ready'][0]
        ready_command = "call writefile(['READY'], '/proc/self/fd/" + str(ready_fd) + "')"
        child = subprocess.Popen(['/usr/bin/vim.tiny', '-Nu', 'NONE', '-U', 'NONE', '-i', 'NONE', '-n', '--noplugin',
                                  '-c', 'set nobackup nowritebackup noswapfile backupcopy=yes encoding=utf-8 fileencoding=utf-8',
                                  '-c', ready_command, '--', document.document_path], pass_fds=(ready_fd,))
        end = time.monotonic() + 12
        while time.monotonic() < end and child.poll() is None:
            document.verify()
            if os.pread(ready_fd, 16, 0) == b'READY\n':
                break
            time.sleep(0.02)
        if child.poll() is not None or os.pread(ready_fd, 16, 0) != b'READY\n':
            raise Refused()
        emit(nonce, 'vim-ready')  # Not based on arbitrary Vim screen/prompt matching.
        if child.wait(timeout=15) != 0:
            raise Refused()
        child = None
        data = document.contents()
        if data != VIM_SAMPLE:
            raise Refused()
        emit(nonce, 'vim', len(data), hashlib.sha256(data).hexdigest())
        termios.tcsetattr(0, termios.TCSANOW, initial)
        if termios.tcgetattr(0) != initial:
            raise Refused()
        cleaned = document.close()
        document = None
        if not cleaned:
            raise Refused()
    finally:
        try:
            reap(child)
        finally:
            try:
                if document is not None:
                    cleaned = document.close()
            finally:
                try:
                    termios.tcsetattr(0, termios.TCSANOW, initial)
                finally:
                    signal.alarm(0)
                    for number, handler in prior.items():
                        signal.signal(number, handler)
    emit(nonce, 'done', 1 if cleaned else 0)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    value = args[0] if len(args) == 1 else ''
    try:
        run(value)
    except BaseException:
        if nonce_ok(value):
            emit(value, 'failed', 1)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
