#!/usr/bin/env python3
"""Fixed container-only held-FD helper. No defaults, shell, secrets or path option."""
import errno
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import sys
import time
import uuid

TOTAL = 64 * 1024 * 1024
FILL = 60 * 1024 * 1024 - 4096  # reserve one block for errno probe; total <=60MiB
CHUNK = 65536
TTL = 120
MAX_COMMANDS = 8
COMMAND_LIMIT = 1024


def canonical_id(value):
    if str(uuid.UUID(value)) != value:
        raise ValueError('caseID')
    return value


class Owner:
    def __init__(self, case_id):
        canonical_id(case_id)
        self.case_id = case_id
        self.deadline = time.monotonic() + TTL
        self.parent = self.directory = self.filler = None
        self.directory_identity = self.filler_identity = None
        self.filled = 0
        self.phase = 'initial'
        self.sampled = False
        self.directory_removed = False

    def check(self):
        if time.monotonic() >= self.deadline:
            raise TimeoutError('helperTTL')

    def fs(self):
        self.check()
        value = os.fstatvfs(self.parent)
        return {'totalBytes': value.f_blocks * value.f_frsize,
                'availableBytes': value.f_bavail * value.f_frsize,
                'blockBytes': value.f_frsize}

    def prepare(self):
        self.check()
        if sys.platform != 'linux' or os.getuid() != 10000 or os.getgid() != 10000:
            raise ValueError('UID10000ContainerOnly')
        self.parent = os.open('/dev/shm', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(self.parent)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o1777 or os.listdir(self.parent):
            raise ValueError('shmMustBeEmpty')
        mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()
                  if line.split()[4] == '/dev/shm']
        if len(mounts) != 1 or mounts[0][mounts[0].index('-') + 1] != 'tmpfs':
            raise ValueError('notExistingTmpfs')
        fs = self.fs()
        if fs['totalBytes'] != TOTAL or fs['availableBytes'] != TOTAL or fs['blockBytes'] != 4096:
            raise ValueError('wrongCapacity')
        maximum = int(Path('/sys/fs/cgroup/memory.max').read_text())
        current = int(Path('/sys/fs/cgroup/memory.current').read_text())
        if maximum != 384 * 1024 * 1024 or current + TOTAL + 96 * 1024 * 1024 > maximum:
            raise ValueError('insufficientMemoryHeadroom')
        self.memory_before = current
        self.memory_events_before = Path('/sys/fs/cgroup/memory.events').read_text().strip()
        name = 'openlxssh-enospc-' + self.case_id
        os.mkdir(name, 0o700, dir_fd=self.parent)
        self.directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent)
        info = os.fstat(self.directory)
        if info.st_uid != 10000 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('directoryOwnership')
        self.directory_identity = (info.st_dev, info.st_ino)
        self.filler = os.open('filler.bin', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                              0o600, dir_fd=self.directory)
        info = os.fstat(self.filler)
        self.filler_identity = (info.st_dev, info.st_ino)
        self.phase = 'ready'
        return self.event('ready', memoryBefore=current, memoryEventsBefore=self.memory_events_before,
                          directoryDevice=info.st_dev, directoryInode=os.fstat(self.directory).st_ino)

    def event(self, name, **extra):
        return dict(schema=1, caseID=self.case_id, event=name, uid=os.getuid(),
                    filledBytes=self.filled, **self.fs(), **extra)

    def fill(self):
        self.check()
        if self.phase != 'ready':
            raise ValueError('fillOnceOnly')
        # Consumer must already have made+hashed its target. Only the exact
        # allowed two names may exist; no adoption or cleanup of other files.
        if set(os.listdir(self.directory)) != {'filler.bin', 'target.bin'}:
            raise ValueError('targetNotReady')
        info = os.stat('target.bin', dir_fd=self.directory, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 10000 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 65536):
            raise ValueError('targetIdentity')
        block = b'OpenLXSSH-public-ENOSPC-test-data\n'
        block = (block * (CHUNK // len(block) + 1))[:CHUNK]
        while self.filled < FILL:
            self.check()
            written = os.write(self.filler, block[:min(CHUNK, FILL - self.filled)])
            if written <= 0:
                raise OSError('fillShortWrite')
            self.filled += written
        info = os.fstat(self.filler)
        if info.st_size != FILL or info.st_blocks * 512 < FILL:
            raise ValueError('fillerMustBeRealAllocatedBytes')
        self.phase = 'filled'
        return self.event('filled', fillerAllocatedBytes=info.st_blocks * 512)

    def sample(self):
        self.check()
        if self.phase != 'filled' or self.sampled:
            raise ValueError('sampleOnceAfterFill')
        self.sampled = True
        before = self.fs()
        result_errno = None
        try:
            # A real append on this helper's owned FD, at most one block. It is
            # diagnostic only; consumer's real SFTP error is never fabricated.
            written = os.write(self.filler, b'x' * before['blockBytes'])
            self.filled += written
        except OSError as error:
            result_errno = error.errno
        after = self.fs()
        return self.event('sampled', errno=result_errno, beforeAvailableBytes=before['availableBytes'],
                          afterAvailableBytes=after['availableBytes'],
                          realENOSPC=result_errno == errno.ENOSPC and before['availableBytes'] == 0 and after['availableBytes'] == 0)

    def release(self):
        # Always free pages FIRST, including after TTL/EOF/errors. unlink alone
        # would retain allocation while the held filler descriptor is open.
        if self.filler is not None:
            os.ftruncate(self.filler, 0)
            self.filled = 0
        self.phase = 'released'
        value = os.fstatvfs(self.parent) if self.parent is not None else None
        try:
            events = Path('/sys/fs/cgroup/memory.events').read_text().strip()
            current = int(Path('/sys/fs/cgroup/memory.current').read_text())
        except OSError:
            events, current = None, None
        return {'schema': 1, 'caseID': self.case_id, 'event': 'released', 'uid': os.getuid(),
                'filledBytes': 0, 'availableBytes': value.f_bavail * value.f_frsize if value else 0,
                'memoryEventsAfter': events, 'memoryAfter': current}

    def close(self):
        try:
            self.release()
        finally:
            if self.filler is not None:
                try:
                    info = os.stat('filler.bin', dir_fd=self.directory, follow_symlinks=False)
                    if (stat.S_ISREG(info.st_mode) and info.st_uid == 10000
                            and (info.st_dev, info.st_ino) == self.filler_identity):
                        os.unlink('filler.bin', dir_fd=self.directory)
                except FileNotFoundError:
                    pass
                finally:
                    os.close(self.filler)
                    self.filler = None
            if self.directory is not None:
                try:
                    name = 'openlxssh-enospc-' + self.case_id
                    info = os.stat(name, dir_fd=self.parent, follow_symlinks=False)
                    if (stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == self.directory_identity
                            and not os.listdir(self.directory)):
                        os.rmdir(name, dir_fd=self.parent)
                        self.directory_removed = True
                except FileNotFoundError:
                    pass
                finally:
                    os.close(self.directory)
                    self.directory = None
            if self.parent is not None:
                os.close(self.parent)
                self.parent = None


def emit(value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if len(raw) > 4096:
        raise ValueError('metadataLimit')
    view = memoryview(raw)
    while view:
        count = os.write(1, view)
        if count <= 0:
            raise OSError('metadataPipe')
        view = view[count:]


def serve(case_id):
    owner = Owner(case_id)
    actions = set()
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(InterruptedError()))
    signal.signal(signal.SIGINT, lambda *_: (_ for _ in ()).throw(InterruptedError()))
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
    signal.setitimer(signal.ITIMER_REAL, TTL)
    try:
        emit(owner.prepare())
        for _ in range(MAX_COMMANDS):
            owner.check()
            # Unbuffered bounded input. No arbitrary operation or path selection.
            with selectors.DefaultSelector() as selector:
                selector.register(0, selectors.EVENT_READ)
                if not selector.select(max(0, owner.deadline - time.monotonic())):
                    raise TimeoutError('helperTTL')
                data = bytearray()
                while not data.endswith(b'\n'):
                    part = os.read(0, 1)
                    if not part:
                        return
                    data.extend(part)
                    if len(data) > COMMAND_LIMIT:
                        raise ValueError('commandLimit')
            command = json.loads(data)
            if set(command) != {'caseID', 'action'} or command['caseID'] != case_id:
                raise ValueError('commandSchema')
            action = command['action']
            if action in actions:
                raise ValueError('actionOnceOnly')
            actions.add(action)
            if action == 'fill': emit(owner.fill())
            elif action == 'sample': emit(owner.sample())
            elif action == 'release': emit(owner.release())
            elif action == 'stop':
                owner.release()
                owner.close()
                removed = owner.directory_removed
                remaining = os.statvfs('/dev/shm')
                emit({'schema': 1, 'caseID': case_id, 'event': 'released', 'uid': os.getuid(),
                      'filledBytes': 0, 'availableBytes': remaining.f_bavail * remaining.f_frsize,
                      'directoryRemoved': removed})
                return
            else: raise ValueError('commandAllowlist')
        raise ValueError('commandBudget')
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        owner.close()


if __name__ == '__main__':
    try:
        if len(sys.argv) != 3 or sys.argv[1] != '--container-owned-case':
            raise ValueError('containerEntryOnly')
        serve(canonical_id(sys.argv[2]))
    except BaseException:
        os.write(2, b'ENOSPC helper refused or stopped; metadata only.\n')
        raise SystemExit(2)
