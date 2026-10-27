"""Fixed /proc metadata only, never argv/env/prompts or process signalling.

Owned identities must come from the future outer/nested ACK registration. A PID
supplied by a caller is NOT evidence of ownership. This validates observations,
not who registered them; the consumer/ACK integration is a later review point.
Two equal scans detect churn, not an atomic exclusion against foreign sessions.
"""
from dataclasses import dataclass
import os
import re
import stat

from fd_safety import NOFOLLOW, version
from management_prep import require


@dataclass(frozen=True)
class Process:
    pid: int
    parent: int
    start: int
    uids: tuple
    name: str

    @property
    def token(self):
        return self.pid, self.start


def parse_process(pid, status, raw_stat, comm):
    require(type(pid) is int and pid > 0 and len(status) < 65536 and len(raw_stat) < 8192)
    match = re.search(rb'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$', status, re.M)
    require(match is not None and raw_stat.startswith(str(pid).encode() + b' ('))
    tail = raw_stat[raw_stat.rfind(b')') + 2:].split()
    require(len(tail) >= 20 and tail[1].isdigit() and tail[19].isdigit())
    name = comm.decode('ascii').rstrip('\n')
    require(re.fullmatch('[A-Za-z0-9._-]{1,32}', name) is not None)
    return Process(pid, int(tail[1]), int(tail[19]), tuple(map(int, match.groups())), name)


class ProcReader:
    def __init__(self, fixture_fd):
        fd = os.open('sshd.pid', os.O_RDONLY | NOFOLLOW, dir_fd=fixture_fd)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1)
            require(stat.S_IMODE(info.st_mode) == 0o644 and 0 < info.st_size <= 32)
            raw = os.pread(fd, 32, 0)
            require(raw.strip().isdigit() and len(raw) == info.st_size)
            require(version(os.fstat(fd)) == version(info))
            require(version(os.stat('sshd.pid', dir_fd=fixture_fd, follow_symlinks=False)) == version(info))
            self.master_pid = int(raw)
        finally:
            os.close(fd)
        self.fd = os.open('/proc', os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
        try:
            first, second = self.scan(), self.scan()
            require(first == second and self.master_pid in first)
            self.master = first[self.master_pid]
            require(self.master.name == 'sshd' and self.master.uids == (0, 0, 0, 0))
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _read(parent, name, limit):
        fd = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
        try:
            raw = bytearray()
            while len(raw) <= limit:
                block = os.read(fd, min(8192, limit + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            require(len(raw) <= limit)
            return bytes(raw)
        finally:
            os.close(fd)

    def scan(self):
        result = {}
        for name in os.listdir(self.fd):
            if not name.isdigit():
                continue
            try:
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=self.fd)
            except FileNotFoundError:
                continue
            try:
                first = parse_process(int(name), self._read(fd, 'status', 65536),
                                      self._read(fd, 'stat', 8192), self._read(fd, 'comm', 64))
                second = parse_process(int(name), self._read(fd, 'status', 65536),
                                       self._read(fd, 'stat', 8192), self._read(fd, 'comm', 64))
                require(first == second)
                result[first.pid] = first
            finally:
                os.close(fd)
        return result

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class SessionGate:
    def __init__(self, reader, owned, ssh_tokens):
        self.reader, self.owned, self.ssh_tokens = reader, {}, frozenset()
        self.register(owned, ssh_tokens)

    def register(self, owned, ssh_tokens):
        """Explicit ACK-ledger update, not discovery/adoption from a receipt."""
        require(type(owned) is tuple and all(type(item) is Process for item in owned))
        require(len({item.pid for item in owned}) == len(owned))
        first, current = self.reader.scan(), self.reader.scan()
        require(first == current)
        for item in owned:
            require(current.get(item.pid) == item and self.owned.get(item.pid, item) == item)
        candidate = dict(self.owned)
        candidate.update((item.pid, item) for item in owned)
        tokens = self.ssh_tokens | frozenset(ssh_tokens)
        required = {item.token for item in candidate.values() if item.name == 'ssh' or item.name.startswith('sshd')}
        require(tokens == required)  # Cannot omit an observed owned SSH process to claim closed.
        old = self.owned, self.ssh_tokens
        self.owned, self.ssh_tokens = candidate, tokens
        try:
            self.check()
        except BaseException:
            self.owned, self.ssh_tokens = old
            raise

    def check(self, *, closed=False):
        core_tokens = {item.token for item in self.owned.values() if item.name == 'ssh' or item.name.startswith('sshd')}
        require(self.ssh_tokens == core_tokens)
        first, current = self.reader.scan(), self.reader.scan()
        require(first == current and current.get(self.reader.master.pid) == self.reader.master)
        for expected in self.owned.values():
            now = current.get(expected.pid)
            require(now is None or now == expected)  # A reused PID never counts as closed.
        for item in current.values():
            if item.pid != self.reader.master.pid and (10000 in item.uids or item.name.startswith('sshd')):
                require(self.owned.get(item.pid) == item)
        for item in self.owned.values():
            seen = set()
            while item.pid != self.reader.master.pid:
                require(item.pid not in seen)
                seen.add(item.pid)
                item = self.owned.get(item.parent, self.reader.master if item.parent == self.reader.master.pid else None)
                require(item is not None)
        if closed:
            require(all(pid not in current for pid, _start in self.ssh_tokens))
        return {'master': self.reader.master.token, 'owned': sorted(item.token for item in current.values()
                if item.pid in self.owned), 'foreign_sessions': 0, 'owned_ssh_closed': closed}
