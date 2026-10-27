"""Fixed-fixture FD helpers. Import is inert; no recursive cleanup or path adoption."""
import os
import stat
import sys

from management_prep import require

NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def linux_user(uid):
    require(sys.platform == 'linux' and os.getuid() == os.geteuid() == uid and os.getgid() == os.getegid() == uid)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink)


def version(info):
    return identity(info) + (info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def regular(info, uid, mode):
    require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == uid)
    require(stat.S_IMODE(info.st_mode) == mode and info.st_nlink == 1)


class Directories:
    def __init__(self, components):
        self.nodes = []
        root = os.open('/', os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
        self.nodes.append((None, '/', root, identity(os.fstat(root))[:5]))
        try:
            self._check(root, 0, 0o755)
            for name, uid, mode in components:
                parent = self.fd
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=parent)
                self.nodes.append((parent, name, fd, identity(os.fstat(fd))[:5]))
                self._check(fd, uid, mode)
            self.verify()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _check(fd, uid, mode):
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == uid and stat.S_IMODE(info.st_mode) == mode)

    @property
    def fd(self):
        return self.nodes[-1][2]

    def create(self, name, uid):
        self.verify()
        parent = self.fd
        os.mkdir(name, 0o700, dir_fd=parent)  # EEXIST refuses stale/foreign case directories.
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=parent)
        self.nodes.append((parent, name, fd, identity(os.fstat(fd))[:5]))
        self._check(fd, uid, 0o700)
        os.fsync(parent)
        self.verify()

    def verify(self):
        for parent, name, fd, expected in self.nodes:
            require(identity(os.fstat(fd))[:5] == expected)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(identity(named)[:5] == expected)

    def close(self):
        while self.nodes:
            os.close(self.nodes.pop()[2])


def read_held(parent, name, fd, uid, mode, limit=65536):
    before = os.fstat(fd)
    regular(before, uid, mode)
    require(0 <= before.st_size <= limit)
    require(version(os.stat(name, dir_fd=parent, follow_symlinks=False)) == version(before))
    data = bytearray()
    while len(data) < before.st_size:
        block = os.pread(fd, before.st_size - len(data), len(data))
        require(block)
        data.extend(block)
    require(len(data) == before.st_size and version(os.fstat(fd)) == version(before))
    require(version(os.stat(name, dir_fd=parent, follow_symlinks=False)) == version(before))
    return bytes(data)


def write_all(fd, data, offset=0):
    view = memoryview(data)
    while view:
        count = os.pwrite(fd, view, offset)
        require(count > 0)
        offset += count
        view = view[count:]


def durable_public(tree, name, data, ledger):
    """Only callers' validated public receipt bytes; never a private-key writer."""
    tree.verify()
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600, dir_fd=tree.fd)
    ledger[name] = fd  # Retain partial own receipts too; never adopt an existing name.
    regular(os.fstat(fd), 0, 0o600)
    write_all(fd, data)
    os.fsync(fd)
    os.fsync(tree.fd)
    tree.verify()
    require(read_held(tree.fd, name, fd, 0, 0o600) == data)
    return fd
