"""NEST-KEY-LEDGER-A: inert source, same live root management owner only.
ssh-keygen alone runs as UID/GID10000. Root never reads/copies private-key bytes.
No bridge/IPC, process registry, SSH consumer or autonomous cleanup is added.
Unknown/partial files are retained; only confirmed same-run restore + closed SSH
permits unlink. Filesystem checks are not atomic against foreign same-UID writers.
"""
import os
import subprocess

import fd_safety as fs
import management_prep as core
from root_adapter import RootAdapter, public_json

NAMES = ('id_ed25519', 'id_ed25519.pub')


class KeyLedger:
    def __init__(self, owner):
        fs.linux_user(0)
        core.require(type(owner) is RootAdapter and not owner.closed and owner.receipt is None)
        self.owner, self.plan = owner, core.key_plan(owner.nonce)
        self.tree = self.child = self.receipt = None
        self.files, self.started, self.closed = {}, False, False
        try:
            owner._exclusion()
            self.tree = fs.Directories((('fixture', 0, 0o755), ('home', 10000, 0o700)))
            parent = self.tree.fd
            name = '.openlxssh-nested-' + owner.nonce
            os.mkdir(name, 0o700, dir_fd=parent)  # Exclusive; never adopt a prior case.
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | fs.NOFOLLOW, dir_fd=parent)
            self.tree.nodes.append((parent, name, fd, fs.identity(os.fstat(fd))[:5]))
            self.tree._check(fd, 0, 0o700)
            self.tree.verify()
            os.fchown(fd, 10000, 10000)
            self.tree.nodes[-1] = (parent, name, fd, fs.identity(os.fstat(fd))[:5])
            self.tree._check(fd, 10000, 0o700)
            self.tree.verify()
            os.fsync(fd)
            os.fsync(parent)
        except BaseException:
            self.close()  # Preserve names; no recovery receipt is deletion authority.
            raise

    def _stop_child(self):
        if self.child is None:
            return
        child = self.child  # Only this unreaped Popen, never a PID/PGID from input.
        if child.poll() is None:
            try:
                child.terminate()
            except ProcessLookupError:
                pass
        try:
            child.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            try:
                child.kill()
            except ProcessLookupError:
                pass
            child.wait(timeout=0.25)
        self.child = None

    def _keygen(self):
        path = self.plan['argv'][-1].rsplit('/', 1)[0]
        try:
            self.child = subprocess.Popen(self.plan['argv'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL, shell=False, close_fds=True, cwd=path,
                                          user=10000, group=10000, extra_groups=(), umask=0o077,
                                          env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/fixture/home'})
            # 4.5s + .25s TERM + .25s KILL/reap wait budget; no background retry.
            status = self.child.wait(timeout=4.5)
            self.child = None
            core.require(status == 0)
        except BaseException:
            try:
                self._stop_child()
            except BaseException:
                raise core.Refused('nested-keygen-unreaped') from None
            raise core.Refused('nested-keygen-refused') from None

    def generate(self):
        core.require(not self.closed and not self.started and not self.owner.closed and self.owner.receipt is None)
        self.started = True
        self.owner._exclusion()
        original = self.owner._observed()
        self.tree.verify()
        core.require(not os.listdir(self.tree.fd))
        self._keygen()
        self.tree.verify()
        core.require(set(os.listdir(self.tree.fd)) == set(NAMES))
        for name in NAMES:
            fd = os.open(name, os.O_RDONLY | fs.NOFOLLOW, dir_fd=self.tree.fd)
            self.files[name] = (fd, None)
            fs.regular(os.fstat(fd), 10000, 0o600)  # Child umask077 covers .pub too.
            info = os.fstat(fd)
            core.require(0 < info.st_size <= 16384)
            core.require(fs.version(os.stat(name, dir_fd=self.tree.fd, follow_symlinks=False)) == fs.version(info))
            os.fsync(fd)
            self.files[name] = (fd, fs.version(info))
        os.fsync(self.tree.fd)
        # Only .pub is read. Nonce subject and distinctness reuse the reviewed pure core.
        public = fs.read_held(self.tree.fd, NAMES[1], self.files[NAMES[1]][0], 10000, 0o600, 4096)
        exclusion = self.owner._exclusion()
        core.require(self.owner._observed() == original and self.owner.receipt is None)
        self.receipt = core.prepare(self.owner.nonce, original, public, exclusion)
        self.prepared_hash = core.digest(core.public_receipt(self.receipt))
        self.verify()
        return public  # No private value crosses the management boundary.

    def verify(self):
        core.require(not self.closed and self.child is None and self.receipt is not None)
        self.tree.verify()
        core.require(set(self.files) == set(NAMES) == set(os.listdir(self.tree.fd)))
        for name, (fd, expected) in self.files.items():
            fs.regular(os.fstat(fd), 10000, 0o600)
            core.require(fs.version(os.fstat(fd)) == expected)
            core.require(fs.version(os.stat(name, dir_fd=self.tree.fd, follow_symlinks=False)) == expected)
        core.require(self.files[NAMES[0]][1][:2] != self.files[NAMES[1]][1][:2])
        core.require(fs.read_held(self.tree.fd, NAMES[1], self.files[NAMES[1]][0], 10000, 0o600, 4096) == self.receipt.new_public_line)

    def _restored(self):
        owner = self.owner  # Object identity held since creation; no serializable bool proof.
        core.require(type(owner) is RootAdapter and not owner.closed and owner.restored is True)
        core.require(owner.receipt == self.receipt and owner.nonce == self.receipt.nonce)
        exclusion = owner._exclusion(closed=True)  # Actual reader, not caller flags/counts.
        current = owner._observed()
        core.owned(current, exclusion)
        core.require(current.held == self.receipt.stamp and current.data == self.receipt.original)
        core.require(owner.prepared_hash == self.prepared_hash == owner._receipt_hash('prepared.json'))
        expected = public_json({'schema': 1, 'case': 'NESTrealpublickeyonly', 'phase': 'restored',
                                'prepared_sha256': self.prepared_hash, 'original_sha256': core.digest(current.data)})
        core.require(owner._receipt_hash('restored.json') == core.digest(expected))

    def cleanup(self):
        self.verify()
        self._restored()
        self.verify()  # Check all unknown additions/replacements before first unlink.
        for name in reversed(NAMES):
            self.tree.verify()
            fd, stamp = self.files[name]
            core.require(set(os.listdir(self.tree.fd)) == set(self.files))
            core.require(fs.version(os.fstat(fd)) == fs.version(os.stat(name, dir_fd=self.tree.fd, follow_symlinks=False)) == stamp)
            os.unlink(name, dir_fd=self.tree.fd)
            os.close(fd)
            del self.files[name]
        self.tree.verify()
        core.require(not os.listdir(self.tree.fd))
        parent, name, directory, _stamp = self.tree.nodes[-1]
        os.fsync(directory)
        os.rmdir(name, dir_fd=parent)
        os.fsync(parent)
        self.close()

    def close(self):
        if self.closed:
            return
        failure = None
        try:
            self._stop_child()
        except BaseException:
            failure = core.Refused('nested-keygen-unreaped')
        finally:
            for fd, _stamp in self.files.values():
                os.close(fd)
            self.files.clear()
            if self.tree is not None:
                self.tree.close()
            self.closed = self.child is None  # Never discard an unreaped Popen handle.
        if failure is not None:
            raise failure
