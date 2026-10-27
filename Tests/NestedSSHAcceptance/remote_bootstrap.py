"""Fixed public-source stdio bootstrap. Import/help are inert; only the reviewed
host runner may execute main inside the exact Linux fixture. No host mounts,
private-key copying, shell, service changes or remote process signalling.
"""
import base64
import hashlib
import json
import os
import signal
import stat
import sys
import types

PLAN_SHA256 = '41ecda1b8d5955e67243b123712ef9673a403779cc8f196f75a0be8cc3f117f1'
NAMES = ('management_prep', 'fd_safety', 'session_metadata', 'root_adapter', 'key_ledger',
         'nested_probe', 'build_integrated', 'manager_control')
RECEIPTS = {'integrated-plan.json', 'prepared.json', 'appended.json', 'restore-intent.json', 'restored.json'}
FLAGS = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def require(value):
    if not value:
        raise ValueError('nested-public-staging-refused')


def sha(value):
    return hashlib.sha256(value).hexdigest()


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink)


def read(fd, limit=65536):
    first = os.fstat(fd)
    require(stat.S_ISREG(first.st_mode) and first.st_uid == first.st_gid == 0 and first.st_nlink == 1)
    require(stat.S_IMODE(first.st_mode) in (0o600, 0o644) and first.st_size <= limit)
    value = os.pread(fd, limit + 1, 0)
    last = os.fstat(fd)
    require(stamp(first) == stamp(last) and first.st_size == last.st_size == len(value)
            and first.st_mtime_ns == last.st_mtime_ns and first.st_ctime_ns == last.st_ctime_ns)
    return value


def event(value):
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n')
    sys.stdout.flush()


class Stage:
    def __init__(self, nonce):
        require(len(nonce) == 32 and all(char in '0123456789abcdef' for char in nonce))
        self.parents, self.files, self.directory = [], {}, None
        self.name = 'nested-source-' + nonce
        try:
            parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | FLAGS)
            self.parents.append((None, '/', parent, stamp(os.fstat(parent))[:5]))
            require(self.parents[0][3][2:] == (0, 0, 0o40755))
            for name in ('run', 'openlxssh-fixture'):
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | FLAGS, dir_fd=parent)
                self.parents.append((parent, name, fd, stamp(os.fstat(fd))[:5]))
                info = os.fstat(fd)
                require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o755)
                parent = fd
            os.mkdir(self.name, 0o700, dir_fd=parent)
            self.directory = os.open(self.name, os.O_RDONLY | os.O_DIRECTORY | FLAGS, dir_fd=parent)
            self.identity = stamp(os.fstat(self.directory))[:5]
            require(self.identity[2:] == (0, 0, 0o40700))
            os.fsync(parent)
            self.verify()
        except BaseException:
            self.close()
            raise

    @property
    def path(self):
        return '/run/openlxssh-fixture/' + self.name

    def verify(self):
        for parent, name, fd, expected in self.parents:
            require(stamp(os.fstat(fd))[:5] == expected == stamp(os.stat(name, dir_fd=parent, follow_symlinks=False))[:5])
        require(stamp(os.fstat(self.directory))[:5] == self.identity)
        require(stamp(os.stat(self.name, dir_fd=self.parents[-1][2], follow_symlinks=False))[:5] == self.identity)

    def put(self, name, value):
        require(name in {item + '.py' for item in NAMES} | {'workplan.json'} and name not in self.files)
        self.verify()
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | FLAGS, 0o600, dir_fd=self.directory)
        self.files[name] = (fd, stamp(os.fstat(fd)), sha(value))
        offset = 0
        while offset < len(value):
            count = os.pwrite(fd, value[offset:], offset)
            require(count > 0)
            offset += count
        os.fsync(fd)
        os.fsync(self.directory)
        self.verify()
        require(read(fd) == value and stamp(os.stat(name, dir_fd=self.directory, follow_symlinks=False)) == self.files[name][1])

    def cleanup(self):
        self.verify()
        require(set(os.listdir(self.directory)) == set(self.files))
        for name, (fd, identity, digest) in self.files.items():
            require(stamp(os.fstat(fd)) == identity == stamp(os.stat(name, dir_fd=self.directory, follow_symlinks=False)))
            require(sha(read(fd)) == digest)
        for name in self.files:
            os.unlink(name, dir_fd=self.directory)
        require(not os.listdir(self.directory))
        os.rmdir(self.name, dir_fd=self.parents[-1][2])
        os.fsync(self.parents[-1][2])

    def close(self):
        for fd, _identity, _digest in self.files.values():
            os.close(fd)
        self.files.clear()
        if self.directory is not None:
            os.close(self.directory)
            self.directory = None
        while self.parents:
            os.close(self.parents.pop()[2])


def snapshot(modules, fixture_fd, nonce):
    fs, proc, core = modules['fd_safety'], modules['session_metadata'], modules['management_prep']
    reader = proc.ProcReader(fixture_fd)
    try:
        rows = reader.scan()
        require(rows == reader.scan())
        require(not any(10000 in item.uids or (item.pid != reader.master.pid and item.name.startswith('sshd')) for item in rows.values()))
        result = {'daemon': reader.master.token, 'user_processes': 0, 'sshd_children': 0}
    finally:
        reader.close()
    for name, mode in (('authorized_keys', 0o644), ('sshd_config', 0o600)):
        fd = os.open(name, os.O_RDONLY | FLAGS, dir_fd=fixture_fd)
        try:
            data = fs.read_held(fixture_fd, name, fd, 0, mode)
            result[name + '_sha256'] = sha(data)
        finally:
            os.close(fd)
    home = fs.Directories((('fixture', 0, 0o755), ('home', 10000, 0o700), ('.ssh', 10000, 0o700)))
    try:
        fd = os.open('known_hosts', os.O_RDONLY | FLAGS, dir_fd=home.fd)
        try:
            known = fs.read_held(home.fd, 'known_hosts', fd, 10000, 0o600, 4096)
        finally:
            os.close(fd)
        fields = known.decode('ascii').split()
        require(len(fields) == 3 and fields[:2] == ['[127.0.0.1]:2222', 'ssh-ed25519'])
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(fields[2], validate=True)).digest()).decode().rstrip('=')
        require(fingerprint == core.HOST_FINGERPRINT)
        result.update(known_hosts_sha256=sha(known), fingerprint=fingerprint)
    finally:
        home.close()
    result['key_directory_absent'] = not os.path.lexists('/fixture/home/.openlxssh-nested-' + nonce)
    return result


class PublicReceipts:
    def __init__(self, fs):
        self.fs, self.parent, self.directory, self.name, self.identity = fs, None, None, None, None
        self.files = {}
        self.original = fs.durable_public

    def capture(self, tree, name, data, ledger):
        require(name in RECEIPTS)
        fd = self.original(tree, name, data, ledger)
        if self.directory is None:
            parent, self.name, directory, self.identity = tree.nodes[-1]
            self.parent, self.directory = os.dup(parent), os.dup(directory)
        require(stamp(os.fstat(self.directory))[:5] == tree.nodes[-1][3] == self.identity)
        self.files[name] = (os.dup(fd), stamp(os.fstat(fd)), sha(data))
        return fd

    def export(self):
        values = {}
        if self.directory is not None:
            for name, (fd, identity, digest) in self.files.items():
                require(stamp(os.fstat(fd)) == identity == stamp(os.stat(name, dir_fd=self.directory, follow_symlinks=False)))
                value = self.fs.read_held(self.directory, name, fd, 0, 0o600)
                require(sha(value) == digest)
                values[name] = base64.b64encode(value).decode('ascii')
        return values

    def cleanup(self):
        require(self.directory is not None and set(self.files) == RECEIPTS and set(os.listdir(self.directory)) == RECEIPTS)
        self.export()
        require(stamp(os.fstat(self.directory))[:5] == self.identity == stamp(os.stat(self.name, dir_fd=self.parent, follow_symlinks=False))[:5])
        for name in self.files:
            os.unlink(name, dir_fd=self.directory)
        require(not os.listdir(self.directory))
        os.rmdir(self.name, dir_fd=self.parent)
        os.fsync(self.parent)

    def close(self):
        self.fs.durable_public = self.original
        for fd, _identity, _digest in self.files.values():
            os.close(fd)
        for fd in (self.directory, self.parent):
            if fd is not None:
                os.close(fd)


def main():
    require(sys.platform == 'linux' and os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 0)
    line = sys.stdin.readline(196609)
    require(0 < len(line) <= 196608 and line.endswith('\n'))
    envelope = json.loads(line)
    require(set(envelope) == {'workplan_base64', 'modules_base64'})
    raw = base64.b64decode(envelope['workplan_base64'], validate=True)
    require(sha(raw) == PLAN_SHA256)
    plan = json.loads(raw)
    require(set(envelope['modules_base64']) == set(NAMES))
    stage, receipts, status = None, None, 2
    try:
        stage = Stage(plan['nonce'])
        stage.put('workplan.json', raw)
        modules = {}
        for name in NAMES:
            source = base64.b64decode(envelope['modules_base64'][name], validate=True)
            require(sha(source) == plan['source_sha256'][name + '.py'])
            stage.put(name + '.py', source)
            module = types.ModuleType(name)
            module.__file__ = stage.path + '/' + name + '.py'
            sys.modules[name] = modules[name] = module
            exec(compile(source, module.__file__, 'exec'), module.__dict__)
        modules['manager_control'].validate_plan(raw, PLAN_SHA256)
        receipts = PublicReceipts(modules['fd_safety'])
        modules['fd_safety'].durable_public = receipts.capture
        before = snapshot(modules, stage.parents[-1][2], plan['nonce'])
        require(before['key_directory_absent'])
        event({'event': 'BASELINE', 'snapshot': before, 'workplan_sha256': PLAN_SHA256})
        # manager consumes its existing plan envelope, then the host's finish line.
        status = modules['manager_control'].serve(PLAN_SHA256, sys.stdin, sys.stdout)
        payload = {'event': 'PUBLIC-RECEIPTS', 'workplan_sha256': PLAN_SHA256, 'receipts_base64': receipts.export(), 'manager_exit': status}
        payload_hash = sha(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('ascii'))
        event(dict(payload, receipt_export_sha256=payload_hash))
        signal.signal(signal.SIGALRM, lambda *_args: (_ for _ in ()).throw(ValueError('receipt-ack-timeout')))
        signal.alarm(20)
        require(sys.stdin.readline(128) == 'receipt-ack ' + payload_hash + '\n')
        signal.alarm(0)
        if status == 0:
            after = snapshot(modules, stage.parents[-1][2], plan['nonce'])
            require(after == before)
            receipts.cleanup()
            stage.cleanup()
            event({'event': 'STAGING-CLEANED', 'snapshot': after, 'workplan_sha256': PLAN_SHA256})
        return status
    finally:
        signal.alarm(0)
        if receipts is not None:
            receipts.close()
        if stage is not None:
            stage.close()  # Names survive unsafe/partial states; never recursive cleanup.


def start():
    signal.signal(signal.SIGALRM, lambda *_args: (_ for _ in ()).throw(ValueError('bootstrap-input-timeout')))
    signal.alarm(20)
    try:
        return main()
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    try:
        result = start()
    except BaseException:
        sys.stderr.write('Nested bootstrap refused/retained; public recovery state may remain.\n')
        result = 2
    sys.exit(result)
