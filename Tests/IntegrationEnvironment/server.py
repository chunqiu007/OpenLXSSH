#!/usr/bin/env python3
"""Container-only lifecycle. No host sshd, systemd or SSH config is touched."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import time
import challenge_owner

RUN = Path('/run/openlxssh-fixture')
HOME = Path('/fixture/home')
USER_ID = 10000
MODES = {
    'keyonly': ('yes', 'no', 'no', 'publickey', 22221),
    'passwordonly': ('no', 'yes', 'no', 'password', 22222),
    'key-kbd': ('yes', 'no', 'yes', 'publickey,keyboard-interactive:pam', 22223),
    'password-kbd': ('no', 'yes', 'yes', 'password,keyboard-interactive:pam', 22224),
}
SCENARIOS = ('multi', 'zero', 'approval', 'reject', 'cancel')
SOURCE = Path(__file__).resolve().parent
CHILD = None
STOP_REQUESTED = False


def require_container():
    if sys.platform != 'linux' or os.geteuid() != 0 or not Path('/.dockerenv').is_file():
        raise RuntimeError('container-only operation; no host execution allowed')
    if not Path('/fixture').is_mount():
        raise RuntimeError('expected isolated /fixture named volume')


def private_file(path, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def replace_private(path, data):
    temporary = path.with_name('.' + path.name + '-' + secrets.token_hex(8))
    private_file(temporary, data)
    os.replace(str(temporary), str(path))


def secret_command(argv):
    # A failing tool must not cause a captured key or passphrase to be logged.
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=40, check=False)
    if result.returncode:
        raise RuntimeError('fixture crypto tool failed (output suppressed)')


def render_config(mode):
    pubkey, password, kbd, methods, _ = MODES[mode]
    result = (SOURCE / 'sshd_config.in').read_text(encoding='utf-8')
    for key, value in {'PUBKEY': pubkey, 'PASSWORD': password,
                       'KBD': kbd, 'METHODS': methods}.items():
        result = result.replace('@' + key + '@', value)
    if '@' in result:
        raise RuntimeError('unresolved sshd template')
    return result


def password_record(password):
    salt = secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1)
    return {'salt': salt, 'digest': digest.hex()}


def make_host_generation():
    generation = RUN / ('host-' + secrets.token_hex(8))
    generation.mkdir(mode=0o700)
    secret_command(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                    '-C', 'OpenLXSSH disposable server', '-f', str(generation / 'host_ed25519')])
    for key in generation.iterdir():
        key.chmod(0o600)
    return generation


def host_metadata(generation, mode):
    public_key = (generation / 'host_ed25519.pub').read_text().split()
    port = MODES[mode][4]
    known = '[127.0.0.1]:{} {} {}\n'.format(port, public_key[0], public_key[1])
    local = '[127.0.0.1]:2222 {} {}\n'.format(public_key[0], public_key[1])
    fingerprint = subprocess.run(['/usr/bin/ssh-keygen', '-l', '-E', 'sha256', '-f',
                                  str(generation / 'host_ed25519.pub')], check=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
    replace_private(RUN / 'host_known_hosts', known)
    replace_private(RUN / 'nested_known_hosts', local)
    replace_private(RUN / 'host_fingerprint', fingerprint)


def bootstrap(mode):
    RUN.mkdir(mode=0o700)
    # The directory holds only test keys; sshd's user child must be able to stat
    # the root-owned authorized_keys. Everything else remains under 0700 dirs.
    RUN.chmod(0o755)
    (RUN / 'private').mkdir(mode=0o700)
    (RUN / 'sessions').mkdir(mode=0o700)
    (RUN / 'client').mkdir(mode=0o700)
    (RUN / 'export').mkdir(mode=0o700)
    Path('/run/sshd').mkdir(mode=0o755, exist_ok=True)
    if HOME.is_symlink():
        raise RuntimeError('unexpected test home symlink')
    HOME.mkdir(mode=0o700, exist_ok=True)
    HOME.chmod(0o700)
    os.chown(str(HOME), USER_ID, USER_ID)
    config = {'version': 1, 'mode': mode, 'scenario': 'multi', 'delay': 8}
    password = secrets.token_urlsafe(24)
    passphrase = secrets.token_urlsafe(24)
    replace_private(RUN / 'private' / 'password-record.json', json.dumps(password_record(password)))
    replace_private(RUN / 'export' / 'password.txt', password + '\n')
    replace_private(RUN / 'private' / 'key-passphrase', passphrase + '\n')
    replace_private(RUN / 'export' / 'key-passphrase.txt', passphrase + '\n')
    for name, kind, encrypted in (('id_ed25519', 'ed25519', False),
                                   ('id_ed25519_encrypted', 'ed25519', True),
                                   ('id_rsa', 'rsa', False),
                                   ('id_rsa_encrypted', 'rsa', True)):
        target = RUN / 'client' / name
        args = ['/usr/bin/ssh-keygen', '-q', '-t', kind, '-C', 'OpenLXSSH disposable client',
                '-f', str(target)]
        if kind == 'rsa':
            args += ['-b', '3072']
        # Secret read from a private file, never from argv, environment or stdout.
        args += ['-N', '', '-P', '']
        secret_command(args)
        if encrypted:
            # ssh-keygen cannot read a *new* passphrase from a file. Its mature
            # askpass interface supplies both rekey prompts without shell text.
            askpass = SOURCE / 'key_askpass.py'
            env = dict(os.environ, SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE='force',
                       DISPLAY='fixture', OPENLXSSH_FIXTURE_KEYGEN='1')
            result = subprocess.run(['/usr/bin/ssh-keygen', '-q', '-p', '-f', str(target), '-P', ''],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, env=env, timeout=40, check=False)
            if result.returncode:
                raise RuntimeError('fixture key encryption failed (output suppressed)')
        target.chmod(0o600)
        target.with_suffix('.pub').chmod(0o600)
    authorized = ''.join((RUN / 'client' / (name + '.pub')).read_text()
                         for name in ('id_ed25519', 'id_ed25519_encrypted', 'id_rsa', 'id_rsa_encrypted'))
    private_file(RUN / 'authorized_keys', authorized)
    (RUN / 'authorized_keys').chmod(0o644)  # public keys only, root-owned
    generation = make_host_generation()
    (RUN / 'current').symlink_to(generation.name)
    host_metadata(generation, mode)
    replace_private(RUN / 'config.json', json.dumps(config))
    replace_private(RUN / 'sshd_config', render_config(mode))
    # Dedicated nested client's trust files, no App secrets or copied local keys.
    ssh_dir = HOME / '.ssh'
    if ssh_dir.is_symlink():
        raise RuntimeError('unexpected nested SSH directory symlink')
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    ssh_dir.chmod(0o700)
    replace_private(ssh_dir / 'known_hosts', (RUN / 'nested_known_hosts').read_bytes())
    private_config = ('Host *\n    User fixture\n    IdentityAgent none\n    IdentitiesOnly yes\n'
                      '    ForwardAgent no\n    StrictHostKeyChecking yes\n'
                      '    UserKnownHostsFile /fixture/home/.ssh/known_hosts\n'
                      '    GlobalKnownHostsFile /dev/null\n    UpdateHostKeys no\n')
    replace_private(ssh_dir / 'config', private_config)
    for path in (ssh_dir, ssh_dir / 'known_hosts', ssh_dir / 'config'):
        os.chown(str(path), USER_ID, USER_ID)
    # Denied files sit outside the user's writable home so SFTP cannot delete
    # them merely by unlinking from a user-owned parent directory.
    protected = Path('/fixture/protected')
    protected.mkdir(mode=0o755, exist_ok=True)
    protected.chmod(0o755)
    os.chown(str(protected), 0, 0)
    replace_private(protected / 'denied.txt', 'permission-denied fixture\n')
    denied_dir = protected / 'denied-directory'
    denied_dir.mkdir(mode=0o700, exist_ok=True)
    denied_dir.chmod(0o700)
    os.chown(str(denied_dir), 0, 0)
    secret_command(['/usr/sbin/sshd', '-t', '-f', str(RUN / 'sshd_config')])


def rotate_host():
    config = json.loads((RUN / 'config.json').read_text())
    generation = make_host_generation()
    next_link = RUN / ('current-' + secrets.token_hex(8))
    next_link.symlink_to(generation.name)
    os.replace(str(next_link), str(RUN / 'current'))
    secret_command(['/usr/sbin/sshd', '-t', '-f', str(RUN / 'sshd_config')])
    pid = int((RUN / 'sshd.pid').read_text())
    if not Path('/proc/{}/exe'.format(pid)).resolve().name == 'sshd':
        raise RuntimeError('refusing signal to non-sshd process')
    os.kill(pid, signal.SIGHUP)
    host_metadata(generation, config['mode'])
    # Old generations live in tmpfs until stop; never rewrite existing clients'
    # known_hosts or the nested known_hosts during mismatch testing.


def set_scenario(scenario, delay):
    config = json.loads((RUN / 'config.json').read_text())
    if config['mode'] not in ('key-kbd', 'password-kbd'):
        raise RuntimeError('scenario requires keyboard-interactive service')
    config.update(scenario=scenario, delay=delay)
    replace_private(RUN / 'config.json', json.dumps(config))


def export_metadata(session=None):
    if session is None:
        data = {name: (RUN / 'export' / name).read_text().strip()
                for name in ('password.txt', 'key-passphrase.txt')}
        data['keys'] = {path.name: path.read_text() for path in (RUN / 'client').iterdir()}
        data['known_hosts'] = (RUN / 'host_known_hosts').read_text()
        data['fingerprint'] = (RUN / 'host_fingerprint').read_text().strip()
        data['packages'] = (SOURCE / 'packages.txt').read_text()
    else:
        if len(session) != 24 or any(ch not in '0123456789abcdef' for ch in session):
            raise RuntimeError('invalid session identifier')
        # The lifetime owner serializes export with lease EOF/close. A separate
        # read-then-write here could recreate an export after cancellation.
        challenge_owner.export_challenge(RUN, session)
        return
    # Keep secrets in files on tmpfs. The host wrapper uses docker cp into an
    # ignored 0700 directory; neither exec output nor engine logs carry them.
    name = 'metadata.json' if session is None else 'challenge-' + session + '.json'
    replace_private(RUN / 'export' / name, json.dumps(data))


def request_stop(_signal, _frame):
    global STOP_REQUESTED
    STOP_REQUESTED = True


def stop_child():
    if CHILD is not None and CHILD.poll() is None:
        try:
            os.killpg(CHILD.pid, signal.SIGTERM)
            CHILD.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(CHILD.pid, signal.SIGKILL)
            CHILD.wait()
        except ProcessLookupError:
            CHILD.wait()


def serve(mode):
    global CHILD, STOP_REQUESTED
    STOP_REQUESTED = False
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    owner = None
    try:
        bootstrap(mode)
        if STOP_REQUESTED:
            return 0
        if mode in ('key-kbd', 'password-kbd'):
            owner = challenge_owner.ChallengeOwner(RUN)
        CHILD = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', str(RUN / 'sshd_config')],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
        if owner is not None:
            owner.start()
        while CHILD.poll() is None and not STOP_REQUESTED:
            if owner is not None:
                owner.check_health()
            time.sleep(0.1)
        return CHILD.returncode if CHILD.returncode is not None else 0
    finally:
        try:
            stop_child()
        finally:
            # If an unknown file/socket replacement prevented exact cleanup,
            # fail visibly; do not let broad rmtree disguise that failure.
            if owner is not None:
                owner.close()
        # tmpfs disappears on container stop; eagerly remove runtime secrets.
        if RUN.exists():
            shutil.rmtree(str(RUN))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('serve', 'health', 'scenario', 'rotate-host', 'export', 'challenge'))
    parser.add_argument('--authorized-run', action='store_true')
    parser.add_argument('--mode', choices=tuple(MODES))
    parser.add_argument('--scenario', choices=SCENARIOS)
    parser.add_argument('--delay', type=int, default=8)
    parser.add_argument('--session')
    args = parser.parse_args()
    if not args.authorized_run:
        parser.error('requires --authorized-run AND prior user authorization')
    require_container()
    if not 1 <= args.delay <= 60:
        parser.error('delay must be 1..60 seconds')
    if args.action == 'serve':
        if args.mode is None:
            parser.error('serve requires --mode')
        return serve(args.mode)
    if args.action == 'health':
        pid = int((RUN / 'sshd.pid').read_text())
        if Path('/proc/{}/exe'.format(pid)).resolve().name != 'sshd':
            raise RuntimeError('sshd is not running')
        os.kill(pid, 0)
        if json.loads((RUN / 'config.json').read_text())['mode'] in ('key-kbd', 'password-kbd'):
            challenge_owner.health(RUN)
    elif args.action == 'scenario':
        if args.scenario is None:
            parser.error('scenario requires --scenario')
        set_scenario(args.scenario, args.delay)
    elif args.action == 'rotate-host':
        rotate_host()
    elif args.action == 'export':
        export_metadata()
    elif args.action == 'challenge':
        if args.session is None:
            parser.error('challenge requires --session')
        export_metadata(args.session)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        # Do not emit tracebacks that could contain secret subprocess data.
        sys.stderr.write('container fixture operation failed; no secret output emitted\n')
        sys.exit(1)
