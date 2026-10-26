#!/usr/bin/env python3
"""Narrow external coordination helpers; import/default has no filesystem/network work.

No consumer signalling, socket proxy, server command or process discovery. The owner
must supply its already-live Popen for the reviewed finite root relay and validated
case directory. This module is NOT a standalone launcher and never starts a campaign.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time
import uuid

FIXTURE_WRAPPER = '/Users/liuwenshuo/Desktop/OpenLXSSH/Tests/IntegrationEnvironment/fixture.sh'
OWN_ROOT = '/Users/liuwenshuo/Desktop/OpenLXSSH/Tests/RemoteFileAcceptance'


def metadata_identity(info):
    # Reading can update atime. It is neither identity nor content integrity.
    # Use explicit nanosecond timestamps: os.stat_result tuple equality can lose
    # sub-second changes as well as rejecting a benign access-time update.
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_private(path, limit=8192):
    path = Path(path)
    if not path.is_absolute() or any(part in ('.', '..') for part in path.parts):
        raise ValueError('unsafeMetadataPath')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory); directory = following
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('unsafeMetadataParent')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > limit:
                raise ValueError('unsafeMetadataFile')
            value = os.read(fd, limit + 1)
            if len(value) > limit or metadata_identity(os.fstat(fd)) != metadata_identity(before):
                raise ValueError('changedMetadata')
            return value
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def case_directory(path):
    path = str(path)
    prefix = OWN_ROOT + '/.runtime/disconnect-'
    if not path.startswith(prefix):
        raise ValueError('wrongCaseRoot')
    suffix = path[len(prefix):]
    if str(uuid.UUID(suffix)) != suffix:
        raise ValueError('wrongCaseUUID')
    return Path(path), suffix


def parse_ready(data, case_id):
    ready = json.loads(data)
    if (set(ready) != {'schema','caseID','event','progressBytes','sourceBytes','at','serverBinding','createdPaths'}
            or ready['schema'] != 1 or ready['caseID'] != case_id
            or ready['event'] != 'upload-real-progress-ready-to-terminate-owned-relay'
            or ready['sourceBytes'] != 16*1024*1024 or not 4*1024*1024 <= ready['progressBytes'] < 4*1024*1024+65536
            or not isinstance(ready['at'], (float,int)) or not isinstance(ready['createdPaths'], list) or len(ready['createdPaths']) != 3):
        raise ValueError('wrongReadyEvent')
    return ready


def wait_for_ready(case_path, timeout=90):
    directory, case_id = case_directory(case_path)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            data = read_private(directory/'ready.json')
            return data, parse_ready(data, case_id)
        except FileNotFoundError:
            time.sleep(.01)
        except (json.JSONDecodeError, ValueError):
            # The exclusive writer may still be fsyncing. Never TERM on partial/unvalidated data.
            time.sleep(.01)
    raise TimeoutError('noRealQuarterProgress')


def terminate_exact_owned_relay(relay, case_path, ready_data, ready, stdout_path, *, owned_pid):
    directory, case_id = case_directory(case_path)
    parse_ready(ready_data, case_id)
    if (not isinstance(relay, subprocess.Popen) or relay.pid != owned_pid or relay.poll() is not None
            or relay.args != [FIXTURE_WRAPPER,'relay','--authorized-run','--max-duration','180']):
        raise ValueError('notExactOwnedFiniteRelayPopen')
    requested = time.time()
    relay.send_signal(signal.SIGTERM)  # Popen child owner only. Never consumer/token/server.
    code = relay.wait(timeout=30)
    completed = time.time()
    events = [json.loads(line) for line in read_private(stdout_path, limit=8192).splitlines()]
    stopped = [event for event in events if event.get('event') == 'relay-stopped']
    if code != 0 or not stopped:
        raise ValueError('relayTerminationNotClean')
    counters = stopped[-1]['counters']
    if counters != {'accepted':1,'finished':1,'rejected':0,'cleanup_failed':0}:
        raise ValueError('relayCountersNotExactSingleCase')
    receipt = {'schema':1,'caseID':case_id,'reason':'SIGTERM-exact-owned-relay-after-ready',
        'readySHA256':hashlib.sha256(ready_data).hexdigest(),'ownedRelayPID':owned_pid,
        'requestedAt':requested,'completedAt':completed,'relayExitCode':code,
        'accepted':1,'finished':1,'rejected':0,'cleanupFailed':0}
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open('relay-termination.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        with os.fdopen(fd,'w') as stream:
            json.dump(receipt,stream,indent=2,sort_keys=True);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    finally:
        os.close(parent)
    return receipt


if __name__ == '__main__':
    print('Library only: no default filesystem/network/process action. Primary owns the exact relay Popen and explicit live release.')
