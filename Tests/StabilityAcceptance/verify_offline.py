#!/usr/bin/env python3
"""Finite OFFLINE verification only; never builds/signs/runs the real driver.

SwiftPM's implicit debug ad-hoc entitlement step is disabled explicitly. The
small dependency-free build plan is generated and checked before tests run.
No network, credentials, fixture runtime, Keychain, signing identity or scheduler.
All new scratch/log/cache outputs are inside one exclusive .build/offline-UUID.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

HERE = Path(__file__).resolve().parent
BUILD = HERE / '.build'


def run(command, log, env):
    with log.open('x') as stream:
        result = subprocess.run(command, cwd=HERE, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=180)
    print(json.dumps({'cwd': str(HERE), 'command': command, 'exitCode': result.returncode, 'log': str(log)}), flush=True)
    if result.returncode:
        raise RuntimeError('Offline verification failed; see local log')


def main():
    if len(sys.argv) > 1:
        if sys.argv[1:] in (['--help'], ['-h']):
            print(__doc__)
            return 0
        raise RuntimeError('No run/connect/scheduling flags are accepted')
    os.umask(0o077)
    if BUILD.is_symlink() or BUILD.resolve() != BUILD:
        raise RuntimeError('Unsafe offline output parent')
    BUILD.mkdir(exist_ok=True, mode=0o700)
    work = BUILD / ('offline-' + str(uuid.uuid4()))
    work.mkdir(mode=0o700)
    scratch, logs = work / 'scratch', work / 'logs'
    logs.mkdir(mode=0o700)
    (work / 'tmp').mkdir(mode=0o700)
    env = os.environ.copy()
    env.update({'PYTHONDONTWRITEBYTECODE': '1', 'TMPDIR': str(work / 'tmp') + '/',
                'CLANG_MODULE_CACHE_PATH': str(work / 'clang-cache'),
                'OPENLXSSH_STABILITY_OFFLINE_SCRATCH': str(scratch),
                'OPENLXSSH_STABILITY_TYPECHECK_CACHE': str(work / 'typecheck-cache')})
    common = ['--package-path', str(HERE), '--scratch-path', str(scratch), '--jobs', '2',
              '--cache-path', str(work / 'cache'), '--config-path', str(work / 'config'),
              '--security-path', str(work / 'security'), '--disable-automatic-resolution',
              '--disable-get-task-allow-entitlement']
    # This first command only creates the job graph; no commands in that graph
    # execute. Refuse before tests if the current toolchain added a sign step.
    run(['swift', 'build'] + common + ['--print-manifest-job-graph'], logs / 'no-debug-sign-plan.log', env)
    plan = (scratch / 'debug.yaml').read_text()
    if 'codesign' in plan or 'Applying debug entitlements' in plan:
        raise RuntimeError('Unexpected implicit signing step; no tests started')
    run(['swift', 'test'] + common, logs / 'offline-swift.log', env)
    run([sys.executable, str(HERE / 'test_offline.py')], logs / 'offline-python.log', env)
    run([sys.executable, str(HERE / 'test_build_driver.py')], logs / 'recipe-python.log', env)
    run(['xcrun', 'clang', '-fsyntax-only', '-Wall', '-Wextra', '-Werror',
         '-I', str(HERE / 'Sources' / 'StabilityPOSIX' / 'include'),
         str(HERE / 'Sources' / 'StabilityPOSIX' / 'StabilityPOSIX.c')], logs / 'clang.log', env)
    print('Offline preparation checks passed only. Actual SSH/200-cycle/24h/App/PERF acceptance remains unverified.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        sys.stderr.write(str(error) + '\n')
        sys.exit(1)
