#!/usr/bin/env python3
"""Run offline safety tests with every writable cache under this subtree.

No Docker, SSH key generation, socket, signing, registry or package dependency.
The separate signed real consumer is never executed by this command.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
BUILD = HERE / '.build'


def main():
    BUILD.mkdir(mode=0o700, exist_ok=True)
    for name in ('tmp', 'test-home'):
        (BUILD / name).mkdir(mode=0o700, exist_ok=True)
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(BUILD / 'test-home'), 'TMPDIR': str(BUILD / 'tmp') + '/',
           'CLANG_MODULE_CACHE_PATH': str(BUILD / 'test-clang-cache'), 'SWIFTPM_MODULECACHE_OVERRIDE': str(BUILD / 'test-module-cache')}
    command = ['/usr/bin/swift', 'test', '--package-path', str(HERE), '--scratch-path', str(BUILD / 'swiftpm'),
               '--cache-path', str(BUILD / 'cache'), '--config-path', str(BUILD / 'config'), '--security-path', str(BUILD / 'security'),
               '--manifest-cache', 'local', '--disable-dependency-cache', '--disable-keychain', '--disable-netrc', '--disable-index-store', '-j', '2']
    result = subprocess.run(command, cwd=HERE, env=env, capture_output=True, timeout=180)
    log = BUILD / 'offline-tests-final.log'
    log.write_bytes(result.stdout + result.stderr)
    checks = [{'command': command, 'cwd': str(HERE), 'exitCode': result.returncode, 'log': str(log)}]
    if result.returncode == 0:
        preflight = BUILD / 'swiftpm/arm64-apple-macosx/debug/real-integration-preflight'
        # These all use nonexistent paths and MUST succeed/refuse without opening them.
        for arguments, expected in [([], 0), (['--help'], 0), (['validate', '--contract', '/not/a/file/real-integration.json'], 0),
            (['--live', '--contract', '/not/a/file/real-integration.json'], 2),
            (['--live', '--authorized-local-fixture', '--engine-ready', '--contract', '/not/a/file/real-integration.json'], 2),
            (['--auth-only', '--help'], 0),
            (['--auth-only', 'validate', '--contract', '/not/a/file/auth-only.json'], 0),
            (['--auth-only', '--live', '--contract', '/not/a/file/auth-only.json'], 2),
            (['--auth-only', '--live', '--authorized-local-fixture', '--engine-ready', '--contract', '/not/a/file/auth-only.json'], 2),
            (['--openssh-auth', '--help'], 0),
            (['--openssh-auth', 'validate', '--contract', '/not/a/file/openssh-auth.json'], 0),
            (['--openssh-auth', '--live', '--contract', '/not/a/file/openssh-auth.json'], 2),
            (['--openssh-auth', '--live', '--authorized-local-fixture', '--engine-ready', '--contract', '/not/a/file/openssh-auth.json'], 2),
            (['--sftp-auth', '--help'], 0),
            (['--sftp-auth', 'validate', '--contract', '/not/a/file/sftp-auth.json'], 0),
            (['--sftp-auth', '--live', '--contract', '/not/a/file/sftp-auth.json'], 2),
            (['--sftp-auth', '--live', '--authorized-local-fixture', '--engine-ready', '--contract', '/not/a/file/sftp-auth.json'], 2),
            (['--sftp-otp-negative', '--help'], 0),
            (['--sftp-otp-negative', 'validate', '--contract', '/not/a/file/sftp-otp-negative.json'], 0),
            (['--sftp-otp-negative', '--live', '--contract', '/not/a/file/sftp-otp-negative.json'], 2),
            (['--sftp-otp-negative', '--live', '--authorized-local-fixture', '--engine-ready', '--contract', '/not/a/file/sftp-otp-negative.json'], 2),
            (['--saved-password-public', '--help'], 0),
            (['--saved-password-public', 'validate', '--contract', '/not/a/file/saved-password-public.json'], 0),
            (['--saved-password-public', '--live', '--contract', '/not/a/file/saved-password-public.json'], 2),
            (['--saved-password-public', '--live', '--authorized-local-fixture', '--engine-ready', '--contract', '/not/a/file/saved-password-public.json'], 2)]:
            output = subprocess.run([str(preflight), *arguments], cwd=HERE, env=env, capture_output=True, timeout=10)
            checks.append({'command': [str(preflight), *arguments], 'cwd': str(HERE), 'exitCode': output.returncode, 'expectedExitCode': expected})
            if output.returncode != expected:
                result = output
                break
        static = subprocess.run([sys.executable, '-B', str(HERE / 'test_static.py')], cwd=HERE, env=env, capture_output=True, timeout=30)
        (BUILD / 'static-tests.log').write_bytes(static.stdout + static.stderr)
        checks.append({'command': [sys.executable, '-B', str(HERE / 'test_static.py')], 'cwd': str(HERE), 'exitCode': static.returncode, 'log': str(BUILD / 'static-tests.log')})
        if static.returncode:
            result = static
    (BUILD / 'offline-verification.json').write_text(json.dumps(checks, indent=2) + '\n')
    print('Offline checks exit ' + str(result.returncode) + '; logs: ' + str(log) + ' and ' + str(BUILD / 'static-tests.log'))
    print((result.stdout + result.stderr).decode()[-14000:])
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())
