#!/usr/bin/env python3
"""Offline-only independent Disconnect build; default/help/validate do no I/O.

Reuses the accepted build class read-only, never its full-campaign build/run action.
No SwiftPM, native rebuild, credential reads, Docker, relay or network is invoked.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
PARENT = HERE.parent
ROOT = PARENT.parent.parent


def build():
    # Imports the reviewed builder only after explicit offline build action.
    spec = importlib.util.spec_from_file_location('accepted_remote_builder', PARENT / 'build_host.py')
    accepted = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(accepted)
    os.umask(0o077)
    build_root = PARENT / '.build'
    build_root.mkdir(mode=0o700, exist_ok=True)
    if build_root.resolve() != build_root or build_root.stat().st_uid != os.getuid() or build_root.stat().st_mode & 0o777 != 0o700:
        raise accepted.Refusal('unsafeBuildRoot')
    work = build_root / ('disconnect-host-' + str(uuid.uuid4()))
    work.mkdir(mode=0o700)
    print('Independent disconnect offline build: ' + str(work), flush=True)
    b = accepted.Builder(work)
    b.record['taskID'] = 'REAL-SFTP-DISCONNECT-PREP-A'
    b.record['fullCampaignExecuted'] = False
    try:
        for path in [PARENT / 'build_host.py', PARENT / '.gitignore', HERE / 'build_host.py', HERE / 'test_static.py', HERE / 'coordinator.py',
                     accepted.FILES / 'Package.swift', accepted.FILES / 'native-inputs.json', ROOT / 'Packages/OpenLXSSHTrust/Package.swift']:
            b.snapshot(path)
        manifest = json.loads(b.snapshot(accepted.NATIVE / 'manifest.json').read_bytes())
        lock = json.loads((accepted.FILES / 'native-inputs.json').read_bytes())
        if (manifest['dependencies']['toolchain']['deploymentTarget'] != '15.0'
                or manifest['inputs']['lockSHA256'] != accepted.digest(accepted.FILES / 'native-inputs.json')
                or any(manifest['dependencies'][key] != lock[key] for key in ('libssh2', 'openssl'))):
            raise accepted.Refusal('nativeInputMismatch')
        for relative, expected in manifest['outputs'].items():
            if not relative.startswith('install/') or '..' in Path(relative).parts or accepted.digest(accepted.NATIVE / relative, True) != expected:
                raise accepted.Refusal('nativeOutputMismatch')
            b.snapshot(accepted.NATIVE / relative, True)
        native = work / 'inputs' / accepted.NATIVE.relative_to(ROOT) / 'install'
        b.swiftc = b.run('locate-swiftc', ['/usr/bin/xcrun', '-f', 'swiftc']).decode().strip()
        b.clang = b.run('locate-clang', ['/usr/bin/xcrun', '-f', 'clang']).decode().strip()
        b.sdk = b.run('locate-sdk', ['/usr/bin/xcrun', '--show-sdk-path']).decode().strip()
        b.run('swift-version', [b.swiftc, '--version'])
        cobjects = b.c('COpenLXSSHFiles', accepted.FILES / 'Sources/COpenLXSSHFiles', native / 'include')
        cobjects += b.c('RealIntegrationPOSIX', accepted.CORE / 'RealIntegrationPOSIX')
        cobjects += b.c('StressMetrics', ROOT / 'Tests/LocalFileStress/Sources/StressMetrics')
        cobjects += b.c('RemoteFileMetrics', PARENT / 'POSIX')
        objects = []
        for name, directory, package in [
            ('OpenLXSSHTrust', ROOT / 'Packages/OpenLXSSHTrust/Sources/OpenLXSSHTrust', 'openlxsshtrust'),
            ('OpenLXSSHFiles', accepted.FILES / 'Sources/OpenLXSSHFiles', 'openlxsshfiles'),
            ('RealIntegrationCore', accepted.CORE / 'RealIntegrationCore', 'realintegration')]:
            objects.append(b.swift(name, b.sources(directory), native / 'include', package))
        location = work / 'BuildLocation.swift'
        location.write_text('enum BuildLocation { static let ownRoot = ' + json.dumps(str(PARENT)) +
            '; static let fixtureRoot = ' + json.dumps(str(ROOT / 'Tests/IntegrationEnvironment')) +
            '; static let offlineRoot = ' + json.dumps(str(work / 'test-data')) +
            '; static let buildEvidence = ' + json.dumps(str(work / 'result.json')) +
            '; static let offlinePreparedAt = ' + repr(time.time()) + ' }\n')
        shared = [b.snapshot(PARENT / name) for name in ('Core.swift', 'Observation.swift', 'Campaign.swift')]
        shared += [b.snapshot(HERE / name) for name in ('DisconnectCore.swift', 'DisconnectCase.swift')]
        obj = b.swift('OpenLXSSHUploadDisconnectCase', shared + [location, b.snapshot(HERE / 'Main.swift')], native / 'include')
        undefined = b.run('production-symbols', ['/usr/bin/xcrun', 'nm', '-u', obj])
        for required in (b'LibSSH2FileService', b'SafeTransferEngine', b'TransferManager'):
            if required not in undefined:
                raise accepted.Refusal('missingProductionAPI')
        archives = [native / 'lib' / name for name in ('libssh2.a', 'libssl.a', 'libcrypto.a')]
        driver = b.link('OpenLXSSHUploadDisconnectCase', [obj, *objects, *cobjects], archives)
        test_obj = b.swift('OpenLXSSHDisconnectOfflineTests', shared + [location, b.snapshot(HERE / 'OfflineMain.swift')], native / 'include')
        tests = b.link('OpenLXSSHDisconnectOfflineTests', [test_obj, *objects, *cobjects], archives)
        b.unchanged()
        b.run('static-disconnect-tests', [sys.executable, '-B', HERE / 'test_static.py'])
        b.run('offline-disconnect-tests', [tests])
        b.run('cli-default-no-io', [driver])
        b.run('cli-help-no-io', [driver, '--help'])
        b.run('cli-validate-no-io', [driver, 'validate', '--case', '/not/opened/case.json'])
        b.run('cli-upload-no-authorization', [driver, '--disconnect-case', '--case', '/not/opened/case.json'], expected=2)
        b.run('cli-verify-no-authorization', [driver, '--verify-disconnect-case', '--case', '/not/opened/case.json'], expected=2)
        b.unchanged()
        b.record.update(status='passed-disconnect-offline-only-live-not-run', driver=str(driver), driverSHA256=accepted.digest(driver),
            nativeOutputsChecked=len(manifest['outputs']), architecture=accepted.macho(driver, 2))
        print('Disconnect source/offline point passed. NO relay, credential read, generation or live connection.')
        print('Exact driver: ' + str(driver)); return 0
    except (OSError, ValueError, KeyError) as error:
        b.record.update(status='failed-disconnect-offline', failure=type(error).__name__)
        raise
    finally:
        b.save()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('help', 'validate', 'build'), nargs='?', default='help')
    args = parser.parse_args(argv)
    if args.action == 'help':
        parser.print_help(); return 0
    if args.action == 'validate':
        print('Offline recipe syntax only; no files, compiler, Docker, credential or network I/O.'); return 0
    return build()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.stderr.write('Disconnect offline build failed: ' + type(error).__name__ + '. No secret details.\n')
        sys.exit(2)
