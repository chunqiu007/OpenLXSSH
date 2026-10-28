#!/usr/bin/env python3
"""Independent offline native read-only/transfer-phase source/test/build checkpoint. NO live action.

Default/help/validate performs no file/subprocess/network I/O. 'build' copies cached
SPM material into its own DerivedData UUID, uses automatic resolution OFF, runs App
unit tests without any --real-fixture-test invocation, builds shipping min26 variants,
and Development-signs only the independently built HostProbe App/helper. No Docker,
collect, relay, credential generation read, certificate creation or Apple upload.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parent.parent
BASE = ROOT / 'DerivedData/AppRealIntegration'
CACHED = ROOT / 'DerivedData/SourcePackages'
NATIVE = ROOT / 'Packages/OpenLXSSHFiles/.build/native'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')


def build(reuse_diagnostic=False):
    os.umask(0o077)
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if BASE.resolve() != BASE or stat.S_IMODE(BASE.stat().st_mode) != 0o700:
        raise ValueError('unsafeIndependentRoot')
    if reuse_diagnostic:
        tree = BASE / 'offline-853dd2e8-feff-4491-bc00-cf97bedfbfe4'
        prior = json.loads((tree / 'result.json').read_bytes())
        if prior['status'] != 'passed-source-offline-only-no-live': raise ValueError('invalidOwnedReuseBaseline')
        work = tree / ('diagnostic-' + str(uuid.uuid4()))
        work.mkdir(mode=0o700)
        for name in ('home', 'tmp', 'logs', 'module-cache', 'clang-cache'): (work / name).mkdir(mode=0o700)
    else:
        work = BASE / ('offline-' + str(uuid.uuid4()))
        work.mkdir(mode=0o700)
        for name in ('home', 'tmp', 'logs', 'module-cache', 'clang-cache', 'SourcePackages'): (work / name).mkdir(mode=0o700)
        tree = work
    print('Independent App-real offline checkpoint: ' + str(work), flush=True)
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(work / 'home'), 'LANG': 'C', 'LC_ALL': 'C',
           'TMPDIR': str(work / 'tmp') + '/', 'CLANG_MODULE_CACHE_PATH': str(work / 'clang-cache'),
           'SWIFTPM_MODULECACHE_OVERRIDE': str(work / 'module-cache'), 'PYTHONDONTWRITEBYTECODE': '1', 'GIT_OPTIONAL_LOCKS': '0'}
    record = {'taskID': 'APP-REAL-BATCH-OVERWRITE-PREP-A' if reuse_diagnostic else 'APP-REAL-TRANSFER-PREP-A', 'liveExecuted': False, 'fixtureRead': False, 'dockerInvoked': False,
              'resolutionRequested': False, 'status': 'building', 'startedAt': time.time()}
    commands = []
    inputs = [ROOT / 'OpenLXSSH.xcodeproj/project.pbxproj', ROOT / 'OpenLXSSH.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved',
              *sorted((ROOT / 'Application/OpenLXSSH').glob('*.swift')), *sorted((ROOT / 'Tests/OpenLXSSHAppTests').glob('*.swift')),
              Path(__file__).absolute(), ROOT / 'Scripts/verify-build-plugin.py', ROOT / 'Scripts/verify-files-native.py',
              *sorted((ROOT / 'Packages').glob('*/Package.swift')), *sorted((ROOT / 'Packages').glob('*/Package.resolved'))]
    hashes = {str(path): sha(path) for path in inputs}

    def run(label, args, configuration=None, private=False, expected=0, timeout=600):
        current = dict(env)
        if configuration == 'HostProbe': current['OPENLXSSH_TRANSPORT_HOST_PROBE'] = '1'
        elif configuration is not None: current['OPENLXSSH_FILES_TARGET26'] = '1'
        if private: current['HOME'] = str(Path.home())
        start = time.monotonic()
        result = subprocess.run(list(map(str, args)), cwd=ROOT, env=current, capture_output=True, timeout=timeout)
        entry = {'label': label, 'cwd': str(ROOT), 'command': '<existing Development identity signing only>' if private else list(map(str, args)),
                 'exitCode': result.returncode, 'expectedExitCode': expected, 'elapsedSeconds': time.monotonic()-start}
        commands.append(entry)
        if not private:
            log = work / 'logs' / (label + '.log'); log.write_bytes(result.stdout + result.stderr); entry['log'] = str(log)
        if result.returncode != expected: raise ValueError(label + 'Failed')
        return result.stdout + result.stderr

    def unchanged():
        if any(sha(Path(path)) != value for path, value in hashes.items()): raise ValueError('sourceChangedDuringOfflineBuild')

    try:
        # Existing exact checkout gate is read-only. All build workspaces/checkouts below are copies.
        run('cached-checkout-gate', [sys.executable, '-B', ROOT / 'Scripts/verify-build-plugin.py', CACHED / 'checkouts'])
        run('native-readonly-gate', [sys.executable, '-B', ROOT / 'Scripts/verify-files-native.py'])
        manifest = json.loads((NATIVE / 'manifest.json').read_bytes())
        for relative, expected in manifest['outputs'].items():
            if sha(NATIVE / relative) != expected: raise ValueError('nativeManifestChanged')
        record['nativeOutputsChecked'] = len(manifest['outputs'])
        if not reuse_diagnostic:
            for name in ('checkouts', 'repositories', 'artifacts'):
                shutil.copytree(CACHED / name, tree / 'SourcePackages' / name, symlinks=True)
            workspace = (CACHED / 'workspace-state.json').read_text().replace(str(CACHED), str(tree / 'SourcePackages'))
            (tree / 'SourcePackages/workspace-state.json').write_text(workspace)
            shutil.copyfile(ROOT / 'OpenLXSSH.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved', work / 'Package.resolved.before')
        else:
            record['reusedPrivateDerivedData'] = str(tree)
            record['reusedPriorShippingMin26Evidence'] = str(tree / 'result.json')
        plugin = tree / 'SourcePackages/checkouts'
        run('private-checkout-gate', [sys.executable, '-B', ROOT / 'Scripts/verify-build-plugin.py', plugin])
        for configuration in (('HostProbe',) if reuse_diagnostic else ('HostProbe', 'Debug', 'Release')):
            common = ['/usr/bin/xcodebuild', '-project', ROOT / 'OpenLXSSH.xcodeproj', '-scheme', 'OpenLXSSH-HostProbe' if configuration == 'HostProbe' else 'OpenLXSSH',
                '-configuration', configuration, '-destination', 'platform=macOS,arch=arm64', '-derivedDataPath', tree / configuration,
                '-clonedSourcePackagesDirPath', tree / 'SourcePackages', '-disableAutomaticPackageResolution', '-onlyUsePackageVersionsFromResolvedFile',
                '-skipPackageUpdates', '-skipPackagePluginValidation', '-disablePackageRepositoryCache',
                'CODE_SIGNING_ALLOWED=NO', 'ARCHS=arm64', 'ONLY_ACTIVE_ARCH=YES',
                'MACOSX_DEPLOYMENT_TARGET=' + ('15.0' if configuration == 'HostProbe' else '26.0')]
            run(configuration + '-build', common + ['build-for-testing' if configuration == 'HostProbe' else 'build'], configuration)
            app = tree / configuration / 'Build/Products' / configuration / 'OpenLXSSH.app'
            binary = app / 'Contents/MacOS/OpenLXSSH'
            load = run(configuration + '-vtool', ['/usr/bin/xcrun', 'vtool', '-show-build', binary]).decode()
            if not re.search(r'minos\s+' + ('15.0' if configuration == 'HostProbe' else '26.0'), load): raise ValueError('minimumOSMismatch')
            if configuration == 'HostProbe':
                run('HostProbe-unit-tests', common + ['test-without-building'], configuration)
            else:
                # Compiled shipping binaries must exclude runtime/test implementation and flag is guarded.
                symbols = run(configuration + '-symbols', ['/usr/bin/xcrun', 'nm', binary])
                if b'AppRealOwnedStore' in symbols or b'AppRealObservedFiles' in symbols: raise ValueError('realFixtureRuntimeInShippingBinary')
        helper = ROOT / 'DerivedData/Askpass-HostProbe/arm64-apple-macosx/debug/openlxssh-askpass'
        helper_digest = sha(helper)
        if 'minos 15.0' not in run('cached-helper-vtool', ['/usr/bin/xcrun', 'vtool', '-show-build', helper]).decode():
            raise ValueError('helperNotHost15')
        app = tree / 'HostProbe/Build/Products/HostProbe/OpenLXSSH.app'
        (app / 'Contents/Helpers').mkdir(mode=0o700, exist_ok=True)
        shutil.copyfile(helper, app / 'Contents/Helpers/openlxssh-askpass'); (app / 'Contents/Helpers/openlxssh-askpass').chmod(0o700)
        for path in (ROOT / 'Packages/OpenLXSSHTransport/ThirdPartyNotices').iterdir(): shutil.copyfile(path, app / 'Contents/Resources' / path.name)
        plist = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
        plist['OpenLXSSHRealFixtureHostProbe'] = True; plist['OpenLXSSHRealFixtureBuildEpoch'] = time.time()
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(plist))
        # Existing Development identity lookup stays private; no certificate/identity details stored.
        query = subprocess.run(['/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning'], cwd=ROOT,
            env={**env, 'HOME': str(Path.home())}, capture_output=True, timeout=20)
        matches = re.findall(rb'^\s*\d+\)\s+([A-F0-9]{40})\s+"Apple Development:[^"\r\n]+"\s*$', query.stdout, re.M)
        if query.returncode or len(matches) != 1: raise ValueError('oneExistingDevelopmentIdentityRequired')
        signing_teams = []
        for label, path, identifier in [('helper', app / 'Contents/Helpers/openlxssh-askpass', 'org.openlxssh.askpass'), ('app', app, 'org.openlxssh.OpenLXSSH')]:
            run('sign-' + label, ['/usr/bin/codesign', '--force', '--sign', matches[0].decode(), '--identifier', identifier, '--options', 'runtime', '--timestamp=none', path], private=True)
            run('strict-' + label, ['/usr/bin/codesign', '--verify', '--strict', *(['--deep'] if label == 'app' else []), path])
            display = subprocess.run(['/usr/bin/codesign', '--display', '--verbose=4', str(path)], cwd=ROOT, env=env, capture_output=True, timeout=20)
            text = display.stdout + display.stderr
            entitlements = subprocess.run(['/usr/bin/codesign', '--display', '--entitlements', ':-', str(path)], cwd=ROOT, env=env, capture_output=True, timeout=20)
            team = re.search(rb'^TeamIdentifier=([A-Z0-9]{10})$', text, re.M)
            if (display.returncode or entitlements.returncode or not team or b'Identifier=' + identifier.encode() + b'\n' not in text
                    or b'Signature=adhoc' in text or not re.search(rb'^CodeDirectory .*\bruntime\b', text, re.M)
                    or not re.search(rb'^Authority=Apple Development:', text, re.M)
                    or (entitlements.stdout.strip() and plistlib.loads(entitlements.stdout))):
                raise ValueError('strictDevelopmentSignaturePolicy')
            signing_teams.append(team[1].decode())
        if len(set(signing_teams)) != 1: raise ValueError('helperAppTeamMismatch')
        record['signature'] = {'sameTeam': True, 'appIdentifier': 'org.openlxssh.OpenLXSSH', 'helperIdentifier': 'org.openlxssh.askpass',
            'runtime': True, 'entitlements': {}, 'Development': True, 'identityDetailsRecorded': False, 'timestamp': 'none'}
        binary = app / 'Contents/MacOS/OpenLXSSH'
        run('pure-help', [binary, '--real-fixture-help'])
        run('pure-validate', [binary, '--real-fixture-validate', '--real-fixture-contract', '/not/opened/app-real-integration.json'])
        run('missing-live-gate', [binary, '--real-fixture-test', '--real-fixture-contract', '/not/opened/app-real-integration.json'], expected=64)
        unchanged()
        if sha(helper) != helper_digest: raise ValueError('sharedHelperChanged')
        record.update(status='passed-source-offline-only-no-live', app=str(app), appBinarySHA256=sha(binary), helperSHA256=sha(app / 'Contents/Helpers/openlxssh-askpass'),
            buildEpoch=plist['OpenLXSSHRealFixtureBuildEpoch'], sourceSHA256=hashes, hostMinimum='15.0', productMinimum='26.0')
        print('App-real source/offline tests/build complete; NO live fixture/App connection. App: ' + str(app))
        return 0
    except Exception as error:
        record.update(status='failed-offline-only', failure=str(error) if isinstance(error, ValueError) else type(error).__name__)
        raise
    finally:
        save(work / 'commands.json', commands); save(work / 'result.json', record)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('help', 'validate', 'build', 'diagnostic'), nargs='?', default='help')
    args = parser.parse_args(argv)
    if args.action == 'help': parser.print_help(); return 0
    if args.action == 'validate': print('Offline command recipe syntax only; no filesystem/network work.'); return 0
    return build(reuse_diagnostic=args.action == 'diagnostic')


if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as error:
        sys.stderr.write('App-real offline checkpoint failed: ' + type(error).__name__ + '. Inspect independent logs.\n'); sys.exit(2)
