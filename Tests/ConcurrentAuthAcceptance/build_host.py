#!/usr/bin/env python3
"""Incremental host15 test-only build/sign and inert CLI checks. Never executes live mode.

Default/help/validate do not import the compiler recipe or inspect parent files.
Only build --sign-development uses the reviewed f201 inputs read-only. No dependency,
C, helper or native rebuild, package resolution, Docker, fixture collection or network.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
ROOT = HERE.parent.parent
PARENT = ROOT / 'Tests/RealIntegration/.build/host-f20119c1-8514-4545-b4d0-eb9562da4d0d'
PARENT_SHA = '1130bd88aae8c286f2271cff2cee7c67caa3f915c508d17dc4187ea1cd93225c'
RECIPE = ROOT / 'Tests/RealIntegration/build_host.py'
RECIPE_SHA = '81113daf0d03b79fc623bde0037f65f0f14afa7dc8fe9b8fc2222a1bf91a9883'
CORE_MODULE_HASHES = {'RealIntegrationCore.swiftmodule': 'c2169b89eefed705f970ea0fc8c8c8158762bf44ecedc0612ed37288baabc302',
    'RealIntegrationCore.swiftdoc': '7dcfebbc58a20f495b27ab9e25357a7056be201e2716ee3bff9b4209c83c6f5e',
    'RealIntegrationCore.swiftsourceinfo': '77cee6c9b9eb82fd06a91da3bea1e63018ca451f45d8d2fee416440c9bbf5550',
    'RealIntegrationCore.abi.json': '4277ac6b49f8511196028a5ac20f5b1b1dfa754c24615d34068089f0b1739728'}


def digest(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o022 or path.resolve() != path:
        raise ValueError('unsafeRecipeOrManifest')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(sign):
    if not sign:
        raise ValueError('explicitDevelopmentSigningRequired')
    if digest(RECIPE) != RECIPE_SHA or digest(PARENT / 'result.json') != PARENT_SHA:
        raise ValueError('reviewedRecipeOrF201Changed')
    spec = importlib.util.spec_from_file_location('concurrent_reviewed_builder', RECIPE)
    accepted = importlib.util.module_from_spec(spec); spec.loader.exec_module(accepted)
    accepted.HERE = HERE
    parent = json.loads((PARENT / 'result.json').read_bytes())
    os.umask(0o077)
    base = HERE / '.build'; base.mkdir(mode=0o700, exist_ok=True)
    if base.resolve() != base or base.stat().st_uid != os.getuid() or stat.S_IMODE(base.stat().st_mode) != 0o700:
        raise accepted.Refusal('unsafeOwnBuildRoot')
    work = base / ('host-' + str(uuid.uuid4())); work.mkdir(mode=0o700)

    class IncrementalBuilder(accepted.Builder):
        def run(self, label, argv, private=False, timeout=300, expected=0):
            env = accepted.environment(self.work)
            if private: env['HOME'] = str(Path.home())
            result = subprocess.run(list(map(str, argv)), cwd=HERE, env=env, capture_output=True, timeout=timeout)
            entry = {'label': label, 'cwd': str(HERE), 'command': '<private existing Development identity command>' if private else list(map(str, argv)),
                     'exitCode': result.returncode, 'expectedExitCode': expected}
            self.commands.append(entry)
            if not private:
                log = self.work / 'logs' / (str(len(self.commands)).zfill(3) + '-' + label + '.log')
                with log.open('xb') as stream: stream.write(result.stdout + result.stderr)
                entry['log'] = str(log)
            if result.returncode != expected: raise accepted.Refusal(label + 'Failed')
            return result.stdout + result.stderr

    b = IncrementalBuilder(work)
    b.record.update(taskID='CONCURRENT-AUTH-BUILD-A', parentBuild=str(PARENT), parentManifestSHA256=PARENT_SHA,
        incrementalOnly=True, compiledModules=['OpenLXSSHConcurrentAuth'], dependencyCompiles=0, nativeCompiles=0, helperCompiles=0,
        generationRead=False, credentialStoreInstantiated=False, credentialSecItemActionsExecuted=False, runtimeModes='inert-only', productAcceptance=False)
    print('Own incremental offline build: ' + str(work), flush=True)
    tracked = {}

    def pin(path, expected, exported=False):
        path = Path(path)
        if not path.is_relative_to(ROOT) or accepted.sha(path, native_export=exported) != expected: raise accepted.Refusal('parentInputChanged')
        tracked[path] = (expected, exported)
        return path

    def unchanged():
        for path, (expected, exported) in tracked.items():
            if accepted.sha(path, native_export=exported) != expected: raise accepted.Refusal('parentChangedDuringBuild')
        b.unchanged()

    try:
        pin(PARENT / 'result.json', PARENT_SHA); pin(RECIPE, RECIPE_SHA)
        if parent['target'] != accepted.TARGET or not parent['testOnly'] or parent['liveExecuted'] or parent['dockerInvoked'] or len(parent['reusedObjects']) != 12:
            raise accepted.Refusal('wrongParentPolicy')
        for item in parent['inputs']:
            exported = item['path'].startswith(str(accepted.NATIVE / 'install') + '/')
            pin(item['path'], item['sha256'], exported); pin(item['snapshot'], item['sha256'])
        for item in parent['newSourceHashes']: pin(item['path'], item['sha256'])
        for item in parent['reusedModulesAndMaps']: pin(item['path'], item['sha256'])
        reused = parent['reusedObjects'] + [item for item in parent['objects'] if item['module'] == 'RealIntegrationCore']
        if len(reused) != 13 or len({item['path'] for item in reused}) != 13: raise accepted.Refusal('wrongObjectClosure')
        objects = [pin(item['path'], item['sha256']) for item in reused]
        for item in reused: accepted.minimum(item['path'], 1)
        b.record['reusedObjects'] = reused
        helper = pin(Path(parent['app']) / 'Contents/Helpers/openlxssh-askpass', parent['helper']['sha256'])
        parent_driver = pin(Path(parent['app']) / 'Contents/MacOS/OpenLXSSHRealIntegration', parent['driver']['sha256'])
        accepted.minimum(helper, 2); accepted.minimum(parent_driver, 2)
        b.record.update(parentDriverSHA256=parent['driver']['sha256'], parentHelperSHA256=parent['helper']['sha256'])
        if b.verify_signature(helper, accepted.HELPER_ID) != b.verify_signature(Path(parent['app']), accepted.APP_ID, deep=True):
            raise accepted.Refusal('parentTeamMismatch')
        for path in [RECIPE, HERE / 'build_host.py', HERE / 'test_static.py', HERE / '.gitignore', *sorted(HERE.glob('*.swift'))]: b.snapshot(path)
        if accepted.sha(accepted.GATE) != accepted.GATE_SHA256: raise accepted.Refusal('pluginGateChanged')
        b.snapshot(accepted.GATE)
        b.run('readonly-pinned-checkout-gate', [sys.executable, '-B', accepted.GATE, accepted.CHECKOUTS, '--helper'])
        module_pins = dict(CORE_MODULE_HASHES)
        for item in parent['reusedModulesAndMaps']:
            source = Path(item['path'])
            if source.parent.name == 'modules': module_pins[source.name] = item['sha256']
            else:
                relative = source.relative_to(Path(parent['parentBuild']) / 'cmodules')
                current = pin(PARENT / 'cmodules' / relative, item['sha256'])
                target = work / 'cmodules' / relative; target.parent.mkdir(mode=0o700, exist_ok=True)
                shutil.copyfile(b.snapshot(current), target); target.chmod(0o400)
                tracked[target] = (item['sha256'], False)
        for name, expected in module_pins.items():
            source = pin(PARENT / 'modules' / name, expected)
            target = work / 'modules' / name; shutil.copyfile(b.snapshot(source), target); target.chmod(0o400)
            tracked[target] = (expected, False)
        b.record['reusedModulesAndMaps'] = [{'path': str(p), 'sha256': v[0]} for p, v in tracked.items() if '/modules/' in str(p) or p.suffix == '.modulemap']
        by_source = {item['path']: item for item in parent['inputs']}
        archives = [Path(by_source[str(accepted.NATIVE / 'install/lib' / name)]['snapshot']) for name in ('libssh2.a', 'libssl.a', 'libcrypto.a')]
        native_include = Path(by_source[str(accepted.NATIVE / 'install/include/libssh2.h')]['snapshot']).parent
        b.record['reusedNativeArchives'] = [{'path': str(p), 'sha256': accepted.sha(p)} for p in archives]
        # Only the exact reviewed pre-SSHCase prefix is needed. No parent's @main,
        # broad OpenSSHCaseOwner, SFTP, saved-password or CredentialStore consumer.
        source = by_source[str(ROOT / 'Tests/RealIntegration/Consumer/ProductionConsumer.swift')]
        production = Path(source['snapshot']).read_bytes()
        marker = b'@MainActor final class SSHCase {'
        if production.count(marker) != 1: raise accepted.Refusal('guardPrefixChanged')
        guards = work / 'generated/ParentGuards.swift'
        guards.write_bytes(production.split(marker)[0]); guards.chmod(0o400)
        tracked[guards] = (accepted.sha(guards), False)
        management = by_source[str(ROOT / 'Tests/RealIntegration/Consumer/OpenSSHManagement.swift')]
        sources = [b.snapshot(HERE / name) for name in ('Core.swift', 'ConcurrentCase.swift', 'Main.swift')]
        sources += [guards, b.snapshot(Path(management['snapshot']))]
        b.record['compiledSources'] = [{'path': str(p), 'sha256': accepted.sha(p)} for p in sources]
        b.tools()
        obj = b.swift_compile('OpenLXSSHConcurrentAuth', sources, package='realintegration',
            extra=['-warnings-as-errors', '-DTRANSPORT_HOST_PROBE', '-Xcc', '-I' + str(native_include)])
        symbols = b.run('consumer-public-api-symbols', ['/usr/bin/xcrun', 'nm', '-u', obj])
        if b'DirectSSHSession' not in symbols or any(value in symbols for value in (b'startProbe', b'configureProbe', b'probeStore', b'CredentialStore', b'LibSSH2FileService')):
            raise accepted.Refusal('notSolePublicTransportAPI')
        driver = b.link('OpenLXSSHConcurrentAuth', [obj, *objects], archives)
        app = work / 'OpenLXSSHConcurrentAuth.app'
        for name in ('Contents/MacOS', 'Contents/Helpers'): (app / name).mkdir(mode=0o700, parents=True)
        executable = app / 'Contents/MacOS/OpenLXSSHConcurrentAuth'
        shutil.copyfile(driver, executable); shutil.copyfile(helper, app / 'Contents/Helpers/openlxssh-askpass')
        for binary in (executable, app / 'Contents/Helpers/openlxssh-askpass'): binary.chmod(0o700)
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': accepted.APP_ID, 'CFBundleName': 'OpenLXSSHConcurrentAuth',
            'CFBundleExecutable': 'OpenLXSSHConcurrentAuth', 'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1', 'LSMinimumSystemVersion': '15.0', 'LSUIElement': True,
            'OpenLXSSHRealIntegrationTestOnly': True, 'OpenLXSSHConcurrentAuthTestOnly': True,
            'RealIntegrationFixtureRoot': str(ROOT / 'Tests/IntegrationEnvironment'), 'RealIntegrationBuildRoot': str(ROOT / 'Tests/RealIntegration/.build'),
            'ConcurrentAuthBuildRoot': str(base)}))
        b.sign(app)
        b.run('source-contract-tests', [sys.executable, '-B', '-m', 'unittest', 'discover', '-s', HERE, '-p', 'test_*.py', '-v'])
        before = sorted(p.name for p in base.iterdir())
        for name, args, expected in [('default', [], 0), ('help', ['--help'], 0), ('validate', ['--validate'], 0), ('offline', ['--offline-check'], 0),
                                    ('missing-release', ['--execute', '--contract', '/not/opened/contract.json'], 2),
                                    ('invalid-path', ['--execute', '--primary-release', '--contract', '/not/../opened'], 2)]:
            b.run('cli-' + name, [executable, *args], expected=expected, timeout=30)
        if sorted(p.name for p in base.iterdir()) != before: raise accepted.Refusal('inertModeCreatedRun')
        unchanged()
        b.record.update(status='signed-offline-passed-live-not-run', app=str(app), parentInputsAndObjectsUnchanged=True,
            parentInputCount=len(parent['inputs']), trackedHashCount=len(tracked),
            driver={'sha256': accepted.sha(executable), 'metadata': accepted.minimum(executable, 2)},
            helper={'sha256': accepted.sha(app / 'Contents/Helpers/openlxssh-askpass'), 'metadata': accepted.minimum(app / 'Contents/Helpers/openlxssh-askpass', 2)})
        print('Signed concurrent auth consumer offline checks passed; NO real concurrent authentication, Docker or fixture input reads.')
        print('Exact App: ' + str(app)); return 0
    except BaseException as error:
        b.record.update(status='failed-offline-live-not-run', failure=str(error) if isinstance(error, accepted.Refusal) else type(error).__name__)
        raise
    finally:
        b.save()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='help', choices=('help', 'validate', 'build'))
    parser.add_argument('--sign-development', action='store_true')
    args = parser.parse_args(argv)
    if args.action == 'help': parser.print_help(); return 0
    if args.action == 'validate' and not args.sign_development: print('Syntax only; no input/build/signing/live operations.'); return 0
    if args.action != 'build': raise ValueError('invalidArguments')
    return build(args.sign_development)


if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as error:
        sys.stderr.write('Concurrent auth offline build refused: ' + type(error).__name__ + '; no private details.\n'); sys.exit(2)
