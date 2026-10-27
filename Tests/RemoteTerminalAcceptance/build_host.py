#!/usr/bin/env python3
"""Own-subtree host15 static build/sign only. No generation read, Docker, socket or live."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
ROOT = HERE.parent.parent
RECIPE = ROOT / 'Tests/RealIntegration/build_host.py'


def build(sign):
    spec = importlib.util.spec_from_file_location('remote_terminal_reviewed_builder', RECIPE)
    accepted = importlib.util.module_from_spec(spec); spec.loader.exec_module(accepted)
    # Reuse the reviewed compiler/snapshot/signature owner, not its broad consumer builder.
    accepted.HERE = HERE
    os.umask(0o077)
    base = HERE / '.build'; base.mkdir(mode=0o700, exist_ok=True)
    if base.is_symlink() or base.resolve() != base or base.stat().st_uid != os.getuid() or stat.S_IMODE(base.stat().st_mode) != 0o700:
        raise accepted.Refusal('unsafeOwnBuildRoot')
    work = base / ('host-' + str(uuid.uuid4())); work.mkdir(mode=0o700)
    builder = accepted.Builder(work)
    builder.record.update(taskID='REAL-OUTER-PTY-TUI-PREP-A', generationRead=False, socketsOpened=False,
                          nestedAuthentication=False, ime=False, productAcceptance=False)
    print('Own offline terminal build: ' + str(work), flush=True)
    try:
        builder.snapshot(RECIPE)
        for path in sorted(HERE.glob('*')):
            if path.is_file() and path.suffix in ('.swift', '.py') or path.name == '.gitignore': builder.snapshot(path)
        if accepted.sha(accepted.GATE) != accepted.GATE_SHA256: raise accepted.Refusal('pluginGateChanged')
        builder.snapshot(accepted.GATE)
        builder.run('readonly-pinned-checkout-gate', [sys.executable, '-B', accepted.GATE, accepted.CHECKOUTS, '--helper'])
        builder.snapshot(accepted.TRANSPORT / 'Package.swift'); builder.snapshot(accepted.TRANSPORT / 'Package.resolved')
        builder.snapshot(ROOT / 'Packages/OpenLXSSHTrust/Package.swift')
        builder.tools()
        swiftterm = accepted.CHECKOUTS / 'SwiftTerm'
        builder.snapshot(swiftterm / 'swifterm-terminfo'); builder.snapshot(swiftterm / 'Package.swift')
        generator = work / 'artifacts/SwiftTermBuildInfoGenerator-host-only'
        builder.run('compile-official-generator', [builder.swift, '-O', '-parse-as-library', '-target', accepted.TARGET, '-sdk', builder.sdk,
                    '-module-cache-path', work / 'module-cache', *builder.sources(swiftterm / 'Sources/SwiftTermBuildInfoGenerator'), '-o', generator])
        generated = [work / 'generated/SwiftTermBuildInfo.swift', work / 'generated/SwiftTermTerminfo.swift']
        builder.run('run-official-generator-only', [generator, swiftterm, *generated])
        cobjects = builder.c_module('COpenLXSSHAskpass', accepted.TRANSPORT / 'Sources/COpenLXSSHAskpass', probe=True)
        cobjects += builder.c_module('RealIntegrationPOSIX', ROOT / 'Tests/RealIntegration/Sources/RealIntegrationPOSIX')
        objects = []
        for name, directory, version, package, extra in [
            ('OpenLXSSHTrust', ROOT / 'Packages/OpenLXSSHTrust/Sources/OpenLXSSHTrust', '6', 'openlxsshtrust', []),
            ('SwiftTerm', swiftterm / 'Sources/SwiftTerm', '6', 'swiftterm', ['-DPortableGraphics', '-user-module-version', '1.99.1']),
            ('OpenLXSSHAskpass', accepted.TRANSPORT / 'Sources/OpenLXSSHAskpass', '5', 'openlxsshtransport', []),
            ('OpenLXSSHTransport', accepted.TRANSPORT / 'Sources/OpenLXSSHTransport', '5', 'openlxsshtransport', ['-DTRANSPORT_HOST_PROBE'])]:
            sources = builder.sources(directory) + (generated if name == 'SwiftTerm' else [])
            objects.append(builder.swift_compile(name, sources, version, package, extra=extra))
        core = builder.swift_compile('RemoteTerminalCore', [builder.snapshot(HERE / 'Core.swift')], extra=['-warnings-as-errors'])
        tests_object = builder.swift_compile('RemoteTerminalOffline', [builder.snapshot(HERE / 'OfflineMain.swift')], extra=['-warnings-as-errors'])
        tests = builder.link('RemoteTerminalOffline', [tests_object, core])
        builder.run('offline-core-tests', [tests]); builder.run('offline-python-tests', [sys.executable, '-B', HERE / 'test_static.py'])
        location = work / 'BuildLocation.swift'
        source = (HERE / 'remote_probe.py').read_bytes()
        # Team is filled after resolving the already-present Development identity below.
        team = 'UNSIGNED00'
        if sign:
            env = accepted.environment(work); env['HOME'] = str(Path.home())
            result = subprocess.run(['/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning'], cwd=HERE, env=env, capture_output=True, timeout=20)
            import re
            matches = re.findall(rb'^\s*\d+\)\s+([A-F0-9]{40})\s+"Apple Development:[^"\r\n]+"\s*$', result.stdout, re.M)
            if result.returncode or len(matches) != 1: raise accepted.Refusal('oneExistingDevelopmentIdentityRequired')
            # Read public Team metadata from an existing signed helper, never create certificates.
            candidates = sorted((ROOT / 'Tests/RealIntegration/.build').glob('host-*/OpenLXSSHRealIntegration.app/Contents/Helpers/openlxssh-askpass'))
            teams = set()
            for candidate in candidates:
                displayed = subprocess.run(['/usr/bin/codesign', '--display', '--verbose=4', str(candidate)], cwd=HERE, env=accepted.environment(work), capture_output=True, timeout=10)
                found = re.search(rb'^TeamIdentifier=([A-Z0-9]{10})$', displayed.stderr, re.M)
                if displayed.returncode == 0 and found: teams.add(found[1].decode())
            if len(teams) != 1: raise accepted.Refusal('oneExistingHelperTeamRequired')
            team = teams.pop()
        location.write_text('enum BuildLocation { static let ownRoot = ' + json.dumps(str(HERE)) + '; static let buildRoot = ' + json.dumps(str(base)) + '; static let fixtureRoot = ' + json.dumps(str(ROOT / 'Tests/IntegrationEnvironment')) + '; static let team = ' + json.dumps(team) + '; static let probeBase64 = ' + json.dumps(base64.b64encode(source).decode()) + '; static let probeSHA256 = ' + json.dumps(hashlib.sha256(source).hexdigest()) + ' }\n')
        helper_object = builder.swift_compile('OpenLXSSHAskpassHelper', builder.sources(accepted.TRANSPORT / 'Sources/OpenLXSSHAskpassHelper'), '5', 'openlxsshtransport', library=False)
        consumer_object = builder.swift_compile('OpenLXSSHRemoteTerminal', [builder.snapshot(HERE / 'Main.swift'), builder.snapshot(HERE / 'LiveInput.swift'), location], extra=['-warnings-as-errors'])
        symbols = builder.run('public-api-symbols', ['/usr/bin/xcrun', 'nm', '-u', consumer_object])
        if b'DirectSSHSession' not in symbols or any(value in symbols for value in (b'startProbe', b'configureProbe', b'probeStore', b'LibSSH2FileService')):
            raise accepted.Refusal('notSolePublicOuterAPI')
        helper = builder.link('openlxssh-askpass', [helper_object, objects[2], *cobjects])
        consumer = builder.link('OpenLXSSHRemoteTerminal', [consumer_object, core, *objects, *cobjects])
        app = work / 'OpenLXSSHRemoteTerminal.app'
        for name in ('Contents/MacOS', 'Contents/Helpers'): (app / name).mkdir(mode=0o700, parents=True)
        import shutil
        shutil.copyfile(helper, app / 'Contents/Helpers/openlxssh-askpass'); shutil.copyfile(consumer, app / 'Contents/MacOS/OpenLXSSHRemoteTerminal')
        for binary in (app / 'Contents/Helpers/openlxssh-askpass', app / 'Contents/MacOS/OpenLXSSHRemoteTerminal'): binary.chmod(0o700)
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': accepted.APP_ID, 'CFBundleName': 'OpenLXSSHRemoteTerminal',
            'CFBundleExecutable': 'OpenLXSSHRemoteTerminal', 'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1', 'LSMinimumSystemVersion': '15.0',
            'LSUIElement': True, 'OpenLXSSHRemoteTerminalTestOnly': True}))
        if sign:
            builder.sign(app)
            if builder.verify_signature(app, accepted.APP_ID, deep=True) != team: raise accepted.Refusal('embeddedTeamMismatch')
        builder.unchanged()
        builder.record.update(status='signed-static-only-not-run' if sign else 'unsigned-static-only-not-run', app=str(app),
            driverSHA256=accepted.sha(app / 'Contents/MacOS/OpenLXSSHRemoteTerminal'), remoteProbeSHA256=hashlib.sha256(source).hexdigest(),
            teamBound=sign, liveExecuted=False, dockerInvoked=False)
        print('Terminal consumer/helper static build complete; NO generation, Docker, sockets or live execution.')
        print('Exact App: ' + str(app))
        return 0
    except BaseException as error:
        builder.record.update(status='failed-static-only', failure=type(error).__name__)
        raise
    finally:
        builder.save()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='help', choices=('help', 'validate', 'build'))
    parser.add_argument('--sign-development', action='store_true')
    args = parser.parse_args(argv)
    if args.action == 'help': parser.print_help(); return 0
    if args.action == 'validate' and not args.sign_development: print('Recipe syntax only; no input/cache/signature/live operations.'); return 0
    if args.action != 'build': raise ValueError('invalid arguments')
    return build(args.sign_development)


if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as error:
        sys.stderr.write('RemoteTerminal static build refused: ' + type(error).__name__ + '; no private details.\n'); sys.exit(2)
