#!/usr/bin/env python3
"""Offline host15 TEST-ONLY build. No resolution/download/Docker/live execution.

Uses reviewed existing SwiftTerm checkout sources and native min15 archives,
read-only. All compiler/generator/cache/signing outputs stay in this subtree's
.build/host-UUID. Default/help/validate perform no source/file I/O. Only 'build'
checks inputs or writes; signing additionally requires --sign-development.
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
import struct
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
ROOT = HERE.parent.parent
BUILD = HERE / '.build'
TRANSPORT = ROOT / 'Packages/OpenLXSSHTransport'
FILES = ROOT / 'Packages/OpenLXSSHFiles'
NATIVE = FILES / '.build/native'
CHECKOUTS = TRANSPORT / '.build/macos26/checkouts'
TARGET = 'arm64-apple-macosx15.0'
APP_ID = 'org.openlxssh.OpenLXSSH'
HELPER_ID = 'org.openlxssh.askpass'
GATE = ROOT / 'Scripts/verify-build-plugin.py'
GATE_SHA256 = 'dec240e64f0a27b66790715d65597df45f3f581c5f82231df28959895cd75dbe'


class Refusal(ValueError):
    pass


def sha(path, native_export=False):
    path = Path(path)
    info = path.lstat()
    # A few reviewed public native export headers/licenses are 0664. They are
    # not credentials: accept only exact locked-manifest outputs, hash-checked
    # before using a private immutable snapshot; never chmod shared inputs.
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or (info.st_mode & (0o002 if native_export else 0o022)) or path.resolve() != path:
        raise Refusal('unsafeBuildInput')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def environment(work):
    return {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(work / 'home'), 'LANG': 'C', 'LC_ALL': 'C',
            'TMPDIR': str(work / 'tmp') + '/', 'CLANG_MODULE_CACHE_PATH': str(work / 'clang-cache'),
            'SWIFTPM_MODULECACHE_OVERRIDE': str(work / 'module-cache'), 'GIT_OPTIONAL_LOCKS': '0',
            'PYTHONDONTWRITEBYTECODE': '1', 'OPENLXSSH_TRANSPORT_HOST_PROBE': '1'}


def write_json(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write('\n')


def minimum(path, kind):
    data = Path(path).read_bytes()
    if len(data) < 32:
        raise Refusal('missingMachOHeader')
    magic, cpu, subtype, actual_kind, count, size, flags, reserved = struct.unpack_from('<IiiIIIII', data)
    if magic != 0xfeedfacf or cpu != 0x0100000c or actual_kind != kind or count > 4096:
        raise Refusal('notArm64MachO')
    position, found = 32, []
    for _ in range(count):
        command, length = struct.unpack_from('<II', data, position)
        if length < 8 or position + length > 32 + size:
            raise Refusal('invalidLoadCommands')
        if command == 0x32:
            platform, version = struct.unpack_from('<II', data, position + 8)
            found.append((platform, version))
        position += length
    if position != 32 + size or found != [(1, 15 << 16)]:
        raise Refusal('notHost15Input')
    return {'architecture': 'arm64', 'minimumOS': '15.0', 'kind': kind}


class Builder:
    def __init__(self, work):
        self.work = work
        self.commands, self.inputs, self.objects = [], {}, []
        for name in ('home', 'tmp', 'logs', 'modules', 'objects', 'module-cache', 'clang-cache', 'cmodules', 'generated', 'artifacts'):
            (work / name).mkdir(mode=0o700)
        self.record = {'taskID': 'LIVE-SMOKE-HOST15-A', 'target': TARGET, 'testOnly': True,
                       'productRuntime': False, 'liveExecuted': False, 'dockerInvoked': False,
                       'hostProbeOptIn': 'OPENLXSSH_TRANSPORT_HOST_PROBE=1', 'status': 'building'}

    def run(self, label, argv, private=False, timeout=300):
        env = environment(self.work)
        if private:  # Existing signing keychain lookup only; compiler caches stay private.
            env['HOME'] = str(Path.home())
        result = subprocess.run(list(map(str, argv)), cwd=HERE, env=env, capture_output=True, timeout=timeout)
        entry = {'label': label, 'cwd': str(HERE), 'command': '<private existing Development identity command>' if private else list(map(str, argv)), 'exitCode': result.returncode}
        self.commands.append(entry)
        if not private:
            log = self.work / 'logs' / (label + '.log')
            log.write_bytes(result.stdout + result.stderr)
            entry['log'] = str(log)
        if result.returncode:
            raise Refusal(label + 'Failed')
        return result.stdout + result.stderr

    def snapshot(self, path, native_export=False):
        path = Path(path)
        if path in self.inputs:
            return self.inputs[path]['snapshot']
        digest = sha(path, native_export=native_export)
        target = self.work / 'inputs' / path.relative_to(ROOT)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(path.read_bytes())
        target.chmod(0o400)
        self.inputs[path] = {'sha256': digest, 'snapshot': target, 'nativeExport': native_export}
        return target

    def sources(self, directory):
        return [self.snapshot(path) for path in sorted(directory.rglob('*.swift'))]

    def unchanged(self):
        for path, item in self.inputs.items():
            if sha(path, native_export=item['nativeExport']) != item['sha256'] or sha(item['snapshot']) != item['sha256']:
                raise Refusal('inputChangedDuringBuild')

    def tools(self):
        self.swift = self.run('locate-swiftc', ['/usr/bin/xcrun', '-f', 'swiftc']).decode().strip()
        self.clang = self.run('locate-clang', ['/usr/bin/xcrun', '-f', 'clang']).decode().strip()
        self.sdk = self.run('locate-sdk', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path']).decode().strip()
        for label, command in [('swift-version', [self.swift, '--version']), ('sdk-version', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version'])]:
            self.run(label, command)

    def swift_compile(self, module, sources, version='6', package=None, extra=(), library=True):
        output = self.work / 'objects' / (module + '.o')
        command = [self.swift, '-emit-object', '-emit-module', '-whole-module-optimization', '-O', '-swift-version', version,
                   '-target', TARGET, '-sdk', self.sdk, '-module-name', module,
                   '-module-cache-path', self.work / 'module-cache', '-I', self.work / 'modules',
                   '-I', self.work / 'cmodules', '-DSWIFT_PACKAGE', '-DSWIFT_MODULE_RESOURCE_BUNDLE_UNAVAILABLE',
                   '-emit-module-path', self.work / 'modules' / (module + '.swiftmodule')]
        for directory in (self.work / 'cmodules').iterdir():
            command += ['-I', directory]
        if library:
            command += ['-parse-as-library']
        if package:
            command += ['-package-name', package]
        self.run('compile-' + module, command + list(extra) + sources + ['-o', output])
        self.objects.append({'module': module, 'path': str(output), 'sha256': sha(output), 'metadata': minimum(output, 1)})
        return output

    def c_module(self, module, directory, native=None, probe=False):
        include = directory / 'include'
        header = self.snapshot(include / (module + '.h'))
        module_dir = self.work / 'cmodules' / module
        module_dir.mkdir(mode=0o700)
        (module_dir / 'module.modulemap').write_text('module ' + module + ' { header "' + str(header) + '" export * }\n')
        result = []
        for source in sorted(directory.glob('*.c')):
            snapshot = self.snapshot(source)
            output = self.work / 'objects' / (module + '-' + source.stem + '.o')
            args = [self.clang, '-c', '-O2', '-fPIC', '-target', TARGET, '-isysroot', self.sdk,
                    '-fmodules', '-fmodules-cache-path=' + str(self.work / 'clang-cache'), '-I', header.parent]
            if native:
                args += ['-I', native]
            if probe:
                args += ['-DTRANSPORT_HOST_PROBE']
            self.run('compile-' + output.stem, args + [snapshot, '-o', output])
            self.objects.append({'module': module, 'path': str(output), 'sha256': sha(output), 'metadata': minimum(output, 1)})
            result.append(output)
        return result

    def link(self, name, objects, archives=()):
        output = self.work / 'artifacts' / name
        self.run('link-' + name, [self.swift, '-emit-executable', '-target', TARGET, '-sdk', self.sdk,
            '-no-toolchain-stdlib-rpath', '-Xlinker', '-no_adhoc_codesign', '-Xlinker', '-map', '-Xlinker', str(output) + '.map',
            *objects, *archives, '-framework', 'AppKit', '-framework', 'Security', '-lbsm', '-lutil', '-lz', '-o', output])
        minimum(output, 2)
        for tool, flags in [('vtool', ['-show-build']), ('otool', ['-L']), ('nm', [])]:
            self.run(tool + '-' + name, ['/usr/bin/xcrun', tool, *flags, output])
        return output

    def verify_signature(self, path, identifier, deep=False):
        self.run('strict-' + identifier, ['/usr/bin/codesign', '--verify', '--strict', *(['--deep'] if deep else []), path])
        # Do not store display/certificate details in logs. Only fixed booleans/Team metadata.
        def display(flags):
            result = subprocess.run(['/usr/bin/codesign', '--display', *flags, str(path)], env=environment(self.work), cwd=HERE, capture_output=True, timeout=30)
            if result.returncode:
                raise Refusal('signatureMetadataFailed')
            return result.stdout, result.stderr
        out, err = display(['--verbose=4'])
        text = out + err
        entitlements, _ = display(['--entitlements', ':-'])
        team = re.search(rb'^TeamIdentifier=([A-Z0-9]{10})$', text, re.M)
        if (b'Identifier=' + identifier.encode() + b'\n' not in text or not team or b'Signature=adhoc' in text
                or not re.search(rb'^CodeDirectory .*\bruntime\b', text, re.M) or re.search(rb'^Timestamp=', text, re.M)
                or not re.search(rb'^Authority=Apple Development:', text, re.M)
                or (entitlements.strip() and plistlib.loads(entitlements))):
            raise Refusal('incorrectSignaturePolicy')
        requirement = '=anchor apple generic and identifier "' + identifier + '" and certificate leaf[subject.OU] = "' + team[1].decode() + '"'
        self.run('requirement-' + identifier, ['/usr/bin/codesign', '--verify', '--strict', '-R', requirement, path])
        return team[1].decode()

    def sign(self, app):
        env = environment(self.work)
        env['HOME'] = str(Path.home())
        result = subprocess.run(['/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning'], env=env, cwd=HERE, capture_output=True, timeout=20)
        matches = re.findall(rb'^\s*\d+\)\s+([A-F0-9]{40})\s+"Apple Development:[^"\r\n]+"\s*$', result.stdout, re.M)
        if result.returncode or len(matches) != 1:
            raise Refusal('oneExistingDevelopmentIdentityRequired')
        teams = []
        for label, path, identifier in [('helper', app / 'Contents/Helpers/openlxssh-askpass', HELPER_ID), ('app', app, APP_ID)]:
            self.run('sign-' + label, ['/usr/bin/codesign', '--force', '--sign', matches[0].decode(), '--identifier', identifier, '--options', 'runtime', '--timestamp=none', path], private=True, timeout=30)
            teams.append(self.verify_signature(path, identifier, deep=label == 'app'))
        if teams[0] != teams[1]:
            raise Refusal('helperTeamMismatch')
        self.record['signature'] = {'status': 'strictDevelopmentVerified', 'sameTeam': True,
            'brokerIdentifier': APP_ID, 'helperIdentifier': HELPER_ID, 'runtime': True, 'entitlements': {}, 'timestamp': 'none', 'identityDetailsRecorded': False}

    def save(self):
        self.record['inputs'] = [{'path': str(p), 'sha256': v['sha256'], 'snapshot': str(v['snapshot'])} for p, v in self.inputs.items()]
        self.record['objects'] = self.objects
        write_json(self.work / 'commands.json', self.commands)
        write_json(self.work / 'result.json', self.record)


def build(sign):
    BUILD.mkdir(mode=0o700, exist_ok=True)
    if BUILD.is_symlink() or BUILD.resolve() != BUILD or BUILD.stat().st_uid != os.getuid() or stat.S_IMODE(BUILD.stat().st_mode) != 0o700:
        raise Refusal('unsafeBuildDirectory')
    work = BUILD / ('host-' + str(uuid.uuid4()))
    work.mkdir(mode=0o700)
    print('Independent offline build: ' + str(work), flush=True)
    builder = Builder(work)
    try:
        if sha(GATE) != GATE_SHA256:
            raise Refusal('reviewedPluginGateChanged')
        builder.snapshot(GATE)
        builder.run('readonly-pinned-checkout-gate', [sys.executable, '-B', GATE, CHECKOUTS, '--helper'])
        builder.snapshot(TRANSPORT / 'Package.swift')
        builder.snapshot(TRANSPORT / 'Package.resolved')
        builder.snapshot(FILES / 'Package.swift')
        builder.snapshot(ROOT / 'Packages/OpenLXSSHTrust/Package.swift')
        builder.snapshot(HERE / 'build_host.py'); builder.snapshot(HERE / 'Package.swift')
        # Read/hashes only: never invoke native builders or mutate native caches.
        manifest = json.loads((NATIVE / 'manifest.json').read_bytes())
        builder.snapshot(NATIVE / 'manifest.json'); builder.snapshot(FILES / 'native-inputs.json')
        if (manifest['dependencies']['toolchain']['deploymentTarget'] != '15.0'
                or manifest['inputs']['lockSHA256'] != sha(FILES / 'native-inputs.json')
                or any(manifest['dependencies'][name] != json.loads((FILES / 'native-inputs.json').read_bytes())[name] for name in ('libssh2', 'openssl'))):
            raise Refusal('nativeNotLockedHost15')
        for relative, expected in manifest['outputs'].items():
            if not relative.startswith('install/') or '..' in Path(relative).parts or sha(NATIVE / relative, native_export=True) != expected:
                raise Refusal('nativeManifestMismatch')
            builder.snapshot(NATIVE / relative, native_export=True)
        native = work / 'inputs' / NATIVE.relative_to(ROOT) / 'install'
        archives = [native / 'lib' / name for name in ('libssh2.a', 'libssl.a', 'libcrypto.a')]
        builder.tools()
        swiftterm = CHECKOUTS / 'SwiftTerm'
        builder.snapshot(swiftterm / 'swifterm-terminfo'); builder.snapshot(swiftterm / 'Package.swift')
        generator_sources = builder.sources(swiftterm / 'Sources/SwiftTermBuildInfoGenerator')
        generator = work / 'artifacts/SwiftTermBuildInfoGenerator-host-only'
        builder.run('compile-official-generator', [builder.swift, '-O', '-parse-as-library', '-target', TARGET, '-sdk', builder.sdk,
                    '-module-cache-path', work / 'module-cache', *generator_sources, '-o', generator])
        generated = [work / 'generated/SwiftTermBuildInfo.swift', work / 'generated/SwiftTermTerminfo.swift']
        builder.run('run-official-generator-only', [generator, swiftterm, *generated])
        cobjects = builder.c_module('COpenLXSSHAskpass', TRANSPORT / 'Sources/COpenLXSSHAskpass', probe=True)
        cobjects += builder.c_module('COpenLXSSHFiles', FILES / 'Sources/COpenLXSSHFiles', native=native / 'include')
        cobjects += builder.c_module('RealIntegrationPOSIX', HERE / 'Sources/RealIntegrationPOSIX')
        swift_objects = []
        for name, directory, version, package, extra in [
            ('OpenLXSSHTrust', ROOT / 'Packages/OpenLXSSHTrust/Sources/OpenLXSSHTrust', '6', 'openlxsshtrust', []),
            ('SwiftTerm', swiftterm / 'Sources/SwiftTerm', '6', 'swiftterm', ['-DPortableGraphics', '-user-module-version', '1.99.1']),
            ('OpenLXSSHAskpass', TRANSPORT / 'Sources/OpenLXSSHAskpass', '5', 'openlxsshtransport', []),
            ('OpenLXSSHTransport', TRANSPORT / 'Sources/OpenLXSSHTransport', '5', 'openlxsshtransport', ['-DTRANSPORT_HOST_PROBE']),
            ('OpenLXSSHFiles', FILES / 'Sources/OpenLXSSHFiles', '6', 'openlxsshfiles', ['-Xcc', '-I' + str(native / 'include')]),
            ('RealIntegrationCore', HERE / 'Sources/RealIntegrationCore', '6', 'realintegration', ['-warnings-as-errors']),
        ]:
            sources = builder.sources(directory) + (generated if name == 'SwiftTerm' else [])
            swift_objects.append(builder.swift_compile(name, sources, version, package, extra=extra))
        helper_object = builder.swift_compile('OpenLXSSHAskpassHelper', builder.sources(TRANSPORT / 'Sources/OpenLXSSHAskpassHelper'), '5', 'openlxsshtransport', library=False)
        consumer_object = builder.swift_compile('OpenLXSSHRealIntegration', builder.sources(HERE / 'Consumer'), package='realintegration',
            extra=['-warnings-as-errors', '-Xcc', '-I' + str(native / 'include')])
        undefined = builder.run('consumer-public-api-symbols', ['/usr/bin/xcrun', 'nm', '-u', consumer_object])
        if b'DirectSSHSession' not in undefined or b'LibSSH2FileService' not in undefined or any(x in undefined for x in (b'startProbe', b'probeStore', b'configureProbe')):
            raise Refusal('consumerNotPublicProductionAPI')
        helper = builder.link('openlxssh-askpass', [helper_object, swift_objects[2], *[p for p in cobjects if p.name.startswith('COpenLXSSHAskpass-')]])
        consumer = builder.link('OpenLXSSHRealIntegration', [consumer_object, *swift_objects, *cobjects], archives)
        app = work / 'OpenLXSSHRealIntegration.app'
        for relative in ('Contents/MacOS', 'Contents/Helpers'):
            (app / relative).mkdir(parents=True, mode=0o700)
        shutil.copyfile(helper, app / 'Contents/Helpers/openlxssh-askpass')
        shutil.copyfile(consumer, app / 'Contents/MacOS/OpenLXSSHRealIntegration')
        for binary in (app / 'Contents/Helpers/openlxssh-askpass', app / 'Contents/MacOS/OpenLXSSHRealIntegration'):
            binary.chmod(0o700)
        plist = {'CFBundleIdentifier': APP_ID, 'CFBundleName': 'OpenLXSSHRealIntegration', 'CFBundleExecutable': 'OpenLXSSHRealIntegration',
                 'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1', 'LSMinimumSystemVersion': '15.0', 'LSUIElement': True,
                 'OpenLXSSHRealIntegrationTestOnly': True, 'RealIntegrationFixtureRoot': str(ROOT / 'Tests/IntegrationEnvironment'),
                 'RealIntegrationBuildRoot': str(BUILD)}
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(plist))
        if sign:
            builder.sign(app)
        builder.unchanged()
        builder.record.update({'status': 'signed-static-only-not-run' if sign else 'linked-unsigned-not-run', 'app': str(app),
            'driver': {'sha256': sha(app / 'Contents/MacOS/OpenLXSSHRealIntegration'), 'metadata': minimum(app / 'Contents/MacOS/OpenLXSSHRealIntegration', 2)},
            'helper': {'sha256': sha(app / 'Contents/Helpers/openlxssh-askpass'), 'metadata': minimum(app / 'Contents/Helpers/openlxssh-askpass', 2)}})
        print('Host15 test-only production consumer/helper linked; static checks only. NO live interop or product acceptance.')
        print('Exact App: ' + str(app))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        builder.record.update({'status': 'failed-not-run', 'failure': str(error) if isinstance(error, Refusal) else type(error).__name__})
        raise
    finally:
        builder.save()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('help', 'validate', 'build'), nargs='?', default='help')
    parser.add_argument('--sign-development', action='store_true')
    args = parser.parse_args(argv)
    if args.action == 'help':
        parser.print_help(); return 0
    if args.action == 'validate' and not args.sign_development:
        print('Offline recipe syntax only; no I/O, build, signing, Docker or live execution.'); return 0
    if args.action != 'build':
        raise Refusal('invalidArguments')
    return build(args.sign_development)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        sys.stderr.write('Host15 offline build refused: ' + (str(error) if isinstance(error, Refusal) else type(error).__name__) + '. No identity/secret details emitted.\n')
        sys.exit(2)
