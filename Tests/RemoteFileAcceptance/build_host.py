#!/usr/bin/env python3
"""Offline host15 Release build/test, no SwiftPM resolution, downloads, Docker or live I/O.

Default/help/validate perform no filesystem or subprocess work. Only build snapshots
read-only production/native/core inputs and writes inside this subtree .build/host-UUID.
The isolated executable has no SSH/Transport/Askpass/UI dependency and uses ad-hoc
signing only, without a Development identity, keychain query or Apple upload.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
ROOT = HERE.parent.parent
FILES = ROOT / 'Packages/OpenLXSSHFiles'
CORE = ROOT / 'Tests/RealIntegration/Sources'
NATIVE = FILES / '.build/native'
TARGET = 'arm64-apple-macosx15.0'


class Refusal(ValueError):
    pass


def digest(path, exported=False):
    info = path.lstat()
    if (path.resolve() != path or info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1 or info.st_mode & (0o002 if exported else 0o022)):
        raise Refusal('unsafeReadOnlyInput')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def macho(path, kind):
    data = path.read_bytes()
    if len(data) < 32:
        raise Refusal('missingMachO')
    magic, cpu, subtype, actual_kind, count, size, flags, reserved = struct.unpack_from('<IiiIIIII', data)
    if magic != 0xfeedfacf or cpu != 0x0100000c or actual_kind != kind or count > 4096:
        raise Refusal('notArm64MachO')
    offset, found = 32, []
    for _ in range(count):
        command, length = struct.unpack_from('<II', data, offset)
        if length < 8 or offset + length > 32 + size:
            raise Refusal('invalidLoadCommands')
        if command == 0x32:
            found.append(struct.unpack_from('<II', data, offset + 8))
        offset += length
    if offset != 32 + size or found != [(1, 15 << 16)]:
        raise Refusal('notHost15TestOnly')
    return {'architecture': 'arm64', 'minimumOS': '15.0', 'kind': kind}


class Builder:
    def __init__(self, work):
        self.work, self.inputs, self.commands, self.objects = work, {}, [], []
        for name in ('home', 'tmp', 'logs', 'modules', 'objects', 'cmodules', 'clang-cache', 'module-cache', 'artifacts', 'test-data'):
            (work / name).mkdir(mode=0o700)
        self.record = {'taskID': 'REAL-SFTP-FILE-ACCEPTANCE-A', 'status': 'building', 'testOnlyHostMinimum': '15.0',
                       'productAcceptance': False, 'dockerInvoked': False, 'networkInvoked': False, 'secretRead': False,
                       'nativeRebuilt': False, 'swiftPMInvoked': False}
        self.env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(work / 'home'), 'LANG': 'C', 'LC_ALL': 'C',
                    'TMPDIR': str(work / 'tmp') + '/', 'CLANG_MODULE_CACHE_PATH': str(work / 'clang-cache'),
                    'SWIFTPM_MODULECACHE_OVERRIDE': str(work / 'module-cache'), 'PYTHONDONTWRITEBYTECODE': '1', 'GIT_OPTIONAL_LOCKS': '0'}

    def run(self, label, args, expected=0, timeout=300):
        command = list(map(str, args))
        result = subprocess.run(command, env=self.env, cwd=HERE, capture_output=True, timeout=timeout)
        log = self.work / 'logs' / (label + '.log')
        with log.open('xb') as stream:
            stream.write(result.stdout + result.stderr)
        self.commands.append({'label': label, 'cwd': str(HERE), 'command': command, 'exitCode': result.returncode,
                              'expectedExitCode': expected, 'log': str(log)})
        if result.returncode != expected:
            raise Refusal(label + 'Failed')
        return result.stdout

    def snapshot(self, path, exported=False):
        if path in self.inputs:
            return self.inputs[path]['snapshot']
        sha = digest(path, exported)
        destination = self.work / 'inputs' / path.relative_to(ROOT)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            stream.write(path.read_bytes())
        destination.chmod(0o400)
        if digest(destination) != sha:
            raise Refusal('inputChangedDuringSnapshot')
        self.inputs[path] = {'snapshot': destination, 'sha256': sha, 'exported': exported}
        return destination

    def sources(self, directory):
        return [self.snapshot(path) for path in sorted(directory.rglob('*.swift'))]

    def unchanged(self):
        for source, item in self.inputs.items():
            if digest(source, item['exported']) != item['sha256'] or digest(item['snapshot']) != item['sha256']:
                raise Refusal('inputChangedDuringOfflineBuild')
        expected_core = {path for path in self.inputs if path.parent == CORE / 'RealIntegrationCore'}
        if set((CORE / 'RealIntegrationCore').glob('*.swift')) != expected_core:
            raise Refusal('sharedCoreSourceSetChanged')

    def c(self, name, directory, native=None):
        header = self.snapshot(directory / 'include' / (name + '.h'))
        module = self.work / 'cmodules' / name
        module.mkdir(mode=0o700)
        (module / 'module.modulemap').write_text('module ' + name + ' { header "' + str(header) + '" export * }\n')
        objects = []
        for source in sorted(directory.glob('*.c')):
            output = self.work / 'objects' / (name + '-' + source.stem + '.o')
            args = [self.clang, '-c', '-O2', '-fPIC', '-target', TARGET, '-isysroot', self.sdk,
                    '-fmodules', '-fmodules-cache-path=' + str(self.work / 'clang-cache'), '-I', header.parent]
            if native:
                args += ['-I', native]
            self.run('compile-' + output.stem, args + [self.snapshot(source), '-o', output])
            macho(output, 1); objects.append(output)
        return objects

    def swift(self, name, sources, native=None, package=None):
        output = self.work / 'objects' / (name + '.o')
        args = [self.swiftc, '-emit-object', '-emit-module', '-whole-module-optimization', '-O', '-swift-version', '6',
                '-target', TARGET, '-sdk', self.sdk, '-module-name', name, '-module-cache-path', self.work / 'module-cache',
                '-I', self.work / 'modules', '-I', self.work / 'cmodules', '-DSWIFT_PACKAGE', '-parse-as-library',
                '-emit-module-path', self.work / 'modules' / (name + '.swiftmodule')]
        for module in sorted((self.work / 'cmodules').iterdir()):
            args += ['-I', module]
        if native:
            args += ['-Xcc', '-I' + str(native)]
        if package:
            args += ['-package-name', package]
        self.run('compile-' + name, args + sources + ['-o', output])
        self.objects.append({'module': name, 'path': str(output), 'sha256': digest(output), 'metadata': macho(output, 1)})
        return output

    def link(self, name, objects, archives):
        output = self.work / 'artifacts' / name
        self.run('link-' + name, [self.swiftc, '-emit-executable', '-target', TARGET, '-sdk', self.sdk,
            '-no-toolchain-stdlib-rpath', '-Xlinker', '-no_adhoc_codesign', *objects, *archives,
            '-framework', 'Security', '-lz', '-o', output])
        macho(output, 2)
        self.run('adhoc-' + name, ['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', output])
        self.run('strict-' + name, ['/usr/bin/codesign', '--verify', '--strict', output])
        self.run('otool-' + name, ['/usr/bin/xcrun', 'otool', '-L', output])
        return output

    def save(self):
        self.record['inputs'] = [{'path': str(path), 'snapshot': str(item['snapshot']), 'sha256': item['sha256']} for path, item in self.inputs.items()]
        self.record['objects'] = self.objects
        write_json(self.work / 'commands.json', self.commands)
        write_json(self.work / 'result.json', self.record)


def build():
    os.umask(0o077)
    root = HERE / '.build'
    root.mkdir(mode=0o700, exist_ok=True)
    if root.resolve() != root or root.stat().st_uid != os.getuid() or stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise Refusal('unsafeBuildRoot')
    work = root / ('host-' + str(uuid.uuid4()))
    work.mkdir(mode=0o700)
    print('Independent offline build/test: ' + str(work), flush=True)
    b = Builder(work)
    try:
        for path in [HERE / 'build_host.py', HERE / 'test_static.py', HERE / '.gitignore', FILES / 'Package.swift', FILES / 'native-inputs.json',
                     ROOT / 'Packages/OpenLXSSHTrust/Package.swift']:
            b.snapshot(path)
        manifest = json.loads(b.snapshot(NATIVE / 'manifest.json').read_bytes())
        lock = json.loads((FILES / 'native-inputs.json').read_bytes())
        if (manifest['dependencies']['toolchain']['deploymentTarget'] != '15.0'
                or manifest['inputs']['lockSHA256'] != digest(FILES / 'native-inputs.json')
                or any(manifest['dependencies'][name] != lock[name] for name in ('libssh2', 'openssl'))):
            raise Refusal('nativeInputMismatch')
        for relative, expected in manifest['outputs'].items():
            if not relative.startswith('install/') or '..' in Path(relative).parts or digest(NATIVE / relative, True) != expected:
                raise Refusal('nativeOutputMismatch')
            b.snapshot(NATIVE / relative, True)
        native = work / 'inputs' / NATIVE.relative_to(ROOT) / 'install'
        b.swiftc = b.run('locate-swiftc', ['/usr/bin/xcrun', '-f', 'swiftc']).decode().strip()
        b.clang = b.run('locate-clang', ['/usr/bin/xcrun', '-f', 'clang']).decode().strip()
        b.sdk = b.run('locate-sdk', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path']).decode().strip()
        for label, args in [('swift-version', [b.swiftc, '--version']), ('sdk-version', ['/usr/bin/xcrun', '--show-sdk-version']),
                            ('macos-version', ['/usr/bin/sw_vers', '-productVersion']), ('physical-memory', ['/usr/sbin/sysctl', '-n', 'hw.memsize'])]:
            b.run(label, args)
        cobjects = b.c('COpenLXSSHFiles', FILES / 'Sources/COpenLXSSHFiles', native / 'include')
        cobjects += b.c('RealIntegrationPOSIX', CORE / 'RealIntegrationPOSIX')
        cobjects += b.c('StressMetrics', ROOT / 'Tests/LocalFileStress/Sources/StressMetrics')
        cobjects += b.c('RemoteFileMetrics', HERE / 'POSIX')
        objects = []
        for name, sources, package in [
            ('OpenLXSSHTrust', ROOT / 'Packages/OpenLXSSHTrust/Sources/OpenLXSSHTrust', 'openlxsshtrust'),
            ('OpenLXSSHFiles', FILES / 'Sources/OpenLXSSHFiles', 'openlxsshfiles'),
            ('RealIntegrationCore', CORE / 'RealIntegrationCore', 'realintegration')]:
            objects.append(b.swift(name, b.sources(sources), native / 'include', package))
        # Compile-time paths are generated in OUR work dir, not substituted in shared sources.
        location = work / 'BuildLocation.swift'
        location.write_text('enum BuildLocation { static let ownRoot = ' + json.dumps(str(HERE)) + '; static let fixtureRoot = ' +
                            json.dumps(str(ROOT / 'Tests/IntegrationEnvironment')) + '; static let offlineRoot = ' + json.dumps(str(work / 'test-data')) +
                            '; static let buildEvidence = ' + json.dumps(str(work / 'result.json')) +
                            '; static let offlinePreparedAt = ' + repr(time.time()) + ' }\n')
        shared = [b.snapshot(HERE / name) for name in ('Core.swift', 'Observation.swift', 'Campaign.swift')]
        driver_object = b.swift('OpenLXSSHRemoteFileAcceptance', shared + [location, b.snapshot(HERE / 'Main.swift')], native / 'include')
        symbols = b.run('consumer-production-symbols', ['/usr/bin/xcrun', 'nm', '-u', driver_object])
        if any(name not in symbols for name in (b'LibSSH2FileService', b'SafeTransferEngine', b'TransferManager', b'ServerCommitProbe')):
            raise Refusal('missingProductionAPIs')
        archives = [native / 'lib' / name for name in ('libssh2.a', 'libssl.a', 'libcrypto.a')]
        driver = b.link('OpenLXSSHRemoteFileAcceptance', [driver_object, *objects, *cobjects], archives)
        test_object = b.swift('OpenLXSSHRemoteFileOfflineTests', shared + [location, b.snapshot(HERE / 'OfflineMain.swift')], native / 'include')
        tests = b.link('OpenLXSSHRemoteFileOfflineTests', [test_object, *objects, *cobjects], archives)
        b.unchanged()
        b.run('source-only-policy-tests', [sys.executable, '-B', HERE / 'test_static.py'])
        b.run('offline-safety-tests', [tests], timeout=120)
        b.run('cli-default-no-io', [driver])
        b.run('cli-help-no-io', [driver, '--help'])
        b.run('cli-validate-no-io', [driver, 'validate', '--campaign', '/does/not/exist/campaign.json'])
        b.run('cli-live-refuses-before-io', [driver, '--live', '--campaign', '/does/not/exist/campaign.json'], expected=2)
        b.run('cli-prepare-refuses-before-io', [driver, 'prepare', '--generation', '/does/not/exist'], expected=2)
        b.unchanged()
        b.record.update(status='passed-offline-only-live-not-run', driver=str(driver), driverSHA256=digest(driver),
            offlineTests=str(tests), nativeOutputsChecked=len(manifest['outputs']), architecture=macho(driver, 2))
        print('Offline tests/build passed; NO generation/secret read/relay/auth/remote files executed.')
        print('Exact driver: ' + str(driver))
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        b.record.update(status='failed-offline-not-run', failure=str(error) if isinstance(error, Refusal) else type(error).__name__)
        raise
    finally:
        b.save()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('help', 'validate', 'build'), default='help', nargs='?')
    args = parser.parse_args(argv)
    if args.action == 'help':
        parser.print_help(); return 0
    if args.action == 'validate':
        print('Recipe syntax only. No filesystem, compiler, signing, Docker or network I/O.'); return 0
    return build()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        sys.stderr.write('Offline build refused: ' + (str(error) if isinstance(error, Refusal) else type(error).__name__) + '.\n')
        sys.exit(2)
