#!/usr/bin/env python3
"""Offline min26 fixture-consumer build. Default/help/validate are inert.

Only 'build' reads public source/native inputs and writes immutable snapshots under
this probe's .build/live-UUID. No package resolution, Docker, collect, credentials,
relay, socket, Keychain, helper, codesign command or live artifact execution.
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
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
ROOT = HERE.parent.parent
BUILD = HERE / '.build'
FIXTURE = ROOT / 'Tests/IntegrationEnvironment'
INTEGRATION = ROOT / 'Tests/RealIntegration'
FILES = ROOT / 'Packages/OpenLXSSHFiles'
NATIVE = FILES / '.build/native'
TARGET = 'arm64-apple-macosx26.0'
MARKER = b'OpenLXSSH-U0-NativeShellProbe-v1\n'


class Refusal(ValueError):
    pass


def read_source(path, exported=False):
    """Public build-input only; hold/revalidate FD metadata and reject symlinks."""
    path = Path(path)
    if path.resolve() != path:
        raise Refusal('symlinkBuildInput')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or before.st_mode & (0o002 if exported else 0o022):
            raise Refusal('unsafeBuildInput')
        data = bytearray()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(after) or len(data) != before.st_size or path.stat().st_ino != before.st_ino:
            raise Refusal('changedBuildInput')
        return bytes(data)
    finally:
        os.close(fd)


def write_private(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def json_private(path, value):
    write_private(path, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())


def mach_metadata(path, executable=False):
    data = path.read_bytes()
    magic, cpu, _, kind, count, size, _, _ = struct.unpack_from('<IiiIIIII', data)
    if magic != 0xfeedfacf or cpu != 0x0100000c or kind != (2 if executable else 1):
        raise Refusal('notArm64MachO')
    position, versions = 32, []
    for _ in range(count):
        command, length = struct.unpack_from('<II', data, position)
        if length < 8 or position + length > 32 + size:
            raise Refusal('invalidLoadCommands')
        if command == 0x32:
            platform, minimum = struct.unpack_from('<II', data, position + 8)
            versions.append((platform, minimum))
        position += length
    if position != 32 + size or versions != [(1, 26 << 16)]:
        raise Refusal('notMin26')
    return {'architecture': 'arm64', 'minimumOS': '26.0', 'kind': kind}


class Builder:
    def __init__(self, work):
        self.work, self.inputs, self.commands, self.objects = work, {}, [], []
        for directory in ['inputs', 'modules', 'cmodules', 'objects', 'logs', 'generated', 'module-cache', 'clang-cache', 'home', 'tmp', 'artifacts']:
            (work / directory).mkdir(mode=0o700)
        self.env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(work / 'home'),
                    'LANG': 'C', 'LC_ALL': 'C', 'TMPDIR': str(work / 'tmp') + '/',
                    'CLANG_MODULE_CACHE_PATH': str(work / 'clang-cache'), 'PYTHONDONTWRITEBYTECODE': '1'}
        self.record = {'taskID': 'U0-NATIVE-SHELL-LIVE-PREP', 'target': TARGET, 'testOnly': True,
                       'liveExecuted': False, 'credentialFilesRead': False, 'dockerInvoked': False,
                       'packageResolution': False, 'nativeRebuilt': False, 'helperUsed': False,
                       'identitySigningInvoked': False, 'sameTeamGateClaimed': False, 'status': 'building'}

    def snapshot(self, path, exported=False):
        path = Path(path)
        if path in self.inputs:
            return self.inputs[path]['snapshot']
        data = read_source(path, exported=exported)
        target = self.work / 'inputs' / path.relative_to(ROOT)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_private(target, data, mode=0o400)
        self.inputs[path] = {'sha256': hashlib.sha256(data).hexdigest(), 'snapshot': target, 'exported': exported}
        return target

    def sources(self, directory):
        return [self.snapshot(path) for path in sorted(directory.glob('*.swift'))]

    def run(self, label, command):
        log = self.work / 'logs' / (label + '.log')
        with log.open('wb') as output:
            try:
                result = subprocess.run(list(map(str, command)), cwd=HERE, env=self.env,
                                        stdout=output, stderr=subprocess.STDOUT, timeout=180)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = 124
        self.commands.append({'label': label, 'cwd': str(HERE), 'command': list(map(str, command)), 'exitCode': code, 'log': str(log)})
        if code:
            raise Refusal(label + 'Failed')
        return log.read_text()

    def tools(self):
        self.swift = self.run('locate-swiftc', ['/usr/bin/xcrun', '-f', 'swiftc']).strip()
        self.clang = self.run('locate-clang', ['/usr/bin/xcrun', '-f', 'clang']).strip()
        self.sdk = self.run('locate-sdk', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path']).strip()
        self.run('swift-version', [self.swift, '--version'])
        self.run('sdk-version', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version'])

    def c_module(self, module, header, sources, native=None):
        snapshot_header = self.snapshot(header)
        directory = self.work / 'cmodules' / module
        directory.mkdir(mode=0o700)
        write_private(directory / 'module.modulemap', ('module ' + module + ' { header "' + str(snapshot_header) + '" export * }\n').encode())
        objects = []
        for source in sources:
            output = self.work / 'objects' / (module + '-' + source.stem + '.o')
            command = [self.clang, '-c', '-O2', '-fPIC', '-target', TARGET, '-isysroot', self.sdk,
                       '-Wall', '-Wextra', '-Werror', '-fmodules', '-I', snapshot_header.parent]
            if native:
                command += ['-I', native]
            command += getattr(self, 'cflags', [])
            self.run('compile-' + output.stem, command + [self.snapshot(source), '-o', output])
            self.objects.append(output); objects.append(output)
        return objects

    def swift_module(self, module, sources, extra=()):
        output = self.work / 'objects' / (module + '.o')
        command = [self.swift, '-emit-object', '-emit-module', '-whole-module-optimization', '-O',
                   '-swift-version', '6', '-warnings-as-errors', '-parse-as-library', '-target', TARGET,
                   '-sdk', self.sdk, '-module-name', module, '-module-cache-path', self.work / 'module-cache',
                   '-emit-module-path', self.work / 'modules' / (module + '.swiftmodule'), '-I', self.work / 'modules']
        for directory in sorted((self.work / 'cmodules').iterdir()):
            command += ['-I', directory]
        self.run('compile-' + module, command + list(extra) + sources + ['-o', output])
        self.objects.append(output)
        return output

    def link(self, name, objects, archives):
        output = self.work / 'artifacts' / name
        # Normal linker ad-hoc platform signature, no identity/keychain/codesign invocation or Team gate.
        self.run('link-' + name, [self.swift, '-emit-executable', '-target', TARGET, '-sdk', self.sdk,
            '-no-toolchain-stdlib-rpath', *objects, *archives, '-o', output])
        output.chmod(0o700)
        return output

    def save(self):
        self.record['inputs'] = [{'path': str(path), 'sha256': item['sha256'], 'snapshot': str(item['snapshot'])} for path, item in self.inputs.items()]
        self.record['objects'] = [{'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                                   'metadata': mach_metadata(path)} for path in self.objects]
        json_private(self.work / 'commands.json', self.commands)
        json_private(self.work / 'result.json', self.record)


def build():
    os.umask(0o077)
    BUILD.mkdir(mode=0o700, exist_ok=True)
    if BUILD.resolve() != BUILD or BUILD.stat().st_uid != os.getuid() or stat.S_IMODE(BUILD.stat().st_mode) != 0o700:
        raise Refusal('unsafeBuildRoot')
    marker = BUILD / '.native-shell-probe-owner'
    if not marker.exists():
        write_private(marker, MARKER)
    if read_source(marker) != MARKER or stat.S_IMODE(marker.stat().st_mode) != 0o600:
        raise Refusal('incorrectBuildMarker')
    work = BUILD / ('live-' + str(uuid.uuid4()).lower())
    work.mkdir(mode=0o700)
    builder = Builder(work)
    print('Offline min26 probe build: ' + str(work), flush=True)
    try:
        builder.snapshot(HERE / 'build_live.py'); builder.snapshot(HERE / 'Package.swift')
        builder.snapshot(FILES / 'Package.swift'); builder.snapshot(ROOT / 'Packages/OpenLXSSHTrust/Package.swift')
        manifest = json.loads(read_source(NATIVE / 'manifest.json'))
        builder.snapshot(NATIVE / 'manifest.json')
        lock = builder.snapshot(FILES / 'native-inputs.json')
        script = builder.snapshot(FILES / 'Scripts/build-native.py')
        if hashlib.sha256(lock.read_bytes()).hexdigest() != manifest['inputs']['lockSHA256'] or hashlib.sha256(script.read_bytes()).hexdigest() != manifest['inputs']['scriptSHA256']:
            raise Refusal('nativeInputsChanged')
        for relative, expected in manifest['outputs'].items():
            if not relative.startswith('install/') or '..' in Path(relative).parts:
                raise Refusal('invalidNativeOutputPath')
            snapshot = builder.snapshot(NATIVE / relative, exported=True)
            if hashlib.sha256(snapshot.read_bytes()).hexdigest() != expected:
                raise Refusal('nativeOutputChanged')
        native = work / 'inputs' / NATIVE.relative_to(ROOT) / 'install'
        archives = [native / 'lib' / name for name in ['libssh2.a', 'libssl.a', 'libcrypto.a']]
        from verify_native_source import verify as verify_native_source
        source_gate = verify_native_source(read_source=read_source)
        builder.record['nativeLivenessSourceGate'] = source_gate
        builder.snapshot(HERE / 'verify_native_source.py')
        builder.snapshot(NATIVE / 'downloads/libssh2-1.11.1.tar.gz', exported=True)
        builder.tools()
        cobjects = builder.c_module('COpenLXSSHFiles', FILES / 'Sources/COpenLXSSHFiles/include/COpenLXSSHFiles.h',
            [FILES / 'Sources/COpenLXSSHFiles/Bridge.c'], native / 'include')
        cobjects += builder.c_module('RealIntegrationPOSIX', INTEGRATION / 'Sources/RealIntegrationPOSIX/include/RealIntegrationPOSIX.h',
            [INTEGRATION / 'Sources/RealIntegrationPOSIX/PrivateInput.c'])
        askpass = ROOT / 'Packages/OpenLXSSHTransport/Sources/COpenLXSSHAskpass'
        cobjects += builder.c_module('COpenLXSSHAskpass', askpass / 'include/COpenLXSSHAskpass.h', [askpass / 'BoundedTool.c'])
        trust = builder.swift_module('OpenLXSSHTrust', builder.sources(ROOT / 'Packages/OpenLXSSHTrust/Sources/OpenLXSSHTrust'))
        files = builder.swift_module('OpenLXSSHFiles', builder.sources(FILES / 'Sources/OpenLXSSHFiles'), ['-Xcc', '-I' + str(native / 'include')])
        core = builder.swift_module('RealIntegrationCore', builder.sources(INTEGRATION / 'Sources/RealIntegrationCore'))
        support = builder.swift_module('UXNativeShellProbeSupport', builder.sources(HERE / 'Sources/UXNativeShellProbeSupport'), ['-Xcc', '-I' + str(native / 'include')])
        generated = work / 'generated/ShellProbeBuildContext.swift'
        write_private(generated, ('public enum ShellProbeBuildContext {\n public static let buildRoot = ' + json.dumps(str(BUILD)) +
            '\n public static let fixtureRoot = ' + json.dumps(str(FIXTURE)) + '\n}\n').encode())
        fixtures = builder.sources(HERE / 'Fixture') + [builder.snapshot(INTEGRATION / 'Consumer/OpenSSHManagement.swift'),
            builder.snapshot(INTEGRATION / 'Consumer/SFTPAuthCallbacks.swift'), generated]
        fixture = builder.swift_module('UXNativeShellFixture', fixtures, ['-Xcc', '-I' + str(native / 'include')])
        main = builder.swift_module('UXNativeShellProbe', builder.sources(HERE / 'Sources/UXNativeShellProbe'),
            ['-DNATIVE_SHELL_LIVE_CONSUMER', '-Xcc', '-I' + str(native / 'include')])
        executable = builder.link('UXNativeShellProbe', [main, fixture, support, core, files, trust, *cobjects], archives)
        # A separate finite offline executable exercises only synthetic in-memory schemas/budgets.
        checks = builder.swift_module('UXNativeShellFixtureOfflineChecks', builder.sources(HERE / 'OfflineChecks'), ['-Xcc', '-I' + str(native / 'include')])
        offline = builder.link('UXNativeShellFixtureOfflineChecks', [checks, fixture, support, core, files, trust, *cobjects], archives)
        for path, item in builder.inputs.items():
            if hashlib.sha256(read_source(path, exported=item['exported'])).hexdigest() != item['sha256']:
                raise Refusal('inputChangedDuringBuild')
        builder.record.update({'status': 'linked-not-live-run', 'generatedContextSHA256': hashlib.sha256(generated.read_bytes()).hexdigest(),
            'binary': {'path': str(executable), 'sha256': hashlib.sha256(executable.read_bytes()).hexdigest(), 'metadata': mach_metadata(executable, True)},
            'offlineChecks': {'path': str(offline), 'sha256': hashlib.sha256(offline.read_bytes()).hexdigest(), 'metadata': mach_metadata(offline, True)}})
        print('Linked only, no live/Docker/credential access: ' + str(executable))
    except Exception as error:
        builder.record.update({'status': 'failed-not-run', 'failure': str(error) if isinstance(error, Refusal) else type(error).__name__})
        raise
    finally:
        builder.save()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='help', choices=['help', 'validate', 'build'])
    args = parser.parse_args(argv)
    if args.action == 'help':
        parser.print_help(); return 0
    if args.action == 'validate':
        print('Recipe syntax only; no input reads, writes, compilation, signing, credentials or live execution.'); return 0
    return build()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        sys.stderr.write('Offline native-shell build refused: ' + (str(error) if isinstance(error, Refusal) else type(error).__name__) + '.\n')
        sys.exit(2)
