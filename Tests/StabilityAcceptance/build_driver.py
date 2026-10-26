#!/usr/bin/env python3
"""Offline min26 real driver build; default help does not build, sign or query identities.

Uses only the existing pinned Transport checkout cache. No SwiftPM invocation,
resolution, download, HostProbe, connection, credential read or driver execution.
Only the reviewed upstream source generator runs on this host. 'build' creates
an exclusive .build/driver-UUID; --sign-development explicitly uses an existing
Apple Development identity, offline (runtime, timestamp=none), helper first.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import struct
import subprocess
import sys
import uuid

# Help/validate must not leave import caches beside source, even without -B.
sys.dont_write_bytecode = True
import prepare_wrapper

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BUILD = HERE / '.build'
TRANSPORT = ROOT / 'Packages/OpenLXSSHTransport'
DEFAULT_CACHE = TRANSPORT / '.build/macos26'
GATE = ROOT / 'Scripts/verify-build-plugin.py'
GATE_SHA256 = 'dec240e64f0a27b66790715d65597df45f3f581c5f82231df28959895cd75dbe'
PINS = {
    'swiftterm': '2f573f73af5e768d90847dce20c97fa9535d7164',
    'swift-argument-parser': '6a52f3251125d74daf04fcbd5e6f08a75d074382',
    'swift-png': '2d17c6c51c098628574c0383f1119892655a73a2',
    'h': 'aa3626829160917d4378330617971977cbd78f5b',
}
TARGET = 'arm64-apple-macosx26.0'
APP_ID = 'org.openlxssh.OpenLXSSH'
HELPER_ID = 'org.openlxssh.askpass'
KIND = 'OpenLXSSHStabilityDriverBuild'


class Refusal(ValueError):
    """Only fixed, non-secret diagnostic categories are emitted."""


def checked_path(value, directory=False):
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts or path.resolve(strict=True) != path:
        raise Refusal('unsafePath')
    info = path.lstat()
    kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not kind or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise Refusal('unsafeInputMetadata')
    if not directory and info.st_nlink != 1:
        raise Refusal('unsafeInputLinks')
    return path


def digest(path):
    result = hashlib.sha256()
    with checked_path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def write_json(path, value):
    # The work directory is private and exclusively created; never follow links.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def environment(work=None):
    result = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(Path.home()),
              'LANG': 'C', 'LC_ALL': 'C', 'GIT_OPTIONAL_LOCKS': '0', 'PYTHONDONTWRITEBYTECODE': '1'}
    if work is not None:
        result.update({'TMPDIR': str(work / 'tmp') + '/',
                       'CLANG_MODULE_CACHE_PATH': str(work / 'clang-cache'),
                       'SWIFTPM_MODULECACHE_OVERRIDE': str(work / 'module-cache')})
    # In particular no HOST_PROBE, SWIFTTERM fallback metadata, injected compiler
    # flags, DYLD_*, credential environment or remote package configuration.
    return result


def capture(command, work=None, timeout=60):
    return subprocess.run(command, cwd=HERE, env=environment(work), capture_output=True, timeout=timeout)


def git_state():
    revision = capture(['/usr/bin/git', '-C', str(ROOT), 'rev-parse', 'HEAD'])
    status = capture(['/usr/bin/git', '-C', str(ROOT), 'status', '--porcelain=v1', '--untracked-files=all'])
    commit = revision.stdout.decode().strip()
    if revision.returncode or status.returncode or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise Refusal('gitProvenanceUnavailable')
    return {'commit': commit, 'dirty': bool(status.stdout.strip()),
            'status': status.stdout.decode().splitlines()}


def approved_pins(lock):
    try:
        actual = {pin['identity']: pin['state']['revision'] for pin in lock['pins']}
        if len(actual) != len(lock['pins']) or actual != PINS:
            raise Refusal('packagePinsChanged')
    except (KeyError, TypeError):
        raise Refusal('packagePinsChanged') from None
    return actual


def swift_sources(path):
    checked_path(path, directory=True)
    files = sorted(path.rglob('*.swift'))
    if not files:
        raise Refusal('sourceSetMissing')
    for source in files:
        checked_path(source)
    return files


def source_layout(cache):
    checkouts = checked_path(cache / 'checkouts', directory=True)
    # These are fixed directory names in the already populated official cache.
    swiftterm = checked_path(checkouts / 'SwiftTerm', directory=True)
    modules = {
        'SwiftTerm': swift_sources(swiftterm / 'Sources/SwiftTerm'),
        'OpenLXSSHTrust': swift_sources(ROOT / 'Packages/OpenLXSSHTrust/Sources/OpenLXSSHTrust'),
        'OpenLXSSHAskpass': swift_sources(TRANSPORT / 'Sources/OpenLXSSHAskpass'),
        'OpenLXSSHTransport': swift_sources(TRANSPORT / 'Sources/OpenLXSSHTransport'),
        'OpenLXSSHAskpassHelper': swift_sources(TRANSPORT / 'Sources/OpenLXSSHAskpassHelper'),
        'StabilityCore': swift_sources(HERE / 'Sources/StabilityCore'),
        'OpenLXSSHStability': [checked_path(HERE / 'SignedDriver/Main.swift')],
        'SwiftTermBuildInfoGenerator': swift_sources(swiftterm / 'Sources/SwiftTermBuildInfoGenerator'),
    }
    c_sources = sorted((TRANSPORT / 'Sources/COpenLXSSHAskpass').glob('*.c'))
    c_sources += [HERE / 'Sources/StabilityPOSIX/StabilityPOSIX.c']
    headers = [TRANSPORT / 'Sources/COpenLXSSHAskpass/include/COpenLXSSHAskpass.h',
               HERE / 'Sources/StabilityPOSIX/include/StabilityPOSIX.h']
    metadata = [HERE / 'build_driver.py', HERE / 'prepare_wrapper.py', HERE / 'Package.swift',
                TRANSPORT / 'Package.swift', TRANSPORT / 'Package.resolved',
                ROOT / 'Packages/OpenLXSSHTrust/Package.swift', GATE,
                swiftterm / 'Package.swift', swiftterm / 'swifterm-terminfo']
    # Hash every pinned manifest/plugin/generator gate input, not only linked code.
    for checkout in checkouts.iterdir():
        metadata.append(checkout / 'Package.swift')
        metadata += sorted((checkout / 'Plugins').rglob('*.swift'))
    paths = sorted(set(c_sources + headers + metadata + [p for group in modules.values() for p in group]))
    for path in paths:
        checked_path(path)
    return {'modules': modules, 'cSources': c_sources, 'headers': headers,
            'paths': paths, 'swiftterm': swiftterm}


def validate_cache(cache):
    cache = checked_path(cache, directory=True)
    # Only task-approved, pre-existing package cache storage can supply inputs.
    if cache != DEFAULT_CACHE:
        raise Refusal('unapprovedCachePath')
    if digest(GATE) != GATE_SHA256:
        raise Refusal('pluginGateChanged')
    approved_pins(json.loads(checked_path(TRANSPORT / 'Package.resolved').read_text()))
    result = capture([sys.executable, '-B', str(GATE), str(cache / 'checkouts'), '--helper'])
    if result.returncode:
        raise Refusal('pinnedCheckoutOrPluginChanged')
    return source_layout(cache)


def fingerprint(paths):
    return [{'path': str(path), 'sha256': digest(path), 'size': path.stat().st_size} for path in paths]


def require_unchanged(inputs):
    for item in inputs:
        if digest(Path(item['path'])) != item['sha256']:
            raise Refusal('sourceChanged')
        if 'snapshot' in item and digest(Path(item['snapshot'])) != item['sha256']:
            raise Refusal('sourceSnapshotChanged')


def validate_source_record(record, work):
    layout = validate_cache(DEFAULT_CACHE)
    inputs = record.get('inputs')
    if not isinstance(inputs, list) or len(inputs) != len(layout['paths']):
        raise Refusal('sourceInventoryChanged')
    if {item.get('path') for item in inputs} != {str(path) for path in layout['paths']}:
        raise Refusal('sourceSetChanged')
    # Check every allowed path BEFORE hashing anything from a supplied record.
    # In particular a hand-edited record cannot direct this verifier into .runtime.
    for item in inputs:
        path = Path(item['path'])
        expected = work / 'inputs' / path.relative_to(ROOT)
        if item.get('snapshot') != str(expected) or not re.fullmatch(r'[0-9a-f]{64}', item.get('sha256', '')):
            raise Refusal('sourceSnapshotPathChanged')
    if canonical_hash(inputs) != record.get('inputSetSHA256'):
        raise Refusal('sourceInventoryChanged')
    approved_pins(record['packagePins'])
    require_unchanged(inputs)
    generated = record.get('generator', {})
    expected_outputs = [work / 'generated/SwiftTermBuildInfo.swift', work / 'generated/SwiftTermTerminfo.swift']
    if [item.get('path') for item in generated.get('outputs', [])] != list(map(str, expected_outputs)):
        raise Refusal('generatedSourceSetChanged')
    tool = work / 'artifacts/SwiftTermBuildInfoGenerator-host-only'
    if (generated.get('path') != str(tool) or generated.get('hostOnlyNotLinked') is not True
            or digest(tool) != generated.get('sha256')):
        raise Refusal('officialGeneratorChanged')
    for item in generated['outputs']:
        if digest(Path(item['path'])) != item['sha256']:
            raise Refusal('generatedSourceChanged')
    return layout


def verify_link_map(path, objects, sdk):
    text = checked_path(path).read_text()
    try:
        section = text.split('# Object files:\n', 1)[1].split('# Sections:', 1)[0]
    except IndexError:
        raise Refusal('linkMapUnavailable') from None
    entries = re.findall(r'^\[\s*\d+\]\s+(.+)$', section, re.M)
    if not entries or entries[0] != 'linker synthesized':
        raise Refusal('linkMapUnavailable')
    expected = list(map(str, objects))
    actual = []
    sdk = Path(sdk).resolve(strict=True)
    for value in entries[1:]:
        if value.endswith('.tbd'):
            stub = Path(value)
            if not stub.is_absolute() or '..' in stub.parts:
                raise Refusal('nonSDKLinkInput')
            # Apple's linker writes the versioned SDK alias in maps, while
            # xcrun may return the unversioned canonical directory (or vice versa).
            stub = stub.resolve(strict=True)
            if not stub.is_relative_to(sdk):
                raise Refusal('nonSDKLinkInput')
            relative = str(stub.relative_to(sdk))
            if not relative.startswith(('usr/lib/', 'System/Library/Frameworks/', 'System/Library/PrivateFrameworks/')):
                raise Refusal('nonSDKLinkInput')
        else:
            actual.append(value)
    if len(actual) != len(expected) or set(actual) != set(expected):
        # Includes compiler compatibility archives or unexpected min15/host tool
        # objects, even if they would not appear in LC_LOAD_DYLIB metadata.
        raise Refusal('unexpectedLinkedObjectOrArchive')


def validate_link_record(record, work, layout):
    expected = {}
    snapshots = {path: work / 'inputs' / path.relative_to(ROOT) for path in layout['paths']}
    for module in ('OpenLXSSHTrust', 'SwiftTerm', 'OpenLXSSHAskpass', 'OpenLXSSHTransport',
                   'StabilityCore', 'OpenLXSSHAskpassHelper', 'OpenLXSSHStability'):
        sources = [snapshots[p] for p in layout['modules'][module]]
        if module == 'SwiftTerm':
            sources += [work / 'generated/SwiftTermBuildInfo.swift', work / 'generated/SwiftTermTerminfo.swift']
        expected[str(work / 'objects' / (module + '.o'))] = (module, list(map(str, sources)))
    for source in layout['cSources']:
        module = 'StabilityPOSIX' if source.name == 'StabilityPOSIX.c' else 'COpenLXSSHAskpass'
        expected[str(work / 'objects' / (module + '-' + source.stem + '.o'))] = (module, [str(snapshots[source])])
    objects = record.get('objects', [])
    if len(objects) != len(expected) or {item.get('path') for item in objects} != set(expected):
        raise Refusal('linkedObjectSetChanged')
    for item in objects:
        module, sources = expected[item['path']]
        path = Path(item['path'])
        if item.get('module') != module or item.get('sources') != sources or digest(path) != item['sha256']:
            raise Refusal('linkedObjectChanged')
        if macho_metadata(path) != item['metadata']:
            raise Refusal('linkedObjectMetadataChanged')
    for label, name, main in (('driver', 'OpenLXSSHStability', 'OpenLXSSHStability'),
                               ('helper', 'openlxssh-askpass', 'OpenLXSSHAskpassHelper')):
        artifact = record['artifacts'][label]
        path = work / 'artifacts' / name
        if artifact.get('path') != str(path) or digest(path) != artifact['sha256']:
            raise Refusal('linkedExecutableChanged')
        if macho_metadata(path, executable=True) != artifact['metadata']:
            raise Refusal('linkedExecutableMetadataChanged')
        required = {p for p, (module, _) in expected.items() if module in (
            (main, 'OpenLXSSHAskpass', 'COpenLXSSHAskpass') if label == 'helper' else
            (main, 'OpenLXSSHTrust', 'SwiftTerm', 'OpenLXSSHAskpass', 'OpenLXSSHTransport', 'StabilityCore', 'COpenLXSSHAskpass', 'StabilityPOSIX'))}
        if set(artifact.get('linkedObjects', [])) != required or len(artifact['linkedObjects']) != len(required):
            raise Refusal('linkedInputClosureChanged')
        link_map = work / 'artifacts' / (name + '.link-map')
        if artifact.get('linkMap') != str(link_map) or digest(link_map) != artifact.get('linkMapSHA256'):
            raise Refusal('linkMapChanged')
        verify_link_map(link_map, artifact['linkedObjects'], record['toolchain']['sdk'])
    if digest(work / 'link-commands.json') != record.get('linkCommandsSHA256'):
        raise Refusal('compileLinkCommandsChanged')


def macho_metadata(path, executable=False):
    data = checked_path(path).read_bytes()
    if len(data) < 32:
        raise Refusal('notMachO')
    magic, cpu, subtype, kind, count, length, flags, reserved = struct.unpack_from('<IiiIIIII', data)
    if magic != 0xfeedfacf or cpu != 0x0100000c or kind != (2 if executable else 1):
        raise Refusal('incorrectMachOArchitectureOrKind')
    if count > 4096 or 32 + length > len(data):
        raise Refusal('invalidLoadCommands')
    position = 32
    builds, libraries, rpaths, dyld, signatures = [], [], [], [], 0
    for _ in range(count):
        if position + 8 > 32 + length:
            raise Refusal('invalidLoadCommands')
        command, size = struct.unpack_from('<II', data, position)
        if size < 8 or size % 8 or position + size > 32 + length:
            raise Refusal('invalidLoadCommands')
        if command == 0x32:  # LC_BUILD_VERSION
            if size < 24:
                raise Refusal('invalidLoadCommands')
            platform, minimum, sdk, tools = struct.unpack_from('<IIII', data, position + 8)
            builds.append((platform, minimum, sdk))
        if command in (0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023, 0x8000001c, 0xe):
            if size < 12:
                raise Refusal('invalidLoadCommands')
            offset, = struct.unpack_from('<I', data, position + 8)
            if offset < 12 or offset >= size:
                raise Refusal('invalidLoadCommands')
            value = data[position + offset:position + size].split(b'\0', 1)[0].decode('utf-8')
            if command == 0x8000001c:
                rpaths.append(value)
            elif command == 0xe:
                dyld.append(value)
            else:
                libraries.append(value)
        if command == 0x1d:  # LC_CODE_SIGNATURE
            signatures += 1
        position += size
    if position != 32 + length or len(builds) != 1:
        raise Refusal('invalidBuildVersion')
    platform, minimum, sdk = builds[0]
    if platform != 1 or minimum != 26 << 16 or sdk >> 16 != 26:
        raise Refusal('notArm64MacOS26Input')
    if executable:
        for library in libraries:
            if '..' in Path(library).parts or not library.startswith(('/usr/lib/', '/System/Library/Frameworks/', '/System/Library/PrivateFrameworks/')):
                raise Refusal('nonSystemRuntimeDependency')
        if not libraries or any(path != '/usr/lib/swift' for path in rpaths) or dyld != ['/usr/lib/dyld']:
            raise Refusal('nonSystemRuntimeSearchPath')
    return {'architecture': 'arm64', 'fileType': 'MH_EXECUTE' if executable else 'MH_OBJECT',
            'minimumOS': '26.0', 'sdk': f'{sdk >> 16}.{(sdk >> 8) & 255}.{sdk & 255}',
            'libraries': libraries, 'rpaths': rpaths, 'codeSignatureCommands': signatures}


class Builder:
    def __init__(self, work):
        self.work = work
        self.commands = []
        self.objects = []
        for name in ('tmp', 'logs', 'objects', 'modules', 'module-cache', 'clang-cache', 'artifacts', 'cmodules', 'generated'):
            (work / name).mkdir(mode=0o700)
        self.record = {'schema': 1, 'kind': KIND, 'taskID': 'P7-STABILITY-DRIVER-BUILD-B',
                       'createdUTC': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                       'target': TARGET, 'status': 'building', 'driverExecuted': False,
                       'runtimeVerified': False, 'signature': {'status': 'unsigned'}}

    def command(self, label, arguments, timeout=300, private=False):
        result = capture(arguments, self.work, timeout)
        entry = {'label': label, 'cwd': str(HERE), 'command': arguments if not private else '<private existing-identity signing command>',
                 'exitCode': result.returncode}
        self.commands.append(entry)
        if not private:
            path = self.work / 'logs' / (label + '.log')
            path.write_bytes(result.stdout + result.stderr)
            entry['log'] = str(path)
            entry['warningCount'] = (result.stdout + result.stderr).count(b'warning:')
        # Identity discovery, certificate names and signing diagnostic output are
        # NEVER written to logs, records or terminal (including error paths).
        if result.returncode:
            raise Refusal(label + 'Failed')
        return result.stdout + result.stderr

    def snapshot(self, layout):
        inputs = fingerprint(layout['paths'])
        for item in inputs:
            original = Path(item['path'])
            target = self.work / 'inputs' / original.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with target.open('xb') as stream:
                stream.write(original.read_bytes())
            target.chmod(0o400)
            item['snapshot'] = str(target)
        require_unchanged(inputs)
        self.record['inputs'] = inputs
        self.record['inputSetSHA256'] = canonical_hash(inputs)
        self.snapshots = {Path(item['path']): Path(item['snapshot']) for item in inputs}

    def tools(self):
        self.swift = self.command('locate-swiftc', ['/usr/bin/xcrun', '-f', 'swiftc']).decode().strip()
        self.clang = self.command('locate-clang', ['/usr/bin/xcrun', '-f', 'clang']).decode().strip()
        self.sdk = self.command('locate-sdk', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path']).decode().strip()
        sdk_version = self.command('sdk-version', ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version']).decode().strip()
        if not sdk_version.startswith('26.'):
            raise Refusal('macOS26SDKRequired')
        self.record['toolchain'] = {
            'swiftc': self.swift, 'clang': self.clang, 'sdk': self.sdk, 'sdkVersion': sdk_version,
            'swiftVersion': self.command('swift-version', [self.swift, '--version']).decode(),
            'clangVersion': self.command('clang-version', [self.clang, '--version']).decode(),
            'xcodeVersion': self.command('xcode-version', ['/usr/bin/xcodebuild', '-version']).decode(),
            'hostOS': self.command('host-os', ['/usr/bin/sw_vers', '-productVersion']).decode().strip(),
        }

    def swift_compile(self, name, sources, version, package=None, library=True, extra=()):
        output = self.work / 'objects' / (name + '.o')
        command = [self.swift, '-emit-object', '-emit-module', '-whole-module-optimization',
                   '-O', '-swift-version', version, '-target', TARGET, '-sdk', self.sdk,
                   '-module-name', name, '-module-cache-path', str(self.work / 'module-cache'),
                   '-I', str(self.work / 'modules'), '-I', str(self.work / 'cmodules'),
                   '-DSWIFT_PACKAGE', '-DSWIFT_MODULE_RESOURCE_BUNDLE_UNAVAILABLE',
                   '-emit-module-path', str(self.work / 'modules' / (name + '.swiftmodule'))]
        if library:
            command.append('-parse-as-library')
        if package:
            command += ['-package-name', package]
        command += list(extra) + [str(p) for p in sources] + ['-o', str(output)]
        self.command('compile-' + name, command)
        self.track_object(output, name, sources)
        return output

    def track_object(self, path, module, sources):
        metadata = macho_metadata(path)
        self.command('metadata-' + path.stem, ['/usr/bin/xcrun', 'vtool', '-show-build', str(path)])
        self.objects.append({'path': str(path), 'sha256': digest(path), 'module': module,
                             'sources': [str(p) for p in sources], 'metadata': metadata})

    def c_compile(self, source, module, include):
        snapshot = self.snapshots[source]
        output = self.work / 'objects' / (module + '-' + source.stem + '.o')
        self.command('compile-' + output.stem, [self.clang, '-c', '-O2', '-fPIC', '-target', TARGET,
                     '-isysroot', self.sdk, '-fmodules', '-fmodules-cache-path=' + str(self.work / 'clang-cache'),
                     '-I', str(include), str(snapshot), '-o', str(output)])
        self.track_object(output, module, [snapshot])
        return output

    def generate(self, layout):
        # Host-only official build tool. NOT a runtime linked input, HostProbe or
        # deployment override of any product component. No mocked build info.
        tool = self.work / 'artifacts/SwiftTermBuildInfoGenerator-host-only'
        sources = [self.snapshots[p] for p in layout['modules']['SwiftTermBuildInfoGenerator']]
        self.command('compile-official-generator-host-only', [self.swift, '-O', '-parse-as-library',
                     '-target', 'arm64-apple-macosx15.0', '-sdk', self.sdk,
                     '-module-cache-path', str(self.work / 'module-cache'),
                     '-Xlinker', '-no_adhoc_codesign', *map(str, sources), '-o', str(tool)])
        generated = [self.work / 'generated/SwiftTermBuildInfo.swift', self.work / 'generated/SwiftTermTerminfo.swift']
        self.command('run-official-source-generator-only', [str(tool), str(layout['swiftterm']), *map(str, generated)])
        self.record['generator'] = {'hostOnlyNotLinked': True, 'path': str(tool), 'sha256': digest(tool),
                                    'sources': [str(p) for p in sources],
                                    'repositoryInput': str(layout['swiftterm']),
                                    'terminfoInput': str(layout['swiftterm'] / 'swifterm-terminfo'),
                                    'outputs': fingerprint(generated)}
        require_unchanged(self.record['inputs'])
        return generated

    def link(self, name, objects):
        output = self.work / 'artifacts' / name
        frameworks = ['-framework', 'Security', '-lbsm']
        if name == 'OpenLXSSHStability':
            frameworks += ['-framework', 'AppKit', '-lutil']
        link_map = self.work / 'artifacts' / (name + '.link-map')
        self.command('link-' + name, [self.swift, '-v', '-emit-executable', '-target', TARGET, '-sdk', self.sdk,
                     '-no-toolchain-stdlib-rpath', '-Xlinker', '-no_adhoc_codesign',
                     '-Xlinker', '-map', '-Xlinker', str(link_map),
                     *map(str, objects), *frameworks, '-o', str(output)])
        verify_link_map(link_map, objects, self.sdk)
        metadata = macho_metadata(output, executable=True)
        if metadata['codeSignatureCommands']:
            raise Refusal('unexpectedImplicitSignature')
        unsigned = capture(['/usr/bin/codesign', '--verify', '--strict', str(output)], self.work)
        if unsigned.returncode == 0:
            raise Refusal('unsignedExecutableUnexpectedlyAccepted')
        for label, tool, flags in (('vtool', 'vtool', ['-show-build']), ('otool', 'otool', ['-L']), ('header', 'otool', ['-hv'])):
            self.command(label + '-' + name, ['/usr/bin/xcrun', tool, *flags, str(output)])
        symbols = self.command('nm-' + name, ['/usr/bin/xcrun', 'nm', str(output)])
        required = b'runAskpassHelper' if name == 'openlxssh-askpass' else b'DirectSSHSession'
        if required not in symbols or any(value in symbols for value in (b'OfflineSession', b'startProbe', b'configureProbe', b'deliverProbeOutput')):
            raise Refusal('incorrectRuntimeSymbols')
        return {'path': str(output), 'sha256': digest(output), 'metadata': metadata,
                'linkedObjects': [str(path) for path in objects],
                'linkMap': str(link_map), 'linkMapSHA256': digest(link_map),
                'unsignedStrictVerificationExitCode': unsigned.returncode}

    def save(self):
        # JSON evidence is local and deliberately not a report or acceptance claim.
        write_json(self.work / 'commands.json', self.commands)
        write_json(self.work / 'result.json', self.record)


def select_development_identity(output):
    match = re.search(rb'^\s*\d+\)\s+([A-F0-9]{40})\s+"Apple Development:[^"\r\n]+"\s*$', output, re.M)
    return match.group(1).decode() if match else None


def signature_fields(display, entitlements, expected_id):
    identifier = re.search(rb'^Identifier=(.+)$', display, re.M)
    team = re.search(rb'^TeamIdentifier=([A-Z0-9]{10})$', display, re.M)
    if not identifier or identifier.group(1).decode() != expected_id or not team:
        raise Refusal('signatureIdentityMismatch')
    if b'Signature=adhoc' in display or not re.search(rb'^CodeDirectory .*\bruntime\b', display, re.M):
        raise Refusal('hardenedDevelopmentSignatureRequired')
    if re.search(rb'^Timestamp=', display, re.M) or not re.search(rb'^Authority=Apple Development:', display, re.M):
        raise Refusal('offlineDevelopmentSignatureRequired')
    # No entitlements at all: neither get-task-allow nor a bypass allow-list.
    if entitlements.strip():
        try:
            value = plistlib.loads(entitlements)
        except (ValueError, plistlib.InvalidFileException):
            raise Refusal('unreadableEntitlements') from None
        if value:
            raise Refusal('entitlementsNotAllowed')
    return {'identifier': expected_id, 'teamIdentifier': team.group(1).decode(),
            'hardenedRuntime': True, 'entitlements': {}, 'timestamp': 'none', 'strictVerified': True}


def verify_signature(path, expected_id, work=None, deep=False):
    for args in (['--verify', '--strict'] + (['--deep'] if deep else []),):
        if capture(['/usr/bin/codesign', *args, str(path)], work).returncode:
            raise Refusal('strictSignatureVerificationFailed')
    display = capture(['/usr/bin/codesign', '--display', '--verbose=4', str(path)], work)
    entitlements = capture(['/usr/bin/codesign', '--display', '--entitlements', ':-', str(path)], work)
    if display.returncode or entitlements.returncode:
        raise Refusal('signatureMetadataUnavailable')
    fields = signature_fields(display.stdout + display.stderr, entitlements.stdout, expected_id)
    requirement = ('anchor apple generic and identifier "' + expected_id +
                   '" and certificate leaf[subject.OU] = "' + fields['teamIdentifier'] + '"')
    if capture(['/usr/bin/codesign', '--verify', '--strict', '-R', '=' + requirement, str(path)], work).returncode:
        raise Refusal('appleTeamRequirementFailed')
    return fields


def sign_wrapper(builder, app):
    # Query once, only AFTER all compilation/linking. Never print/store identity,
    # certificate/private-key material, identity output or signing diagnostics.
    result = capture(['/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning'], builder.work)
    identity = select_development_identity(result.stdout) if not result.returncode else None
    if identity is None:
        builder.record['signature'] = {'status': 'noExistingDevelopmentIdentity', 'identityDetailsRecorded': False}
        return False
    helper = app / 'Contents/Helpers/openlxssh-askpass'
    builder.record['signature']['method'] = {
        'sign': '--force --sign <existing Apple Development identity kept in memory> --identifier <official identifier> --options runtime --timestamp=none',
        'verify': '--verify --strict; App additionally --deep; anchor apple generic + identifier + same Team requirement',
        'entitlementsSupplied': False, 'systemAuthorizationSupplied': False}
    for label, path, identifier in (('helper', helper, HELPER_ID), ('app', app, APP_ID)):
        builder.command('sign-' + label, ['/usr/bin/codesign', '--force', '--sign', identity,
                        '--identifier', identifier, '--options', 'runtime', '--timestamp=none', str(path)], private=True)
        fields = verify_signature(path, identifier, builder.work, deep=label == 'app')
        builder.record['signature'][label] = fields
        if label == 'app' and fields['teamIdentifier'] != builder.record['signature']['helper']['teamIdentifier']:
            raise Refusal('helperAppTeamMismatch')
    builder.record['signature'].update({'status': 'strictDevelopmentVerified', 'identityDetailsRecorded': False})
    return True


def verify_record(path):
    path = checked_path(path)
    work = checked_path(path.parent, directory=True)
    if work.parent != BUILD or not re.fullmatch(r'driver-[0-9a-f-]{36}', work.name) or path.name != 'result.json':
        raise Refusal('unapprovedRecordPath')
    record = json.loads(path.read_text())
    if record.get('kind') != KIND or record.get('signature', {}).get('status') != 'strictDevelopmentVerified':
        raise Refusal('strictSignedRecordRequired')
    layout = validate_source_record(record, work)
    validate_link_record(record, work, layout)
    app = work / 'wrapper/OpenLXSSHStability.app'
    if record['wrapper'].get('path') != str(app):
        raise Refusal('unapprovedWrapperPath')
    checked_path(app, directory=True)
    linked_record = work / 'linked-build.json'
    plist = plistlib.loads(checked_path(app / 'Contents/Info.plist').read_bytes())
    if (plist.get('CFBundleIdentifier') != APP_ID or plist.get('CFBundleExecutable') != 'OpenLXSSHStability'
            or plist.get('LSMinimumSystemVersion') != '26.0'
            or plist.get('StabilitySourceRevision') != record['gitStart']['commit']
            or plist.get('StabilitySourceDirty') != record['gitStart']['dirty']
            or plist.get('StabilityInputSetSHA256') != record['inputSetSHA256']
            or plist.get('StabilityLinkedBuildRecordSHA256') != digest(linked_record)):
        raise Refusal('wrapperProvenanceChanged')
    for label, binary, identifier in (('helper', app / 'Contents/Helpers/openlxssh-askpass', HELPER_ID),
                                      ('driver', app / 'Contents/MacOS/OpenLXSSHStability', APP_ID)):
        if digest(binary) != record['wrapper'][label + 'SHA256']:
            raise Refusal('wrapperBinaryChanged')
        macho_metadata(binary, executable=True)
    helper = verify_signature(app / 'Contents/Helpers/openlxssh-askpass', HELPER_ID)
    own = verify_signature(app, APP_ID, deep=True)
    if helper['teamIdentifier'] != own['teamIdentifier']:
        raise Refusal('helperAppTeamMismatch')
    return record


def build(cache, sign=False):
    layout = validate_cache(cache)  # Fail before creating output if cache/pins are absent or changed.
    state = git_state()
    if BUILD.exists():
        checked_path(BUILD, directory=True)
    else:
        BUILD.mkdir(mode=0o700)
    work = BUILD / ('driver-' + str(uuid.uuid4()))
    work.mkdir(mode=0o700)  # No user-supplied output path and never overwrite an existing UUID.
    builder = Builder(work)
    builder.record.update({'gitStart': state, 'cache': str(cache),
                           'packagePins': json.loads((TRANSPORT / 'Package.resolved').read_text())})
    print('Exclusive local build evidence: ' + str(work), flush=True)
    try:
        builder.snapshot(layout)
        builder.tools()
        generated = builder.generate(layout)
        c_objects = {}
        for module, header in zip(('COpenLXSSHAskpass', 'StabilityPOSIX'), layout['headers']):
            include = builder.snapshots[header].parent
            (work / 'cmodules' / (module + '.modulemap')).write_text(
                f'module {module} {{\n    header "{builder.snapshots[header]}"\n    export *\n}}\n')
            # Clang discovers an individual module map via an explicitly named directory.
            module_dir = work / 'cmodules' / module
            module_dir.mkdir(mode=0o700)
            (module_dir / 'module.modulemap').write_text((work / 'cmodules' / (module + '.modulemap')).read_text())
            c_objects[module] = [builder.c_compile(p, module, include) for p in layout['cSources']
                                 if (p.name == 'StabilityPOSIX.c') == (module == 'StabilityPOSIX')]
        runtime = {}
        for name, version, package in (('OpenLXSSHTrust', '6', 'openlxsshtrust'), ('SwiftTerm', '6', 'swiftterm'),
                                       ('OpenLXSSHAskpass', '5', 'openlxsshtransport'),
                                       ('OpenLXSSHTransport', '5', 'openlxsshtransport'), ('StabilityCore', '6', None)):
            sources = [builder.snapshots[p] for p in layout['modules'][name]]
            extra = ['-I', str(work / 'cmodules/COpenLXSSHAskpass'), '-I', str(work / 'cmodules/StabilityPOSIX')]
            if name == 'SwiftTerm':
                sources += generated
                extra += ['-DPortableGraphics', '-user-module-version', '1.99.1']
            runtime[name] = builder.swift_compile(name, sources, version, package=package, extra=extra)
        extra = ['-I', str(work / 'cmodules/COpenLXSSHAskpass'), '-I', str(work / 'cmodules/StabilityPOSIX')]
        helper = builder.swift_compile('OpenLXSSHAskpassHelper', [builder.snapshots[p] for p in layout['modules']['OpenLXSSHAskpassHelper']],
                                       '5', package='openlxsshtransport', library=False, extra=extra)
        driver = builder.swift_compile('OpenLXSSHStability', [builder.snapshots[p] for p in layout['modules']['OpenLXSSHStability']],
                                       '6', extra=extra + ['-warnings-as-errors'])
        builder.record['artifacts'] = {
            'helper': builder.link('openlxssh-askpass', [helper, runtime['OpenLXSSHAskpass'], *c_objects['COpenLXSSHAskpass']]),
            'driver': builder.link('OpenLXSSHStability', [driver, *runtime.values(), *c_objects['COpenLXSSHAskpass'], *c_objects['StabilityPOSIX']]),
        }
        builder.record['objects'] = builder.objects
        require_unchanged(builder.record['inputs'])
        if source_layout(cache)['paths'] != layout['paths']:
            raise Refusal('sourceSetChanged')
        validate_cache(cache)
        builder.record.update({'status': 'linked-not-run', 'gitEnd': git_state()})
        write_json(work / 'link-commands.json', builder.commands)
        builder.record['linkCommandsSHA256'] = digest(work / 'link-commands.json')
        provenance = work / 'linked-build.json'
        write_json(provenance, builder.record)
        app = prepare_wrapper.prepare_verified(provenance)
        builder.record['wrapper'] = {'path': str(app)}
        if sign:
            builder.record['signature']['status'] = 'signing-requested-existing-identity-only'
        if sign and not sign_wrapper(builder, app):
            builder.record['status'] = 'linked-unsigned-no-identity-not-run'
            return 3
        # After signing there is NO driver/helper/generator execution. Metadata
        # tools and strict signature verification only; binaries remain min26.
        for label, binary in (('driver', app / 'Contents/MacOS/OpenLXSSHStability'),
                              ('helper', app / 'Contents/Helpers/openlxssh-askpass')):
            builder.record['wrapper'][label + 'SHA256'] = digest(binary)
            builder.record['wrapper'][label + 'Metadata'] = macho_metadata(binary, executable=True)
            for tool, flags in (('vtool', ['-show-build']), ('otool', ['-L']), ('nm', [])):
                builder.command('wrapper-' + tool + '-' + label, ['/usr/bin/xcrun', tool, *flags, str(binary)])
        require_unchanged(builder.record['inputs'])
        builder.record['status'] = 'signed-static-only-not-run' if sign else 'linked-unsigned-not-run'
        print('Real min26 driver/helper linked; ' + ('strict Development signatures verified.' if sign else 'UNSIGNED; no identity queried.'))
        print('No driver execution, real connection or stability acceptance performed.')
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        builder.record['status'] = 'failed-not-run'
        builder.record['failure'] = str(error) if isinstance(error, Refusal) else type(error).__name__
        raise
    finally:
        builder.save()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=('help', 'validate', 'build', 'verify'), default='help')
    parser.add_argument('--cache', default=str(DEFAULT_CACHE), help='exact existing approved macos26 cache; never created or resolved')
    parser.add_argument('--sign-development', action='store_true', help='build only: existing identity, helper then App; no authorization supplied')
    parser.add_argument('--record', help='verify only: exact result.json from a signed UUID build')
    args = parser.parse_args(argv)
    if args.action == 'help':
        parser.print_help()
        return 0
    if (args.sign_development and args.action != 'build') or (args.record is not None and args.action != 'verify'):
        raise Refusal('incompatibleArguments')
    if args.action == 'verify':
        if not args.record or args.cache != str(DEFAULT_CACHE):
            raise Refusal('explicitSignedRecordRequired')
        verify_record(Path(args.record))
        print('Read-only provenance/object/min26/strict Development signature checks passed; driver NOT run.')
        return 0
    cache = checked_path(args.cache, directory=True)
    if args.action == 'validate':
        layout = validate_cache(cache)
        print(json.dumps({'check': 'read-only-pins-plugin-and-source-metadata-only',
                          'inputCount': len(layout['paths']), 'noBuildSignOrRun': True}))
        return 0
    os.umask(0o077)
    return build(cache, sign=args.sign_development)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        category = str(error) if isinstance(error, Refusal) else type(error).__name__
        sys.stderr.write('Offline driver recipe refused: ' + category + '. No identity or secret details emitted.\n')
        sys.exit(2)
