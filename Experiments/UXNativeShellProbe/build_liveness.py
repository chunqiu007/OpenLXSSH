#!/usr/bin/env python3
"""Offline-only native liveness build, inert by default. No credential/fixture/live access.

Normal/DROP binary links an unmodified frozen Bridge.c object. The separately named
MaxSessions artifact alone compiles that object's public API symbol remap to the approved
same-session test shim. This never changes runtime sources, libraries, archive or pins.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

sys.dont_write_bytecode = True
from build_live import (Builder, BUILD, FILES, FIXTURE, HERE, INTEGRATION, MARKER, NATIVE,
                        ROOT, TARGET, Refusal, json_private, mach_metadata, read_source, write_private)
from verify_native_source import verify as source_gate

FROZEN = BUILD / 'live-6a50390d-93df-4e21-9824-61f13d76fe61'
FROZEN_BINARY = '1808b3bd411e30384be31fbd5d645967981bb8aa951b152ed2c251000a392818'
NATIVE_SUPPORT = ROOT / 'Tests/KeepaliveAcceptance/NativeSupport'


def frozen_runtime():
    record = json.loads(read_source(FROZEN / 'result.json'))
    if len(record['inputs']) != 228 or record['binary']['sha256'] != FROZEN_BINARY:
        raise Refusal('readiness-receipt-not-frozen-228')
    if hashlib.sha256(read_source(Path(record['binary']['path']))).hexdigest() != FROZEN_BINARY:
        raise Refusal('readiness-consumer-changed')
    bound = []
    for item in record['inputs']:
        snapshot = read_source(Path(item['snapshot']), exported=True)
        if hashlib.sha256(snapshot).hexdigest() != item['sha256']:
            raise Refusal('readiness-snapshot-changed')
        path = Path(item['path'])
        # Experiment evolves; every production/dependency source stays byte-for-byte frozen.
        if '/Experiments/UXNativeShellProbe/' not in str(path):
            if hashlib.sha256(read_source(path, exported='/install/' in str(path) or path.suffix == '.gz')).hexdigest() != item['sha256']:
                raise Refusal('frozen-runtime-or-dependency-changed')
            bound.append({'path': str(path), 'sha256': item['sha256']})
    return bound


def build(instrumented):
    os.umask(0o077)
    BUILD.mkdir(mode=0o700, exist_ok=True)
    if read_source(BUILD / '.native-shell-probe-owner') != MARKER:
        raise Refusal('incorrectBuildMarker')
    frozen = frozen_runtime()
    gate = source_gate(read_source=read_source)
    work = BUILD / ('liveness-' + ('maxsessions-' if instrumented else 'normal-') + str(uuid.uuid4()).lower())
    work.mkdir(mode=0o700)
    builder = Builder(work)
    builder.record.update({'taskID': 'NATIVE-LIVENESS-SUPERVISOR-R2-BUILD', 'instrumented': instrumented,
                           'normalAndDropUninstrumented': not instrumented, 'frozenReadinessBinary': FROZEN_BINARY,
                           'frozenReadinessInputCount': 228, 'frozenRuntimeInputs': frozen,
                           'nativeLivenessSourceGate': gate})
    print('Offline native liveness build: ' + str(work), flush=True)
    try:
        for filename in ['build_live.py', 'build_liveness.py', 'verify_native_source.py']:
            builder.snapshot(HERE / filename)
        builder.snapshot(FROZEN / 'result.json')
        for path in sorted(NATIVE_SUPPORT.glob('*.py')):
            builder.snapshot(path)
        # Bind the exact offline proof-age assertions used to approve this consumer as well.
        auxiliary = HERE / 'Tests/UXNativeShellProbeTests/LivenessControlTests.swift'
        builder.snapshot(auxiliary)
        builder.record['auxiliaryVerificationInputs'] = [str(auxiliary)]
        sys.path.insert(0, str(NATIVE_SUPPORT))
        from fixture_identity import PUBLIC_EVIDENCE
        for name, expected in PUBLIC_EVIDENCE.items():
            snapshot = builder.snapshot(Path(name))
            if hashlib.sha256(snapshot.read_bytes()).hexdigest() != expected:
                raise Refusal('current-fixture-public-evidence-changed')
        for name in ['core.py', 'relay_control.py', 'frozen-inputs.json', 'identity.c']:
            builder.snapshot(ROOT / 'Tests/KeepaliveAcceptance' / name)
        builder.snapshot(NATIVE / 'manifest.json')
        builder.snapshot(NATIVE / 'downloads/libssh2-1.11.1.tar.gz', exported=True)
        manifest = json.loads(read_source(NATIVE / 'manifest.json'))
        for relative, expected in manifest['outputs'].items():
            if not relative.startswith('install/') or '..' in Path(relative).parts:
                raise Refusal('invalidNativeOutputPath')
            snapshot = builder.snapshot(NATIVE / relative, exported=True)
            if hashlib.sha256(snapshot.read_bytes()).hexdigest() != expected:
                raise Refusal('nativeOutputChanged')
        native = work / 'inputs' / NATIVE.relative_to(ROOT) / 'install'
        archives = [native / 'lib' / name for name in ['libssh2.a', 'libssl.a', 'libcrypto.a']]
        builder.tools()
        if instrumented:
            builder.cflags = ['-Dlibssh2_channel_open_ex=ns_test_channel_open_ex', '-Dlibssh2_session_free=ns_test_session_free']
        cobjects = builder.c_module('COpenLXSSHFiles', FILES / 'Sources/COpenLXSSHFiles/include/COpenLXSSHFiles.h',
            [FILES / 'Sources/COpenLXSSHFiles/Bridge.c'], native / 'include')
        builder.cflags = ['-DNATIVE_MAXSESSIONS_TEST_ONLY'] if instrumented else []
        helpers = HERE / 'LivenessTestSupport'
        sources = [helpers / 'Metadata.c'] + ([helpers / 'MaxSessions.c'] if instrumented else [])
        cobjects += builder.c_module('CNativeLivenessTest', helpers / 'include/NativeLivenessTest.h', sources, native / 'include')
        builder.cflags = []
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
        fixture_sources = builder.sources(HERE / 'Fixture') + builder.sources(HERE / 'LivenessFixture') + [
            builder.snapshot(INTEGRATION / 'Consumer/OpenSSHManagement.swift'), builder.snapshot(INTEGRATION / 'Consumer/SFTPAuthCallbacks.swift'), generated]
        fixture = builder.swift_module('UXNativeShellLivenessFixture', fixture_sources, ['-Xcc', '-I' + str(native / 'include')])
        main = builder.swift_module('UXNativeShellLiveness', builder.sources(HERE / 'LivenessCLI'),
            ['-DNATIVE_LIVENESS_FIXTURE', '-Xcc', '-I' + str(native / 'include')])
        executable = builder.link('UXNativeShellLivenessMaxSessions' if instrumented else 'UXNativeShellLiveness',
            [main, fixture, support, core, files, trust, *cobjects], archives)
        identity = work / 'artifacts/native-liveness-identity'
        builder.run('compile-identity', [builder.clang, '-Wall', '-Wextra', '-Werror', '-O2', '-target', TARGET, '-isysroot', builder.sdk,
            builder.snapshot(ROOT / 'Tests/KeepaliveAcceptance/identity.c'), '-o', identity])
        identity.chmod(0o700)
        for path, item in builder.inputs.items():
            if hashlib.sha256(read_source(path, exported=item['exported'])).hexdigest() != item['sha256']:
                raise Refusal('inputChangedDuringBuild')
        builder.record.update({'status': 'linked-not-live-run',
            'binary': {'path': str(executable), 'sha256': hashlib.sha256(executable.read_bytes()).hexdigest(), 'metadata': mach_metadata(executable, True)},
            'identityTool': {'path': str(identity), 'sha256': hashlib.sha256(identity.read_bytes()).hexdigest(), 'metadata': mach_metadata(identity, True)}})
    except Exception as error:
        builder.record.update({'status': 'failed-not-run', 'failure': str(error) if isinstance(error, Refusal) else type(error).__name__})
        raise
    finally:
        builder.save()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='help', choices=['help', 'validate', 'build', 'build-maxsessions'])
    args = parser.parse_args(argv)
    if args.action == 'help': parser.print_help(); return 0
    if args.action == 'validate': print('Syntax only; no public/native/fixture reads or compilation.'); return 0
    return build(args.action == 'build-maxsessions')


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as error:
        sys.stderr.write('Native liveness build refused: ' + (str(error) if isinstance(error, Refusal) else type(error).__name__) + '.\n')
        raise SystemExit(2)
