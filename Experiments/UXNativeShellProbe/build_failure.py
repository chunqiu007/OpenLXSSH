#!/usr/bin/env python3
"""New NativeFailure R1 OFFLINE build recipe. Default/help/validate are inert.

No package resolution, dependency/native rebuild, fixture collection, credential reads,
Docker, relay, live client, Keychain or signing identity. Only explicit `build` reads public
inputs and compiles immutable snapshots. It NEVER relaxes build_liveness.frozen_runtime.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import uuid

sys.dont_write_bytecode = True
from build_live import (Builder, BUILD, FILES, FIXTURE, HERE, INTEGRATION, MARKER, NATIVE,
                        ROOT, TARGET, Refusal, json_private, mach_metadata, read_source, write_private)
from verify_native_source import verify as source_gate

TASK = 'NATIVE-FAILURE-LIVE-CONSUMER-R1'
FROZEN = BUILD / 'live-6a50390d-93df-4e21-9824-61f13d76fe61'
FROZEN_BINARY = '1808b3bd411e30384be31fbd5d645967981bb8aa951b152ed2c251000a392818'
FROZEN_RECEIPT = '5eb91bfe2f14fd066660ba4acccc55fed3eb86c34664e79d32a09c7f35209685'
LEDGER = ROOT / 'DerivedData/UXVerification/NativeFailurePackage-R1/final-sha256.json'
LEDGER_SHA256 = 'd8c9d63f71e6d7de230db38d911743439287939df8743ee5aa3affdb6c354eb1'
PREFIX = 'Packages/OpenLXSSHFiles/Sources/OpenLXSSHFiles/'
# Explicit reviewed old -> new diff list. No blanket approval of worktree/package changes.
REPLACEMENTS = {
    PREFIX + 'NativeShellAuthentication.swift': (
        'a3497c9d7c3c3696cdd8aa1d5643633bf61cf6471fc20fab21b9acbe9d1f984e',
        '6e092a9d1a6a42909929aa49cfebc432cd721ef7844cffafee3e26b388895834'),
    PREFIX + 'NativeShellSession.swift': (
        '9ed29b1c9b1f1d6c90d1488b5643c9f1d903fe2ba332f5009cf20c1ef1a45ddd',
        'd071aa61e8261fec4ed760c6999e40b72001ab9769a0f256ab1674a2e5b09c7f'),
    PREFIX + 'NativeShellTypes.swift': (
        'ec1b4a98c1ae6171159adb6973bd953be0e481f79d478b48caad4054ccf9115f',
        '055e26929a1f633483ba9d962d065debd866fd3554d210344ba453d73ff073d3'),
    PREFIX + 'RemoteFileService.swift': (
        '4c0a94d9b3a06e8d98fb63c9fa0b6da61017d92c9eaff6117e6a61d34c972abc',
        'c4bdc3c72003a7541b08c3ff02e6eaa59e5a9bc0cad06e3c79cd3d4b42e4250a'),
    PREFIX + 'SharedHostTrust.swift': (
        '287b0333a5f2b67093c6e010d9db3bf165f9b5b87ab3da05e9e67db536a7ea64',
        'd486633c4ca8077e5995f8b865c3534bc5de35f5dbe3f3788da4aafa95217d48'),
}
# Public frozen identity references only. NOT credential paths to be opened during a build.
PUBLIC_IDENTITIES = {
    'keyonly': ('Experiments/UXNativeShellProbe/.build/sftp-auth-case-41e459dd6c2a/sftp-auth.json',
                'c250f0ab43d317599265a0521bf71069c1e02a7081f830f58f6f1eafe4d5febc'),
    'key-kbd': ('Experiments/UXNativeShellProbe/.build/sftp-auth-case-e9d63db42dab/sftp-auth.json',
                '235f0ecd418594d18031e4b01cdceab192760d9f9ca2fcbd25a2a7d011092ca2'),
    'password-kbd': ('Experiments/UXNativeShellProbe/.build/sftp-auth-case-9ba5ce999a93/sftp-auth.json',
                     '9f9af356b05d6f0cd25287e2c9810720d45c24dd274b07c4cf190cad86fb3a32'),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def reviewed_runtime(builder):
    receipt = builder.snapshot(FROZEN / 'result.json')
    ledger_path = builder.snapshot(LEDGER)
    if digest(receipt.read_bytes()) != FROZEN_RECEIPT or digest(ledger_path.read_bytes()) != LEDGER_SHA256:
        raise Refusal('review-ledger-or-old-receipt-changed')
    record, ledger = json.loads(receipt.read_bytes()), json.loads(ledger_path.read_bytes())
    if len(record['inputs']) != 228 or record['binary']['sha256'] != FROZEN_BINARY:
        raise Refusal('old-readiness-not-exact-228')
    binary = builder.snapshot(Path(record['binary']['path']))
    if digest(binary.read_bytes()) != FROZEN_BINARY:
        raise Refusal('old-readiness-binary-changed')
    for relative, (_, expected) in REPLACEMENTS.items():
        if ledger['files'].get(relative) != expected:
            raise Refusal('reviewed-five-source-ledger-mismatch')
    bound, changed, seen = [], [], set()
    for item in record['inputs']:
        old = builder.snapshot(Path(item['snapshot']), exported=True)
        if digest(old.read_bytes()) != item['sha256']:
            raise Refusal('old-readiness-snapshot-changed')
        path = Path(item['path'])
        if HERE in path.parents:
            continue
        relative = str(path.relative_to(ROOT))
        if relative in seen:
            raise Refusal('duplicate-old-runtime-input')
        seen.add(relative)
        old_hash = item['sha256']
        expected = old_hash
        if relative in REPLACEMENTS:
            before, expected = REPLACEMENTS[relative]
            if old_hash != before:
                raise Refusal('reviewed-old-runtime-comparison-mismatch')
            changed.append({'path': relative, 'oldSHA256': before, 'newSHA256': expected})
        exported = '/install/' in str(path) or path.suffix == '.gz'
        current = builder.snapshot(path, exported=exported)
        if digest(current.read_bytes()) != expected:
            raise Refusal('nonreviewed-runtime-or-dependency-change')
        bound.append({'path': str(path), 'sha256': expected, 'unchangedFromOld': expected == old_hash})
    if {item['path'] for item in changed} != set(REPLACEMENTS):
        raise Refusal('not-exactly-five-reviewed-runtime-replacements')
    # Glob additions are not implicitly authorized merely because they compile.
    for directory in [FILES / 'Sources/OpenLXSSHFiles', ROOT / 'Packages/OpenLXSSHTrust/Sources/OpenLXSSHTrust',
                      INTEGRATION / 'Sources/RealIntegrationCore']:
        if any(str(path.relative_to(ROOT)) not in seen for path in directory.glob('*.swift')):
            raise Refusal('unreviewed-additional-production-source')
    builder.record.update({'oldReadinessBinary': FROZEN_BINARY, 'oldReadinessInputs': 228,
        'reviewLedgerSHA256': LEDGER_SHA256, 'reviewedProductionReplacements': changed,
        'boundRuntimeInputs': bound, 'oldR4GateModified': False})


class FailureBuilder(Builder):
    def run(self, label, command):
        command = list(command)
        if '-swift-version' in command:
            command += ['-strict-concurrency=complete']
        return super().run(label, command)


def generated_context(builder):
    values = {}
    for service, (relative, expected) in PUBLIC_IDENTITIES.items():
        path = builder.snapshot(ROOT / relative)
        if digest(path.read_bytes()) != expected:
            raise Refusal('approved-public-fixture-identity-changed')
        value = json.loads(path.read_bytes())
        if value['service'] != service:
            raise Refusal('approved-public-fixture-service-changed')
        values[service] = value
    def identity(service):
        value = values[service]
        keys = ['containerID', 'expectedFingerprint', 'networkID', 'imageID', 'project', 'context', 'endpoint']
        labels = ['containerID', 'fingerprint', 'networkID', 'imageID', 'project', 'context', 'endpoint']
        return 'NativeFailureFixtureIdentity(' + ', '.join(label + ': ' + json.dumps(value[key]) for key, label in zip(keys, labels)) + ')'
    text = ('import UXNativeFailureSupport\n'
        'public enum ShellProbeBuildContext {\n public static let buildRoot = ' + json.dumps(str(BUILD)) +
        '\n public static let fixtureRoot = ' + json.dumps(str(FIXTURE)) + '\n}\n'
        'public enum NativeFailureBuildContext {\n public static let buildRoot = ' + json.dumps(str(BUILD)) +
        '\n public static func identity(for testCase: NativeFailureCase) -> NativeFailureFixtureIdentity {\n'
        '  switch testCase {\n'
        '  case .nativeChangedNoHandler, .nativeCancelledProvider, .sftpChangedNoHandler: return ' + identity('keyonly') + '\n'
        '  case .keyKIPositive: return ' + identity('key-kbd') + '\n'
        '  case .passwordKIPositive: return ' + identity('password-kbd') + '\n'
        '  }\n }\n}\n')
    path = builder.work / 'generated/NativeFailureBuildContext.swift'
    write_private(path, text.encode(), mode=0o400)
    builder.record['generatedPublicContextSHA256'] = digest(text.encode())
    return path


def build():
    os.umask(0o077)
    if BUILD.resolve() != BUILD or BUILD.stat().st_uid != os.getuid() or stat.S_IMODE(BUILD.stat().st_mode) != 0o700:
        raise Refusal('unsafe-existing-build-root')
    marker = BUILD / '.native-shell-probe-owner'
    if read_source(marker) != MARKER or stat.S_IMODE(marker.stat().st_mode) != 0o600:
        raise Refusal('incorrectBuildMarker')
    work = BUILD / ('failure-r1-' + str(uuid.uuid4()).lower())
    work.mkdir(mode=0o700)
    builder = FailureBuilder(work)
    builder.record.update({'taskID': TASK, 'liveExecuted': False, 'credentialFilesRead': False,
        'productAcceptance': False, 'instrumented': False, 'strictConcurrency': 'complete',
        'swiftVersion': '6', 'swiftWarningsAsErrors': True, 'cWarningsAsErrors': True,
        'pureContractReportChecks': 14, 'pureChecksExecuted': False})
    print('Offline NativeFailure R1 build only: ' + str(work), flush=True)
    try:
        for name in ['build_failure.py', 'build_live.py', 'build_liveness.py', 'verify_native_source.py']:
            builder.snapshot(HERE / name)
        builder.snapshot(marker)
        reviewed_runtime(builder)
        builder.record['nativeLivenessSourceGate'] = source_gate(read_source=read_source)
        # The original exact archive/source/library gate is called unmodified above.
        manifest = json.loads(builder.snapshot(NATIVE / 'manifest.json').read_bytes())
        lock = builder.snapshot(FILES / 'native-inputs.json')
        script = builder.snapshot(FILES / 'Scripts/build-native.py')
        if digest(lock.read_bytes()) != manifest['inputs']['lockSHA256'] or digest(script.read_bytes()) != manifest['inputs']['scriptSHA256']:
            raise Refusal('nativeInputsChanged')
        builder.snapshot(NATIVE / 'downloads/libssh2-1.11.1.tar.gz', exported=True)
        for relative, expected in manifest['outputs'].items():
            if not relative.startswith('install/') or '..' in Path(relative).parts:
                raise Refusal('invalidNativeOutputPath')
            if digest(builder.snapshot(NATIVE / relative, exported=True).read_bytes()) != expected:
                raise Refusal('nativeOutputChanged')
        # All Swift/C inputs INCLUDING auxiliary test sources are snapshotted BEFORE tools run.
        directories = ['FailureSupport', 'FailureFixture', 'FailureCLI', 'FailureTests', 'Fixture',
                       'Sources/UXNativeShellProbeSupport']
        for name in directories:
            for path in sorted((HERE / name).rglob('*')):
                if path.is_file():
                    builder.snapshot(path)
        for path in [HERE / 'LivenessTestSupport/Metadata.c', HERE / 'LivenessTestSupport/include/NativeLivenessTest.h',
                     INTEGRATION / 'Consumer/OpenSSHManagement.swift', INTEGRATION / 'Consumer/SFTPAuthCallbacks.swift']:
            builder.snapshot(path)
        checks = sorted((HERE / 'FailureTests').glob('*.swift'))
        builder.record['auxiliaryVerificationInputs'] = [str(path) for path in checks]
        context = generated_context(builder)
        native = work / 'inputs' / NATIVE.relative_to(ROOT) / 'install'
        archives = [native / 'lib' / name for name in ['libssh2.a', 'libssl.a', 'libcrypto.a']]
        builder.tools()
        cobjects = builder.c_module('COpenLXSSHFiles', FILES / 'Sources/COpenLXSSHFiles/include/COpenLXSSHFiles.h',
            [FILES / 'Sources/COpenLXSSHFiles/Bridge.c'], native / 'include')
        cobjects += builder.c_module('RealIntegrationPOSIX', INTEGRATION / 'Sources/RealIntegrationPOSIX/include/RealIntegrationPOSIX.h',
            [INTEGRATION / 'Sources/RealIntegrationPOSIX/PrivateInput.c'])
        askpass = ROOT / 'Packages/OpenLXSSHTransport/Sources/COpenLXSSHAskpass'
        cobjects += builder.c_module('COpenLXSSHAskpass', askpass / 'include/COpenLXSSHAskpass.h', [askpass / 'BoundedTool.c'])
        cobjects += builder.c_module('CNativeLivenessTest', HERE / 'LivenessTestSupport/include/NativeLivenessTest.h',
            [HERE / 'LivenessTestSupport/Metadata.c'], native / 'include')
        cobjects += builder.c_module('CNativeFailureResources', HERE / 'FailureFixture/include/NativeFailureResources.h',
            [HERE / 'FailureFixture/Resources.c'])
        swift_extra = ['-Xcc', '-I' + str(native / 'include')]
        trust = builder.swift_module('OpenLXSSHTrust', builder.sources(ROOT / 'Packages/OpenLXSSHTrust/Sources/OpenLXSSHTrust'))
        files = builder.swift_module('OpenLXSSHFiles', builder.sources(FILES / 'Sources/OpenLXSSHFiles'), swift_extra)
        core = builder.swift_module('RealIntegrationCore', builder.sources(INTEGRATION / 'Sources/RealIntegrationCore'))
        shell = builder.swift_module('UXNativeShellProbeSupport', builder.sources(HERE / 'Sources/UXNativeShellProbeSupport'), swift_extra)
        support = builder.swift_module('UXNativeFailureSupport', builder.sources(HERE / 'FailureSupport'), swift_extra)
        fixtures = builder.sources(HERE / 'Fixture') + builder.sources(HERE / 'FailureFixture') + [
            builder.snapshot(INTEGRATION / 'Consumer/OpenSSHManagement.swift'),
            builder.snapshot(INTEGRATION / 'Consumer/SFTPAuthCallbacks.swift'), context]
        fixture = builder.swift_module('UXNativeFailureFixture', fixtures, swift_extra)
        main = builder.swift_module('UXNativeFailureConsumer', builder.sources(HERE / 'FailureCLI'), swift_extra)
        objects = [support, shell, core, files, trust, *cobjects]
        executable = builder.link('UXNativeFailureConsumer', [main, fixture, *objects], archives)
        offline = builder.swift_module('UXNativeFailureOfflineChecks', [builder.snapshot(path) for path in checks], swift_extra)
        pure = builder.link('UXNativeFailureOfflineChecks', [offline, *objects], archives)
        for path, item in builder.inputs.items():
            if digest(read_source(path, exported=item['exported'])) != item['sha256']:
                raise Refusal('inputChangedDuringBuild')
        builder.record.update({'status': 'linked-not-run',
            'binary': {'path': str(executable), 'sha256': digest(executable.read_bytes()), 'metadata': mach_metadata(executable, True)},
            'offlineChecks': {'path': str(pure), 'sha256': digest(pure.read_bytes()), 'metadata': mach_metadata(pure, True)}})
        print('Linked only; primary must separately approve and run pure/live gates: ' + str(executable))
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
        print('Syntax only; no input, fixture, credential, source-gate reads or compilation.'); return 0
    return build()


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        sys.stderr.write('NativeFailure build refused: ' + (str(error) if isinstance(error, Refusal) else type(error).__name__) + '.\n')
        raise SystemExit(2)
