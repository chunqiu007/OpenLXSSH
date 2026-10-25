#!/usr/bin/python3
"""Local-only repeatable verification. No endpoint, credentials or protocol server."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '.build/verification'
OUT.mkdir(parents=True, exist_ok=True)
results = []


def run(name, args, environment=None):
    log = OUT / (name + '.log')
    with log.open('w') as output:
        output.write('$ ' + ' '.join(map(str, args)) + '\n')
        output.flush()
        rc = subprocess.run(list(map(str, args)), cwd=ROOT, env=os.environ | (environment or {}),
                            stdout=output, stderr=subprocess.STDOUT).returncode
        output.write(f'\nexit={rc}\n')
    results.append({'name': name, 'cwd': str(ROOT), 'command': list(map(str, args)),
                    'environmentOverrides': environment or {}, 'exitCode': rc, 'log': str(log)})
    (OUT / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    if rc:
        raise RuntimeError(f'{name}: exit {rc}; see {log}')
    return log.read_text()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_existing_native():
    """Hash-only by default: a Swift manager change must never implicitly rebuild/download C inputs."""
    native = ROOT / '.build/native'
    manifest = json.loads((native / 'manifest.json').read_text())
    if sha(ROOT / 'native-inputs.json') != manifest['inputs']['lockSHA256'] or sha(ROOT / 'Scripts/build-native.py') != manifest['inputs']['scriptSHA256']:
        raise RuntimeError('Native input fingerprint changed; review explicitly before rebuilding')
    for relative, expected in manifest['outputs'].items():
        if sha(native / relative) != expected:
            raise RuntimeError('Existing native output hash mismatch: ' + relative)
    for relative, expected in manifest['licenseSHA256'].items():
        if sha(native / 'install/licenses' / relative) != expected:
            raise RuntimeError('Packaged license/notice hash mismatch: ' + relative)
    (OUT / 'native-hash-verification.json').write_text(json.dumps({'outputCount': len(manifest['outputs']),
        'archiveSHA256': {name: sha(native / 'install/lib' / name) for name in ('libssh2.a', 'libssl.a', 'libcrypto.a')},
        'rebuilt': False, 'remoteInteroperability': 'NOT TESTED'}, indent=2) + '\n')
    return manifest


def main():
    manifest = verify_existing_native()
    (OUT / 'license-verification.json').write_text(json.dumps({'verifiedFiles': manifest['licenseSHA256'],
        'opensslVersion': manifest['dependencies']['openssl']['version'], 'remoteInteroperability': 'NOT TESTED'}, indent=2) + '\n')
    description_log = run('package-description', ['swift', 'package', '--package-path', ROOT, 'describe', '--type', 'json'])
    description = json.JSONDecoder().raw_decode(description_log[description_log.index('{'):])[0]
    if [(p['name'], p['type']) for p in description['products']] != [('OpenLXSSHFiles', {'library': ['automatic']})]:
        raise RuntimeError('Runtime package must publish only the OpenLXSSHFiles library')
    # Replan local consumers: SwiftPM's cached dependency source list can miss newly added files.
    fixture = ROOT / 'Tests/Fixtures/OpenLXSSHFilesNativeSmoke'
    smoke_path = ROOT / '.build/native-smoke-fixture'
    strict = ['-Xswiftc', '-warnings-as-errors', '-Xcc', '-Wall', '-Xcc', '-Wextra', '-Xcc', '-Werror']
    for configuration in ('debug', 'release'):
        run(configuration + '-build', ['swift', 'build', '--package-path', ROOT, '-c', configuration, '--target', 'OpenLXSSHFiles'] + strict)
        run(configuration + '-smoke-build', ['swift', 'build', '--disable-build-manifest-caching', '--package-path', fixture, '--scratch-path', smoke_path, '-c', configuration] + strict)
        run(configuration + '-test', ['swift', 'test', '--package-path', ROOT, '-c', configuration] + strict)
        binary = smoke_path / configuration / 'OpenLXSSHFilesNativeSmoke'
        run(configuration + '-smoke', [binary])
        libraries = run(configuration + '-otool', ['otool', '-L', binary])
        if any(not line.strip().split()[0].startswith(('/usr/lib/', '/System/Library/'))
               for line in libraries.splitlines()[2:] if line.strip() and not line.startswith('exit=')):
            raise RuntimeError('Unexpected non-system runtime dependency')
    run('asan-test', ['swift', 'test', '--package-path', ROOT, '--sanitize=address'] + strict)
    run('tsan-test', ['swift', 'test', '--package-path', ROOT, '--sanitize=thread'] + strict)
    # Product target compile/link only. Do NOT execute a min-26 binary on the macOS-15 host.
    target_path = ROOT / '.build/target26-fixture'
    run('target26-build', ['swift', 'build', '--disable-build-manifest-caching', '--package-path', fixture, '--scratch-path', target_path,
                           '--triple', 'arm64-apple-macosx26.0', '-c', 'release'] + strict,
        environment={'OPENLXSSH_FILES_TARGET26': '1'})
    load = run('target26-load-commands', ['otool', '-l', target_path / 'arm64-apple-macosx/release/OpenLXSSHFilesNativeSmoke'])
    if 'minos 26.0' not in load or 'sdk 26.2' not in load:
        raise RuntimeError('Compile-only product did not acquire the required minos/SDK')
    # Verify an App-like local consumer receives the native module/link settings transitively.
    consumer = ROOT / '.build/consumer-check'
    (consumer / 'Sources/Consumer').mkdir(parents=True, exist_ok=True)
    (consumer / 'Package.swift').write_text(
        '// swift-tools-version: 6.2\nimport PackageDescription\n'
        'let package = Package(name: "Consumer", platforms: [.macOS(.v15)], '
        'dependencies: [.package(path: ' + json.dumps(str(ROOT)) + ')], '
        'targets: [.executableTarget(name: "Consumer", dependencies: '
        '[.product(name: "OpenLXSSHFiles", package: "OpenLXSSHFiles")])])\n')
    (consumer / 'Sources/Consumer/main.swift').write_text('import OpenLXSSHFiles\nprint(NativeDiagnostics.libssh2)\n')
    run('consumer-build', ['swift', 'build', '--disable-build-manifest-caching', '--package-path', consumer] + strict)
    run('consumer-smoke', [consumer / '.build/debug/Consumer'])
    manifest = json.loads((ROOT / '.build/native/manifest.json').read_text())
    native_hashes = {name: manifest['outputs']['install/lib/' + name] for name in ('libssh2.a', 'libssl.a', 'libcrypto.a')}
    if '--rebuild' in sys.argv:
        run('native-rebuild', ['/usr/bin/python3', ROOT / 'Scripts/build-native.py', '--rebuild'])
        repeated = {name: sha(ROOT / '.build/native/install/lib' / name) for name in native_hashes}
        comparison = {'nativeInputsSHA256': sha(ROOT / 'native-inputs.json'),
                      'opensslVersion': manifest['dependencies']['openssl']['version'],
                      'before': native_hashes, 'after': repeated, 'bitIdentical': native_hashes == repeated}
        (OUT / 'native-reproducibility.json').write_text(json.dumps(comparison, indent=2) + '\n')
        if native_hashes != repeated:
            raise RuntimeError('Clean repeat build archive hashes differ; review native-reproducibility.json')
    trust = ROOT.parent.parent / 'Packages/OpenLXSSHTrust'
    local_inputs = {str(path.relative_to(ROOT.parent.parent)): sha(path)
                    for path in sorted((trust / 'Sources/OpenLXSSHTrust').glob('*.swift'))}
    local_inputs['Packages/OpenLXSSHTrust/Package.swift'] = sha(trust / 'Package.swift')
    (OUT / 'local-package-inputs.json').write_text(json.dumps(local_inputs, indent=2) + '\n')
    print('Local checks completed. Real SSH/SFTP interoperability: NOT TESTED.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
