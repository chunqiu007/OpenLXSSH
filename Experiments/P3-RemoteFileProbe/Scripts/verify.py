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


def main():
    run('native-input-check', ['/usr/bin/python3', ROOT / 'Scripts/build-native.py'])
    strict = ['-Xswiftc', '-warnings-as-errors', '-Xcc', '-Wall', '-Xcc', '-Wextra', '-Xcc', '-Werror']
    for configuration in ('debug', 'release'):
        run(configuration + '-build', ['swift', 'build', '--package-path', ROOT, '-c', configuration] + strict)
        run(configuration + '-test', ['swift', 'test', '--package-path', ROOT, '-c', configuration] + strict)
        binary = ROOT / '.build' / configuration / 'OpenLXSSHRemoteFileSmoke'
        run(configuration + '-smoke', [binary])
        libraries = run(configuration + '-otool', ['otool', '-L', binary])
        if any(not line.strip().split()[0].startswith(('/usr/lib/', '/System/Library/'))
               for line in libraries.splitlines()[2:] if line.strip() and not line.startswith('exit=')):
            raise RuntimeError('Unexpected non-system runtime dependency')
    run('asan-test', ['swift', 'test', '--package-path', ROOT, '--sanitize=address'] + strict)
    run('tsan-test', ['swift', 'test', '--package-path', ROOT, '--sanitize=thread'] + strict)
    # Product target compile/link only. Do NOT execute a min-26 binary on the macOS-15 host.
    target_path = ROOT / '.build/target26'
    run('target26-build', ['swift', 'build', '--package-path', ROOT, '--scratch-path', target_path,
                           '--triple', 'arm64-apple-macosx26.0', '-c', 'release'] + strict,
        environment={'OPENLXSSH_P3_TARGET26': '1'})
    load = run('target26-load-commands', ['otool', '-l', target_path / 'arm64-apple-macosx/release/OpenLXSSHRemoteFileSmoke'])
    if 'minos 26.0' not in load or 'sdk 26.2' not in load:
        raise RuntimeError('Compile-only product did not acquire the required minos/SDK')
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
