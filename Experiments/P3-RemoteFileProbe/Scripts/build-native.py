#!/usr/bin/python3
"""Build pinned public source archives. Never installs tools or touches system paths."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / '.build/native'
VERIFY = ROOT / '.build/verification'
LOCK = json.loads((ROOT / 'native-inputs.json').read_text())
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(NATIVE / 'home'),
       'LC_ALL': 'C', 'TZ': 'UTC', 'SOURCE_DATE_EPOCH': '0', 'ZERO_AR_DATE': '1'}


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def capture(args):
    return subprocess.check_output(args, env=ENV, text=True).strip()


def main():
    for tool in ('clang', 'make', 'perl', 'curl', 'tar', 'xcrun', 'otool', 'lipo'):
        if not shutil.which(tool, path=ENV['PATH']):
            raise RuntimeError(f'Missing {tool}; no tools were installed')
    if capture(['/usr/bin/uname', '-m']) != 'arm64':
        raise RuntimeError('This probe builds only on arm64 macOS')
    sdk = capture(['xcrun', '--show-sdk-path'])
    if capture(['xcrun', '--show-sdk-version']) != LOCK['toolchain']['sdkVersion']:
        raise RuntimeError('SDK differs from native-inputs.json; review and repin explicitly')
    clang = capture(['xcrun', '--find', 'clang'])
    if capture([clang, '--version']).splitlines()[0] != LOCK['toolchain']['clangVersion']:
        raise RuntimeError('clang differs from native-inputs.json; review and repin explicitly')
    if digest(clang) != LOCK['toolchain']['clangSHA256'] or digest(Path(sdk) / 'SDKSettings.json') != LOCK['toolchain']['sdkSettingsSHA256']:
        raise RuntimeError('Compiler or SDK input hash differs; review and repin explicitly')
    NATIVE.mkdir(parents=True, exist_ok=True)
    VERIFY.mkdir(parents=True, exist_ok=True)
    (NATIVE / 'home').mkdir(exist_ok=True)
    fingerprint = {'lockSHA256': digest(ROOT / 'native-inputs.json'),
                   'scriptSHA256': digest(Path(__file__)), 'sdk': sdk,
                   'sdkSettingsSHA256': digest(Path(sdk) / 'SDKSettings.json'),
                   'xcode': capture(['xcodebuild', '-version']),
                   'clang': capture([clang, '--version'])}
    manifest = NATIVE / 'manifest.json'
    if manifest.exists() and '--rebuild' not in sys.argv:
        previous = json.loads(manifest.read_text())
        if previous['inputs'] == fingerprint and all(
                (NATIVE / path).is_file() and digest(NATIVE / path) == sha
                for path, sha in previous['outputs'].items()):
            print('Verified existing native inputs and output hashes; use --rebuild for a clean rebuild')
            return
    log = open(VERIFY / 'native-build.log', 'w', buffering=1)

    def run(args, cwd=ROOT, extra=None):
        log.write('\n$ ' + ' '.join(map(str, args)) + '\n')
        result = subprocess.run(list(map(str, args)), cwd=cwd, env=ENV | (extra or {}),
                                stdout=log, stderr=subprocess.STDOUT)
        log.write(f'exit={result.returncode}\n')
        if result.returncode:
            raise RuntimeError(f'Build command failed ({result.returncode}); see {log.name}')

    cache = NATIVE / 'downloads'
    cache.mkdir(exist_ok=True)
    downloads = {}
    for name in ('openssl', 'libssh2'):
        item = LOCK[name]
        archive = cache / f'{name}-{item["version"]}.tar.gz'
        provenance = cache / f'{name}-{item["version"]}.provenance.json'
        if not archive.exists() or not provenance.exists():
            temporary = archive.with_suffix('.download')
            args = ['curl', '--fail', '--location', '--silent', '--show-error', '--proto', '=https',
                    '--proto-redir', '=https', '--tlsv1.2', '--retry', '2', '--output', str(temporary),
                    '--write-out', '%{json}', item['url']]
            log.write('\n$ curl [fixed public archive URL; redacted download metadata retained]\n')
            transport = subprocess.run(args, env=ENV, stdout=subprocess.PIPE, stderr=log, check=True, text=True)
            if digest(temporary) != item['sha256']:
                temporary.unlink()
                raise RuntimeError(f'{name} archive hash mismatch')
            temporary.replace(archive)
            raw = json.loads(transport.stdout)
            # Signed CDN redirect query strings are short-lived download tokens; retain only origin/path.
            from urllib.parse import urlsplit, urlunsplit
            final = urlsplit(raw['url_effective'])
            clean_final = urlunsplit((final.scheme, final.netloc, final.path, '', ''))
            provenance.write_text(json.dumps({'originalURL': item['url'], 'finalOriginAndPath': clean_final,
                'redirectQueryRedacted': bool(final.query), 'httpStatus': raw['http_code'],
                'redirectCount': raw['num_redirects'], 'archiveSHA256': digest(archive)}, indent=2) + '\n')
        if digest(archive) != item['sha256']:
            raise RuntimeError(f'{name} cached archive hash mismatch; refusing to build')
        downloads[name] = json.loads(provenance.read_text())
        if name == 'openssl':
            official = cache / f'openssl-{item["version"]}.official.sha256'
            if not official.exists():
                run(['curl', '--fail', '--location', '--silent', '--show-error', '--proto', '=https',
                     '--proto-redir', '=https', '--tlsv1.2', '--output', official, item['checksumURL']])
            if official.read_text().split()[0] != item['sha256']:
                raise RuntimeError('Official OpenSSL release checksum differs from pin')
    work = NATIVE / 'work'
    prefix = NATIVE / 'install'
    for path in (work, prefix):
        if path.exists():
            shutil.rmtree(path)  # Only this script's own build outputs.
        path.mkdir()
    for name in ('openssl', 'libssh2'):
        item = LOCK[name]
        with tarfile.open(cache / f'{name}-{item["version"]}.tar.gz') as archive:
            base = work.resolve()
            for entry in archive.getmembers():
                if not (base / entry.name).resolve().is_relative_to(base):
                    raise RuntimeError('Archive contains escaping path')
                if entry.islnk() or entry.issym():
                    target = (base / entry.name).parent / entry.linkname
                    if not target.resolve().is_relative_to(base):
                        raise RuntimeError('Archive contains escaping link')
            archive.extractall(work)
    flags = ' '.join(LOCK['toolchain']['cflags']) + f' -isysroot {sdk}'
    buildenv = {'CC': clang, 'CFLAGS': flags, 'CPPFLAGS': '', 'LDFLAGS': flags,
                'SDKROOT': sdk, 'MACOSX_DEPLOYMENT_TARGET': '15.0',
                'AR': '/usr/bin/ar', 'RANLIB': '/usr/bin/ranlib'}
    openssl = work / ('openssl-' + LOCK['openssl']['version'])
    if digest(openssl / 'LICENSE.txt') != LOCK['openssl']['licenseSHA256']:
        raise RuntimeError('OpenSSL release license differs from the reviewed source license')
    run(['perl', 'Configure', 'darwin64-arm64', 'no-shared', 'no-tests', 'no-apps',
         'no-docs', 'no-module', 'no-dso', 'no-zlib', f'--prefix={prefix}', '--libdir=lib'],
        openssl, buildenv)
    run(['make', '-j4', 'build_libs'], openssl, buildenv)
    run(['make', 'install_dev'], openssl, buildenv)
    ssh = work / 'libssh2-1.11.1'
    sshbuild = work / 'ssh-build'
    sshbuild.mkdir()
    sshenv = buildenv | {'CPPFLAGS': f'-I{prefix}/include',
                         'LDFLAGS': flags + f' -L{prefix}/lib',
                         'PKG_CONFIG': '/usr/bin/false'}
    run([ssh / 'configure', '--host=aarch64-apple-darwin', f'--prefix={prefix}',
         '--with-crypto=openssl', f'--with-libssl-prefix={prefix}', '--without-libz',
         '--disable-shared', '--enable-static', '--disable-examples-build',
         '--disable-docker-tests', '--disable-sshd-tests'], sshbuild, sshenv)
    run(['make', '-C', 'src', '-j4'], sshbuild, sshenv)
    shutil.copy2(sshbuild / 'src/.libs/libssh2.a', prefix / 'lib/libssh2.a')
    for header in ssh.glob('include/*.h'):
        shutil.copy2(header, prefix / 'include' / header.name)
    licenses = prefix / 'licenses'
    licenses.mkdir()
    for source, name in ((openssl, 'openssl'), (ssh, 'libssh2')):
        dest = licenses / name
        dest.mkdir()
        for pattern in ('LICENSE*', 'NOTICE*', 'COPYING*', 'AUTHORS*', 'REUSE.toml'):
            for path in source.glob(pattern):
                if path.is_dir():
                    shutil.copytree(path, dest / path.name)
                else:
                    shutil.copy2(path, dest / path.name)
    # Release tarball does not contain the repository's newer LICENSES/ layout.
    # Preserve complete copyright/license headers from every shipped C/header input.
    header_notices = []
    for path in sorted(list((ssh / 'src').glob('*.[ch]')) + list((ssh / 'include').glob('*.h'))):
        text = path.read_text(errors='replace')
        end = text.find('*/')
        if text.startswith('/*') and end >= 0:
            header_notices.append(str(path.relative_to(ssh)) + '\n' + text[:end + 2])
    (licenses / 'libssh2/SOURCE-NOTICES.txt').write_text('\n\n'.join(header_notices) + '\n')
    # Preserve file-level notices for crypto/assembly/provider inputs as well as root Apache text.
    openssl_notices = []
    for folder in ('crypto', 'ssl', 'providers', 'include'):
        for path in sorted((openssl / folder).rglob('*')):
            if not path.is_file() or path.suffix not in ('.c', '.h', '.pl', '.s', '.S', '.asm', '.in'):
                continue
            text = path.read_text(errors='replace')
            lines = text.splitlines()
            start = 1 if lines and lines[0].startswith('#!') else 0
            notice = []
            if start < len(lines) and lines[start].startswith('/*'):
                end = text.find('*/')
                notice = text[:end + 2].splitlines() if end >= 0 else []
            else:
                for line in lines[start:]:
                    if line.startswith(('#', ';', '//')) or not line.strip(): notice.append(line)
                    else: break
            joined = '\n'.join(notice)
            if any(word in joined.lower() for word in ('copyright', 'license', 'public domain')):
                openssl_notices.append(str(path.relative_to(openssl)) + '\n' + joined)
    (licenses / 'openssl/SOURCE-NOTICES.txt').write_text('\n\n'.join(openssl_notices) + '\n')
    (licenses / 'openssl/build-tool-Text-Template').mkdir()
    shutil.copy2(openssl / 'external/perl/Text-Template-1.56/LICENSE',
                 licenses / 'openssl/build-tool-Text-Template/LICENSE')
    (licenses / 'NOTICE.txt').write_text(
        'OpenLXSSH P3 local probe: libssh2 1.11.1 (OpenSSL backend) + OpenSSL ' + LOCK['openssl']['version'] + '.\n'
        'Both are unmodified upstream source archives; see adjacent complete license texts.\n'
        'OpenSSL: Apache-2.0. libssh2: BSD-3-Clause plus bundled file-level licenses.\n'
        'Static arm64, no shared crypto, no compression, no external OpenSSL modules/config.\n'
        'Not FIPS certified; source provenance and hashes are in manifest.json.\n')
    for lib in ('libssh2.a', 'libcrypto.a', 'libssl.a'):
        run(['lipo', prefix / 'lib' / lib, '-verify_arch', 'arm64'])
    outputs = {str(path.relative_to(NATIVE)): digest(path) for path in sorted(prefix.rglob('*')) if path.is_file()}
    manifest.write_text(json.dumps({'inputs': fingerprint, 'dependencies': LOCK,
                                   'downloads': downloads,
                                   'licenseSHA256': {str(path.relative_to(licenses)): digest(path)
                                                     for path in sorted(licenses.rglob('*')) if path.is_file()},
                                   'outputs': outputs, 'remoteInteroperability': 'NOT TESTED'}, indent=2) + '\n')
    shutil.copy2(manifest, licenses / 'manifest.json')
    log.close()
    print(f'Built pinned static arm64 libraries; manifest={manifest}')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
