#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-all}"
case "$MODE" in all|build|gui|signed-security) ;; *) printf 'Use all, build, gui, or signed-security.\n' >&2; exit 64 ;; esac
LOGS="$ROOT/DerivedData/Verification"
mkdir -p "$LOGS"
if [[ "$MODE" == signed-security ]]; then
    "$ROOT/Scripts/build-app.sh" HostProbe build > "$LOGS/HostProbe-build.log" 2>&1
    python3 "$ROOT/Scripts/verify-signed-app.py"
    exit $?
fi
if [[ "$MODE" != gui ]]; then
    for configuration in Debug Release; do
        "$ROOT/Scripts/build-app.sh" "$configuration" build-for-testing > "$LOGS/${configuration}-build.log" 2>&1
        xcodebuild -project "$ROOT/OpenLXSSH.xcodeproj" -scheme OpenLXSSH -configuration "$configuration" \
            -destination 'platform=macOS,arch=arm64' -derivedDataPath "$ROOT/DerivedData/$configuration" \
            -clonedSourcePackagesDirPath "$ROOT/DerivedData/SourcePackages" \
            -onlyUsePackageVersionsFromResolvedFile -skipPackageUpdates -showBuildSettings \
            CODE_SIGNING_ALLOWED=NO > "$LOGS/${configuration}-settings.log" 2>&1
        BINARY="$ROOT/DerivedData/$configuration/Build/Products/$configuration/OpenLXSSH.app/Contents/MacOS/OpenLXSSH"
        xcrun vtool -show-build "$BINARY" > "$LOGS/${configuration}-vtool.log"
        /usr/bin/otool -L "$BINARY" > "$LOGS/${configuration}-libraries.log"
        python3 - "$ROOT" "$configuration" <<'PY'
import json, pathlib, plistlib, re, subprocess, sys
root, config = pathlib.Path(sys.argv[1]), sys.argv[2]
logs = root / 'DerivedData/Verification'
settings = (logs / f'{config}-settings.log').read_text()
assert re.search(r'^\s*ARCHS = arm64$', settings, re.M), 'Expected arm64 only'
assert re.search(r'^\s*MACOSX_DEPLOYMENT_TARGET = 26.0$', settings, re.M), 'Expected macOS 26'
assert 'PRODUCT_MODULE_NAME = OpenLXSSH' in settings
assert 'ENABLE_HARDENED_RUNTIME = YES' in settings
vtool = (logs / f'{config}-vtool.log').read_text()
assert re.search(r'minos\s+26.0', vtool)
app = root / f'DerivedData/{config}/Build/Products/{config}/OpenLXSSH.app'
binary = app / 'Contents/MacOS/OpenLXSSH'
assert subprocess.check_output(['lipo','-archs',str(binary)], text=True).strip() == 'arm64'
info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
assert info['CFBundleDisplayName'] == 'OpenLXSSH' and info['LSMinimumSystemVersion'] == '26.0'
assert (app / 'Contents/Resources/GRDB-LICENSE.txt').is_file()
for line in (logs / f'{config}-libraries.log').read_text().splitlines()[1:]:
    library = line.strip().split(' (')[0]
    assert library.startswith(('/System/Library/', '/usr/lib/')), f'External runtime library: {library}'
lock = json.loads((root / 'OpenLXSSH.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved').read_text())
assert len(lock['pins']) == 1
assert lock['pins'][0]['state'] == {'revision':'b83108d10f42680d78f23fe4d4d80fc88dab3212', 'version':'7.11.1'}
project = (root / 'OpenLXSSH.xcodeproj/project.pbxproj').read_text()
assert 'relativePath = Packages/OpenLXSSHSecurity' in project
assert 'productName = OpenLXSSHSecurity' in project
assert 'OpenLXSSHTransport' not in project
print(f'{config}: arm64 / min26 / module / runtime libraries / GRDB pin checked')
PY
    done
    "$ROOT/Scripts/build-app.sh" HostProbe test > "$LOGS/HostProbe-tests.log" 2>&1
fi
if [[ "$MODE" != build ]]; then
    "$ROOT/Scripts/build-app.sh" HostProbe build > "$LOGS/HostProbe-build.log" 2>&1
    python3 - "$ROOT" <<'PY'
import json, os, pathlib, subprocess, sys, tempfile
root = pathlib.Path(sys.argv[1])
logs = root / 'DerivedData/Verification'
data = pathlib.Path(tempfile.mkdtemp(prefix='OpenLXSSH-AppSmoke-'))
os.chmod(data, 0o700)
(data / '.openlxssh-app-smoke').write_text('OpenLXSSH isolated GUI smoke\n')
(logs / 'gui-data-path.txt').write_text(str(data) + '\n')
binary = root / 'DerivedData/HostProbe/Build/Products/HostProbe/OpenLXSSH.app/Contents/MacOS/OpenLXSSH'
for phase in ('exercise', 'reopen', 'security-sheets'):
    phase_data = data
    if phase == 'security-sheets':
        phase_data = pathlib.Path(tempfile.mkdtemp(prefix='OpenLXSSH-AppSmoke-'))
        os.chmod(phase_data, 0o700)
        (phase_data / '.openlxssh-app-smoke').write_text('OpenLXSSH isolated GUI smoke\n')
        (logs / 'gui-security-sheets-data-path.txt').write_text(str(phase_data) + '\n')
    with (logs / f'gui-{phase}.log').open('w') as log:
        try:
            result = subprocess.run([str(binary), '--self-test-data-dir', str(phase_data), '--self-test-phase', phase], stdout=log, stderr=subprocess.STDOUT, timeout=120)
        except subprocess.TimeoutExpired:
            raise SystemExit(f'Native GUI {phase} timed out; owned process was terminated; inspect {log.name}')
    if result.returncode:
        raise SystemExit(f'Native GUI {phase} exited {result.returncode}; inspect sanitized log {log.name}')
    report = json.loads((phase_data / f'smoke-{phase}.json').read_text())
    assert report['passed'] and not report['productRuntimeVerified']
    assert report['checks'] and all(check['passed'] for check in report['checks'])
    print(f'HostProbe native GUI {phase}: {len(report["checks"])} checks passed')
print('Isolated GUI data and window captures:', data)
print('HostProbe does not validate macOS 26 runtime, IME, SSH, SFTP, signing or notarization.')
PY
fi
printf 'Verification logs: %s\n' "$LOGS"
