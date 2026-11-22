#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-all}"
case "$MODE" in all|build) ;; *) printf 'Use all or build.\n' >&2; exit 64 ;; esac
LOGS="$ROOT/DerivedData/Verification"
mkdir -p "$LOGS"
for configuration in Debug Release; do
    BUILD_ACTION=build
    [[ "$configuration" != Debug ]] || BUILD_ACTION=build-for-testing
    "$ROOT/Scripts/build-app.sh" "$configuration" "$BUILD_ACTION" > "$LOGS/${configuration}-build.log" 2>&1
    OPENLXSSH_FILES_TARGET26=1 xcodebuild -project "$ROOT/OpenLXSSH.xcodeproj" -scheme OpenLXSSH -configuration "$configuration" \
        -destination 'platform=macOS,arch=arm64' -derivedDataPath "$ROOT/DerivedData/$configuration" \
        -clonedSourcePackagesDirPath "$ROOT/DerivedData/SourcePackages" \
        -onlyUsePackageVersionsFromResolvedFile -skipPackageUpdates -showBuildSettings \
        CODE_SIGNING_ALLOWED=NO ARCHS=arm64 ONLY_ACTIVE_ARCH=YES > "$LOGS/${configuration}-settings.log" 2>&1
    BINARY="$ROOT/DerivedData/$configuration/Build/Products/$configuration/OpenLXSSH.app/Contents/MacOS/OpenLXSSH"
    xcrun vtool -show-build "$BINARY" > "$LOGS/${configuration}-vtool.log"
    /usr/bin/otool -L "$BINARY" > "$LOGS/${configuration}-libraries.log"
    python3 - "$ROOT" "$configuration" <<'PY'
import hashlib, json, pathlib, plistlib, re, subprocess, sys
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
assert len(lock['pins']) == 5
pins = {p['identity']: p['state'] for p in lock['pins']}
assert pins['grdb.swift'] == {'revision':'b83108d10f42680d78f23fe4d4d80fc88dab3212', 'version':'7.11.1'}
assert pins['swiftterm'] == {'revision':'2f573f73af5e768d90847dce20c97fa9535d7164', 'version':'1.99.1'}
for p in json.loads((root / 'Packages/OpenLXSSHTransport/Package.resolved').read_text())['pins']:
    assert pins[p['identity']] == p['state']
assert not (app / 'Contents/Helpers').exists(), 'Unexpected Contents/Helpers directory'
for notice in ('SwiftTerm-LICENSE', 'ArgumentParser-LICENSE', 'SwiftPNG-LICENSE', 'H-LICENSE'):
    assert (app / 'Contents/Resources' / notice).is_file()
project = (root / 'OpenLXSSH.xcodeproj/project.pbxproj').read_text()
assert 'relativePath = Packages/OpenLXSSHSecurity' in project
assert 'productName = OpenLXSSHSecurity' in project
assert 'productName = OpenLXSSHTransport' in project
assert 'productName = OpenLXSSHFiles' in project
bridge = root / f'DerivedData/{config}/Build/Intermediates.noindex/OpenLXSSHFiles.build/{config}/COpenLXSSHFiles.build/Objects-normal/arm64/Bridge.o'
assert re.search(r'minos\s+26.0', subprocess.check_output(['xcrun','vtool','-show-build',str(bridge)], text=True))
native_manifest = json.loads((root / 'Packages/OpenLXSSHFiles/.build/native/manifest.json').read_text())
for relative, digest in native_manifest['licenseSHA256'].items():
    assert hashlib.sha256((app / 'Contents/Resources/FilesNativeLicenses' / relative).read_bytes()).hexdigest() == digest
print(f'{config}: arm64 / min26 App+Files C object / static native libraries / pinned graph checked')
PY
done
if [[ "$MODE" == all ]]; then
    "$ROOT/Scripts/build-app.sh" Debug test > "$LOGS/Debug-tests.log" 2>&1
fi
printf 'Verification logs: %s\n' "$LOGS"
