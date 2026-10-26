#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIGURATION="${1:-Debug}"
ACTION="${2:-build}"
case "$CONFIGURATION" in Debug|Release|HostProbe) ;; *) printf 'Use Debug, Release, or HostProbe.\n' >&2; exit 64 ;; esac
case "$ACTION" in build|test|build-for-testing) ;; *) printf 'Use build, test, or build-for-testing.\n' >&2; exit 64 ;; esac
DERIVED="$ROOT/DerivedData/$CONFIGURATION"
SCHEME="OpenLXSSH"
OVERRIDES=(MACOSX_DEPLOYMENT_TARGET=26.0)
# Do not enable optional SwiftTerm manifests/modes through an inherited shell.
for variable in $(env | /usr/bin/grep '^SWIFTTERM_' | /usr/bin/cut -d= -f1); do unset "$variable"; done
unset OPENLXSSH_TRANSPORT_HOST_PROBE OPENLXSSH_FILES_TARGET26
if [[ "$CONFIGURATION" != HostProbe ]]; then export OPENLXSSH_FILES_TARGET26=1; fi
if [[ "$CONFIGURATION" == HostProbe ]]; then
    export OPENLXSSH_TRANSPORT_HOST_PROBE=1
    SCHEME="OpenLXSSH-HostProbe"
    OVERRIDES=(MACOSX_DEPLOYMENT_TARGET=15.0)
    printf 'HostProbe is a local macOS 15 test build, NOT macOS 26 product runtime acceptance.\n'
fi
# Core pins GRDB exactly; Xcode's own lock is required and is never updated by this script.
# First-time resolution may download the pinned development dependency. Runtime stays offline.
# Resolve only; no plugin executes here. Then check the actual clean checkout,
# exact reviewed plugin/generator/input hashes before Xcode's approval override.
python3 "$ROOT/Scripts/verify-files-native.py"
xcodebuild -resolvePackageDependencies -project "$ROOT/OpenLXSSH.xcodeproj" -scheme "$SCHEME" \
    -clonedSourcePackagesDirPath "$ROOT/DerivedData/SourcePackages" \
    -onlyUsePackageVersionsFromResolvedFile -skipPackageUpdates
python3 "$ROOT/Scripts/verify-build-plugin.py" "$ROOT/DerivedData/SourcePackages/checkouts"
xcodebuild -project "$ROOT/OpenLXSSH.xcodeproj" -scheme "$SCHEME" \
    -configuration "$CONFIGURATION" -destination 'platform=macOS,arch=arm64' \
    -derivedDataPath "$DERIVED" -clonedSourcePackagesDirPath "$ROOT/DerivedData/SourcePackages" \
    -onlyUsePackageVersionsFromResolvedFile -skipPackageUpdates -skipPackagePluginValidation \
    CODE_SIGNING_ALLOWED=NO ARCHS=arm64 ONLY_ACTIVE_ARCH=YES "${OVERRIDES[@]}" "$ACTION"
HELPER_CONFIGURATION=debug
[[ "$CONFIGURATION" != Release ]] || HELPER_CONFIGURATION=release
HELPER_BUILD="$ROOT/DerivedData/Askpass-$CONFIGURATION"
swift package --package-path "$ROOT/Packages/OpenLXSSHTransport" --scratch-path "$HELPER_BUILD" \
    --disable-automatic-resolution resolve
python3 "$ROOT/Scripts/verify-build-plugin.py" "$HELPER_BUILD/checkouts" --helper
swift build --package-path "$ROOT/Packages/OpenLXSSHTransport" --scratch-path "$HELPER_BUILD" \
    --configuration "$HELPER_CONFIGURATION" --product openlxssh-askpass --disable-automatic-resolution \
    --triple "arm64-apple-macosx$( [[ "$CONFIGURATION" == HostProbe ]] && printf 15.0 || printf 26.0 )"
HELPER="$HELPER_BUILD/arm64-apple-macosx/$HELPER_CONFIGURATION/openlxssh-askpass"
APP="$DERIVED/Build/Products/$CONFIGURATION/OpenLXSSH.app"
mkdir -p "$APP/Contents/Helpers"
install -m 755 "$HELPER" "$APP/Contents/Helpers/openlxssh-askpass"
for notice in "$ROOT/Packages/OpenLXSSHTransport/ThirdPartyNotices/"*; do
    install -m 644 "$notice" "$APP/Contents/Resources/$(basename "$notice")"
done
mkdir -p "$APP/Contents/Resources/FilesNativeLicenses"
cp -R "$ROOT/Packages/OpenLXSSHFiles/.build/native/install/licenses/" "$APP/Contents/Resources/FilesNativeLicenses/"
printf 'App: %s\n' "$APP"
