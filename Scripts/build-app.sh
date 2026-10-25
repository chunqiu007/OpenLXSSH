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
if [[ "$CONFIGURATION" == HostProbe ]]; then
    SCHEME="OpenLXSSH-HostProbe"
    OVERRIDES=(MACOSX_DEPLOYMENT_TARGET=15.0)
    printf 'HostProbe is a local macOS 15 test build, NOT macOS 26 product runtime acceptance.\n'
fi
# Core pins GRDB exactly; Xcode's own lock is required and is never updated by this script.
# First-time resolution may download the pinned development dependency. Runtime stays offline.
xcodebuild -project "$ROOT/OpenLXSSH.xcodeproj" -scheme "$SCHEME" \
    -configuration "$CONFIGURATION" -destination 'platform=macOS,arch=arm64' \
    -derivedDataPath "$DERIVED" -clonedSourcePackagesDirPath "$ROOT/DerivedData/SourcePackages" \
    -onlyUsePackageVersionsFromResolvedFile -skipPackageUpdates \
    CODE_SIGNING_ALLOWED=NO "${OVERRIDES[@]}" "$ACTION"
printf 'App: %s/Build/Products/%s/OpenLXSSH.app\n' "$DERIVED" "$CONFIGURATION"
