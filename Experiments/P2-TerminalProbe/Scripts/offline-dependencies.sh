#!/bin/bash
# Optional, no network or global Git config. Reuse the P0 exact-tag object store
# and already-present SwiftPM caches on this machine. Fails if either is absent.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="${P2_SWIFTTERM_GIT:-/tmp/openlxssh-p0-03/SwiftTerm/.git}"
CACHE="${P2_SPM_CACHE:-$HOME/Library/Caches/org.swift.swiftpm/repositories}"
BARE="$ROOT/.build/offline/SwiftTerm.git"
mkdir -p "$ROOT/.build/offline"
export GIT_NO_LAZY_FETCH=1
if [[ ! -d "$BARE" ]]; then git clone --bare --depth 1 --branch v1.20.0 "file://$SOURCE" "$BARE"; fi
git --git-dir="$BARE" fetch --depth 1 "file://$SOURCE" refs/tags/v1.99.1:refs/tags/v1.99.1
[[ "$(git --git-dir="$BARE" rev-parse v1.20.0)" == 5d14406844143538cd8f8851d2d8a67c1fe443e5 ]]
[[ "$(git --git-dir="$BARE" rev-parse v1.99.1)" == 2f573f73af5e768d90847dce20c97fa9535d7164 ]]
export GIT_CONFIG_COUNT=7
export GIT_CONFIG_KEY_0="url.file://$BARE.insteadOf" GIT_CONFIG_VALUE_0=https://github.com/migueldeicaza/SwiftTerm.git
export GIT_CONFIG_KEY_1="url.file://$CACHE/swift-argument-parser-54a11a8d.insteadOf" GIT_CONFIG_VALUE_1=https://github.com/apple/swift-argument-parser
export GIT_CONFIG_KEY_2="url.file://$CACHE/swift-docc-plugin-30a0bdda.insteadOf" GIT_CONFIG_VALUE_2=https://github.com/apple/swift-docc-plugin
export GIT_CONFIG_KEY_3="url.file://$CACHE/swift-docc-symbolkit-64eb2630.insteadOf" GIT_CONFIG_VALUE_3=https://github.com/swiftlang/swift-docc-symbolkit
export GIT_CONFIG_KEY_4="url.file://$CACHE/swift-png-fab7dc4e.insteadOf" GIT_CONFIG_VALUE_4=https://github.com/tayloraswift/swift-png
export GIT_CONFIG_KEY_5="url.file://$CACHE/h-1c482571.insteadOf" GIT_CONFIG_VALUE_5=https://github.com/tayloraswift/h
export GIT_CONFIG_KEY_6="url.file://$CACHE/h-1c482571.insteadOf" GIT_CONFIG_VALUE_6=https://github.com/rarestype/h
# No remote fallback for an omitted URL.
export GIT_ALLOW_PROTOCOL=file
if [[ $# -gt 0 ]]; then exec "$@"; fi
swift package --package-path "$ROOT" --disable-dependency-cache resolve --skip-update
