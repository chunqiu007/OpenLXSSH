#!/bin/bash
# Reuse existing reviewed object stores without network/global configuration.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROBE="$ROOT/../../Experiments/P2-TerminalProbe/.build"
export GIT_NO_LAZY_FETCH=1 GIT_ALLOW_PROTOCOL=file
export GIT_CONFIG_COUNT=4
export GIT_CONFIG_KEY_0="url.file://$PROBE/offline/SwiftTerm.git.insteadOf" GIT_CONFIG_VALUE_0=https://github.com/migueldeicaza/SwiftTerm.git
export GIT_CONFIG_KEY_1="url.file://$PROBE/repositories/swift-argument-parser-54a11a8d.insteadOf" GIT_CONFIG_VALUE_1=https://github.com/apple/swift-argument-parser
export GIT_CONFIG_KEY_2="url.file://$PROBE/repositories/swift-png-fab7dc4e.insteadOf" GIT_CONFIG_VALUE_2=https://github.com/tayloraswift/swift-png
export GIT_CONFIG_KEY_3="url.file://$PROBE/repositories/h-1c482571.insteadOf" GIT_CONFIG_VALUE_3=https://github.com/rarestype/h
export CLANG_MODULE_CACHE_PATH="$ROOT/.build/clang-cache"
exec "$@"
