#!/usr/bin/env python3
"""Identity-only adapter for current approved keyonly. Default is inert; old relay unchanged.

Every original Relay initialization, validate, worker, dispatch, serve, Flow, DROP, cleanup,
private PIPE owner and frozen-normal rule is retained. Identity is substituted only at
FrozenDockerTarget construction. Blackhole alone attaches an owned backend-instance spawn
prewarmer and fresh guardian queries; no original Relay/Flow/drop method is replaced.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
OLD = HERE.parent
if str(OLD) not in sys.path: sys.path.insert(0, str(OLD))
from fixture_identity import CONTAINER, CONTEXT, ENDPOINT, IMAGE, NETWORK, PROJECT
from relay_observations import RelayObservations
from guardian import GuardianRegistry

ORIGINAL_SHA256 = 'f6978885583a9ae609460bcd2917d8792928e736469cd766fe4b07c3c07b4a2a'
CORE_SHA256 = '02abadb76fb931547477f9100b3dfef04e39f9a1d9ca13dc830d16a056e08480'


def load_original():
    for name, expected in [('relay_control.py', ORIGINAL_SHA256), ('core.py', CORE_SHA256)]:
        path = OLD / name
        if path.resolve() != path or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('original-relay-source-changed')
    import relay_control
    return relay_control


def construct(original, role, run, parent):
    bridge = original.load_bridge()  # Verifies unchanged immutable frozen-normal dependencies.
    previous_load, target_factory = original.load_bridge, bridge.FrozenDockerTarget
    expected_old = (CONTEXT, ENDPOINT, '1253a29501483eb71f80e39b9af5c85e10c3a49329d5e93700fecd3f00f334f2',
                    IMAGE, PROJECT, 'keyonly', 'env-fixture-a', NETWORK, 22221)

    def exact_target(*args, **kwargs):
        if kwargs or args != expected_old:
            raise ValueError('unexpected-original-target-constructor')
        return target_factory(CONTEXT, ENDPOINT, CONTAINER, IMAGE, PROJECT, 'keyonly', 'env-fixture-a', NETWORK, 22221)

    # Initialization is single-threaded before any relay worker. No validate/flow method override.
    bridge.FrozenDockerTarget = exact_target
    original.load_bridge = lambda: bridge
    try:
        relay = original.Relay(role, run, parent)
    finally:
        original.load_bridge = previous_load; bridge.FrozenDockerTarget = target_factory
    if (relay.target.container_id != CONTAINER or relay.target.image_id != IMAGE or
            relay.target.network_id != NETWORK or relay.target.project != PROJECT or relay.target.host_port != 22221):
        raise ValueError('current-target-not-exact')
    return relay


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live-test-only', action='store_true'); parser.add_argument('--role', choices=['normal', 'blackhole'])
    parser.add_argument('--run'); parser.add_argument('--owner-pid', type=int)
    args = parser.parse_args(argv)
    if not args.live_test_only: return 64
    if args.role is None or args.run is None or len(args.run) != 32 or args.owner_pid != os.getppid(): return 64
    original = load_original(); relay = construct(original, args.role, args.run, args.owner_pid)
    previous = {number: signal.signal(number, lambda *_: relay.cancelled.set()) for number in (signal.SIGINT, signal.SIGTERM)}
    observations = RelayObservations()
    registry = None; original_remote = original.remote_bridge_alive
    if args.role == 'blackhole':
        registry = GuardianRegistry(relay.backend, relay.deadline)
        original.remote_bridge_alive = registry.remote_alive
        observations.install(original)
    serve_ok = False; cleanup_ok = registry is None
    try:
        relay.serve(); serve_ok = True
    finally:
        observations.restore()
        original.remote_bridge_alive = original_remote
        if registry is not None:
            facts = registry.close(); cleanup_ok = facts['success']
            raw = (json.dumps({'tag': 'native-guardian-cleanup-v1', **facts}, separators=(',', ':'), sort_keys=True) + '\n').encode()
            if len(raw) <= 16384: os.write(2, raw)
            else: cleanup_ok = False
        for number, handler in previous.items(): signal.signal(number, handler)
    return 0 if serve_ok and cleanup_ok else 1


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception: raise SystemExit(1)
