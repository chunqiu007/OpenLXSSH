import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from fixture_identity import CONTAINER, FINGERPRINT, IMAGE, NETWORK, PROJECT, PUBLIC_EVIDENCE
from relay_native import construct, load_original


class CurrentFixtureIdentityTests(unittest.TestCase):
    def test_current_exact_pin_matches_independent_public_material_evidence(self):
        for name, digest in PUBLIC_EVIDENCE.items():
            self.assertEqual(hashlib.sha256(Path(name).read_bytes()).hexdigest(), digest)
        values = [json.loads(Path(name).read_bytes()) for name in PUBLIC_EVIDENCE]
        identity = values[0]['keyonly']; material = values[1]
        self.assertEqual(identity['containerID'], CONTAINER); self.assertEqual(identity['fingerprint'], FINGERPRINT)
        self.assertEqual(material['containerID'], CONTAINER); self.assertEqual(material['expectedFingerprint'], FINGERPRINT)
        self.assertEqual(material['imageID'], IMAGE); self.assertEqual(material['networkID'], NETWORK)
        self.assertEqual(material['project'], PROJECT)

    def test_adapter_preserves_original_relay_methods_and_initialization(self):
        original = load_original()
        methods = {name: getattr(original.Relay, name) for name in ('__init__', 'worker', 'dispatch', 'serve')}
        drops = original.drop_pump; flow = original.Flow
        # load_bridge performs source hashes/import only; no Docker process or network calls.
        with patch('subprocess.Popen', side_effect=AssertionError('offline cannot launch')):
            relay = construct(original, 'blackhole', 'a' * 32, 1234)
        self.assertIs(type(relay), original.Relay)
        for name, method in methods.items(): self.assertIs(getattr(type(relay), name), method)
        self.assertIs(original.drop_pump, drops); self.assertIs(original.Flow, flow)
        self.assertEqual(relay.target.container_id, CONTAINER); self.assertEqual(relay.target.host_port, 22221)
        self.assertEqual(relay.run, 'a' * 32); self.assertEqual(relay.parent, 1234)
        self.assertEqual(relay.items, {}); self.assertEqual(relay.workers, [])
        self.assertFalse(relay.cancelled.is_set()); self.assertIsNotNone(relay.lock)


if __name__ == '__main__': unittest.main()
