#!/usr/bin/env python3
"""Public-file parser regressions only. Real approved public provenance bytes, no secrets/live.

The selected original generation is READ ONLY. Pretty JSON variants are generated in memory;
no fixture metadata/timestamps are edited and no expired provenance becomes a live contract.
"""
import json
import os
from pathlib import Path
import tempfile
import unittest

from public_files import contract_object, file_object, material_object, provenance_object
from core import Refused, exact_json
from fixture_identity import ROOT
from liveness_protocol import validate_contract
from supervise_native import public_read

MATERIAL = ROOT / 'Experiments/UXNativeShellProbe/.build/sftp-auth-case-68b87b97a090/sftp-auth.json'


class PublicFileJSONTests(unittest.TestCase):
    def actual(self):
        material = material_object(public_read(MATERIAL, 8192, 0o600))
        path = Path(material['credentialDirectory']) / 'provenance.json'
        raw = public_read(path, 4096, 0o600)
        return material, raw, provenance_object(raw, material=material)

    def test_real_generated_provenance_without_pipe_terminator_is_a_valid_file(self):
        material, raw, provenance = self.actual()
        self.assertFalse(raw.endswith(b'\n'))  # Exact producer output at the reported failure.
        with self.assertRaises(Refused): exact_json(raw)
        self.assertEqual(provenance['service'], 'keyonly')
        self.assertEqual(provenance['base_image'], material['baseImage'])
        self.assertEqual(provenance['built_image_id'], material['imageID'])

    def test_pretty_real_provenance_and_contract_allow_legal_file_whitespace(self):
        material, _, provenance = self.actual()
        pretty = (json.dumps(provenance, indent=2, sort_keys=True) + '\n\n').encode()
        self.assertGreater(pretty.count(b'\n'), 1)
        self.assertEqual(provenance_object(pretty, material=material), provenance)
        contract = {'schema': 1, 'taskID': 'NATIVE-LIVENESS-SUPERVISOR-R2', 'run': 'a' * 32, 'role': 'normal',
                    'materialContractPath': '/offline/.build/sftp-auth-case-012345abcdef/sftp-auth.json',
                    'issuedAt': 1000, 'collectedAt': 999}
        self.assertEqual(contract_object((json.dumps(contract, indent=2) + '\n').encode()), contract)
        validate_contract(contract, '/offline/.build/native-liveness-case-012345abcdef/liveness.json', '/offline/.build', 1001)
        with self.assertRaises(Refused):
            validate_contract(contract, '/offline/.build/native-liveness-case-012345abcdef/liveness.json', '/offline/.build', 1120.1)

    def test_file_parser_rejects_duplicate_extra_trailing_nonfinite_and_wrong_types(self):
        fields = {'schema': int, 'name': str, 'at': (int, float)}
        good = b'{"schema":1,"name":"public","at":1}'
        self.assertEqual(file_object(good, fields=fields, limit=100), {'schema': 1, 'name': 'public', 'at': 1})
        for raw in [b'', good + b' {}', b'{"schema":1,"schema":1,"name":"public","at":1}',
                    b'{"schema":true,"name":"public","at":1}', b'{"schema":1.0,"name":"public","at":1}',
                    b'{"schema":1,"name":[],"at":1}', b'{"schema":1,"name":"public","at":true}',
                    b'{"schema":1,"name":"public","at":NaN}', b'{"schema":1,"name":"public","at":1e999}',
                    b'{"schema":1,"name":"public","at":1,"extra":0}', b'{"schema":1,"name":"public"}',
                    b'[1,2]', b'{"schema":1,"name":"\xff","at":1}']:
            with self.subTest(raw=raw), self.assertRaises(Refused): file_object(raw, fields=fields, limit=200)
        self.assertEqual(file_object(good, fields=fields, limit=len(good))['schema'], 1)
        with self.assertRaises(Refused): file_object(good, fields=fields, limit=len(good) - 1)

    def test_material_and_provenance_still_require_exact_fixed_identity_and_shape(self):
        material, _, provenance = self.actual()
        for key, value in [('port', 22222), ('schema', True), ('containerID', 'f' * 64), ('expectedFingerprint', 'wrong'),
                           ('host', 'localhost'), ('key', 'rsaplain'), ('unexpected', 'field')]:
            invalid = dict(material); invalid[key] = value
            with self.subTest(key=key), self.assertRaises(Refused): material_object(json.dumps(invalid).encode())
        for key, value in [('service', 'passwordonly'), ('base_image', 'wrong'), ('built_image_id', 'wrong'),
                           ('collected_at', True), ('collected_at', 0), ('collected_at', '123'), ('extra', 1)]:
            invalid = dict(provenance); invalid[key] = value
            with self.subTest(key=key), self.assertRaises(Refused): provenance_object(json.dumps(invalid).encode(), material=material)

    def test_public_read_permissions_symlink_hardlink_and_byte_limit_unchanged(self):
        with tempfile.TemporaryDirectory(prefix='NativePublicJSON-') as folder:
            root = Path(folder).resolve(); os.chmod(root, 0o700)
            path = root / 'public.json'; path.write_bytes(b'{\n "schema": 1\n}\n'); os.chmod(path, 0o600)
            original = path.read_bytes()
            self.assertEqual(public_read(path, len(original), 0o600), original)
            with self.assertRaises(Refused): public_read(path, len(original) - 1, 0o600)
            os.chmod(path, 0o644)
            with self.assertRaises(Refused): public_read(path, 100, 0o600)
            os.chmod(path, 0o600)
            link = root / 'link.json'; link.symlink_to(path)
            with self.assertRaises(Refused): public_read(link, 100, 0o600)
            link.unlink(); os.link(path, link)
            with self.assertRaises(Refused): public_read(path, 100, 0o600)


if __name__ == '__main__': unittest.main()
