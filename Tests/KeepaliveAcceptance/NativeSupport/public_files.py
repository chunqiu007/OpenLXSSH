#!/usr/bin/env python3
"""Closed public JSON FILE schemas. No I/O on import; deliberately not a PIPE frame parser.

The caller retains public_read's owner/mode/noFollow/stability/byte gates. File JSON accepts
legal whitespace and an absent terminal LF, but rejects duplicate keys, trailing documents,
non-finite numbers, extra/missing fields and incorrect scalar types. No credentials are parsed.
"""
import json
import math
from liveness_protocol import CONTRACT_KEYS, Refused
from fixture_identity import CONTAINER, CONTEXT, ENDPOINT, FINGERPRINT, IMAGE, NETWORK, PROJECT

MATERIAL_FIELDS = {name: str for name in (
    'taskID', 'service', 'host', 'user', 'key', 'credentialDirectory', 'expectedFingerprint',
    'baseImage', 'imageID', 'containerID', 'project', 'networkID', 'context', 'endpoint')}
MATERIAL_FIELDS.update(schema=int, port=int)
PROVENANCE_FIELDS = {'base_image': str, 'built_image_id': str, 'service': str, 'collected_at': (int, float)}
CONTRACT_FIELDS = {'schema': int, 'taskID': str, 'run': str, 'role': str,
                   'materialContractPath': str, 'issuedAt': (int, float), 'collectedAt': (int, float)}
BASE_IMAGE = 'docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d'


def file_object(raw, *, fields, limit):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= limit:
        raise Refused('public-json-file-bounds')

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise Refused('public-json-file-duplicate')
            result[key] = value
        return result

    def constant(_):
        raise Refused('public-json-file-nonfinite')

    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused('public-json-file-document') from None
    if not isinstance(value, dict) or set(value) != set(fields):
        raise Refused('public-json-file-fields')
    for key, expected in fields.items():
        allowed = expected if isinstance(expected, tuple) else (expected,)
        if type(value[key]) not in allowed:
            raise Refused('public-json-file-type')
        if type(value[key]) in (int, float):
            try: finite = math.isfinite(value[key])
            except (OverflowError, ValueError): finite = False
            if not finite: raise Refused('public-json-file-nonfinite')
    return value


def material_object(raw):
    value = file_object(raw, fields=MATERIAL_FIELDS, limit=8192)
    expected = {'schema': 1, 'taskID': 'REAL-SFTP-COMBINED-AUTH-A', 'service': 'keyonly',
                'host': '127.0.0.1', 'port': 22221, 'user': 'fixture', 'key': 'edplain',
                'baseImage': BASE_IMAGE, 'containerID': CONTAINER, 'imageID': IMAGE, 'networkID': NETWORK,
                'expectedFingerprint': FINGERPRINT, 'project': PROJECT, 'context': CONTEXT, 'endpoint': ENDPOINT}
    if any(value[key] != expected_value for key, expected_value in expected.items()):
        raise Refused('fixed-material-reference')
    return value


def provenance_object(raw, *, material):
    value = file_object(raw, fields=PROVENANCE_FIELDS, limit=4096)
    if (value['base_image'] != material['baseImage'] or value['built_image_id'] != material['imageID'] or
            value['service'] != 'keyonly' or value['collected_at'] <= 0):
        raise Refused('public-provenance-binding')
    return value


def contract_object(raw):
    # The unchanged validate_contract still enforces generation and 120-second freshness.
    if set(CONTRACT_FIELDS) != CONTRACT_KEYS: raise Refused('public-contract-schema-internal')
    return file_object(raw, fields=CONTRACT_FIELDS, limit=4096)
