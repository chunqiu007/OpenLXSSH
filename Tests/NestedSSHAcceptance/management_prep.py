"""NEST-PUBLICKEY-PREP-A: pure management-prep only; no file/process/SSH I/O.
Future adapter: held-FD/named nofollow checks, durable receipt read-back BEFORE
append, root exclusion through restore, then key ledger cleanup after owned SSH
closes and exact restoration. Exclusion is a premise, NOT proven here.
Hashes are NOT locks; checks are NOT atomic against foreign writers.
Refused restore must preserve foreign data and retain key/receipt for recovery.
"""
import base64
from collections import namedtuple
import hashlib
import json
import re
import struct

CONTAINER_ID = '1253a29501483eb71f80e39b9af5c85e10c3a49329d5e93700fecd3f00f334f2'
HOST_FINGERPRINT = 'SHA256:MHUel445tN/gQtcvZikLZVE1mlWZf7U38C0zZTTru+Q'
AUTHORIZED_KEYS = '/run/openlxssh-fixture/authorized_keys'
LIMIT = 65536
Stamp = namedtuple('Stamp', 'device inode uid gid mode links')  # mode includes file type.
Observation = namedtuple('Observation', 'held named nofollow data')
Exclusion = namedtuple('Exclusion', 'root_management_serialized foreign_auth_sessions')
Receipt = namedtuple('Receipt', 'nonce stamp original new_public_line exclusion')
class Refused(ValueError):
    pass

def require(condition):
    if not condition:
        raise Refused('nested-publickey-prep-refused')

def digest(data):
    return hashlib.sha256(data).hexdigest()

def key_plan(nonce):
    require(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce) is not None)
    path = '/fixture/home/.openlxssh-nested-' + nonce + '/id_ed25519'
    return {'uid': 10000, 'directory_mode': 0o700, 'private_key_mode': 0o600,
            'argv': ('/usr/bin/ssh-keygen', '-t', 'ed25519', '-N', '',
                     '-C', 'OpenLXSSH-nested-' + nonce, '-f', path)}

def public_blob(line, comment):
    """Fixture public wire validation only, not SSH or cryptographic implementation."""
    require(type(line) is bytes and 0 < len(line) <= 4096 and line.endswith(b'\n'))
    try:
        fields = line[:-1].decode('ascii').split(' ')
        require(len(fields) >= 3 and ' '.join(fields[2:]) == comment)
        algorithm, encoded = fields[:2]
        require(algorithm in ('ssh-ed25519', 'ssh-rsa'))
        blob = base64.b64decode(encoded, validate=True)
        require(base64.b64encode(blob).decode('ascii') == encoded)
        offset, parts = 0, []
        while offset < len(blob):
            require(offset + 4 <= len(blob))
            size = struct.unpack('>I', blob[offset:offset + 4])[0]
            offset += 4
            require(0 < size <= len(blob) - offset)
            parts.append(blob[offset:offset + size])
            offset += size
        require(parts and parts[0] == algorithm.encode('ascii'))
        if algorithm == 'ssh-ed25519':
            require(len(parts) == 2 and len(parts[1]) == 32)
        else:
            require(len(parts) == 3)
            for number in parts[1:]:  # Positive, minimally encoded SSH mpint.
                require(number[0] < 128 and any(number))
                require(number[0] != 0 or (len(number) > 1 and number[1] >= 128))
        return algorithm, blob
    except (UnicodeError, ValueError, struct.error):
        raise Refused('nested-publickey-prep-refused') from None

def owned(observed, exclusion):
    require(type(observed.held) is Stamp and type(observed.named) is Stamp)
    require(all(type(value) is int for value in observed.held + observed.named))
    dev, ino, uid, gid, mode, links = observed.held
    require(dev >= 0 and ino > 0 and uid == gid == 0 and mode == 0o100644 and links == 1)
    require(observed.named == observed.held and observed.nofollow is True)
    require(type(observed.data) is bytes and 0 < len(observed.data) <= LIMIT)
    require(exclusion.root_management_serialized is True)
    require(type(exclusion.foreign_auth_sessions) is int and exclusion.foreign_auth_sessions == 0)

def prepare(nonce, observed, new_public_line, exclusion):
    key_plan(nonce)
    owned(observed, exclusion)
    lines = observed.data.splitlines(keepends=True)
    require(len(lines) == 4)  # This fixture has exactly four original public keys.
    originals = [public_blob(line, 'OpenLXSSH disposable client') for line in lines]
    require([item[0] for item in originals] == ['ssh-ed25519', 'ssh-ed25519', 'ssh-rsa', 'ssh-rsa'])
    algorithm, blob = public_blob(new_public_line, 'OpenLXSSH-nested-' + nonce)
    require(algorithm == 'ssh-ed25519' and all(blob != item[1] for item in originals))
    require(len(observed.data + new_public_line) <= LIMIT)
    return Receipt(nonce, observed.held, observed.data, new_public_line, exclusion)

def public_receipt(receipt):
    original = Observation(receipt.stamp, receipt.stamp, True, receipt.original)
    require(prepare(receipt.nonce, original, receipt.new_public_line, receipt.exclusion) == receipt)
    return (json.dumps({
        'schema': 1, 'case': 'NESTrealpublickeyonly', 'stage': 'management-prep-only',
        'expected_container_id': CONTAINER_ID, 'expected_host_fingerprint': HOST_FINGERPRINT,
        'authorized_keys': AUTHORIZED_KEYS, 'nonce': receipt.nonce, 'stamp': receipt.stamp._asdict(),
        'exclusion_declaration': receipt.exclusion._asdict(),
        'original_public_lines': receipt.original.decode('ascii').splitlines(keepends=True),
        'new_public_line': receipt.new_public_line.decode('ascii'),
        'original_sha256': digest(receipt.original), 'appended_sha256': digest(receipt.original + receipt.new_public_line),
        'not_covered': ['human-inner-password', 'human-inner-OTP'],
        'safety': 'hashes-are-not-locks; not-atomic-against-foreign-writers',
    }, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')

def check(receipt, observed, exclusion, durable_receipt_sha256, expected):
    require(durable_receipt_sha256 == digest(public_receipt(receipt)))  # Adapter must fsync/read back.
    owned(observed, exclusion)
    require(observed.held == receipt.stamp)
    require(observed.data == expected and digest(observed.data) == digest(expected))

def append_suffix(receipt, observed, exclusion, durable_receipt_sha256):
    check(receipt, observed, exclusion, durable_receipt_sha256, receipt.original)
    return receipt.new_public_line

def restore_original(receipt, observed, exclusion, durable_receipt_sha256, *, owned_ssh_closed):
    require(owned_ssh_closed is True)
    check(receipt, observed, exclusion, durable_receipt_sha256, receipt.original + receipt.new_public_line)
    return receipt.original
