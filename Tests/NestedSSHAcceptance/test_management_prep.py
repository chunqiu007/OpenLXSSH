"""Pure/offline tests. Synthetic public wire bytes are NOT SSH authentication."""
import base64
import json
import struct
import unittest

import management_prep as prep

NONCE = '0123456789abcdef' * 2
EXCLUSION = prep.Exclusion(True, 0)
STAMP = prep.Stamp(3, 42, 0, 0, 0o100644, 1)
COMMENT = 'OpenLXSSH-nested-' + NONCE


def public_line(algorithm, number, comment='OpenLXSSH disposable client'):
    def wire(value):
        return struct.pack('>I', len(value)) + value
    parts = [algorithm.encode('ascii')]
    parts += [bytes([number]) * 32] if algorithm == 'ssh-ed25519' else [b'\x01\x00\x01', b'\x00\x80' + bytes([number]) * 383]
    return algorithm.encode('ascii') + b' ' + base64.b64encode(b''.join(map(wire, parts))) + b' ' + comment.encode('ascii') + b'\n'


ORIGINAL = b''.join(public_line(algorithm, number) for number, algorithm in enumerate(
    ('ssh-ed25519', 'ssh-ed25519', 'ssh-rsa', 'ssh-rsa'), 1))


def observation(data=ORIGINAL):
    return prep.Observation(STAMP, STAMP, True, data)


class ManagementPrepTests(unittest.TestCase):
    def setUp(self):
        self.new = public_line('ssh-ed25519', 5, COMMENT)
        self.receipt = prep.prepare(NONCE, observation(), self.new, EXCLUSION)
        self.durable = prep.digest(prep.public_receipt(self.receipt))

    def test_nonce_boundary_and_fixed_uid_keygen_plan(self):
        plan = prep.key_plan(NONCE)
        self.assertEqual((plan['uid'], plan['directory_mode'], plan['private_key_mode']), (10000, 0o700, 0o600))
        self.assertEqual(plan['argv'], ('/usr/bin/ssh-keygen', '-t', 'ed25519', '-N', '', '-C', COMMENT,
                                       '-f', '/fixture/home/.openlxssh-nested-' + NONCE + '/id_ed25519'))
        for nonce in ('', NONCE.upper(), NONCE[:-1], NONCE + '0', '../' + NONCE, NONCE + '\n', None):
            with self.subTest(nonce=nonce), self.assertRaises(prep.Refused):
                prep.key_plan(nonce)

    def test_public_wire_rejection_and_distinct_new_key(self):
        def encoded(blob):
            return b'ssh-ed25519 ' + base64.b64encode(blob) + b' ' + COMMENT.encode('ascii') + b'\n'
        blob = base64.b64decode(self.new.split()[1])
        malformed = (b'-----BEGIN OPENSSH PRIVATE KEY-----\n', b'not-a-public-line\n',
                     self.new + self.new, self.new[:-1], self.new.replace(b'OpenLXSSH-nested-', b'foreign-'),
                     public_line('ssh-rsa', 5, COMMENT), self.new.replace(b'ssh-ed25519 ', b'options ssh-ed25519 ', 1),
                     self.new.replace(b'ssh-ed25519 ', b'ssh-rsa ', 1), b'ssh-ed25519 !!!! ' + COMMENT.encode() + b'\n',
                     encoded(blob[:-1]), encoded(blob + b'\x00'), encoded(blob + struct.pack('>I', 1) + b'x'),
                     encoded(struct.pack('>I', 9999) + blob[4:]))
        for line in malformed:
            with self.subTest(size=len(line)), self.assertRaises(prep.Refused):
                prep.prepare(NONCE, observation(), line, EXCLUSION)
        for number in (1, 2):
            with self.subTest(reused=number), self.assertRaises(prep.Refused):
                prep.prepare(NONCE, observation(), public_line('ssh-ed25519', number, COMMENT), EXCLUSION)
        self.assertEqual(prep.public_blob(self.new, COMMENT), ('ssh-ed25519', blob))

    def test_original_public_only_and_exact_durable_receipt_bytes(self):
        document = json.loads(prep.public_receipt(self.receipt))
        self.assertEqual(''.join(document['original_public_lines']).encode('ascii'), ORIGINAL)
        self.assertEqual(document['new_public_line'].encode('ascii'), self.new)
        self.assertEqual(document['stamp'], STAMP._asdict())
        self.assertEqual(document['original_sha256'], prep.digest(ORIGINAL))
        self.assertEqual(document['appended_sha256'], prep.digest(ORIGINAL + self.new))
        self.assertEqual(document['exclusion_declaration'], EXCLUSION._asdict())
        self.assertEqual(document['expected_container_id'], prep.CONTAINER_ID)
        self.assertEqual(document['expected_host_fingerprint'], prep.HOST_FINGERPRINT)
        self.assertEqual(document['authorized_keys'], '/run/openlxssh-fixture/authorized_keys')
        self.assertEqual((document['case'], document['stage']), ('NESTrealpublickeyonly', 'management-prep-only'))
        self.assertEqual(document['not_covered'], ['human-inner-password', 'human-inner-OTP'])
        self.assertIn('not-atomic-against-foreign-writers', document['safety'])
        self.assertNotIn('PRIVATE KEY', prep.public_receipt(self.receipt).decode('ascii'))
        for data in (b'', ORIGINAL[:-1], ORIGINAL + b'# foreign comment\n', b'x' * (prep.LIMIT + 1),
                     ORIGINAL.replace(b'OpenLXSSH disposable client', b'foreign', 1), b'PRIVATE KEY\n'):
            with self.subTest(size=len(data)), self.assertRaises(prep.Refused):
                prep.prepare(NONCE, observation(data), self.new, EXCLUSION)

    def test_expected_owned_metadata_and_nofollow_checks(self):
        for change in ({'device': -1}, {'inode': 0}, {'uid': 10000}, {'gid': 10000}, {'mode': 0o100666},
                       {'mode': 0o120644}, {'mode': 0o40644}, {'links': 2}, {'inode': True}):
            stamp = STAMP._replace(**change)
            with self.subTest(change=change), self.assertRaises(prep.Refused):
                prep.prepare(NONCE, prep.Observation(stamp, stamp, True, ORIGINAL), self.new, EXCLUSION)
        for observed in (observation()._replace(named=STAMP._replace(inode=43)),
                         observation()._replace(named=STAMP._replace(uid=False)), observation()._replace(nofollow=False)):
            with self.assertRaises(prep.Refused):
                prep.prepare(NONCE, observed, self.new, EXCLUSION)
        # Replacing both held/named inodes with an identical-byte file is still refused.
        stamp = STAMP._replace(inode=99)
        with self.assertRaises(prep.Refused):
            prep.append_suffix(self.receipt, prep.Observation(stamp, stamp, True, ORIGINAL), EXCLUSION, self.durable)
        with self.assertRaises(prep.Refused):
            prep.restore_original(self.receipt, prep.Observation(stamp, stamp, True, ORIGINAL + self.new),
                                  EXCLUSION, self.durable, owned_ssh_closed=True)

    def test_append_then_restore_only_exact_expected_states(self):
        suffix = prep.append_suffix(self.receipt, observation(), EXCLUSION, self.durable)
        self.assertEqual(suffix, self.new)
        restored = prep.restore_original(self.receipt, observation(ORIGINAL + suffix), EXCLUSION,
                                         self.durable, owned_ssh_closed=True)
        self.assertEqual(restored, ORIGINAL)
        self.assertEqual(prep.digest(restored), json.loads(prep.public_receipt(self.receipt))['original_sha256'])
        with self.assertRaises(prep.Refused):  # Cannot append twice or restore twice.
            prep.append_suffix(self.receipt, observation(ORIGINAL + suffix), EXCLUSION, self.durable)
        with self.assertRaises(prep.Refused):
            prep.restore_original(self.receipt, observation(restored), EXCLUSION, self.durable, owned_ssh_closed=True)

    def test_foreign_append_reorder_truncate_and_same_size_edit_refused(self):
        for data in (ORIGINAL + b'# foreign\n', ORIGINAL[:-1], ORIGINAL.replace(b'client', b'Client', 1),
                     b''.join(reversed(ORIGINAL.splitlines(keepends=True)))):
            with self.subTest(stage='append', size=len(data)), self.assertRaises(prep.Refused):
                prep.append_suffix(self.receipt, observation(data), EXCLUSION, self.durable)
        for data in (ORIGINAL + self.new + b'# foreign\n', (ORIGINAL + self.new)[:-1],
                     (ORIGINAL + self.new).replace(b'client', b'Client', 1), self.new + ORIGINAL):
            with self.subTest(stage='restore', size=len(data)), self.assertRaises(prep.Refused):
                prep.restore_original(self.receipt, observation(data), EXCLUSION, self.durable, owned_ssh_closed=True)
        # Pure refusal does not modify caller-owned bytes; a later adapter must likewise never overwrite them.
        self.assertEqual(self.receipt.original, ORIGINAL)

    def test_exclusion_is_required_premise_not_hash_lock(self):
        for exclusion in (prep.Exclusion(False, 0), prep.Exclusion(True, 1), prep.Exclusion(True, -1), prep.Exclusion(True, False)):
            with self.subTest(exclusion=exclusion):
                with self.assertRaises(prep.Refused):
                    prep.prepare(NONCE, observation(), self.new, exclusion)
                with self.assertRaises(prep.Refused):
                    prep.append_suffix(self.receipt, observation(), exclusion, self.durable)
                with self.assertRaises(prep.Refused):
                    prep.restore_original(self.receipt, observation(ORIGINAL + self.new), exclusion,
                                          self.durable, owned_ssh_closed=True)

    def test_receipt_binding_and_owned_ssh_closed_guard(self):
        for receipt_hash in ('', '0' * 64, self.durable[:-1]):
            with self.subTest(receipt_hash=receipt_hash):
                with self.assertRaises(prep.Refused):
                    prep.append_suffix(self.receipt, observation(), EXCLUSION, receipt_hash)
                with self.assertRaises(prep.Refused):
                    prep.restore_original(self.receipt, observation(ORIGINAL + self.new), EXCLUSION,
                                          receipt_hash, owned_ssh_closed=True)
        for receipt in (self.receipt._replace(new_public_line=public_line('ssh-ed25519', 6, COMMENT)),
                        self.receipt._replace(stamp=STAMP._replace(inode=99))):
            with self.assertRaises(prep.Refused):
                prep.append_suffix(receipt, observation(), EXCLUSION, self.durable)
        for closed in (False, None, 1):
            with self.subTest(closed=closed), self.assertRaises(prep.Refused):
                prep.restore_original(self.receipt, observation(ORIGINAL + self.new), EXCLUSION,
                                      self.durable, owned_ssh_closed=closed)


if __name__ == '__main__':
    unittest.main()
