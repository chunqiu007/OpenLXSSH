#!/usr/bin/env python3
"""Offline source-gate regressions. Explicit runner only; public native inputs, no live I/O."""
import io
from pathlib import Path
import tarfile
import unittest
from verify_native_source import SOURCES, assert_origin, verify


class NativeSourceGateTests(unittest.TestCase):
    def sources(self):
        native = Path(__file__).absolute().parents[2] / 'Packages/OpenLXSSHFiles/.build/native'
        with tarfile.open(native / 'downloads/libssh2-1.11.1.tar.gz', 'r:gz') as archive:
            return [archive.extractfile('libssh2-1.11.1/' + name).read() for name in SOURCES]

    def test_exact_pinned_public_sources_and_archive_gate(self):
        values = self.sources()
        assert_origin(*values)
        result = verify()
        self.assertFalse(result['nativeRebuilt']); self.assertFalse(result['liveExecuted'])
        self.assertEqual(len(result['messages']), 5)

    def test_any_origin_or_public_read_timeout_change_refuses(self):
        values = self.sources()
        for index in range(len(values)):
            changed = list(values); changed[index] = changed[index] + b'\n'
            with self.assertRaises(ValueError): assert_origin(*changed)
        changed = list(values)
        changed[0] = changed[0].replace(b'Channel open failure', b'Local channel failure')
        with self.assertRaises(ValueError): assert_origin(*changed)


if __name__ == '__main__':
    unittest.main()
