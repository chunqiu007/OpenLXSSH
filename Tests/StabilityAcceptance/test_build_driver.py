#!/usr/bin/env python3
"""Finite recipe unit/refusal checks only; never build/sign/query identities/run SSH."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import build_driver as recipe
import prepare_wrapper

HERE = Path(__file__).resolve().parent
BUILD = HERE / '.build'


def thin_macho(kind=1, minimum=26 << 16, cpu=0x0100000c, libraries=(), rpaths=()):
    def string_command(command, value, header_size):
        payload = value.encode() + b'\0'
        size = (header_size + len(payload) + 7) // 8 * 8
        return struct.pack('<III', command, size, header_size) + b'\0' * (header_size - 12) + payload + b'\0' * (size - header_size - len(payload))
    commands = [struct.pack('<IIIIII', 0x32, 24, 1, minimum, (26 << 16) | (2 << 8), 0)]
    commands += [string_command(0xc, library, 24) for library in libraries]
    commands += [string_command(0x8000001c, path, 12) for path in rpaths]
    if kind == 2:
        commands.append(string_command(0xe, '/usr/lib/dyld', 12))
    body = b''.join(commands)
    return struct.pack('<IiiIIIII', 0xfeedfacf, cpu, 0, kind, len(commands), len(body), 0, 0) + body


class RecipeChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='recipe-unit-', dir=BUILD)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def test_default_help_has_no_subprocess_writes_or_identity_query(self):
        before = sorted(str(p) for p in self.root.rglob('*'))
        with patch.object(recipe, 'capture', side_effect=AssertionError('subprocess forbidden')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(recipe.main([]), 0)
            with self.assertRaises(SystemExit) as result:
                recipe.main(['--help'])
            self.assertEqual(result.exception.code, 0)
        self.assertEqual(sorted(str(p) for p in self.root.rglob('*')), before)
        # Actual child entry point, not just imported main. No build UUID created.
        before = set(BUILD.iterdir())
        source_before = set(HERE.iterdir())
        env = os.environ.copy()
        env.pop('PYTHONDONTWRITEBYTECODE', None)
        result = subprocess.run([sys.executable, str(HERE / 'build_driver.py')], cwd=HERE,
                                env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('default help', result.stdout)
        self.assertEqual(set(BUILD.iterdir()), before)
        self.assertEqual(set(HERE.iterdir()), source_before)

    def test_invalid_cache_paths_and_symlinks_refused_before_commands(self):
        before = set(BUILD.iterdir())
        alias = self.root / 'cache-alias'
        alias.symlink_to(recipe.DEFAULT_CACHE, target_is_directory=True)
        with patch.object(recipe, 'capture', side_effect=AssertionError('no tool should run')):
            for path in ('relative', str(self.root / 'missing'), str(alias), str(self.root / '..' / self.root.name)):
                with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                    recipe.main(['build', '--cache', path, '--sign-development'])
            with self.assertRaisesRegex(recipe.Refusal, 'unapprovedCachePath'):
                recipe.main(['build', '--cache', str(self.root)])
        self.assertEqual(set(BUILD.iterdir()), before)

    def test_changed_pins_gate_missing_checkout_fail_closed_readonly(self):
        lock = {'pins': [{'identity': name, 'state': {'revision': revision}} for name, revision in recipe.PINS.items()]}
        self.assertEqual(recipe.approved_pins(lock), recipe.PINS)
        for changed in ([], lock['pins'] + lock['pins'][:1], copy.deepcopy(lock['pins'])):
            if len(changed) == 4:
                changed[0]['state']['revision'] = '0' * 40
            with self.assertRaisesRegex(recipe.Refusal, 'packagePinsChanged'):
                recipe.approved_pins({'pins': changed})
        with patch.object(recipe, 'GATE_SHA256', '0' * 64), patch.object(recipe, 'capture', side_effect=AssertionError('gate should not execute')):
            with self.assertRaisesRegex(recipe.Refusal, 'pluginGateChanged'):
                recipe.validate_cache(recipe.DEFAULT_CACHE)
        # No altered production pins or cache files are needed for refusal tests.
        with patch.object(recipe, 'capture', return_value=subprocess.CompletedProcess([], 1, b'', b'')):
            with self.assertRaisesRegex(recipe.Refusal, 'pinnedCheckoutOrPluginChanged'):
                recipe.validate_cache(recipe.DEFAULT_CACHE)

    def test_source_changed_and_snapshot_tampering_refuse(self):
        source = self.write('source.swift', b'// public metadata sentinel only\n')
        item = recipe.fingerprint([source])[0]
        snapshot = self.write('snapshot.swift', source.read_bytes())
        item['snapshot'] = str(snapshot)
        recipe.require_unchanged([item])
        source.write_bytes(b'// changed source\n')
        with self.assertRaisesRegex(recipe.Refusal, 'sourceChanged'):
            recipe.require_unchanged([item])
        source.write_bytes(snapshot.read_bytes())
        snapshot.write_bytes(b'// changed snapshot\n')
        with self.assertRaisesRegex(recipe.Refusal, 'sourceSnapshotChanged'):
            recipe.require_unchanged([item])
        source.unlink()
        source.symlink_to(snapshot)
        with self.assertRaisesRegex(recipe.Refusal, 'unsafePath'):
            recipe.require_unchanged([item])

    def test_all_linked_inputs_must_be_arm64_object_min26(self):
        path = self.write('object', thin_macho())
        metadata = recipe.macho_metadata(path)
        self.assertEqual(metadata['minimumOS'], '26.0')
        self.assertEqual(metadata['fileType'], 'MH_OBJECT')
        for data in (b'not a binary', thin_macho(minimum=15 << 16), thin_macho(minimum=11 << 16),
                     thin_macho(cpu=0x01000007), thin_macho(kind=2)):
            path.write_bytes(data)
            with self.assertRaises(recipe.Refusal):
                recipe.macho_metadata(path)

    def test_executable_system_runtime_closure_rejects_external_and_rpath(self):
        path = self.write('executable', thin_macho(kind=2, libraries=['/usr/lib/libSystem.B.dylib']))
        self.assertEqual(recipe.macho_metadata(path, executable=True)['fileType'], 'MH_EXECUTE')
        for options in ({'libraries': ['@rpath/libswiftCore.dylib']}, {'libraries': ['/tmp/libUnexpected.dylib']},
                        {'libraries': ['/usr/lib/../tmp/escape.dylib']},
                        {'libraries': ['/usr/lib/libSystem.B.dylib'], 'rpaths': ['/Applications/Xcode.app/toolchain/usr/lib/swift/macosx']},
                        {'libraries': []}):
            path.write_bytes(thin_macho(kind=2, **options))
            with self.subTest(options=options), self.assertRaises(recipe.Refusal):
                recipe.macho_metadata(path, executable=True)

    def test_link_map_rejects_unlisted_objects_archives_and_non_sdk_stubs(self):
        sdk = self.root / 'SDK'
        sdk.mkdir()
        runtime = self.root / 'runtime.o'
        stub = sdk / 'usr/lib/libSystem.tbd'
        stub.parent.mkdir(parents=True)
        stub.write_text('public link metadata only\n')
        path = self.write('link-map', b'')
        def contents(extra):
            return ('# Object files:\n[ 0] linker synthesized\n[ 1] ' + str(runtime) + '\n' + extra + '# Sections:\n').encode()
        path.write_bytes(contents('[ 2] ' + str(sdk / 'usr/lib/libSystem.tbd') + '\n'))
        recipe.verify_link_map(path, [runtime], sdk)
        for unexpected in (str(self.root / 'min15.o'), str(self.root / 'compat.a(member.o)'),
                           '/outside/sdk/usr/lib/libSystem.tbd'):
            path.write_bytes(contents('[ 2] ' + unexpected + '\n'))
            with self.subTest(unexpected=unexpected), self.assertRaises((recipe.Refusal, OSError)):
                recipe.verify_link_map(path, [runtime], sdk)
        alias = self.root / 'SDK26.2'
        alias.symlink_to(sdk, target_is_directory=True)
        path.write_bytes(contents('[ 2] ' + str(alias / 'usr/lib/libSystem.tbd') + '\n'))
        recipe.verify_link_map(path, [runtime], sdk)

    def test_noidentity_stops_signing_only_after_link_phase(self):
        class Builder:
            work = self.root
            record = {'signature': {'status': 'unsigned'}}
            def command(self, *args, **kwargs):
                raise AssertionError('No identity must never reach a signing command')
        with patch.object(recipe, 'capture', return_value=subprocess.CompletedProcess([], 0, b'  0 valid identities found\n', b'')) as run:
            self.assertFalse(recipe.sign_wrapper(Builder(), self.root / 'not-created.app'))
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][:2], ['/usr/bin/security', 'find-identity'])
        self.assertEqual(Builder.record['signature']['status'], 'noExistingDevelopmentIdentity')
        self.assertIsNone(recipe.select_development_identity(b' 1) ' + b'F' * 40 + b' "Developer ID Application: Unit (ABCDEFGHIJ)"\n'))
        self.assertEqual(recipe.select_development_identity(b' 1) ' + b'A' * 40 + b' "Apple Development: Unit (ABCDEFGHIJ)"\n'), 'A' * 40)

    def test_unsigned_or_untrusted_signature_and_entitlements_refused(self):
        display = (b'Identifier=org.openlxssh.OpenLXSSH\nTeamIdentifier=ABCDEFGHIJ\n'
                   b'CodeDirectory v=20500 size=100 flags=0x10000(runtime) hashes=1+0 location=embedded\n'
                   b'Authority=Apple Development: Unit (ABCDEFGHIJ)\n')
        self.assertTrue(recipe.signature_fields(display, b'', recipe.APP_ID)['hardenedRuntime'])
        for changed in (display.replace(b'ABCDEFGHIJ', b'not-set'), display.replace(b'(runtime)', b'(adhoc)'),
                        display.replace(b'org.openlxssh.OpenLXSSH', b'org.invalid.test'), display + b'Timestamp=online\n',
                        display.replace(b'Apple Development:', b'Developer ID Application:')):
            with self.assertRaises(recipe.Refusal):
                recipe.signature_fields(changed, b'', recipe.APP_ID)
        with self.assertRaisesRegex(recipe.Refusal, 'entitlementsNotAllowed'):
            recipe.signature_fields(display, plistlib.dumps({'com.apple.security.get-task-allow': True}), recipe.APP_ID)
        with patch.object(recipe, 'capture', return_value=subprocess.CompletedProcess([], 1, b'', b'')):
            with self.assertRaisesRegex(recipe.Refusal, 'strictSignatureVerificationFailed'):
                recipe.verify_signature(self.root / 'unsigned', recipe.APP_ID)

    def test_record_source_allowlist_rejects_arbitrary_path_before_hashing(self):
        permitted = self.root / 'public.swift'
        record = {'inputs': [{'path': '/FORBIDDEN-DO-NOT-OPEN/.runtime/secret', 'sha256': 'a' * 64}]}
        with patch.object(recipe, 'validate_cache', return_value={'paths': [permitted]}), \
                patch.object(recipe, 'digest', side_effect=AssertionError('No unapproved input may be opened')):
            with self.assertRaisesRegex(recipe.Refusal, 'sourceSetChanged'):
                recipe.validate_source_record(record, self.root)

    def test_legacy_revision_cannot_package_or_assert_provenance(self):
        with self.assertRaises(ValueError):
            prepare_wrapper.main(['prepare', '--prepare-reviewed-wrapper', '--driver', '/not-read',
                                  '--helper', '/not-read', '--revision', 'a' * 40])
        path = self.write('invented.json', json.dumps({'kind': recipe.KIND}).encode())
        with self.assertRaises(ValueError):
            prepare_wrapper.prepare_verified(path)
        with self.assertRaises(recipe.Refusal):
            recipe.verify_record(path)

    def test_recipe_static_boundaries_and_no_implicit_debug_signing(self):
        text = (HERE / 'build_driver.py').read_text()
        self.assertIn("'-Xlinker', '-no_adhoc_codesign'", text)
        for forbidden in ('build-app.sh', 'DerivedData/', 'SecItemCopyMatching', 'ssh-keyscan', 'shell=True',
                          'set-key-partition-list', 'import-certificate', 'notarytool', 'curl ', 'docker ', 'StrictHostKeyChecking no'):
            self.assertNotIn(forbidden, text)
        sign = text.index('if sign and not sign_wrapper(builder, app)')
        self.assertGreater(sign, text.index("'helper': builder.link"))
        self.assertGreater(sign, text.index("'driver': builder.link"))
        self.assertIn("'driverExecuted': False", text)


if __name__ == '__main__':
    for name in ('build_driver.py', 'test_build_driver.py'):
        compile((HERE / name).read_text(), str(HERE / name), 'exec')
    unittest.main(verbosity=2)
