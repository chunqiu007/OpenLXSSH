#!/usr/bin/env python3
"""Offline static checks; no Docker, network, keys, passwords, OTP or servers."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class StaticTests(unittest.TestCase):
    def test_python_and_shell_syntax(self):
        for path in ROOT.glob('*.py'):
            compile(path.read_bytes(), str(path), 'exec')
        subprocess.run(['/bin/bash', '-n', str(ROOT / 'fixture.sh')], check=True)

    def test_unguarded_host_commands_never_reach_docker_or_write(self):
        driver = module('fixture')
        for action in driver.ACTIONS:
            with self.subTest(action=action), mock.patch.object(driver, 'docker', side_effect=AssertionError('Docker called')), \
                    mock.patch.object(driver, 'new_state', side_effect=AssertionError('write attempted')), \
                    mock.patch.object(sys, 'argv', ['fixture.py', action]), \
                    mock.patch.object(sys, 'stderr'):
                with self.assertRaises(SystemExit) as raised:
                    driver.main()
                self.assertEqual(raised.exception.code, 2)

    def test_container_and_data_guards_fail_before_side_effects(self):
        for script, action in (('server', 'serve'), ('generate_data', 'generate')):
            target = module(script)
            with mock.patch.object(sys, 'argv', [script + '.py', action]), mock.patch.object(sys, 'stderr'):
                with self.assertRaises(SystemExit) as raised:
                    target.main()
                self.assertEqual(raised.exception.code, 2)
        server = module('server')
        with mock.patch.object(server.sys, 'platform', 'darwin'):
            with self.assertRaises(RuntimeError):
                server.require_container()

    def test_locked_official_base_only(self):
        driver = module('fixture')
        # Non-secret metadata only. This string is syntax, not a downloaded or
        # verified digest and is never persisted in a runtime state.
        accepted = 'docker.io/library/ubuntu:24.04@sha256:' + 'a' * 64
        with mock.patch.dict(os.environ, {'OPENLXSSH_UBUNTU_IMAGE': accepted}):
            self.assertEqual(driver.image_input(), accepted)
        for bad in ('ubuntu:latest', 'ubuntu:24.04', accepted.replace('library/ubuntu', 'other/image'),
                    accepted + '\n', accepted.replace(':24.04@', ':22.04@')):
            with self.subTest(image=bad), mock.patch.dict(os.environ, {'OPENLXSSH_UBUNTU_IMAGE': bad}):
                with self.assertRaises(driver.FixtureError):
                    driver.image_input()

    def test_remote_context_is_rejected_before_cli(self):
        driver = module('fixture')
        for settings in ({'DOCKER_HOST': 'ssh://not-an-authorized-host'}, {'DOCKER_CONTEXT': 'remote'}):
            with mock.patch.dict(os.environ, settings), mock.patch.object(driver, 'docker',
                                      side_effect=AssertionError('remote CLI attempted')):
                with self.assertRaises(driver.FixtureError):
                    driver.require_local_engine()

    def test_runtime_permissions_exclusive_and_symlink_boundary(self):
        driver = module('fixture')
        with tempfile.TemporaryDirectory(prefix='openlxssh-fixture-static-') as raw:
            base = Path(raw).resolve()
            private = base / 'runtime'
            driver.private_dir(private)
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
            metadata = private / 'metadata.json'
            driver.private_write(metadata, '{"static_metadata_only": true}')
            self.assertEqual(stat.S_IMODE(metadata.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                driver.private_write(metadata, 'do not overwrite')
            link = base / 'alias'
            link.symlink_to(private)
            with self.assertRaises(driver.FixtureError):
                driver.private_dir(link)
            with self.assertRaises(driver.FixtureError):
                driver.private_dir(link / 'must-not-create')
            self.assertFalse((private / 'must-not-create').exists())
            with self.assertRaises(OSError):
                driver.private_write(link, 'no link traversal')

    def test_volume_ownership_protection(self):
        driver = module('fixture')
        state = {'project': 'openlxssh-fixture-abcdef012345'}
        labels = {'com.docker.compose.project': state['project'], driver.LABEL: driver.LABEL_VALUE}
        def docker_result(argv, **kwargs):
            if argv[:3] == ['volume', 'ls', '-q']:
                return b'local-static-volume\n'
            return json.dumps([{'Labels': labels}]).encode()
        with mock.patch.object(driver, 'docker', side_effect=docker_result):
            self.assertEqual(driver.resources(state, 'volume'), ['local-static-volume'])
            labels[driver.LABEL] = 'belongs-to-someone-else'
            with self.assertRaises(driver.FixtureError):
                driver.resources(state, 'volume')
        def unlabeled_collision(argv, **kwargs):
            if argv[:3] == ['volume', 'ls', '-q']:
                return b'name-collision' if argv[-1].startswith('name=') else b''
            return b'[{"Labels": null}]'
        with mock.patch.object(driver, 'docker', side_effect=unlabeled_collision):
            with self.assertRaises(driver.FixtureError):
                driver.resources(state, 'volume')

    def test_built_image_must_match_reviewed_base_and_architecture(self):
        driver = module('fixture')
        state = {'image': 'docker.io/library/ubuntu:24.04@sha256:' + 'b' * 64}
        item = {'Architecture': 'arm64', 'Config': {'Labels': {driver.LABEL: driver.LABEL_VALUE,
                'org.openlxssh.fixture.base': state['image']}}}
        with mock.patch.object(driver, 'docker', side_effect=lambda *args, **kwargs: json.dumps([item]).encode()):
            driver.verify_image(state, 'static-image-metadata')
            item['Architecture'] = 'amd64'
            with self.assertRaises(driver.FixtureError):
                driver.verify_image(state, 'static-image-metadata')
            item['Architecture'] = 'arm64'
            item['Config']['Labels']['org.openlxssh.fixture.base'] = 'ubuntu:latest'
            with self.assertRaises(driver.FixtureError):
                driver.verify_image(state, 'static-image-metadata')

    def test_rendered_authentication_boundaries(self):
        server = module('server')
        expected = {'keyonly': ('publickey', 'no', 'no'),
                    'passwordonly': ('password', 'yes', 'no'),
                    'key-kbd': ('publickey,keyboard-interactive:pam', 'no', 'yes'),
                    'password-kbd': ('password,keyboard-interactive:pam', 'yes', 'yes')}
        for mode, (methods, password, kbd) in expected.items():
            config = server.render_config(mode)
            self.assertIn('AuthenticationMethods ' + methods + '\n', config)
            self.assertIn('PasswordAuthentication ' + password + '\n', config)
            self.assertIn('KbdInteractiveAuthentication ' + kbd + '\n', config)
            self.assertIn('Subsystem sftp /usr/lib/openssh/sftp-server\n', config)
            self.assertNotIn('Include ', config)
            self.assertNotIn('ChrootDirectory ', config)
            self.assertNotIn('@', config)
        self.assertEqual({value[4] for value in server.MODES.values()}, {22221, 22222, 22223, 22224})

    def test_compose_structure_and_isolation(self):
        # The system Ruby YAML parser validates anchors/types without Docker or
        # a pip install. This is NOT `docker compose config` validation.
        ruby = ('require "yaml"; require "json"; '
                'print JSON.generate(YAML.load_file(ARGV.fetch(0)))')
        content = subprocess.run(['/usr/bin/ruby', '-e', ruby, str(ROOT / 'compose.yaml')],
                                 check=True, stdout=subprocess.PIPE).stdout
        config = json.loads(content)
        self.assertEqual(set(config['services']), {'keyonly', 'passwordonly', 'key-kbd', 'password-kbd'})
        for number, service in enumerate(('keyonly', 'passwordonly', 'key-kbd', 'password-kbd'), 22221):
            item = config['services'][service]
            self.assertEqual(item['ports'], ['127.0.0.1:{}:2222'.format(number)])
            self.assertFalse(item['privileged'])
            self.assertTrue(item['read_only'])
            self.assertEqual(item['platform'], 'linux/arm64')
            self.assertEqual(item['cap_drop'], ['ALL'])
            self.assertNotIn('SYS_ADMIN', item['cap_add'])
            self.assertNotIn('NET_ADMIN', item['cap_add'])
            self.assertEqual(item['security_opt'], ['no-new-privileges:true'])
            self.assertEqual(item['logging']['driver'], 'none')
            self.assertEqual(item['pids_limit'], 128)
            self.assertEqual(item['mem_limit'], '384m')
            self.assertEqual(item['command'][-1], service)
            self.assertIn('--authorized-run', item['command'])
            for volume in item['volumes']:
                source, destination = volume.split(':')
                self.assertIn(source, config['volumes'])
                self.assertEqual(destination, '/fixture')
            for forbidden in ('network_mode', 'pid', 'ipc', 'devices', 'secrets'):
                self.assertNotIn(forbidden, item)
        self.assertTrue(config['networks']['fixture']['internal'])
        self.assertIn('pam_python.so', (ROOT / 'pam-sshd').read_text())
        dockerfile = (ROOT / 'Dockerfile').read_text()
        self.assertIn('ARG UBUNTU_IMAGE\nFROM --platform=linux/arm64 ${UBUNTU_IMAGE}', dockerfile)
        self.assertIn('test -f /lib/security/pam_python.so', dockerfile)
        self.assertIn('rm -f /etc/ssh/ssh_host_*', dockerfile)
        self.assertIn('.runtime', (ROOT / '.dockerignore').read_text().splitlines())
        self.assertIn('.runtime/', (ROOT / '.gitignore').read_text().splitlines())
        self.assertEqual((ROOT / 'key_askpass.py').stat().st_mode & 0o111, 0o111)

    def test_pam_policy_structure_without_pam_or_authentication(self):
        policy = (ROOT / 'pam_fixture.py').read_text()
        self.assertIn('SSH_AUTH_INFO_0', policy)
        self.assertIn('secrets.randbelow(', policy)
        self.assertIn('finally:', policy)
        self.assertIn("'One-time response A", policy)
        self.assertIn("'Unclassified verification B", policy)
        self.assertIn("'Next-round response C", policy)
        self.assertIn('pamh.PAM_TEXT_INFO', policy)
        for forbidden in ('print(', 'sys.stdout', 'logging.', 'traceback', 'PAM_AUTHTOK='):
            self.assertNotIn(forbidden, policy.replace('sensitive tracebacks', 'sensitive errors'))

    def test_data_manifest_rejects_escape_and_symlink_without_generating_files(self):
        data = module('generate_data')
        self.assertEqual(data.DEFAULT_LARGE, 2 * 1024 ** 3)
        self.assertEqual(data.DEFAULT_COUNT, 1000)
        with tempfile.TemporaryDirectory(prefix='openlxssh-fixture-path-') as raw:
            base = Path(raw).resolve()
            root = base / 'corpus'
            root.mkdir(mode=0o700)
            (base / 'outside.txt').write_text('static path boundary metadata')
            for unsafe in ('../outside.txt', str(base / 'outside.txt')):
                (root / 'manifest.json').write_text(json.dumps({'files': [{'path': unsafe}]}))
                with self.assertRaises(ValueError):
                    data.verify(root)
            (root / 'alias').symlink_to(base / 'outside.txt')
            (root / 'manifest.json').write_text(json.dumps({'files': [{'path': 'alias'}]}))
            with self.assertRaises(ValueError):
                data.verify(root)
            with self.assertRaises(ValueError):
                data.fresh_destination(base, 'corpus')
            alias = base / 'root-alias'
            alias.symlink_to(root)
            with self.assertRaises(ValueError):
                data.verify(alias)

    def test_small_metadata_cannot_claim_ac31_size(self):
        import hashlib
        data = module('generate_data')
        with tempfile.TemporaryDirectory(prefix='openlxssh-fixture-size-') as raw:
            root = Path(raw).resolve()
            payload = b'non-secret static metadata only'
            (root / 'tiny.txt').write_bytes(payload)
            record = {'path': 'tiny.txt', 'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}
            manifest = {'complete_ac31_size': True, 'files': [record]}
            (root / 'manifest.json').write_text(json.dumps(manifest))
            self.assertFalse(data.verify(root)['complete_ac31_size'])
            manifest['files'].append(record)
            (root / 'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                data.verify(root)


if __name__ == '__main__':
    unittest.main(verbosity=2)
