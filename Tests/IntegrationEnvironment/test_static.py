#!/usr/bin/env python3
"""Offline static checks; no Docker, network, keys, passwords, OTP or servers."""
import importlib.util
import io
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
                    mock.patch.object(driver, 'docker_cli', side_effect=AssertionError('Docker CLI called')), \
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
        # Main-session reviewed official ARM64 manifest; syntax check only,
        # never a registry lookup, pull, provenance claim or build in this test.
        reviewed = ('docker.io/library/ubuntu:24.04@sha256:'
                    '18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d')
        for image in (accepted, reviewed):
            with mock.patch.dict(os.environ, {'OPENLXSSH_UBUNTU_IMAGE': image}):
                self.assertEqual(driver.image_input(), image)
        for bad in ('ubuntu:latest', 'ubuntu:24.04', accepted.replace('library/ubuntu', 'other/image'),
                    accepted + '\n', accepted.replace(':24.04@', ':22.04@')):
            with self.subTest(image=bad), mock.patch.dict(os.environ, {'OPENLXSSH_UBUNTU_IMAGE': bad}):
                with self.assertRaises(driver.FixtureError):
                    driver.image_input()

    def test_remote_context_is_rejected_before_cli(self):
        driver = module('fixture')
        for settings in ({'DOCKER_HOST': 'ssh://not-an-authorized-host'}, {'DOCKER_CONTEXT': 'remote'}):
            with mock.patch.dict(os.environ, settings, clear=True), mock.patch.object(driver, 'docker_cli',
                                      side_effect=AssertionError('remote CLI attempted')):
                with self.assertRaises(driver.FixtureError):
                    driver.require_local_engine()

    def test_local_context_selection_pins_all_followup_commands(self):
        for context, endpoint in (('default', 'unix:///var/run/docker.sock'),
                                  ('desktop-linux', 'unix:///Users/static/.docker/run/docker.sock')):
            for explicit in (None, '', context):
                driver = module('fixture')
                settings = {} if explicit is None else {'DOCKER_CONTEXT': explicit}

                def local_metadata(command, **kwargs):
                    if command == ['docker', 'context', 'show']:
                        return subprocess.CompletedProcess(command, 0, (context + '\n').encode(), b'')
                    if command == ['docker', '--context', context, 'context', 'inspect', context]:
                        content = [{'Name': context, 'Endpoints': {'docker': {'Host': endpoint}}}]
                        return subprocess.CompletedProcess(command, 0, json.dumps(content).encode(), b'')
                    return subprocess.CompletedProcess(command, 0, b'[]', b'')

                with self.subTest(context=context, explicit=explicit), mock.patch.dict(os.environ, settings, clear=True), \
                        mock.patch.object(driver.subprocess, 'run', side_effect=local_metadata) as run:
                    self.assertEqual(driver.require_local_engine(), context)
                    self.assertEqual(driver.VERIFIED_ENDPOINT, endpoint)
                    # A changed ambient context cannot redirect a verified run.
                    with mock.patch.dict(os.environ, {'DOCKER_CONTEXT': 'remote', 'DOCKER_HOST': 'ssh://forbidden'}):
                        driver.docker(['ps', '-a', '-q'], capture=True)
                        driver.docker(['image', 'inspect', 'static-image'], capture=True)
                    for call in run.call_args_list[-2:]:
                        self.assertEqual(call.args[0][:3], ['docker', '--context', context])
                        self.assertEqual(call.kwargs['env']['DOCKER_CONTEXT'], context)
                        self.assertNotIn('DOCKER_HOST', call.kwargs['env'])
                        self.assertEqual(call.kwargs['env']['BUILDX_BUILDER'], context)

    def test_context_and_tls_overrides_fail_before_any_cli(self):
        for settings in ({'DOCKER_CONTEXT': 'company'}, {'DOCKER_CONTEXT': 'desktop-linux\n'},
                         {'DOCKER_HOST': 'unix:///tmp/another.sock'}, {'DOCKER_TLS_VERIFY': '1'},
                         {'DOCKER_CERT_PATH': '/not/used'}, {'DOCKER_TLS': '1'}):
            driver = module('fixture')
            with self.subTest(keys=list(settings)), mock.patch.dict(os.environ, settings, clear=True), \
                    mock.patch.object(driver, 'docker_cli', side_effect=AssertionError('CLI attempted')):
                with self.assertRaises(driver.FixtureError):
                    driver.require_local_engine()
                self.assertIsNone(driver.VERIFIED_CONTEXT)

    def test_active_custom_context_is_rejected_before_inspect(self):
        driver = module('fixture')
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(driver, 'docker_cli', return_value=b'company\n') as cli:
            with self.assertRaises(driver.FixtureError):
                driver.require_local_engine()
            cli.assert_called_once_with(['context', 'show'], capture=True)

    def test_local_endpoint_rejects_remote_alias_and_url_suffixes(self):
        driver = module('fixture')
        endpoints = ('tcp://127.0.0.1:2375', 'ssh://localhost', 'unix://host/path/docker.sock',
                     'unix:relative.sock', 'unix:///tmp/../docker.sock', 'unix:///tmp/./docker.sock',
                     'unix:///tmp//docker.sock', 'unix:////tmp/docker.sock', 'unix:///tmp/docker.sock/',
                     'unix:///tmp/docker.sock?host=remote', 'unix:///tmp/docker.sock#remote',
                     'unix:///tmp/%2e%2e/docker.sock', 'unix:///tmp/docker.sock\n', 'unix:///', None)
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint), mock.patch.dict(os.environ, {'DOCKER_CONTEXT': 'desktop-linux'}, clear=True), \
                    mock.patch.object(driver, 'docker_cli', return_value=json.dumps([
                        {'Name': 'desktop-linux', 'Endpoints': {'docker': {'Host': endpoint}}}]).encode()):
                with self.assertRaises(driver.FixtureError):
                    driver.require_local_engine()
                self.assertIsNone(driver.VERIFIED_CONTEXT)
        with self.assertRaises(driver.FixtureError):
            driver.docker(['ps'])

    def test_build_environment_cannot_select_remote_builder_or_compose(self):
        driver = module('fixture')
        driver.VERIFIED_CONTEXT = 'desktop-linux'
        settings = {'PATH': '/usr/bin', 'OPENLXSSH_UBUNTU_IMAGE': 'non-secret-metadata',
                    'DOCKER_HOST': 'ssh://forbidden', 'DOCKER_CONTEXT': 'remote',
                    'DOCKER_TLS_VERIFY': '1', 'DOCKER_CERT_PATH': '/unused', 'DOCKER_CONFIG': '/unreviewed',
                    'BUILDX_BUILDER': 'remote', 'BUILDX_CONFIG': '/unreviewed',
                    'BUILDX_BAKE_GIT_SSH': '/unused', 'BUILDKIT_HOST': 'tcp://forbidden:1234',
                    'COMPOSE_FILE': '/unreviewed.yaml', 'COMPOSE_BAKE': 'true', 'COMPOSE_PROFILES': 'unreviewed'}
        with mock.patch.dict(os.environ, settings, clear=True), \
                mock.patch.object(driver.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'{}', b'')) as run:
            driver.docker(['compose', 'build', '--pull', 'keyonly'], capture=True)
            self.assertEqual(run.call_args.args[0][:3], ['docker', '--context', 'desktop-linux'])
            env = run.call_args.kwargs['env']
            controlled = {key: value for key, value in env.items()
                          if key.startswith(('DOCKER_', 'BUILDX_', 'BUILDKIT_', 'COMPOSE_'))}
            self.assertEqual(controlled, {'DOCKER_CONTEXT': 'desktop-linux', 'BUILDX_BUILDER': 'desktop-linux',
                                          'BUILDX_CONFIG': str(Path.home() / '.docker' / 'buildx'),
                                          'COMPOSE_BAKE': 'false'})
            self.assertEqual(env['OPENLXSSH_UBUNTU_IMAGE'], settings['OPENLXSSH_UBUNTU_IMAGE'])
            self.assertEqual(env['LC_ALL'], 'C')
            self.assertEqual(env['NO_COLOR'], '1')

    def test_buildx_038_inspect_native_output_without_format_or_sweep(self):
        driver = module('fixture')
        driver.VERIFIED_CONTEXT = 'desktop-linux'
        driver.VERIFIED_ENDPOINT = 'unix:///Users/static/.docker/run/docker.sock'
        # Non-secret selected-builder stdout shape observed by the main session
        # with Buildx v0.38.1. The log's appended exit=0 is not command stdout.
        native = (b'Name:   desktop-linux\nDriver: docker\n\nNodes:\n'
                  b'Name:             desktop-linux\nEndpoint:         desktop-linux\n'
                  b'Status:           running\nBuildKit version: v0.34.0\n'
                  b'Platforms:        linux/arm64, linux/amd64\nLabels:\n'
                  b' org.mobyproject.buildkit.worker.network: host\nDevices:\n'
                  b' Name:                  docker.com/gpu=webgpu\n'
                  b' Automatically allowed: false\nGC Policy rule#0:\n All: false\n')

        def buildx_038(command, **kwargs):
            if command[:2] != ['buildx', 'inspect']:
                raise AssertionError('must not sweep unrelated builders')
            if '--format' in command:
                # Actual readiness attempt exited 125: unknown flag: --format.
                raise driver.FixtureError('unknown flag: --format (exit 125)')
            self.assertEqual(command, ['buildx', 'inspect', 'desktop-linux', '--timeout', '10s'])
            return native

        with mock.patch.object(driver, 'docker', side_effect=buildx_038) as cli:
            driver.require_local_builder()
            cli.assert_called_once()

    def test_buildx_last_activity_actual_stdout_shape(self):
        driver = module('fixture')
        native = (b'Name:          desktop-linux\nDriver:        docker\n'
                  b'Last Activity: 2026-10-26 14:25:31 +0000 UTC\n\nNodes:\n'
                  b'Name:             desktop-linux\nEndpoint:         desktop-linux\n'
                  b'Status:           running\nBuildKit version: v0.34.0\nPlatforms: linux/arm64\n')
        self.assertEqual(driver.parse_builder_inspect(native),
                         ('desktop-linux', 'docker', 'desktop-linux', 'desktop-linux'))
        for malformed in (native.replace(b'\n\nNodes:', b'\nLast Activity: 2026-10-26 14:25:31 +0000 UTC\nNodes:'),
                          native.replace(b'Last Activity:', b'Unknown:'),
                          native.replace(b'2026-10-26 14:25:31 +0000 UTC', b'unbounded or unexpected'),
                          native.replace(b'Last Activity:', b' Last Activity:'),
                          native.replace(b'Driver:        docker\nLast Activity:', b'Last Activity:')):
            with self.subTest(shape=malformed[:100]), self.assertRaises(driver.FixtureError):
                driver.parse_builder_inspect(malformed)

    def test_builtin_builder_must_match_selected_local_context(self):
        driver = module('fixture')
        for context, socket in (('default', 'unix:///var/run/docker.sock'),
                                ('desktop-linux', 'unix:///Users/static/.docker/run/docker.sock')):
            driver.VERIFIED_CONTEXT, driver.VERIFIED_ENDPOINT = context, socket
            for endpoint in (context, socket):
                native = ('Name: {0}\nDriver: docker\n\nNodes:\nName: {0}\nEndpoint: {1}\n'
                          'Status: running\n').format(context, endpoint).encode()
                with self.subTest(context=context, endpoint=endpoint), \
                        mock.patch.object(driver, 'docker', return_value=native) as cli:
                    driver.require_local_builder()
                    cli.assert_called_once_with(['buildx', 'inspect', context, '--timeout', '10s'], capture=True)
        valid = b'Name: desktop-linux\nDriver: docker\n\nNodes:\nName: desktop-linux\nEndpoint: desktop-linux\n'
        invalid = (valid.replace(b'Driver: docker', b'Driver: remote'),
                   valid.replace(b'Driver: docker', b'Driver: docker-container'),
                   valid.replace(b'Endpoint: desktop-linux', b'Endpoint: default'),
                   valid.replace(b'Endpoint: desktop-linux', b'Endpoint: tcp://forbidden:1234'),
                   valid.replace(b'Name: desktop-linux', b'Name: other', 1),
                   valid.replace(b'Nodes:\nName: desktop-linux', b'Nodes:\nName: other'),
                   valid + b'Name: second\nEndpoint: desktop-linux\n', valid.split(b'Nodes:')[0] + b'Nodes:\n')
        for native in invalid:
            with self.subTest(native=native), mock.patch.object(driver, 'docker', return_value=native):
                with self.assertRaises(driver.FixtureError):
                    driver.require_local_builder()

    def test_builder_inspect_rejects_ambiguous_unbounded_or_malformed_text(self):
        driver = module('fixture')
        valid = b'Name: desktop-linux\nDriver: docker\n\nNodes:\nName: desktop-linux\nEndpoint: desktop-linux\n'
        malformed = (b'', b'{}', b'\xff', b'x' * (64 * 1024 + 1), valid + b'\n' * 513,
                     valid + b'x' * 4097 + b'\n', b'\x1b[31m' + valid, valid + b'\x00',
                     valid.replace(b'Driver: docker', b'Driver: docker\nDriver: docker'),
                     valid.replace(b'Nodes:', b'Endpoint: desktop-linux\nNodes:'),
                     valid + b'Nodes:\nName: desktop-linux\nEndpoint: desktop-linux\n',
                     valid + b'Endpoint: desktop-linux\n', valid + b'Endpoint:\n',
                     valid + b'Driver: docker\n', valid + b'Error: unavailable\n',
                     valid + b' Name: second\n Endpoint: desktop-linux\n',
                     valid + b'Devices:\n Name: second\n Endpoint: desktop-linux\n',
                     valid.replace(b'Nodes:\nName:', b'Nodes:\n Name:'),
                     valid.replace(b'Nodes:\nName: desktop-linux\n', b'Nodes:\n'),
                     valid.replace(b'\nEndpoint: desktop-linux', b'\nStatus: running\nEndpoint: desktop-linux'))
        for native in malformed:
            with self.subTest(native=native[:80]), self.assertRaises((driver.FixtureError, UnicodeError)):
                driver.parse_builder_inspect(native)

    def test_remote_builder_is_rejected_before_build_state_or_compose(self):
        driver = module('fixture')
        with mock.patch.object(sys, 'argv', ['fixture.py', 'build', '--authorized-run']), \
                mock.patch.object(driver, 'image_input', return_value='static-image'), \
                mock.patch.object(driver, 'require_local_engine'), \
                mock.patch.object(driver, 'require_local_builder', side_effect=driver.FixtureError('not local')), \
                mock.patch.object(driver, 'new_state', side_effect=AssertionError('state written')), \
                mock.patch.object(driver, 'compose', side_effect=AssertionError('build attempted')):
            with self.assertRaises(driver.FixtureError):
                driver.main()

    def test_build_uses_verified_builtin_without_compose_child_routing(self):
        driver = module('fixture')
        driver.VERIFIED_CONTEXT = 'desktop-linux'
        state = {'project': 'openlxssh-fixture-abcdef012345',
                 'image': 'docker.io/library/ubuntu:24.04@sha256:' + 'b' * 64}
        with mock.patch.object(sys, 'argv', ['fixture.py', 'build', '--authorized-run']), \
                mock.patch.object(driver, 'image_input', return_value=state['image']), \
                mock.patch.object(driver, 'require_local_engine'), \
                mock.patch.object(driver, 'require_local_builder'), \
                mock.patch.object(driver, 'new_state', return_value=state), \
                mock.patch.object(driver, 'resources', return_value=[]), \
                mock.patch.object(driver, 'docker', return_value=b'') as cli, \
                mock.patch.object(driver, 'verify_image') as verify, \
                mock.patch.object(driver, 'compose', side_effect=AssertionError('Compose child changed builder context')):
            self.assertEqual(driver.main(), 0)
            cli.assert_any_call(['buildx', 'build', '--builder', 'desktop-linux', '--platform', 'linux/arm64',
                                 '--pull', '--load', '--build-arg', 'UBUNTU_IMAGE=' + state['image'],
                                 '--tag', driver.IMAGE, '--file', str(ROOT / 'Dockerfile'), str(ROOT)])
            verify.assert_called_once_with(state, driver.IMAGE)

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

    def sample_export(self, driver):
        # Deliberately invalid key/password content: schema test strings only,
        # not generated credentials, snapshots or usable authentication input.
        return {'password.txt': 'NONSECRET_SCHEMA_VALUE', 'key-passphrase.txt': 'NONSECRET_SCHEMA_VALUE',
                'keys': {name: 'NOT_A_KEY_SCHEMA_VALUE' for name in driver.EXPORT_KEY_NAMES},
                'known_hosts': 'NOT_A_TRUST_RECORD', 'fingerprint': 'NOT_A_FINGERPRINT',
                'packages': 'NONSECRET_PACKAGE_METADATA'}

    def test_private_export_json_exact_schema_and_single_object(self):
        import copy
        driver = module('fixture')
        source = '/run/openlxssh-fixture/export/metadata.json'
        baseline = self.sample_export(driver)
        self.assertEqual(driver.validate_private_json(json.dumps(baseline).encode(), source), baseline)
        bad = [b'', b'{}', b'[]', b'{}{}', b'\xff', b'x'*(driver.EXPORT_LIMIT+1),
               json.dumps(baseline).encode()+b' {}', b'{"keys":{},"keys":{}}']
        for alteration in ('extra', 'missing', 'key-path', 'extra-key', 'type', 'null-byte'):
            data = copy.deepcopy(baseline)
            if alteration == 'extra': data['foreign'] = 'no'
            elif alteration == 'missing': del data['packages']
            elif alteration == 'key-path': data['keys']['../escape'] = data['keys'].pop('id_rsa')
            elif alteration == 'extra-key': data['keys']['unexpected'] = 'no'
            elif alteration == 'type': data['password.txt'] = ['no']
            elif alteration == 'null-byte': data['keys']['id_rsa'] = 'not\0a-key'
            bad.append(json.dumps(data).encode())
        for index, raw in enumerate(bad):
            with self.subTest(case=index), self.assertRaises(driver.FixtureError):
                driver.validate_private_json(raw, source)
        session = 'a'*24
        source = '/run/openlxssh-fixture/export/challenge-'+session+'.json'
        data = {'session': session, 'expires_at': 200, 'scenario': 'multi', 'responses': ['00000000']*3}
        with mock.patch.object(driver.time, 'time', return_value=100):
            self.assertEqual(driver.validate_private_json(json.dumps(data).encode(), source), data)
            for key, value in (('session', 'b'*24), ('expires_at', 99), ('expires_at', float('nan')),
                               ('expires_at', True), ('scenario', 'other'), ('responses', ['00000000']),
                               ('responses', ['not-an-otp']*3)):
                invalid = dict(data, **{key: value})
                with self.subTest(field=key), self.assertRaises(driver.FixtureError):
                    driver.validate_private_json(json.dumps(invalid).encode(), source)

    def test_private_export_pipe_fixed_route_ownership_allowlist_and_no_local_copy(self):
        import relay
        driver = module('fixture')
        driver.VERIFIED_CONTEXT = 'desktop-linux'
        driver.VERIFIED_ENDPOINT = 'unix:///tmp/static-docker.sock'
        state = {'project': 'openlxssh-fixture-abcdef012345'}
        identifier = 'a'*64
        item = {'Id': identifier, 'Config': {'Labels': {'org.openlxssh.fixture': driver.LABEL_VALUE,
                'com.docker.compose.project': state['project'], 'com.docker.compose.service': 'keyonly'}},
                'State': {'Running': True}}
        payload = json.dumps(self.sample_export(driver)).encode()
        with tempfile.TemporaryDirectory(prefix='openlxssh-export-static-') as raw:
            path = Path(raw).resolve()/'never-created.json'
            with mock.patch.object(driver.shutil, 'which', return_value='/usr/bin/true'), \
                    mock.patch.object(relay, '_bounded_stdout', side_effect=[json.dumps([item]).encode(), payload]) as run:
                result = driver.copy_private_json(identifier[:12], '/run/openlxssh-fixture/export/metadata.json', path,
                                                  state=state, service='keyonly')
            self.assertEqual(result, self.sample_export(driver))
            self.assertFalse(path.exists())
            first, second = run.call_args_list
            self.assertEqual(first.args[0], ['/usr/bin/true','--host',driver.VERIFIED_ENDPOINT,'inspect',identifier[:12]])
            self.assertEqual(second.args[0], ['/usr/bin/true','--host',driver.VERIFIED_ENDPOINT,'exec','--user','0:0',
                                             identifier,'/usr/bin/python3','-c',driver.PRIVATE_EXPORT_READER,
                                             '/run/openlxssh-fixture/export/metadata.json'])
            self.assertEqual(first.args[2], second.args[2])
            self.assertEqual(second.kwargs, {'limit': 65536})
            self.assertFalse(any(key.startswith('DOCKER_') for key in second.args[1]))
            for source in ('/etc/shadow', '/run/openlxssh-fixture/export/../metadata.json',
                           '/run/openlxssh-fixture/export/challenge-a.json',
                           '/run/openlxssh-fixture/export/metadata.json\n', 'metadata.json'):
                with self.subTest(source=source), mock.patch.object(relay, '_bounded_stdout', side_effect=AssertionError('unsafe exec')):
                    with self.assertRaises(driver.FixtureError):
                        driver.copy_private_json(identifier, source, path, state=state, service='keyonly')
            for key in ('org.openlxssh.fixture', 'com.docker.compose.project', 'com.docker.compose.service'):
                old = item['Config']['Labels'][key]
                item['Config']['Labels'][key] = 'foreign'
                with self.subTest(label=key), mock.patch.object(driver.shutil, 'which', return_value='/usr/bin/true'), \
                        mock.patch.object(relay, '_bounded_stdout', return_value=json.dumps([item]).encode()) as run:
                    with self.assertRaises(driver.FixtureError):
                        driver.copy_private_json(identifier, '/run/openlxssh-fixture/export/metadata.json', path,
                                                 state=state, service='keyonly')
                    self.assertEqual(run.call_count, 1)
                item['Config']['Labels'][key] = old
            with mock.patch.object(driver.shutil, 'which', return_value='/usr/bin/true'), \
                    mock.patch.object(relay, '_bounded_stdout', side_effect=RuntimeError('NOT_LOGGED_PAYLOAD')), \
                    mock.patch.object(sys, 'stdout', io.StringIO()) as stdout, mock.patch.object(sys, 'stderr', io.StringIO()) as stderr:
                with self.assertRaises(driver.FixtureError) as error:
                    driver.copy_private_json(identifier, '/run/openlxssh-fixture/export/metadata.json', path,
                                             state=state, service='keyonly')
                self.assertNotIn('NOT_LOGGED_PAYLOAD', str(error.exception))
                self.assertEqual((stdout.getvalue(), stderr.getvalue()), ('',''))
                self.assertFalse(path.exists())

    def test_private_export_reader_exact_program_refuses_links_modes_size_and_paths(self):
        driver = module('fixture')
        compile(driver.PRIVATE_EXPORT_READER, '<fixed-export-reader>', 'exec')
        setup = r'''
import os,sys,types
root,code,source,kind=sys.argv[1:]
real_open=os.open
real_fstat=os.fstat
def openfd(name,flags,mode=0o777,dir_fd=None):
    if name=='/run': name=root
    return real_open(name,flags,mode,dir_fd=dir_fd)
os.open=openfd
def fstat(fd):
    info=real_fstat(fd)
    values={name:getattr(info,name) for name in ('st_mode','st_nlink','st_size','st_dev','st_ino','st_mtime_ns','st_ctime_ns')}
    values['st_uid']=10000 if kind=='uid' else 0
    return types.SimpleNamespace(**values)
os.fstat=fstat
sys.argv=['-c',source]
exec(compile(code,'<exact-private-reader>','exec'),{'__name__':'__main__'})
'''
        for kind in ('normal','symlink','parent-symlink','hardlink','mode','uid','oversize','fifo','wrong-path'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='openlxssh-reader-static-') as raw:
                root = Path(raw).resolve()
                parent = root/'openlxssh-fixture'
                parent.mkdir(mode=0o755)
                parent.chmod(0o755)  # fixture bootstrap explicitly sets this
                export = parent/'export'
                export.mkdir(mode=0o700)
                path = export/'metadata.json'
                content = b'{"non_secret_static_metadata":true}'
                if kind == 'fifo': os.mkfifo(path, 0o600)
                elif kind == 'symlink':
                    (root/'outside').write_bytes(content)
                    path.symlink_to(root/'outside')
                else:
                    path.write_bytes(b'x'*65537 if kind=='oversize' else content)
                    path.chmod(0o644 if kind=='mode' else 0o600)
                    if kind=='hardlink': os.link(path, root/'another-link')
                    if kind=='parent-symlink':
                        export.rename(parent/'real-export')
                        export.symlink_to(parent/'real-export', target_is_directory=True)
                source = '/etc/shadow' if kind=='wrong-path' else '/run/openlxssh-fixture/export/metadata.json'
                result = subprocess.run([sys.executable,'-c',setup,str(root),driver.PRIVATE_EXPORT_READER,source,kind],
                                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=2,check=False)
                if kind=='normal': self.assertEqual((result.returncode,result.stdout,result.stderr),(0,content,b''))
                else:
                    self.assertEqual(result.returncode,1)
                    self.assertEqual(result.stdout,b'')
                    self.assertEqual(result.stderr,b'private fixture export refused; contents suppressed\n')

    def test_collect_schema_failure_leaves_no_partial_credential_files(self):
        import relay
        driver = module('fixture')
        driver.VERIFIED_CONTEXT = 'desktop-linux'
        driver.VERIFIED_ENDPOINT = 'unix:///tmp/static-docker.sock'
        state = {'project': 'openlxssh-fixture-abcdef012345','image':'syntax-only'}
        item = {'Id':'a'*64, 'Config':{'Labels':{'org.openlxssh.fixture':driver.LABEL_VALUE,
                'com.docker.compose.project':state['project'],'com.docker.compose.service':'keyonly'}},
                'State':{'Running':True}}
        invalid = self.sample_export(driver)
        invalid['keys']['../escape'] = invalid['keys'].pop('id_rsa')
        with tempfile.TemporaryDirectory(prefix='openlxssh-collect-static-') as raw:
            runtime = Path(raw).resolve()
            for payload in (json.dumps(invalid).encode(), b'{}{}', b'x'*65537):
                with mock.patch.object(driver,'RUNTIME',runtime), \
                        mock.patch.object(driver,'exec_server',return_value='a'*64), \
                        mock.patch.object(driver.shutil,'which',return_value='/usr/bin/true'), \
                        mock.patch.object(relay,'_bounded_stdout',side_effect=[json.dumps([item]).encode(),payload]), \
                        mock.patch.object(driver,'private_write',side_effect=AssertionError('partial secret write')):
                    with self.assertRaises(driver.FixtureError): driver.collect(state,'keyonly')
            self.assertTrue(list(runtime.rglob('credentials-*')))
            self.assertFalse(any(path.is_file() for path in runtime.rglob('*')))

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
        self.assertIn('.logs', (ROOT / '.dockerignore').read_text().splitlines())
        self.assertIn('multiprompt/', (ROOT / '.dockerignore').read_text().splitlines())
        self.assertIn('relay.py', (ROOT / '.dockerignore').read_text().splitlines())
        self.assertIn('test_relay.py', (ROOT / '.dockerignore').read_text().splitlines())
        self.assertIn('.runtime/', (ROOT / '.gitignore').read_text().splitlines())
        self.assertIn('.logs/', (ROOT / '.gitignore').read_text().splitlines())
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
