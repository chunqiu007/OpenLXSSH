#!/usr/bin/env python3
"""Offline child-runner tests. Docker calls are replaced; no engine/image/SSH is touched."""
import ast
import contextlib
import copy
import dataclasses
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def state_for(driver):
    return {'version': 1, 'project': 'openlxssh-mina-012345abcdef', 'label': driver.VALUE,
            'image': driver.IMAGE, 'base': driver.BASE, 'context': 'desktop-linux',
            'endpoint': 'unix:///Users/static/.docker/run/docker.sock', 'source': 'a' * 64}


def runner_for(driver):
    parent = driver.shared_helpers()
    runner = driver.Runner(parent)
    runner.context = 'desktop-linux'
    runner.endpoint = 'unix:///Users/static/.docker/run/docker.sock'
    return runner


def labels_for(driver, state):
    return {driver.LABEL: driver.VALUE, driver.PROJECT_LABEL: state['project'],
            driver.SOURCE_LABEL: state['source'], driver.BASE_LABEL: driver.BASE}


def compose_for(driver, state):
    service = {'build': {'context': str(ROOT), 'dockerfile': 'Dockerfile'}, 'image': driver.IMAGE,
               'platform': 'linux/arm64', 'labels': {driver.LABEL: driver.VALUE}, 'user': '10000:10000',
               'read_only': True, 'privileged': False, 'init': True, 'restart': 'no', 'cap_drop': ['ALL'],
               'security_opt': ['no-new-privileges:true'], 'cpus': 0.5, 'mem_limit': 536870912,
               'memswap_limit': 536870912, 'pids_limit': 128,
               'ulimits': {'nofile': {'soft': 1024, 'hard': 1024}, 'core': {'soft': 0, 'hard': 0}},
               'tmpfs': [key + ':' + value for key, value in driver.TMPFS.items()],
               'networks': {'multiprompt-private': None},
               'ports': [{'mode': 'ingress', 'host_ip': '127.0.0.1', 'target': 2222,
                          'published': '22225', 'protocol': 'tcp'}],
               'logging': {'driver': 'none'}, 'stop_grace_period': '5s',
               'healthcheck': {'test': ['CMD', 'python3', '/opt/multiprompt/control.py', 'health', '--authorized-run'],
                               'interval': '10s', 'timeout': '3s', 'retries': 3, 'start_period': '30s'}}
    return {'name': state['project'], 'services': {'multiprompt': service},
            'networks': {'multiprompt-private': {'name': state['project'] + '_multiprompt-private',
                                               'internal': True, 'labels': {driver.LABEL: driver.VALUE}}}}


def image_for(driver, state):
    return {'Id': 'sha256:' + 'b' * 64, 'Architecture': 'arm64', 'Os': 'linux',
            'RepoTags': [driver.IMAGE], 'Config': {'Labels': labels_for(driver, state)}}


def resources_for(driver, state):
    image_id = 'sha256:' + 'b' * 64
    network_name = state['project'] + '_multiprompt-private'
    network = {'Id': 'd' * 64, 'Name': network_name, 'Driver': 'bridge', 'Internal': True,
               'Labels': labels_for(driver, state), 'Containers': {}, 'Options': {}, 'Attachable': False}
    labels = labels_for(driver, state)
    labels['com.docker.compose.service'] = 'multiprompt'
    container = {'Id': 'c' * 64, 'Name': '/' + state['project'] + '-multiprompt-1', 'Image': image_id,
                 'Config': {'Image': driver.IMAGE, 'User': '10000:10000', 'Labels': labels,
                            'Healthcheck': {'Test': ['CMD', 'python3', '/opt/multiprompt/control.py', 'health', '--authorized-run'],
                                            'Interval': 10000000000, 'Timeout': 3000000000,
                                            'Retries': 3, 'StartPeriod': 30000000000}},
                 'State': {'Running': True, 'Status': 'running'}, 'Mounts': [],
                 'HostConfig': {'ReadonlyRootfs': True, 'Privileged': False, 'Init': True, 'CapDrop': ['ALL'],
                                'NanoCpus': 500000000, 'Memory': 536870912, 'MemorySwap': 536870912,
                                'PidsLimit': 128, 'LogConfig': {'Type': 'none', 'Config': {}},
                                'Tmpfs': driver.TMPFS, 'PortBindings': {'2222/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '22225'}]},
                                'NetworkMode': network_name, 'IpcMode': 'private', 'PidMode': '',
                                'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                                'SecurityOpt': ['no-new-privileges:true'],
                                'Ulimits': [{'Name': 'nofile', 'Soft': 1024, 'Hard': 1024},
                                            {'Name': 'core', 'Soft': 0, 'Hard': 0}]},
                 'NetworkSettings': {'Networks': {network_name: {'NetworkID': network['Id']}},
                                     'Ports': {'2222/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '22225'}]}}}
    return container, network


class ManagedTests(unittest.TestCase):
    def test_default_help_and_unauthorized_are_inert(self):
        driver = module('managed')
        cases = [[], ['--help']] + [[action] for action in driver.ACTIONS]
        for arguments in cases:
            with self.subTest(arguments=arguments), \
                    mock.patch.object(driver, 'shared_helpers', side_effect=AssertionError('parent loaded')), \
                    mock.patch.object(driver, 'static_preflight', side_effect=AssertionError('file read')), \
                    mock.patch.object(driver, 'load_state', side_effect=AssertionError('state read')), \
                    mock.patch.object(driver.subprocess, 'run', side_effect=AssertionError('process started')), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    driver.main(arguments)
                self.assertEqual(raised.exception.code, 0 if arguments == ['--help'] else 2)

    def test_bad_arguments_and_up_without_release_are_inert(self):
        driver = module('managed')
        bad = [['up', '--authorized-run'], ['build', '--authorized-run', '--allow-start'],
               ['scenario', '--authorized-run'], ['scenario', '--authorized-run', '--scenario', 'two', '--delay', '0'],
               ['status', '--authorized-run', '--delay', '8'], ['challenge', '--authorized-run', '--attempt', '../escape'],
               ['stop', '--authorized-run', '--attempt', 'a' * 24]]
        for args in bad:
            with self.subTest(args=args), mock.patch.object(driver, 'shared_helpers', side_effect=AssertionError('loaded')), \
                    mock.patch.object(driver, 'static_preflight', side_effect=AssertionError('file read')), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                driver.main(args)

    def test_overrides_refuse_before_any_helper_or_file_access(self):
        driver = module('managed')
        for key, value in [('DOCKER_HOST', 'ssh://forbidden'), ('DOCKER_CONTEXT', 'company'),
                           ('DOCKER_CONFIG', '/unreviewed'), ('DOCKER_TLS_VERIFY', '1'),
                           ('BUILDX_BUILDER', 'remote'), ('BUILDX_CONFIG', '/unreviewed'),
                           ('BUILDKIT_HOST', 'tcp://forbidden'), ('COMPOSE_FILE', '/other.yaml')]:
            with self.subTest(key=key), mock.patch.dict(os.environ, {key: value}, clear=True), \
                    mock.patch.object(driver, 'shared_helpers', side_effect=AssertionError('loaded')), \
                    mock.patch.object(driver, 'static_preflight', side_effect=AssertionError('file read')), \
                    self.assertRaises(driver.ManagedError):
                driver.main(['build', '--authorized-run'])

    def test_readonly_parent_helpers_and_pinned_cli_environment(self):
        driver = module('managed')
        runner = runner_for(driver)
        with mock.patch.dict(os.environ, {'PATH': '/usr/bin', 'DOCKER_HOST': 'ssh://forbidden',
                                          'BUILDX_BUILDER': 'remote', 'COMPOSE_FILE': '/other'}, clear=True), \
                mock.patch.object(driver.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'[]', b'')) as run:
            runner.docker(['ps', '-a', '-q'])
        self.assertEqual(run.call_args.args[0], ['docker', '--context', 'desktop-linux', 'ps', '-a', '-q'])
        env = run.call_args.kwargs['env']
        self.assertEqual(env['DOCKER_CONTEXT'], 'desktop-linux')
        self.assertEqual(env['BUILDX_BUILDER'], 'desktop-linux')
        self.assertNotIn('DOCKER_HOST', env)
        self.assertNotIn('COMPOSE_FILE', env)
        source = (ROOT / 'managed.py').read_text()
        self.assertNotIn('parent.main(', source)
        self.assertNotIn('parent.compose(', source)
        self.assertNotIn('parent.load_state(', source)
        self.assertNotIn('parent.resources(', source)

    def test_local_engine_context_socket_and_builder_helpers_reject_remote(self):
        driver = module('managed')
        parent = driver.shared_helpers()
        for setting in ({'DOCKER_HOST': 'tcp://127.0.0.1:2375'}, {'DOCKER_CONTEXT': 'remote'}):
            with mock.patch.dict(os.environ, setting, clear=True), \
                    mock.patch.object(parent, 'docker_cli', side_effect=AssertionError('CLI reached')), \
                    self.assertRaises(parent.FixtureError):
                parent.require_local_engine()
        for endpoint in ('ssh://localhost', 'unix://remote/path', 'unix:///tmp/../docker.sock'):
            with self.assertRaises(parent.FixtureError):
                parent.local_endpoint(endpoint)
        parent.VERIFIED_CONTEXT = 'desktop-linux'
        parent.VERIFIED_ENDPOINT = 'unix:///Users/static/.docker/run/docker.sock'
        with mock.patch.object(parent, 'docker', return_value=(b'Name: desktop-linux\nDriver: remote\n\nNodes:\n'
                                                             b'Name: desktop-linux\nEndpoint: desktop-linux\n')), \
                self.assertRaises(parent.FixtureError):
            parent.require_local_builder()

    def test_desktop_readonly_resource_checks(self):
        driver = module('managed')
        settings = {'LicenseTermsVersion': 2, 'Cpus': 2, 'MemoryMiB': 4096, 'DiskSizeMiB': 40960, 'AutoStart': False}
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / 'settings.json'
            with mock.patch.object(driver, 'SETTINGS', path):
                path.write_text(json.dumps(settings))
                driver.desktop_settings()
                for key, value in [('LicenseTermsVersion', 0), ('Cpus', 8), ('MemoryMiB', 8192),
                                   ('DiskSizeMiB', 20480), ('AutoStart', True)]:
                    bad = dict(settings, **{key: value})
                    path.write_text(json.dumps(bad))
                    with self.assertRaises(driver.ManagedError):
                        driver.desktop_settings()
        runner = runner_for(driver)
        info = {'NCPU': 2, 'MemTotal': 4107407360, 'Architecture': 'aarch64', 'OperatingSystem': 'Docker Desktop'}
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(driver, 'desktop_settings'), \
                mock.patch.object(runner.parent, 'require_local_engine', return_value='desktop-linux'), \
                mock.patch.object(runner.parent, 'VERIFIED_ENDPOINT', runner.endpoint), \
                mock.patch.object(runner.parent, 'require_local_builder') as builder, \
                mock.patch.object(runner, 'docker', return_value=json.dumps(info).encode()):
            runner.preflight()
            builder.assert_called_once()
        for key, value in [('NCPU', 8), ('MemTotal', 8 * 1024 ** 3), ('Architecture', 'amd64'),
                           ('OperatingSystem', 'other')]:
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(driver, 'desktop_settings'), \
                    mock.patch.object(runner.parent, 'require_local_engine', return_value='desktop-linux'), \
                    mock.patch.object(runner.parent, 'VERIFIED_ENDPOINT', runner.endpoint), \
                    mock.patch.object(runner.parent, 'require_local_builder') as builder, \
                    mock.patch.object(runner, 'docker', return_value=json.dumps(dict(info, **{key: value})).encode()), \
                    self.assertRaises(driver.ManagedError):
                runner.preflight(build=True)
            builder.assert_not_called()

    def test_private_immutable_state_lock_and_unknown_content(self):
        driver = module('managed')
        exporter = module('private_export')
        runner = runner_for(driver)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve() / '.runtime'
            with mock.patch.object(driver, 'RUNTIME', root), mock.patch.object(exporter, 'ROOT', root), \
                    mock.patch.object(driver, 'source_hash', return_value='a' * 64):
                state = driver.create_state(runner, exporter)
                self.assertEqual(driver.load_state(), state)
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE((root / 'state.json').stat().st_mode), 0o600)
                with driver.operation_lock():
                    with self.assertRaises(driver.ManagedError):
                        with driver.operation_lock():
                            self.fail('second lock acquired')
                self.assertEqual(driver.create_state(runner, exporter), state)
                exporter.write('unknown-content', 'public-marker')
                with self.assertRaises(driver.ManagedError):
                    driver.load_state()
                (root / 'unknown-content').unlink()
                (root / 'state.json').chmod(0o644)
                with self.assertRaises(driver.ManagedError):
                    driver.load_state()
        state = state_for(driver)
        for key, value in [('project', 'openlxssh-fixture-012345abcdef'), ('label', 'env-fixture-a'),
                           ('base', 'ubuntu:latest'), ('image', 'unrelated'), ('extra', 'unknown')]:
            with self.assertRaises(driver.ManagedError):
                driver.validate_state(dict(state, **{key: value}))
        with self.assertRaises(driver.ManagedError):
            runner.bind(dict(state, endpoint='unix:///tmp/other.sock'))

    def test_source_cache_and_log_exclusions(self):
        driver = module('managed')
        driver.static_preflight()
        self.assertRegex(driver.source_hash(), r'^[0-9a-f]{64}$')
        for name in ('.gitignore', '.dockerignore'):
            self.assertIn('.logs', (ROOT / name).read_text())
        for path in ROOT.glob('managed*.py'):
            ast.parse(path.read_text())
        subprocess.run(['/bin/bash', '-n', str(ROOT / 'managed.sh')], check=True)
        self.assertTrue((ROOT / 'managed.sh').stat().st_mode & 0o111)

    def test_resource_ownership_exact_ids_names_and_no_parent_adoption(self):
        driver = module('managed')
        runner = runner_for(driver)
        state = state_for(driver)
        container, network = resources_for(driver, state)
        for kind, original in (('container', container), ('network', network)):
            for changed in (None, 'fixture', 'project', 'name'):
                item = copy.deepcopy(original)
                labels = item['Config']['Labels'] if kind == 'container' else item['Labels']
                if changed == 'fixture': labels[driver.LABEL] = 'env-fixture-a'
                if changed == 'project': labels[driver.PROJECT_LABEL] = 'another-project'
                if changed == 'name': item['Name'] = '/unrelated' if kind == 'container' else 'unrelated'
                with mock.patch.object(runner, 'docker', return_value=(item['Id'] + '\n').encode()), \
                        mock.patch.object(runner, 'inspect', return_value=item):
                    if changed is None:
                        self.assertEqual(runner.resources(state, kind), [item])
                    else:
                        with self.assertRaises(driver.ManagedError): runner.resources(state, kind)
        with mock.patch.object(runner, 'docker', return_value=b'guessed-name\n'), self.assertRaises(driver.ManagedError):
            runner.resources(state, 'container')
        network['Containers'] = {'e' * 64: {}}
        with mock.patch.object(runner, 'resources', side_effect=[[container], [network]]), self.assertRaises(driver.ManagedError):
            runner.owned(state)

    def test_image_requires_both_labels_tag_base_arch_and_record(self):
        driver = module('managed')
        runner = runner_for(driver)
        state = state_for(driver)
        original = image_for(driver, state)
        record = {'version': 1, 'project': state['project'], 'image_id': original['Id'], 'source': state['source']}
        for change in (None, 'project', 'base', 'source', 'arch', 'tag', 'record'):
            item = copy.deepcopy(original)
            saved = dict(record)
            if change == 'project': item['Config']['Labels'][driver.PROJECT_LABEL] = 'other'
            if change == 'base': item['Config']['Labels'][driver.BASE_LABEL] = 'ubuntu:latest'
            if change == 'source': item['Config']['Labels'][driver.SOURCE_LABEL] = 'f' * 64
            if change == 'arch': item['Architecture'] = 'amd64'
            if change == 'tag': item['RepoTags'] = ['unrelated']
            if change == 'record': saved['image_id'] = 'sha256:' + 'f' * 64
            with mock.patch.object(runner, 'inspect', return_value=item), mock.patch.object(driver, 'read_json', return_value=saved):
                if change is None:
                    self.assertEqual(runner.image(state), item)
                else:
                    with self.assertRaises(driver.ManagedError): runner.image(state)

    def test_compose_port_resources_mounts_network_and_extra_fields_fail_closed(self):
        driver = module('managed')
        state = state_for(driver)
        valid = compose_for(driver, state)
        driver.validate_config(valid, state)
        for field, value in [('ports', [{'host_ip': '0.0.0.0', 'target': 2222, 'published': '22225', 'protocol': 'tcp'}]),
                             ('user', '0:0'), ('read_only', False), ('mem_limit', 1073741824),
                             ('cap_add', ['SYS_ADMIN']), ('volumes', ['/host:/fixture']),
                             ('environment', {'SECRET': 'public-test'}), ('networks', {'default': None}),
                             ('logging', {'driver': 'json-file'}), ('security_opt', []), ('cpus', 2)]:
            bad = copy.deepcopy(valid)
            bad['services']['multiprompt'][field] = value
            with self.subTest(field=field), self.assertRaises(driver.ManagedError):
                driver.validate_config(bad, state)
        bad = copy.deepcopy(valid); bad['networks']['multiprompt-private']['internal'] = False
        with self.assertRaises(driver.ManagedError): driver.validate_config(bad, state)

    def test_real_compose5_shape_captured_from_readonly_child_command(self):
        driver = module('managed'); state = state_for(driver)
        data = json.loads((ROOT / 'fixtures/compose5-config.json').read_text())
        service = data['services']['multiprompt']
        self.assertNotIn('privileged', service)
        self.assertEqual(service['mem_limit'], '536870912')
        self.assertEqual(service['memswap_limit'], '536870912')
        self.assertEqual(data['networks']['multiprompt-private']['ipam'], {})
        self.assertIsNone(service['command'])
        self.assertIsNone(service['entrypoint'])
        self.assertEqual(service['ulimits']['core'], {})
        # Only machine-specific project/context strings are substituted for a portable offline replay.
        data['name'] = state['project']
        data['networks']['multiprompt-private']['name'] = state['project'] + '_multiprompt-private'
        service['build']['context'] = str(ROOT)
        for memory in (536870912, '536870912'):
            for swap in (536870912, '536870912'):
                with self.subTest(memory=memory, swap=swap):
                    service['mem_limit'] = memory
                    service['memswap_limit'] = swap
                    driver.validate_config(data, state)

    def test_compose5_normalization_rejects_missing_noncanonical_and_nonempty_values(self):
        driver = module('managed'); state = state_for(driver)
        valid = compose_for(driver, state)
        for field in ('mem_limit', 'memswap_limit'):
            for value in (None, True, 536870912.0, '0536870912', '+536870912', '-536870912',
                          '536870912.0', ' 536870912', '536870912\n', '5368709120',
                          '5.36870912e8', '512m', '', '9' * 64, [], {}):
                bad = copy.deepcopy(valid); bad['services']['multiprompt'][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(driver.ManagedError):
                    driver.validate_config(bad, state)
            bad = copy.deepcopy(valid); del bad['services']['multiprompt'][field]
            with self.assertRaises(driver.ManagedError): driver.validate_config(bad, state)
        for value in (True, 0, None, 'false'):
            bad = copy.deepcopy(valid); bad['services']['multiprompt']['privileged'] = value
            with self.subTest(privileged=value), self.assertRaises(driver.ManagedError):
                driver.validate_config(bad, state)
        for value in (None, [], '', {'config': []}, {'driver': 'default'}):
            bad = copy.deepcopy(valid); bad['networks']['multiprompt-private']['ipam'] = value
            with self.subTest(ipam=value), self.assertRaises(driver.ManagedError):
                driver.validate_config(bad, state)
        for field in ('command', 'entrypoint'):
            for value in ('', [], ['unreviewed'], False, {}):
                bad = copy.deepcopy(valid); bad['services']['multiprompt'][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(driver.ManagedError):
                    driver.validate_config(bad, state)
        for value in (None, False, 0, [], '', {'soft': -1, 'hard': -1}, {'soft': 0}, {'hard': 0},
                      {'extra': 0}, {'soft': 0, 'hard': 0, 'extra': 0},
                      {'soft': False, 'hard': 0}, {'soft': 0.0, 'hard': 0}):
            bad = copy.deepcopy(valid); bad['services']['multiprompt']['ulimits']['core'] = value
            with self.subTest(core=value), self.assertRaises(driver.ManagedError):
                driver.validate_config(bad, state)
        required = set(valid['services']['multiprompt']) - {'privileged'}
        for field in sorted(required):
            bad = copy.deepcopy(valid); del bad['services']['multiprompt'][field]
            with self.subTest(missing=field), self.assertRaises(driver.ManagedError):
                driver.validate_config(bad, state)
        for field in ('core', 'nofile'):
            bad = copy.deepcopy(valid); del bad['services']['multiprompt']['ulimits'][field]
            with self.subTest(missing_ulimit=field), self.assertRaises(driver.ManagedError):
                driver.validate_config(bad, state)
        for field in ('name', 'services', 'networks'):
            bad = copy.deepcopy(valid); del bad[field]
            with self.subTest(missing_root=field), self.assertRaises(driver.ManagedError):
                driver.validate_config(bad, state)
        for field in ('name', 'internal', 'labels'):
            bad = copy.deepcopy(valid); del bad['networks']['multiprompt-private'][field]
            with self.subTest(missing_network=field), self.assertRaises(driver.ManagedError):
                driver.validate_config(bad, state)

    def test_up_fails_before_metadata_until_reviewed_relay_integration(self):
        driver = module('managed')
        # The former unconditional guard is now a fail-closed reviewed-library gate.
        for action in ('up', 'relay'):
            with self.subTest(action=action), \
                    mock.patch.object(driver, 'require_reviewed_relay', side_effect=driver.ManagedError('reviewed relay missing')), \
                    mock.patch.object(driver, 'static_preflight', side_effect=AssertionError('file read')), \
                    mock.patch.object(driver, 'shared_helpers', side_effect=AssertionError('helper loaded')), \
                    mock.patch.object(driver, 'load_state', side_effect=AssertionError('state read')), \
                    mock.patch.object(driver, 'create_state', side_effect=AssertionError('state created')), \
                    mock.patch.object(driver, 'operation_lock', side_effect=AssertionError('lock created')), \
                    mock.patch.object(driver.os, 'umask', side_effect=AssertionError('umask changed')), \
                    mock.patch.object(driver.subprocess, 'run', side_effect=AssertionError('process reached')), \
                    mock.patch('builtins.open', side_effect=AssertionError('file opened')), \
                    mock.patch.object(driver.os, 'open', side_effect=AssertionError('descriptor opened')), \
                    self.assertRaisesRegex(driver.ManagedError, 'relay'):
                driver.main([action, '--authorized-run', '--allow-start', '--relay-mode'])

    def test_internal_empty_port_metadata_is_not_host_reachability(self):
        driver = module('managed'); state = state_for(driver)
        container, network = resources_for(driver, state)
        container['NetworkSettings']['Ports'] = {'2222/tcp': []}
        with self.assertRaises(driver.ManagedError):
            driver.validate_container(container, network, container['Image'], state)

    def test_relay_cli_release_duration_and_fixed_targets_are_inert(self):
        driver = module('managed')
        release = ['relay', '--authorized-run', '--allow-start', '--relay-mode']
        bad = [['relay', '--authorized-run'], ['relay', '--authorized-run', '--allow-start'],
               ['up', '--authorized-run', '--allow-start'], ['build', '--authorized-run', '--relay-mode'],
               ['status', '--authorized-run', '--max-duration', '5']]
        bad += [release + ['--max-duration', value] for value in ('0', '-1', '1801', 'nan', '1.5')]
        bad += [release + [flag, value] for flag, value in (('--host', '0.0.0.0'), ('--port', '22221'),
                                                          ('--container-id', 'c' * 64), ('--endpoint', 'ssh://other'))]
        for args in bad:
            with self.subTest(args=args), \
                    mock.patch.object(driver, 'require_reviewed_relay', side_effect=AssertionError('library loaded')), \
                    mock.patch.object(driver, 'shared_helpers', side_effect=AssertionError('helper loaded')), \
                    mock.patch.object(driver.subprocess, 'run', side_effect=AssertionError('process reached')), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                driver.main(args)

    def test_relay_import_fixed_source_signature_and_context_restore(self):
        driver = module('managed')
        prior_path = list(sys.path)
        prior_fixture = sys.modules.get('fixture')
        library = driver.require_reviewed_relay()
        self.assertEqual(tuple(library.FrozenDockerTarget.__dataclass_fields__), driver.RELAY_FIELDS)
        self.assertEqual(sys.path, prior_path)
        self.assertIs(sys.modules.get('fixture'), prior_fixture)
        with mock.patch.object(library, 'serve', side_effect=AssertionError('real serve reached')), \
                mock.patch.object(driver.subprocess, 'run', side_effect=AssertionError('Docker reached')):
            parent = driver.shared_helpers()
            with mock.patch.dict(sys.modules, {}, clear=False):
                sys.modules.pop('fixture', None)
                with driver.shared_relay_imports(parent):
                    self.assertIs(sys.modules['fixture'], parent)
                    self.assertEqual(sys.path[0], str(ROOT.parent))
                    self.assertEqual(library.FrozenDockerTarget.__module__, 'openlxssh_child_shared_relay')
                self.assertNotIn('fixture', sys.modules)
        with tempfile.TemporaryDirectory() as raw:
            fake_root = Path(raw).resolve() / 'child'
            fake_root.mkdir()
            path = fake_root.parent / 'relay.py'
            with mock.patch.object(driver, 'ROOT', fake_root):
                with self.assertRaises(driver.ManagedError): driver.require_reviewed_relay()
                path.write_text('class FrozenDockerTarget: pass\ndef serve(targets): pass\n')
                with self.assertRaises(driver.ManagedError): driver.require_reviewed_relay()
                path.unlink(); path.symlink_to(ROOT.parent / 'relay.py')
                with self.assertRaises(driver.ManagedError): driver.require_reviewed_relay()
        self.assertEqual(sys.path, prior_path)
        self.assertIs(sys.modules.get('fixture'), prior_fixture)

    def test_relay_serve_signature_only_allows_reviewed_optional_deadline(self):
        driver = module('managed')
        def original(targets, max_duration=1800): pass
        def compatible(targets, max_duration=1800, *, startup_deadline=None): pass
        self.assertTrue(driver.valid_relay_serve(original))
        self.assertTrue(driver.valid_relay_serve(compatible))
        invalid = ('def serve(targets, max_duration=1800, **kwargs): pass',
                   'def serve(targets, max_duration=1800, *args): pass',
                   'def serve(targets, max_duration=1800, *, startup_deadline): pass',
                   'def serve(targets, max_duration=1800, startup_deadline=None): pass',
                   'def serve(targets, max_duration=1800, *, startup_deadline=8): pass',
                   'def serve(targets, max_duration=1800, *, other=None): pass',
                   'def serve(targets, max_duration): pass',
                   'def serve(targets, max_duration=90000): pass',
                   'def serve(targets=None, max_duration=1800): pass')
        for source in invalid:
            namespace = {}; exec(source, namespace)
            with self.subTest(source=source): self.assertFalse(driver.valid_relay_serve(namespace['serve']))

    def test_relay_mode_accepts_only_exact_empty_effective_port_and_rejects_lan(self):
        driver = module('managed'); state = state_for(driver)
        container, network = resources_for(driver, state)
        container['NetworkSettings']['Ports'] = {'2222/tcp': []}
        driver.validate_container(container, network, container['Image'], state, relay_mode=True)
        for ports in (None, {}, {'2222/tcp': None}, {'2222/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '22225'}]},
                      {'2222/tcp': [], '80/tcp': []}, {'2222/tcp': [{'HostIp': '::1', 'HostPort': '22225'}]}):
            bad = copy.deepcopy(container); bad['NetworkSettings']['Ports'] = ports
            with self.subTest(ports=ports), self.assertRaises(driver.ManagedError):
                driver.validate_container(bad, network, container['Image'], state, relay_mode=True)
        for host in ('0.0.0.0', '::', '127.0.0.2', '192.0.2.1'):
            bad = copy.deepcopy(container)
            bad['HostConfig']['PortBindings']['2222/tcp'][0]['HostIp'] = host
            with self.subTest(requested_host=host), self.assertRaises(driver.ManagedError):
                driver.validate_container(bad, network, container['Image'], state, relay_mode=True)
        with self.assertRaises(driver.ManagedError):
            driver.validate_container(container, network, container['Image'], state, relay_mode=1)

    def test_relay_target_freezes_only_healthy_exact_owned_child_resources(self):
        driver = module('managed'); runner = runner_for(driver); state = state_for(driver)
        runner.relay_mode = True
        library = driver.require_reviewed_relay()
        image = image_for(driver, state)
        container, network = resources_for(driver, state)
        container['State']['Health'] = {'Status': 'healthy'}
        container['NetworkSettings']['Ports'] = {'2222/tcp': []}
        network['Containers'] = {container['Id']: {}}
        with mock.patch.object(driver, 'source_hash', return_value=state['source']), \
                mock.patch.object(runner, 'image', return_value=image), \
                mock.patch.object(runner, 'owned', return_value=([container], [network])), \
                mock.patch.object(driver.subprocess, 'run', side_effect=AssertionError('Docker reached')):
            target = driver.relay_target(runner, state, library)
            self.assertEqual(dataclasses.asdict(target), dict(context=runner.context, endpoint=runner.endpoint,
                             container_id=container['Id'], image_id=image['Id'], project=state['project'],
                             service='multiprompt', fixture_label_value=driver.VALUE, network_id=network['Id'], host_port=22225))
            with self.assertRaises(dataclasses.FrozenInstanceError): target.host_port = 22221
            for changed in ('health', 'running', 'attachment', 'port'):
                bad = copy.deepcopy(container); bad_network = copy.deepcopy(network)
                if changed == 'health': bad['State']['Health']['Status'] = 'unhealthy'
                if changed == 'running': bad['State']['Running'] = False
                if changed == 'attachment': bad_network['Containers'] = {}
                if changed == 'port': bad['HostConfig']['PortBindings']['2222/tcp'][0]['HostPort'] = '22221'
                with self.subTest(changed=changed), \
                        mock.patch.object(runner, 'owned', return_value=([bad], [bad_network])), \
                        self.assertRaises(driver.ManagedError):
                    driver.relay_target(runner, state, library)

    def test_relay_rejects_changed_frozen_target_before_serve(self):
        driver = module('managed'); runner = runner_for(driver); state = state_for(driver)
        library = driver.require_reviewed_relay()
        with driver.shared_relay_imports(runner.parent):
            target = library.FrozenDockerTarget(state['context'], state['endpoint'], 'c' * 64,
                                               'sha256:' + 'b' * 64, state['project'], 'multiprompt', driver.VALUE, 'd' * 64, 22225)
        with driver.shared_relay_imports(runner.parent):
            changed = dataclasses.replace(target, container_id='e' * 64)
        with mock.patch.object(driver, 'operation_lock', return_value=contextlib.nullcontext()), \
                mock.patch.object(driver, 'load_state', return_value=state), \
                mock.patch.object(driver, 'relay_target', return_value=changed), \
                mock.patch.object(library, 'serve', side_effect=AssertionError('changed target served')), \
                self.assertRaisesRegex(driver.ManagedError, 'changed'):
            driver.serve_relay(runner, state, library, target, 30)

    def test_relay_cancellation_restores_imports_and_releases_child_operation_lock(self):
        driver = module('managed'); exporter = module('private_export'); runner = runner_for(driver)
        runner.relay_mode = True; library = driver.require_reviewed_relay()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve() / '.runtime'
            with mock.patch.object(driver, 'RUNTIME', root), mock.patch.object(exporter, 'ROOT', root), \
                    mock.patch.object(driver, 'source_hash', return_value='a' * 64):
                state = driver.create_state(runner, exporter)
                with driver.shared_relay_imports(runner.parent):
                    target = library.FrozenDockerTarget(state['context'], state['endpoint'], 'c' * 64,
                                                       'sha256:' + 'b' * 64, state['project'], 'multiprompt', driver.VALUE, 'd' * 64, 22225)
                prior_path = list(sys.path); prior_fixture = sys.modules.get('fixture')
                cleaned = []
                def cancelled(targets, max_duration=1800):
                    self.assertEqual(targets, (target,)); self.assertEqual(max_duration, 30)
                    with driver.operation_lock(): pass  # foreground serve must not monopolize child operations
                    try: raise KeyboardInterrupt()
                    finally: cleaned.append('shared-library-finally')
                with mock.patch.object(driver, 'relay_target', return_value=target), \
                        mock.patch.object(library, 'serve', side_effect=cancelled), \
                        contextlib.redirect_stdout(io.StringIO()), self.assertRaises(KeyboardInterrupt):
                    driver.serve_relay(runner, state, library, target, 30)
                self.assertEqual(cleaned, ['shared-library-finally'])
                self.assertEqual(sys.path, prior_path); self.assertIs(sys.modules.get('fixture'), prior_fixture)
                with driver.operation_lock(): pass

    def test_relay_refuses_foreign_root_state_module_and_endpoint(self):
        driver = module('managed'); runner = runner_for(driver); state = state_for(driver)
        runner.relay_mode = True; library = driver.require_reviewed_relay()
        for bad in (dict(state, project='openlxssh-fixture-012345abcdef'), dict(state, label='env-fixture-a'),
                    dict(state, endpoint='unix:///tmp/foreign.sock')):
            with mock.patch.object(runner, 'container_resources', side_effect=AssertionError('resource access')), \
                    self.assertRaises(driver.ManagedError):
                driver.relay_target(runner, bad, library)
        with mock.patch.dict(sys.modules, {'fixture': types.SimpleNamespace(__file__='/foreign/fixture.py')}), \
                self.assertRaisesRegex(driver.ManagedError, 'foreign'):
            with driver.shared_relay_imports(runner.parent): self.fail('foreign fixture adopted')
        parent = types.SimpleNamespace(__file__='/foreign/fixture.py')
        with self.assertRaises(driver.ManagedError):
            with driver.shared_relay_imports(parent): self.fail('foreign parent adopted')

    def test_relay_main_delegates_finite_duration_after_lock_and_never_reports_reachability(self):
        driver = module('managed'); state = state_for(driver); runner = mock.Mock(); library = mock.Mock()
        runner.context = state['context']; runner.endpoint = state['endpoint']
        lock_held = []
        @contextlib.contextmanager
        def locked():
            lock_held.append(True)
            try: yield
            finally: lock_held.pop()
        def served(*args):
            self.assertFalse(lock_held)
        output = io.StringIO()
        with mock.patch.object(driver, 'require_reviewed_relay', return_value=library), \
                mock.patch.object(driver, 'static_preflight'), mock.patch.object(driver, 'shared_helpers'), \
                mock.patch.object(driver, 'Runner', return_value=runner), \
                mock.patch.object(driver, 'load_state', return_value=state), \
                mock.patch.object(driver, 'relay_target', return_value='nonsecret-frozen-target'), \
                mock.patch.object(driver, 'operation_lock', side_effect=locked), \
                mock.patch.object(driver, 'serve_relay', side_effect=served) as serve, \
                contextlib.redirect_stdout(output):
            driver.main(['relay', '--authorized-run', '--allow-start', '--relay-mode', '--max-duration', '30'])
        serve.assert_called_once_with(runner, state, library, 'nonsecret-frozen-target', 30)
        self.assertTrue(runner.relay_mode)
        self.assertNotIn('reachability verified', output.getvalue())

    def test_actual_network_accepts_only_known_docker_ip_family_defaults(self):
        driver = module('managed'); state = state_for(driver)
        container, network = resources_for(driver, state)
        defaults = {'com.docker.network.enable_ipv4': 'true', 'com.docker.network.enable_ipv6': 'false'}
        for options in (None, {}, defaults):
            valid = copy.deepcopy(network); valid['Options'] = options
            with self.subTest(options=options):
                driver.validate_container(container, valid, container['Image'], state)
        for options in (False, [], '', {'com.docker.network.enable_ipv4': 'true'},
                        dict(defaults, **{'com.docker.network.enable_ipv6': 'true'}),
                        dict(defaults, **{'com.docker.network.enable_ipv4': False}),
                        dict(defaults, **{'com.docker.network.bridge.enable_ip_masquerade': 'true'})):
            invalid = copy.deepcopy(network); invalid['Options'] = options
            with self.subTest(options=options), self.assertRaises(driver.ManagedError):
                driver.validate_container(container, invalid, container['Image'], state)

    def test_actual_container_confinement_rejects_lan_mount_extra_network(self):
        driver = module('managed'); state = state_for(driver)
        container, network = resources_for(driver, state)
        driver.validate_container(container, network, container['Image'], state)
        for field, value in [('Privileged', True), ('ReadonlyRootfs', False), ('Memory', 1073741824),
                             ('Binds', ['/host:/fixture']), ('CapAdd', ['SYS_ADMIN']), ('NetworkMode', 'host'),
                             ('LogConfig', {'Type': 'json-file', 'Config': {}}),
                             ('PortBindings', {'2222/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '22225'}]})]:
            bad = copy.deepcopy(container); bad['HostConfig'][field] = value
            with self.subTest(field=field), self.assertRaises(driver.ManagedError):
                driver.validate_container(bad, network, container['Image'], state)
        bad = copy.deepcopy(container); bad['NetworkSettings']['Networks']['other'] = {}
        with self.assertRaises(driver.ManagedError): driver.validate_container(bad, network, container['Image'], state)
        bad = copy.deepcopy(container); bad['Mounts'] = [{'Type': 'bind', 'Source': '/host'}]
        with self.assertRaises(driver.ManagedError): driver.validate_container(bad, network, container['Image'], state)
        nofile = {'Name': 'nofile', 'Soft': 1024, 'Hard': 1024}
        core = {'Name': 'core', 'Soft': 0, 'Hard': 0}
        invalid_ulimits = [None, {}, [], [nofile], [nofile, {}], [nofile, None],
                           [nofile, dict(core, Soft=None)], [nofile, dict(core, Hard=None)],
                           [nofile, dict(core, Soft=False)], [nofile, dict(core, Hard=0.0)],
                           [nofile, dict(core, Soft=-1)], [nofile, dict(core, Hard='0')],
                           [nofile, dict(core, extra=0)], [dict(nofile, Soft=1024.0), core]]
        for ulimits in invalid_ulimits:
            bad = copy.deepcopy(container); bad['HostConfig']['Ulimits'] = ulimits
            with self.subTest(actual_ulimits=ulimits), self.assertRaises(driver.ManagedError):
                driver.validate_container(bad, network, container['Image'], state)
        bad = copy.deepcopy(container); del bad['HostConfig']['Ulimits']
        with self.assertRaises(driver.ManagedError):
            driver.validate_container(bad, network, container['Image'], state)

    def test_build_exact_direct_builtin_and_never_overwrites(self):
        driver = module('managed'); runner = runner_for(driver); state = state_for(driver)
        exporter = mock.Mock(); image = image_for(driver, state)
        with mock.patch.object(runner, 'owned', return_value=([], [])), \
                mock.patch.object(runner, 'image', return_value=image), \
                mock.patch.object(runner, 'docker', return_value=b'') as docker, \
                mock.patch.object(driver.Path, 'exists', return_value=False), contextlib.redirect_stdout(io.StringIO()):
            driver.build(runner, state, exporter)
        expected = ['buildx', 'build', '--builder', 'desktop-linux', '--platform', 'linux/arm64', '--pull', '--load',
                    '--label', driver.PROJECT_LABEL + '=' + state['project'],
                    '--label', driver.SOURCE_LABEL + '=' + state['source'], '--tag', driver.IMAGE,
                    '--file', str(ROOT / 'Dockerfile'), str(ROOT)]
        docker.assert_any_call(expected, log=True)
        self.assertEqual(exporter.write.call_args.args[0], 'build.json')
        with mock.patch.object(runner, 'owned', return_value=([], [])), \
                mock.patch.object(runner, 'image', return_value=image), \
                mock.patch.object(runner, 'docker', return_value=(image['Id'] + '\n').encode()) as docker, \
                self.assertRaises(driver.ManagedError):
            driver.build(runner, state, exporter)
        self.assertEqual(len(docker.call_args_list), 1)

    def test_up_requires_rendered_config_before_no_build_and_post_inspection(self):
        driver = module('managed'); state = state_for(driver); runner = mock.Mock()
        runner.context = state['context']; runner.endpoint = state['endpoint']
        runner.owned.return_value = ([], [])
        # Only a mocked shared library is released in this offline ordering test.
        with mock.patch.object(driver, 'require_reviewed_relay'), \
                mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(driver, 'static_preflight'), \
                mock.patch.object(driver, 'shared_helpers'), mock.patch.object(driver, 'Runner', return_value=runner), \
                mock.patch.object(driver, 'load_state', return_value=state), \
                mock.patch.object(driver, 'operation_lock', return_value=contextlib.nullcontext()), \
                contextlib.redirect_stdout(io.StringIO()):
            driver.main(['up', '--authorized-run', '--allow-start', '--relay-mode'])
        methods = [call[0] for call in runner.mock_calls]
        self.assertLess(methods.index('configured'), methods.index('compose'))
        self.assertLess(methods.index('compose'), methods.index('container'))
        runner.compose.assert_called_once_with(state, ['up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '120'])

    def test_status_refuses_unknown_secret_fields(self):
        driver = module('managed')
        valid = {'generated': 1, 'response_callbacks': 0, 'zero_response_callbacks': 0,
                 'ignored_late_results': 0, 'sessions': 1, 'scheduler_queue': 1, 'outcomes': {},
                 'pending': [{'attempt': 'a' * 24, 'scenario': 'two', 'prompt_count': 2,
                              'responded': False, 'expires_at': 1001}]}
        driver.validate_status(valid)
        bad = copy.deepcopy(valid); bad['pending'][0]['responses'] = ['public-test']
        with self.assertRaises(driver.ManagedError): driver.validate_status(bad)
        with self.assertRaises(driver.ManagedError): driver.validate_status(dict(valid, password='public-test'))

    def test_runtime_recognized_names_do_not_adopt_unknown_contents_or_symlinks(self):
        driver = module('managed'); exporter = module('private_export'); runner = runner_for(driver)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve() / '.runtime'
            with mock.patch.object(driver, 'RUNTIME', root), mock.patch.object(exporter, 'ROOT', root), \
                    mock.patch.object(driver, 'source_hash', return_value='a' * 64):
                driver.create_state(runner, exporter)
                name = 'challenge-' + 'a' * 24 + '.json'
                exporter.write(name, json.dumps({'unexpected': 'public-marker'}))
                with self.assertRaises(driver.ManagedError): driver.load_state()
                (root / name).unlink()
                (root / name).symlink_to(root / 'state.json')
                with self.assertRaises(driver.ManagedError): driver.load_state()
                (root / name).unlink()
                exporter.write('operation.lock', 'not-an-empty-lock')
                with self.assertRaises(driver.ManagedError): driver.load_state()

    def test_build_preflight_failure_cannot_create_state_or_reach_builder(self):
        driver = module('managed')
        runner = mock.Mock()
        runner.preflight.side_effect = driver.ManagedError('public bad preflight')
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(driver, 'static_preflight'), \
                mock.patch.object(driver, 'shared_helpers'), mock.patch.object(driver, 'Runner', return_value=runner), \
                mock.patch.object(driver, 'create_state', side_effect=AssertionError('state created')), \
                self.assertRaises(driver.ManagedError):
            driver.main(['build', '--authorized-run'])

    def test_management_copy_uses_exact_id_and_never_extracts_paths(self):
        driver = module('managed'); runner = runner_for(driver); state = state_for(driver)
        container, _ = resources_for(driver, state)
        public = {'known_hosts': '[127.0.0.1]:22225 ssh-rsa QUJD\n', 'fingerprint': 'SHA256:QUJD'}
        for name, kind in [('trust.json', tarfile.REGTYPE), ('../outside', tarfile.REGTYPE), ('trust.json', tarfile.SYMTYPE)]:
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w') as archive:
                entry = tarfile.TarInfo(name); entry.type = kind; entry.mode = 0o600
                content = json.dumps(public).encode()
                if kind == tarfile.REGTYPE:
                    entry.size = len(content); archive.addfile(entry, io.BytesIO(content))
                else:
                    entry.linkname = '/unrelated'; archive.addfile(entry)
            with mock.patch.object(runner, 'container', return_value=container), \
                    mock.patch.object(runner, 'export_tar', return_value=buffer.getvalue()) as exported:
                if name == 'trust.json' and kind == tarfile.REGTYPE:
                    self.assertEqual(runner.copy_json(state, '/run/openlxssh-multiprompt/trust.json'), public)
                    exported.assert_called_once_with(container['Id'], '/run/openlxssh-multiprompt', 'trust.json')
                else:
                    with self.assertRaises(driver.ManagedError): runner.copy_json(state, '/run/openlxssh-multiprompt/trust.json')

    def test_private_tmpfs_export_fixed_argv_bounds_and_owned_child_reap(self):
        driver = module('managed'); runner = runner_for(driver)
        for ending in ('complete', 'oversize', 'nonzero', 'timeout', 'cancelled'):
            read_fd, write_fd = os.pipe()
            stream = os.fdopen(read_fd, 'rb', buffering=0)
            process = mock.Mock(stdout=stream)
            process.poll.return_value = None
            process.wait.return_value = 1 if ending == 'nonzero' else 0
            selector = mock.MagicMock()
            selector.__enter__.return_value = selector
            selector.select.return_value = [(None, None)]
            ticks = [0, 16] if ending == 'timeout' else [0, 0, 0, 0, 0, 0, 0, 0]
            chunks = [b'public-archive-bytes', b'']
            if ending == 'oversize': chunks = [b'x' * 65536, b'x']
            if ending == 'cancelled': chunks = KeyboardInterrupt()
            try:
                with self.subTest(ending=ending), \
                        mock.patch.object(driver.subprocess, 'Popen', return_value=process) as spawned, \
                        mock.patch.object(driver.selectors, 'DefaultSelector', return_value=selector), \
                        mock.patch.object(driver.os, 'read', side_effect=chunks), \
                        mock.patch.object(driver.time, 'monotonic', side_effect=ticks):
                    if ending == 'complete':
                        self.assertEqual(runner.export_tar('c' * 64, '/run/openlxssh-multiprompt', 'trust.json'), b'public-archive-bytes')
                    else:
                        with self.assertRaises(KeyboardInterrupt if ending == 'cancelled' else driver.ManagedError):
                            runner.export_tar('c' * 64, '/run/openlxssh-multiprompt', 'trust.json')
                self.assertEqual(spawned.call_args.args[0], ['docker', '--host', runner.endpoint, 'exec', '--user',
                                 '10000:10000', 'c' * 64, '/usr/bin/tar', '-C', '/run/openlxssh-multiprompt',
                                 '-cf', '-', '--', 'trust.json'])
                self.assertNotIn('DOCKER_CONTEXT', spawned.call_args.kwargs['env'])
                self.assertEqual(spawned.call_args.kwargs['stderr'], subprocess.DEVNULL)
                self.assertTrue(stream.closed)
                process.terminate.assert_called_once()
                process.wait.assert_called()
            finally:
                stream.close(); os.close(write_fd)
        with mock.patch.object(driver.subprocess, 'Popen', side_effect=AssertionError('arbitrary export')):
            for directory, name in (('/tmp', 'trust.json'), ('/run/openlxssh-multiprompt', '../trust.json'),
                                    ('/run/openlxssh-multiprompt/attempts', 'unreviewed.json')):
                with self.assertRaises(driver.ManagedError): runner.export_tar('c' * 64, directory, name)

    def test_management_export_refuses_unreviewed_paths_and_secret_schema(self):
        driver = module('managed'); runner = runner_for(driver); state = state_for(driver)
        with mock.patch.object(runner, 'container', side_effect=AssertionError('unreviewed path used')):
            for source in ('/tmp/trust.json', '/run/openlxssh-multiprompt/../trust.json',
                           '/run/openlxssh-multiprompt/attempts/not-an-attempt.json'):
                with self.assertRaises(driver.ManagedError): runner.copy_json(state, source)
        container, _ = resources_for(driver, state)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            content = b'{"unexpected":"public-marker"}'
            entry = tarfile.TarInfo('trust.json'); entry.mode = 0o600; entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))
        with mock.patch.object(runner, 'container', return_value=container), \
                mock.patch.object(runner, 'export_tar', return_value=buffer.getvalue()), self.assertRaises(driver.ManagedError):
            runner.copy_json(state, '/run/openlxssh-multiprompt/trust.json')

    def test_remove_uses_only_owned_exact_ids_without_image_delete_or_prune(self):
        driver = module('managed'); runner = runner_for(driver); state = state_for(driver)
        container, network = resources_for(driver, state)
        with mock.patch.object(runner, 'image'), mock.patch.object(runner, 'owned', return_value=([container], [network])), \
                mock.patch.object(runner, 'inspect', side_effect=[container, network]), \
                mock.patch.object(runner, 'docker', return_value=b'') as docker, \
                mock.patch.object(driver, 'cleanup_exports'), contextlib.redirect_stdout(io.StringIO()):
            driver.remove(runner, state)
        self.assertEqual([call.args[0] for call in docker.call_args_list], [
            ['stop', '--time', '5', container['Id']], ['rm', container['Id']], ['network', 'rm', network['Id']]])
        self.assertNotIn('prune', (ROOT / 'managed.py').read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
