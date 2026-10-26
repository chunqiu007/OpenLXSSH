#!/usr/bin/env python3
"""Offline boundary checks only: no Docker, Java, network, credentials or SSH."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def private_export_root():
    """Isolated public synthetic metadata only; never a runtime challenge/credential."""
    export = load('private_export')
    with tempfile.TemporaryDirectory() as directory:
        with mock.patch.object(export, 'ROOT', Path(directory).resolve() / '.runtime'):
            export.prepare()
            yield export


def public_challenge():
    return {'attempt': 'a' * 24, 'expires_at': 1001,
            'responses': ['0000000000', '1111111111'], 'echo': [False, True]}


class StaticTests(unittest.TestCase):
    def test_python_syntax_and_no_docker_or_java_execution(self):
        for path in ROOT.glob('*.py'):
            ast.parse(path.read_text(), filename=str(path))
        for name in ('control', 'private_export', 'fetch_inputs'):
            tree = ast.parse((ROOT / (name + '.py')).read_text())
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    imports = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module]
                    self.assertNotIn('subprocess', imports)

    def test_lock_and_download_trust_boundaries(self):
        fetch = load('fetch_inputs')
        lock = fetch.lock_data()
        self.assertEqual(lock['mina_version'], '2.20.0')
        self.assertEqual(lock['mina_commit'], '2221febd396cd3daafdfbf2ff982c6d0eb69a203')
        self.assertEqual(lock['slf4j_version'], '1.7.36')
        runtime = {i['file'] for i in lock['artifacts'] if i['kind'] == 'runtime'}
        self.assertEqual(runtime, {'sshd-core-2.20.0.jar', 'sshd-common-2.20.0.jar',
                                  'slf4j-api-1.7.36.jar', 'jcl-over-slf4j-1.7.36.jar',
                                  'slf4j-nop-1.7.36.jar'})
        with self.assertRaises(ValueError):
            fetch.verify(b'public tamper sample', lock['artifacts'][0])
        request = fetch.urllib.request.Request('https://repo.maven.apache.org/example')
        with self.assertRaises(ValueError):
            fetch.SameHostRedirect().redirect_request(request, None, 302, '', {}, 'https://example.com/other')
        with self.assertRaises(ValueError):
            fetch.SameHostRedirect().redirect_request(request, None, 302, '', {}, 'http://repo.maven.apache.org/other')
        docker = (ROOT / 'Dockerfile').read_text()
        for line in docker.splitlines():
            if line.startswith('FROM '):
                self.assertEqual(line.split()[1], lock['ubuntu_image'])
        self.assertIn('-proc:none --release 21 -Xlint:all', docker)
        self.assertIn('fetch_inputs.py --authorized-download', docker)
        self.assertIn('USER 10000:10000', docker)
        self.assertIn('slf4j-nop-1.7.36.jar', docker)
        self.assertNotIn('mvn ', docker)
        self.assertNotIn('curl ', docker)

    def test_compose_confinement_via_system_ruby(self):
        # Parse YAML, not a mock of Docker output. Docker/Compose are never called.
        result = subprocess.run(['ruby', '-ryaml', '-rjson', '-e',
                                 'puts JSON.generate(YAML.load_file(ARGV[0]))',
                                 str(ROOT / 'compose.contract.yaml')], capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        self.assertEqual(set(data['services']), {'multiprompt'})
        service = data['services']['multiprompt']
        self.assertEqual(service['ports'], ['127.0.0.1:22225:2222'])
        self.assertEqual(service['user'], '10000:10000')
        self.assertTrue(service['read_only'])
        self.assertFalse(service['privileged'])
        self.assertEqual(service['cap_drop'], ['ALL'])
        self.assertNotIn('cap_add', service)
        self.assertEqual(service['security_opt'], ['no-new-privileges:true'])
        self.assertEqual(service['cpus'], 0.5)
        self.assertEqual(service['mem_limit'], '512m')
        self.assertEqual(service['memswap_limit'], '512m')
        self.assertEqual(service['pids_limit'], 128)
        self.assertEqual(service['logging'], {'driver': 'none'})
        self.assertEqual(service['networks'], ['multiprompt-private'])
        self.assertEqual(service['ulimits']['core'], {'soft': 0, 'hard': 0})
        self.assertNotIn('volumes', service)
        self.assertNotIn('network_mode', service)
        self.assertNotIn('pid', service)
        self.assertNotIn('environment', service)
        self.assertTrue(data['networks']['multiprompt-private']['internal'])
        for value in service['tmpfs']:
            self.assertIn('noexec', value)
            self.assertIn('nosuid', value)
            self.assertIn('nodev', value)
        self.assertIn('mode=0700,uid=10000,gid=10000', service['tmpfs'][0])

    def test_public_api_two_and_actual_zero_source_paths(self):
        source = (ROOT / 'src/org/openlxssh/fixture/FixtureServer.java').read_text()
        challenge = source.split('static InteractiveChallenge challengeFor(', 1)[1].split('private String[] policy', 1)[0]
        self.assertIn('new InteractiveChallenge()', challenge)
        self.assertIn('if (scenario.equals("two"))', challenge)
        self.assertEqual(challenge.count('challenge.addPrompt('), 2)
        self.assertIn('"Test response A: ", false', challenge)
        self.assertIn('"Unclassified test response B: ", true', challenge)
        self.assertNotIn('return null', challenge)
        self.assertIn('return challenge;', challenge)
        self.assertIn('attempt.async = new AsyncAuthException()', source)
        self.assertIn('throw attempt.async;', source)
        self.assertIn('result.setAuthed(approved);', source)
        self.assertIn('result.setAuthed(false);', source)
        self.assertNotIn('Thread.sleep', source)
        self.assertNotIn('extends UserAuthKeyboardInteractive', source)
        for forbidden in ('SSH_MSG_', 'writePacket(', 'createBuffer(', 'ProcessBuilder(',
                          'Runtime.getRuntime().exec(', 'getResponses()', 'System.out.print'):
            self.assertNotIn(forbidden, source)
        self.assertIn('MAX_PENDING = 8', source)
        self.assertIn('MAX_ATTEMPTS = 3', source)
        self.assertIn('MAX_SESSIONS = 8', source)
        self.assertIn('TTL_SECONDS = 75', source)
        self.assertIn('AUTH_SECONDS = 90', source)
        self.assertIn('new ScheduledThreadPoolExecutor(2', source)
        self.assertIn('setRemoveOnCancelPolicy(true)', source)
        self.assertIn('pending.get(session) != attempt', source)
        self.assertIn('session.isClosing()', source)
        self.assertIn('attempt.expiry.cancel(false)', source)
        self.assertIn('attempt.decision.cancel(false)', source)
        self.assertIn("Arrays.fill(answer, '\\0')", source)
        closed = source.split('void sessionClosed(Session session)', 1)[1].split('@Override', 1)[0]
        self.assertIn('finishQuietlyLocked', closed)
        self.assertIn('"session-closed"', closed)
        self.assertIn('sessions.remove(session)', closed)
        status = source.split('private void statusLocked()', 1)[1].split('@Override', 1)[0]
        self.assertNotIn('answers[', status)
        self.assertNotIn('responses', status)

    def test_refusal_before_container_or_file_side_effects(self):
        control = load('control')
        for argv in (['control.py', 'health'],
                     ['control.py', 'scenario', '--authorized-run'],
                     ['control.py', 'scenario', '--authorized-run', '--scenario', 'two', '--delay', '61'],
                     ['control.py', 'check-challenge', '--authorized-run', '--attempt', '../escape']):
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(control, 'check_root') as root_check:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    control.main()
                root_check.assert_not_called()
        fetch = load('fetch_inputs')
        with mock.patch.object(sys, 'argv', ['fetch_inputs.py']), mock.patch.object(fetch, 'lock_data') as lock:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                fetch.main()
            lock.assert_not_called()

    def test_private_export_permissions_symlink_and_expiry(self):
        export = load('private_export')
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(export, 'ROOT', Path(directory).resolve() / '.runtime'):
                export.prepare()
                self.assertEqual(stat.S_IMODE(export.ROOT.stat().st_mode), 0o700)
                target = export.write('nonsecret-metadata', 'public-test-marker')
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
                with self.assertRaises(FileExistsError):
                    export.write('nonsecret-metadata', 'no overwrite')
                target.unlink()
                data = {'attempt': 'a' * 24, 'expires_at': time.time() - 1,
                        'responses': ['0000000000', '1111111111'], 'echo': [False, True]}
                with self.assertRaises(ValueError):
                    export.retain_challenge(data, 'a' * 24)
                self.assertFalse(any(export.ROOT.iterdir()))
                export.ROOT.rmdir()
                export.ROOT.symlink_to(Path(directory))
                with self.assertRaises(ValueError):
                    export.prepare()

    def test_private_export_cleans_path_output_errors(self):
        for stage in ('write', 'flush'):
            for failure in (BrokenPipeError('public stdout failure'), KeyboardInterrupt()):
                with self.subTest(stage=stage, failure=type(failure).__name__), private_export_root() as export:
                    data = public_challenge()
                    target = export.ROOT / ('challenge-' + data['attempt'] + '.json')

                    class FailingOutput(io.StringIO):
                        def write(self, value):
                            if stage == 'write':
                                raise failure
                            return super().write(value)
                        def flush(self):
                            if stage == 'flush':
                                raise failure
                            return super().flush()

                    with mock.patch.object(export.time, 'time', return_value=1000), \
                            contextlib.redirect_stdout(FailingOutput()), self.assertRaises(type(failure)):
                        export.retain_challenge(data, data['attempt'])
                    self.assertFalse(target.exists(), 'output error must not retain a created challenge')

    def test_private_export_cleans_deadline_calculation_errors(self):
        for failure in (OSError('public monotonic failure'), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), private_export_root() as export:
                data = public_challenge()
                target = export.ROOT / ('challenge-' + data['attempt'] + '.json')
                with mock.patch.object(export.time, 'time', return_value=1000), \
                        mock.patch.object(export.time, 'monotonic', side_effect=failure), \
                        contextlib.redirect_stdout(io.StringIO()), self.assertRaises(type(failure)):
                    export.retain_challenge(data, data['attempt'])
                self.assertFalse(target.exists(), 'deadline error must not retain a created challenge')

    def test_private_export_ttl_and_ctrl_c_cleanup(self):
        with private_export_root() as export:
            data = public_challenge()
            target = export.ROOT / ('challenge-' + data['attempt'] + '.json')
            output = io.StringIO()
            with mock.patch.object(export.time, 'time', return_value=1000), \
                    mock.patch.object(export.time, 'monotonic', side_effect=[10, 10, 10, 12]), \
                    mock.patch.object(export.time, 'sleep') as sleep, contextlib.redirect_stdout(output):
                export.retain_challenge(data, data['attempt'])
            sleep.assert_called_once_with(0.25)
            self.assertEqual(output.getvalue(), str(target) + '\n')
            self.assertFalse(target.exists())
        with private_export_root() as export:
            data = public_challenge()
            target = export.ROOT / ('challenge-' + data['attempt'] + '.json')
            with mock.patch.object(export.time, 'time', return_value=1000), \
                    mock.patch.object(export.time, 'monotonic', return_value=10), \
                    mock.patch.object(export.time, 'sleep', side_effect=KeyboardInterrupt()), \
                    contextlib.redirect_stdout(io.StringIO()), self.assertRaises(KeyboardInterrupt):
                export.retain_challenge(data, data['attempt'])
            self.assertFalse(target.exists())

    def test_private_export_removes_its_partial_writes(self):
        for failure in (OSError('public partial write failure'), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__), private_export_root() as export:
                target = export.ROOT / 'nonsecret-partial'
                real_fdopen = os.fdopen

                class PartialStream:
                    def __init__(self, stream):
                        self.stream = stream
                    def __enter__(self):
                        return self
                    def __exit__(self, *error):
                        self.stream.close()
                    def write(self, value):
                        self.stream.write(value[:6])
                        self.stream.flush()
                        raise failure

                def partial_fdopen(fd, mode, **kwargs):
                    return PartialStream(real_fdopen(fd, mode, **kwargs))

                with mock.patch.object(export.os, 'fdopen', side_effect=partial_fdopen), \
                        self.assertRaises(type(failure)):
                    export.write('nonsecret-partial', 'public-synthetic-marker')
                self.assertFalse(target.exists(), 'failed writes must remove their own partial file')

    def test_private_export_cleans_stream_setup_and_close_errors(self):
        for stage in ('setup', 'close'):
            for failure in (OSError('public stream failure'), KeyboardInterrupt()):
                with self.subTest(stage=stage, failure=type(failure).__name__), private_export_root() as export:
                    target = export.ROOT / 'nonsecret-stream'
                    real_fdopen = os.fdopen
                    descriptors = []

                    class CloseFailureStream:
                        def __init__(self, stream):
                            self.stream = stream
                        def __enter__(self):
                            return self
                        def __exit__(self, *error):
                            self.stream.close()
                            raise failure
                        def write(self, value):
                            return self.stream.write(value)

                    def failing_fdopen(fd, mode, **kwargs):
                        descriptors.append(fd)
                        if stage == 'setup':
                            raise failure
                        return CloseFailureStream(real_fdopen(fd, mode, **kwargs))

                    with mock.patch.object(export.os, 'fdopen', side_effect=failing_fdopen), \
                            self.assertRaises(type(failure)):
                        export.write('nonsecret-stream', 'public-synthetic-marker')
                    self.assertFalse(target.exists(), 'stream errors must clean a created file')
                    for fd in descriptors:
                        with self.assertRaises(OSError):
                            os.fstat(fd)

    def test_private_export_preserves_existing_and_replacement_files(self):
        with private_export_root() as export:
            data = public_challenge()
            name = 'challenge-' + data['attempt'] + '.json'
            target = export.write(name, 'preexisting-public-marker')
            original = target.stat()
            with mock.patch.object(export.time, 'time', return_value=1000), \
                    self.assertRaises(FileExistsError):
                export.retain_challenge(data, data['attempt'])
            self.assertEqual(target.read_text(), 'preexisting-public-marker')
            self.assertEqual(target.stat().st_ino, original.st_ino)
        for kind in ('regular', 'symlink'):
            with self.subTest(replacement=kind), private_export_root() as export:
                data = public_challenge()
                target = export.ROOT / ('challenge-' + data['attempt'] + '.json')
                saved = export.ROOT / 'moved-public-original'
                unrelated = export.write('unrelated-public-file', 'unrelated-public-marker')

                def replace_during_output(*args, **kwargs):
                    target.rename(saved)
                    if kind == 'regular':
                        target.write_text('replacement-public-marker')
                        target.chmod(0o600)
                    else:
                        target.symlink_to(unrelated)
                    raise BrokenPipeError('public stdout failure after replacement')

                with mock.patch.object(export.time, 'time', return_value=1000), \
                        mock.patch.object(export, 'print', side_effect=replace_during_output, create=True), \
                        self.assertRaises(BrokenPipeError):
                    export.retain_challenge(data, data['attempt'])
                self.assertTrue(target.exists(), 'cleanup must preserve a replacement inode/symlink')
                self.assertEqual(unrelated.read_text(), 'unrelated-public-marker')
                self.assertTrue(saved.exists())
                if kind == 'regular':
                    self.assertEqual(target.read_text(), 'replacement-public-marker')
                else:
                    self.assertTrue(target.is_symlink())

    def test_private_export_partial_write_preserves_replacement_inode(self):
        with private_export_root() as export:
            target = export.ROOT / 'nonsecret-partial'
            saved = export.ROOT / 'moved-public-original'
            real_fdopen = os.fdopen

            class ReplacingStream:
                def __init__(self, stream):
                    self.stream = stream
                def __enter__(self):
                    return self
                def __exit__(self, *error):
                    self.stream.close()
                def write(self, value):
                    self.stream.write('public-partial')
                    self.stream.flush()
                    target.rename(saved)
                    target.write_text('replacement-public-marker')
                    target.chmod(0o600)
                    raise OSError('public partial failure after replacement')

            def replacing_fdopen(fd, mode, **kwargs):
                return ReplacingStream(real_fdopen(fd, mode, **kwargs))

            with mock.patch.object(export.os, 'fdopen', side_effect=replacing_fdopen), \
                    self.assertRaises(OSError):
                export.write('nonsecret-partial', 'public-synthetic-marker')
            self.assertEqual(target.read_text(), 'replacement-public-marker')
            self.assertTrue(saved.exists())

    def test_private_export_ttl_cleanup_preserves_replacement_inode(self):
        for kind in ('regular', 'symlink'):
            with self.subTest(replacement=kind), private_export_root() as export:
                data = public_challenge()
                target = export.ROOT / ('challenge-' + data['attempt'] + '.json')
                saved = export.ROOT / 'moved-public-original'
                unrelated = export.write('unrelated-public-file', 'unrelated-public-marker')

                def replace_during_wait(delay):
                    target.rename(saved)
                    if kind == 'regular':
                        target.write_text('replacement-public-marker')
                        target.chmod(0o600)
                    else:
                        target.symlink_to(unrelated)

                with mock.patch.object(export.time, 'time', return_value=1000), \
                        mock.patch.object(export.time, 'monotonic', side_effect=[10, 10, 10, 12]), \
                        mock.patch.object(export.time, 'sleep', side_effect=replace_during_wait), \
                        contextlib.redirect_stdout(io.StringIO()):
                    export.retain_challenge(data, data['attempt'])
                self.assertTrue(target.exists(), 'TTL cleanup must preserve a replacement inode/symlink')
                self.assertTrue(saved.exists())
                self.assertEqual(unrelated.read_text(), 'unrelated-public-marker')
                if kind == 'regular':
                    self.assertEqual(target.read_text(), 'replacement-public-marker')
                else:
                    self.assertTrue(target.is_symlink())

    def test_no_secret_or_cache_in_build_context(self):
        for name in ('.gitignore', '.dockerignore'):
            text = (ROOT / name).read_text()
            self.assertIn('.runtime', text)
            self.assertIn('.cache', text)
        self.assertFalse((ROOT / '.runtime').exists())
        self.assertTrue((ROOT / 'licenses/MINA-LICENSE.txt').is_file())
        self.assertTrue((ROOT / 'licenses/MINA-NOTICE.txt').is_file())
        self.assertTrue((ROOT / 'licenses/slf4j-api-1.7.36-source-notices.txt').is_file())

    def test_cached_official_source_matches_wire_path_if_available(self):
        archive = ROOT / '.cache/apache-sshd-2.20.0-src.tar.gz'
        if not archive.exists():
            self.skipTest('source cache absent; use authorized-download then verify-cache separately')
        lock = load('fetch_inputs').lock_data()
        item = next(i for i in lock['artifacts'] if i['file'] == archive.name)
        self.assertEqual(hashlib.sha512(archive.read_bytes()).hexdigest(), item['sha512'])
        with tarfile.open(archive) as stream:
            prefix = 'apache-sshd-2.20.0/sshd-core/src/main/java/org/apache/sshd/server/auth/keyboard/'
            auth = stream.extractfile(prefix + 'UserAuthKeyboardInteractive.java').read().decode()
            challenge = stream.extractfile(prefix + 'InteractiveChallenge.java').read().decode()
        initial = auth.split('protected Boolean doInitialAuth(', 1)[1].split('protected Boolean doValidateAuthResponse', 1)[0]
        self.assertIn('if (challenge == null)', initial)
        self.assertIn('return false;', initial)
        self.assertEqual(initial.count('session.writePacket(buffer)'), 1)
        self.assertIn('challenge.append(buffer);', initial)
        self.assertIn('numberOfPrompts = challenge.getPrompts().size();', initial)
        self.assertIn('buffer.putUInt(numEntries);', challenge)
        self.assertIn('e.append(buffer);', challenge)
        response = auth.split('protected Boolean doValidateAuthResponse(', 1)[1]
        self.assertIn('if (num != numberOfPrompts)', response)
        self.assertIn('Collections.emptyList()', response)
        self.assertIn('auth.authenticate(session, username, responses)', response)


if __name__ == '__main__':
    unittest.main(verbosity=2)
