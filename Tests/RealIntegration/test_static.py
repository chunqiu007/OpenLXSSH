#!/usr/bin/env python3
"""Offline source/wrapper boundaries, never a live integration assertion."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location('host_build', HERE / 'build_host.py')
host_build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host_build)


class StaticTests(unittest.TestCase):
    def test_help_validate_never_open_inputs_query_signers_or_spawn(self):
        with mock.patch.object(Path, 'read_bytes', side_effect=AssertionError('fileIO')), \
             mock.patch.object(Path, 'mkdir', side_effect=AssertionError('write')), \
             mock.patch.object(host_build.subprocess, 'run', side_effect=AssertionError('spawn')):
            self.assertEqual(host_build.main(['validate']), 0)
            self.assertEqual(host_build.main(['help']), 0)

    def test_consumer_only_calls_public_production_entrypoints(self):
        body = (HERE / 'Consumer/ProductionConsumer.swift').read_text()
        self.assertIn('session = DirectSSHSession(trustStore:', body)
        self.assertIn('try session.connect(configuration)', body)
        self.assertIn('LibSSH2FileService.connect(configuration:', body)
        self.assertIn('SystemHostKeyScanner(timeoutSeconds: Contract.hostKeyScanSeconds)', body)
        self.assertIn('connectionTimeout: TimeInterval(Contract.connectionSeconds)', body)
        self.assertIn('operationTimeout: Contract.operationSeconds', body)
        self.assertIn('seconds: Contract.caseSeconds, maximumTicks: 600', body)
        self.assertIn('seconds: Contract.drainSeconds, maximumTicks: 240', body)
        watchdog = body.split('let watchdog = Task { @MainActor in', 1)[1].split('defer { watchdog.cancel() }', 1)[0]
        self.assertIn('for _ in 0..<600 {', watchdog)
        self.assertIn('Task.sleep(for: .milliseconds(50))', watchdog)
        self.assertIn('if stop.requested { token.cancel(); return }', watchdog)
        self.assertIn('\n            token.cancel()\n', watchdog)
        main = (HERE / 'Consumer/Main.swift').read_text()
        self.assertIn('connectTimeout: Contract.connectionSeconds,', main)
        self.assertIn('trustStore: trust', body)
        self.assertIn('await service.close()', body)
        self.assertIn('session.state != .closed || session.ownedProcessID != nil', body)
        self.assertNotIn('session.startProbe(', body)
        self.assertNotIn('probeStore:', body)
        self.assertNotIn('session.terminal.text', body)
        self.assertNotIn('savedPassword:', body)
        self.assertNotIn('sendInput(', body)
        self.assertIn('throw SmokeError.negativeUnclassified', body)

    def test_no_fixture_or_product_edits_in_build_recipe(self):
        source = (HERE / 'build_host.py').read_text()
        self.assertNotIn("'docker'", source)
        self.assertNotIn('swift package', source)
        self.assertIn("'OPENLXSSH_TRANSPORT_HOST_PROBE': '1'", source)
        self.assertEqual(host_build.TARGET, 'arm64-apple-macosx15.0')
        self.assertNotEqual(host_build.APP_ID, host_build.HELPER_ID)
        self.assertIn("'--timestamp=none'", source)
        self.assertIn("'--options', 'runtime'", source)
        self.assertIn("('helper', app / 'Contents/Helpers/openlxssh-askpass', HELPER_ID), ('app', app, APP_ID)", source)

    def test_native_manifest_and_sources_are_snapshotted_before_link(self):
        source = (HERE / 'build_host.py').read_text()
        self.assertIn("sha(NATIVE / relative, native_export=True) != expected", source)
        self.assertIn('builder.unchanged()', source)
        self.assertIn("minimum(output, 2)", source)
        self.assertIn("consumer-public-api-symbols", source)
        self.assertIn("'liveExecuted': False", source)

    def test_output_metadata_has_no_secret_surface(self):
        body = (HERE / 'Sources/RealIntegrationCore/Limits.swift').read_text().split('public struct SmokeReport:', 1)[1]
        for name in ('password:', 'privateKey:', 'prompt:', 'terminal:', 'credentialDirectory:', 'hostKeyLine:'):
            self.assertNotIn(name, body)

    def test_auth_only_uses_typed_public_callback_and_strict_outcome(self):
        body = (HERE / 'Consumer/MinaConsumer.swift').read_text()
        self.assertIn('LibSSH2FileService.connect(configuration:', body)
        self.assertIn('authentication: [.keyboardInteractive', body)
        self.assertIn('challenge.prompts.map { $0.bytes }', body)
        self.assertIn('challenge.prompts.map { $0.echo }', body)
        self.assertIn('await service.close()', body)
        self.assertIn('try after.requireExactDelta(from: before', body)
        self.assertIn('owner.closeReplies()', body)
        self.assertIn('try await owner.drain()', body)
        for forbidden in ('startProbe(', 'probeStore:', 'savedPassword:', 'sendInput(', 'terminal.text', 'error.description'):
            self.assertNotIn(forbidden, body)
        policy = (HERE / 'Sources/RealIntegrationCore/MinaPolicy.swift').read_text()
        self.assertIn('kind == "transport", operation == "sftp-init", code == -21', policy)
        self.assertIn('kind == "authentication", operation == "authenticate", code == nil', policy)
        report = policy.split('public struct MinaReport:', 1)[1]
        for forbidden in ('responses:', 'name:', 'instruction:', 'prompt:', 'password:', 'privateKey:'):
            self.assertNotIn(forbidden, report)
        self.assertIn('sftpSuccess = false', report)
        self.assertIn('fileAcceptance = false', report)

    def test_auth_only_tool_owner_keeps_responses_in_private_memory_pipe(self):
        body = (HERE / 'Consumer/MinaManagement.swift').read_text()
        self.assertIn('ap_tool(executable', body)
        self.assertIn('cancellation, seconds, 0,', body)
        self.assertIn('seconds <= MinaContract.managementSeconds', body)
        self.assertIn('bytes.resetBytes', body)
        self.assertIn('"--host", contract.endpoint', body)
        for forbidden in ('Process()', '/bin/sh', 'print(', 'writeExclusive', 'savedPassword', 'Keychain'):
            self.assertNotIn(forbidden, body)

    def test_async_wait_preserves_precise_cancel_and_post_due_checks(self):
        body = (HERE / 'Consumer/MinaConsumer.swift').read_text()
        self.assertIn('ProcessInfo.processInfo.systemUptime >= start + MinaContract.caseSeconds', body)
        self.assertIn('current.requireRespondedCancellation(attempt: attempt, before: before)', body)
        self.assertIn('try owner.cancelExpectedWait()', body)
        self.assertIn('try await cancelTask.value', body)
        self.assertIn('pendingAt + MinaContract.providerDelaySeconds', body)
        self.assertIn('try late.requireExactDelta(from: before, testCase: .cancelWait)', body)
        self.assertIn('try timing.requireExpected(input.contract.testCase)', body)
        policy = (HERE / 'Sources/RealIntegrationCore/MinaPolicy.swift').read_text()
        self.assertIn('kind == "cancelled", operation == "authenticate", code == -10001', policy)
        self.assertIn('backendAt - replyAt >= MinaContract.providerDelaySeconds', policy)
        self.assertIn('cancelled < replyAt + MinaContract.providerDelaySeconds', policy)
        self.assertNotIn('case timeout', (HERE / 'Sources/RealIntegrationCore/MinaContract.swift').read_text().split('public enum MinaCase:', 1)[1].split('// Separate syntax', 1)[0])

    def test_exact_management_reader_private_file_refusals_without_docker(self):
        source = (HERE / 'Sources/RealIntegrationCore/MinaManagementPolicy.swift').read_text()
        script = source.split('public static let reader = #"""\n', 1)[1].split('\n"""#', 1)[0]
        ast.parse(script)
        with tempfile.TemporaryDirectory(prefix='mina-reader-', dir=HERE / '.build') as temporary:
            root = Path(temporary)
            runtime = root / 'run/openlxssh-multiprompt'
            attempts = runtime / 'attempts'
            attempts.mkdir(parents=True, mode=0o700)
            runtime.chmod(0o700)
            token = '0123456789abcdef01234567'
            target = attempts / (token + '.json')
            wrapper = '''import os,sys
real_open=os.open
real_fstat=os.fstat
synthetic_run=sys.argv[3]
class Metadata:
    def __init__(self,value): self.value=value
    def __getattr__(self,name):
        if name in ('st_uid','st_gid'): return 10000
        return getattr(self.value,name)
def substitute(path,flags,*args,**kwargs):
    if path=='/run': path=synthetic_run
    return real_open(path,flags,*args,**kwargs)
os.getuid=lambda:10000
os.getgid=lambda:10000
os.open=substitute
os.fstat=lambda fd:Metadata(real_fstat(fd))
program=SCRIPT
sys.argv=['reader',sys.argv[1],sys.argv[2]]
exec(compile(program,'fixed-reader','exec'))
'''.replace('SCRIPT', repr(script))
            def invoke(mode='responses', attempt=token):
                return subprocess.run([sys.executable, '-B', '-c', wrapper, mode, attempt, str(root / 'run')],
                                      cwd=HERE, stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
            def write_object(value):
                descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(descriptor, 'w') as stream:
                    json.dump(value, stream)
            import time
            value = {'attempt': token, 'expires_at': int(time.time()) + 60,
                     'responses': ['0123456789', '9876543210'], 'echo': [False, True]}
            write_object(value)
            good = invoke()
            self.assertEqual(good.returncode, 0)
            self.assertEqual(json.loads(good.stdout), value)
            target.chmod(0o644)
            refused = invoke()
            self.assertNotEqual(refused.returncode, 0); self.assertEqual(refused.stdout, b'')
            target.chmod(0o600)
            hard = attempts / 'hard'
            os.link(target, hard)
            refused = invoke()
            self.assertNotEqual(refused.returncode, 0); self.assertEqual(refused.stdout, b'')
            hard.unlink(); target.unlink()
            public = root / 'public-synthetic'
            public.write_text('{}'); public.chmod(0o600)
            target.symlink_to(public)
            refused = invoke()
            self.assertNotEqual(refused.returncode, 0); self.assertEqual(refused.stdout, b'')
            target.unlink(); os.mkfifo(target, 0o600)
            refused = invoke()
            self.assertNotEqual(refused.returncode, 0); self.assertEqual(refused.stdout, b'')
            target.unlink()
            for change in ({'attempt': 'f' * 24}, {'expires_at': 1}, {'echo': [0, 1]}, {'responses': ['short']}, {'extra': 1}):
                bad = dict(value); bad.update(change); write_object(bad)
                refused = invoke()
                self.assertNotEqual(refused.returncode, 0); self.assertEqual(refused.stdout, b'')
                target.unlink()
            refused = invoke(attempt='../status')
            self.assertNotEqual(refused.returncode, 0); self.assertEqual(refused.stdout, b'')
            status = {'generated': 1, 'response_callbacks': 1, 'zero_response_callbacks': 0,
                      'ignored_late_results': 0, 'sessions': 0, 'scheduler_queue': 0,
                      'pending': [], 'outcomes': {'accepted': 1}}
            status_path = runtime / 'status.json'
            status_path.write_text(json.dumps(status)); status_path.chmod(0o600)
            good = invoke(mode='status', attempt='none')
            self.assertEqual(good.returncode, 0); self.assertEqual(json.loads(good.stdout), status)
            policy_script = source.split('public static let policyReader = #"""\n', 1)[1].split('\n"""#', 1)[0]
            ast.parse(policy_script)
            policy_wrapper = wrapper.replace(repr(script), repr(policy_script)).replace("sys.argv=['reader',sys.argv[1],sys.argv[2]]", "sys.argv=['reader']")
            policy_file = runtime / 'scenario'
            def read_policy():
                return subprocess.run([sys.executable, '-B', '-c', policy_wrapper, 'unused', 'none', str(root / 'run')],
                                      cwd=HERE, stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
            for scenario in ('approval', 'reject', 'cancel'):
                policy_file.write_text(scenario + ' 8\n'); policy_file.chmod(0o600)
                policy_result = read_policy()
                self.assertEqual(policy_result.returncode, 0)
                self.assertEqual(json.loads(policy_result.stdout), {'scenario': scenario, 'delay': 8})
            policy_file.write_text('cancel 60\n')
            refused = read_policy()
            self.assertNotEqual(refused.returncode, 0); self.assertEqual(refused.stdout, b'')
            policy_file.write_text('cancel 8\n'); policy_file.chmod(0o644)
            refused = read_policy()
            self.assertNotEqual(refused.returncode, 0); self.assertEqual(refused.stdout, b'')
            policy_file.unlink(); policy_file.symlink_to(public)
            refused = read_policy()
            self.assertNotEqual(refused.returncode, 0); self.assertEqual(refused.stdout, b'')
    def test_openssh_four_flow_is_public_outer_only_and_no_saved_or_terminal_input(self):
        body = (HERE / 'Consumer/OpenSSHConsumer.swift').read_text()
        self.assertIn('session = DirectSSHSession(trustStore:', body)
        self.assertIn('try session.connect(configuration)', body)
        self.assertIn('try self.session.respond(.manual', body)
        self.assertIn('request.session == token.sessionID, request.generation == token.generation', body)
        self.assertIn('report.connectedEvents == 1', body)
        self.assertIn('session.state != .closed || session.ownedProcessID != nil || handler != nil', body)
        self.assertIn('observed-request-cancelled-not-auth-pass', body)
        for forbidden in ('startProbe(', 'probeStore:', 'savedPassword:', 'session.terminal.text', 'sendInput(', 'error.description'):
            self.assertNotIn(forbidden, body)
        management = (HERE / 'Consumer/OpenSSHManagement.swift').read_text()
        self.assertIn('ap_tool(executable', management)
        self.assertIn('seconds, 0, buffer.baseAddress', management)
        for forbidden in ('Process()', '/bin/sh', 'print(', 'writeExclusive', 'Keychain'):
            self.assertNotIn(forbidden, management)
        report = (HERE / 'Sources/RealIntegrationCore/OpenSSHPolicy.swift').read_text().split('public struct OpenSSHReport:', 1)[1]
        for forbidden in ('prompt:', 'answer:', 'password:', 'passphrase:', 'response:', 'nonce:'):
            self.assertNotIn(forbidden, report)

    def test_root_private_reader_current_index_and_permissions_without_docker(self):
        source = (HERE / 'Sources/RealIntegrationCore/OpenSSHManagementPolicy.swift').read_text()
        script = source.split('public static let reader = #"""\n', 1)[1].split('\n"""#', 1)[0]
        ast.parse(script)
        with tempfile.TemporaryDirectory(prefix='root-auth-reader-', dir=HERE / '.build') as folder:
            root = Path(folder)
            runtime = root / 'run/openlxssh-fixture'
            sessions = runtime / 'sessions'
            sessions.mkdir(parents=True, mode=0o700); runtime.chmod(0o755)
            session = '0123456789abcdef01234567'
            target = sessions / (session + '.json')
            wrapper = '''import os,sys
real_open=os.open
real_fstat=os.fstat
synthetic_run=sys.argv[4]
class Metadata:
    def __init__(self,value):self.value=value
    def __getattr__(self,name):
        if name in ('st_uid','st_gid'):return 0
        return getattr(self.value,name)
def substitute(path,flags,*args,**kwargs):
    if path=='/run':path=synthetic_run
    return real_open(path,flags,*args,**kwargs)
os.getuid=lambda:0
os.getgid=lambda:0
os.open=substitute
os.fstat=lambda fd:Metadata(real_fstat(fd))
program=SCRIPT
sys.argv=['reader',sys.argv[1],sys.argv[2],sys.argv[3]]
exec(compile(program,'fixed-root-reader','exec'))
'''.replace('SCRIPT', repr(script))
            def invoke(action='response', identifier=session, index='0'):
                return subprocess.run([sys.executable, '-B', '-c', wrapper, action, identifier, index, str(root / 'run')],
                                      cwd=HERE, stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
            import time
            synthetic = {'session': session, 'expires_at': time.time() + 60, 'scenario': 'multi', 'responses': ['01234567', '12345678', '23456789']}
            target.write_text(json.dumps(synthetic));target.chmod(0o600)
            for index in range(3):
                result = invoke(index=str(index))
                self.assertEqual(result.returncode, 0)
                value = json.loads(result.stdout)
                self.assertEqual(set(value), {'session', 'index', 'expires_at', 'response'})
                self.assertEqual(value['response'], synthetic['responses'][index])
            result = invoke(action='session-state', index='none')
            self.assertEqual(result.returncode, 0);self.assertEqual(json.loads(result.stdout), {'present': True})
            target.chmod(0o644)
            result = invoke();self.assertNotEqual(result.returncode, 0);self.assertEqual(result.stdout, b'')
            target.chmod(0o600);hard=sessions/'hard';os.link(target,hard)
            result = invoke();self.assertNotEqual(result.returncode, 0);self.assertEqual(result.stdout, b'')
            hard.unlink();target.unlink();target.symlink_to(root/'missing')
            result = invoke();self.assertNotEqual(result.returncode, 0);self.assertEqual(result.stdout, b'')
            target.unlink();os.mkfifo(target,0o600)
            result = invoke();self.assertNotEqual(result.returncode, 0);self.assertEqual(result.stdout, b'')
            target.unlink()
            for changes in ({'session':'f'*24},{'expires_at':1},{'responses':['bad']},{'scenario':'zero'},{'extra':1}):
                bad=dict(synthetic);bad.update(changes);target.write_text(json.dumps(bad));target.chmod(0o600)
                result = invoke();self.assertNotEqual(result.returncode, 0);self.assertEqual(result.stdout, b'');target.unlink()
            result=invoke(identifier='../secret');self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
            result=invoke(action='session-state',index='none');self.assertEqual(result.returncode,0);self.assertEqual(json.loads(result.stdout),{'present':False})
            policy=runtime/'config.json';policy.write_text(json.dumps({'version':1,'mode':'key-kbd','scenario':'multi','delay':8}));policy.chmod(0o600)
            result=invoke(action='policy',identifier='none',index='none');self.assertEqual(result.returncode,0);self.assertEqual(json.loads(result.stdout)['mode'],'key-kbd')


if __name__ == '__main__':
    unittest.main()
