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
    def test_sftp_combined_auth_requires_returned_sftp_and_real_tiny_roundtrip(self):
        body = (HERE / 'Consumer/SFTPAuthConsumer.swift').read_text()
        self.assertIn('primary = .publicKey(publicKey: input.publicKey, privateKey: privateKey, passphrase: input.passphrase)', body)
        self.assertIn('primary = .password(password)', body)
        self.assertIn('var authentication: [FileAuthentication] = [primary]', body)
        self.assertIn('authentication.append(.keyboardInteractive', body)
        self.assertIn('service = try await LibSSH2FileService.connect(configuration:', body)
        self.assertIn('report?.authenticatedSFTPConnects = 1', body)
        self.assertIn('try await SFTPAuthRoundTrip.run(service:', body)
        self.assertIn('service.cancel(); await service.close()', body)
        self.assertIn('expected-authenticated-sftp-roundtrip', body)
        for forbidden in ('DirectSSHSession(', 'startProbe(', 'savedPassword:', 'authenticatedThenSFTPUnavailable', 'code == -21', 'primaryPromptSHA256'):
            self.assertNotIn(forbidden, body)
        callbacks = (HERE / 'Consumer/SFTPAuthCallbacks.swift').read_text()
        self.assertIn('if case .secret(let session, let index) = claim {', callbacks)
        self.assertIn('management.response(session: session, index: index)', callbacks)
        self.assertIn('budget.resolved(reply.resolve([answer]))', callbacks)
        self.assertIn('budget.resolved(reply.resolve([]))', callbacks)
        self.assertIn('try budget.requireResolutionAccepted()', callbacks)
        self.assertIn('token.cancel(); management.cancel()', callbacks)
        self.assertIn('return active == 0', callbacks)
        policy = (HERE / 'Sources/RealIntegrationCore/SFTPAuthPolicy.swift').read_text()
        self.assertIn('name.isEmpty, instruction.isEmpty', policy)
        self.assertIn('prompts.count == 1, echo == [false]', policy)
        self.assertIn('callbacks == 4', policy)
        self.assertIn('prompts.isEmpty, echo.isEmpty', policy)
        self.assertIn('resolvedReplies == 3', policy)
        self.assertIn('sessionID == nil || sessionID == id', policy)
        report = policy.split('public struct SFTPAuthReport:', 1)[1]
        for forbidden in ('password:', 'privateKey:', 'passphrase:', 'prompt:', 'response:', 'instruction:'):
            self.assertNotIn(forbidden, report)
        roundtrip = (HERE / 'Consumer/SFTPAuthRoundTrip.swift').read_text()
        for required in ('bytes.count == 79', 'mode: .exclusiveWrite', 'PrivateInput.sha256(received) == PrivateInput.sha256(bytes)',
                         'ownership.checkListing', 'attributes.kind == .regular', 'service.remove(directory, directory: true'):
            self.assertIn(required, roundtrip)
        self.assertNotIn('recursive', roundtrip.split('enum SFTPAuthRoundTrip', 1)[1])
    def test_refused_callback_shape_is_recorded_once_under_lock_before_original_cancel(self):
        callbacks = (HERE / 'Consumer/SFTPAuthCallbacks.swift').read_text()
        self.assertIn('if unexpectedShape == nil {', callbacks)
        self.assertEqual(callbacks.count('unexpectedShape = UnexpectedChallengeShape('), 1)
        refused = callbacks.split('} catch {\n                // Diagnostic only', 1)[1].split('var answer: Data?', 1)[0]
        self.assertIn('lock.unlock(); throw error', refused)
        self.assertNotIn('reply.resolve', refused)
        self.assertNotIn('management.response', refused)
        self.assertIn('cancel((error as? SFTPAuthError) ?? .managementFailed)', callbacks)
        consumer = (HERE / 'Consumer/SFTPAuthConsumer.swift').read_text()
        self.assertIn('report?.unexpectedChallenge = owner.unexpectedChallengeSnapshot()', consumer)
        shape = (HERE / 'Sources/RealIntegrationCore/UnexpectedChallengeShape.swift').read_text()
        self.assertIn('maximumPrompts = 32', shape)
        self.assertIn('maximumFieldBytes = 65536', shape)
        self.assertIn('prompts.prefix(Self.maximumPrompts)', shape)
        self.assertIn('sha256 = truncated ? nil : PrivateInput.sha256(data)', shape)
    def test_terminal_zero_is_exact_fourth_nonsecret_phase_not_authentication_success(self):
        callbacks = (HERE / 'Consumer/SFTPAuthCallbacks.swift').read_text()
        branch = callbacks.split('case .terminalZero:', 1)[1].split('lock.unlock()', 1)[0]
        self.assertIn('reply.resolve([])', branch)
        self.assertNotIn('management.response', branch)
        policy = (HERE / 'Sources/RealIntegrationCore/SFTPAuthPolicy.swift').read_text()
        self.assertIn('expectedCallbacks = mfa ? 4 : 0', policy)
        self.assertIn('callbacks <= 4', policy)
        self.assertIn('secretResponses == 3, replies == 3, resolvedReplies == 3, managementReads == 3', policy)
        self.assertIn('terminalZeroReplies == 0, sessionID != nil, prompts.isEmpty, echo.isEmpty', policy)
        self.assertIn('secretResponseCount = budget.secretResponses; terminalZeroReplyCount = budget.terminalZeroReplies', policy)
        consumer = (HERE / 'Consumer/SFTPAuthConsumer.swift').read_text()
        self.assertIn('report?.authenticatedSFTPConnects == 1, report?.bytesWritten == 79, report?.bytesRead == 79', consumer)
        self.assertIn('report?.hashMatched == true, report?.remoteCleanupCompleted == true', consumer)
    def test_otp_negative_has_one_reader_call_real_expiry_gate_no_secret_log_or_file_ops(self):
        callbacks = (HERE / 'Consumer/SFTPOTPNegativeCallbacks.swift').read_text()
        self.assertEqual(callbacks.count('management.response(session:'), 1)
        self.assertIn('budget.recordRead(index: claim.1, expiry: fetched.expiresAt', callbacks)
        self.assertIn('Date().timeIntervalSince1970', callbacks)
        self.assertIn('ProcessInfo.processInfo.systemUptime', callbacks)
        self.assertIn('budget.resolved(reply.resolve([answer]))', callbacks)
        self.assertNotIn('reply.resolve([])', callbacks)
        for forbidden in ('print(', 'writeExclusive', 'sha256(answer', 'sha256(wrong', 'sha256(original'):
            self.assertNotIn(forbidden, callbacks)
        consumer = (HERE / 'Consumer/SFTPOTPNegativeConsumer.swift').read_text()
        self.assertIn('LibSSH2FileService.connect(configuration:', consumer)
        self.assertIn('operationTimeout: SFTPOTPNegativeContract.operationSeconds', consumer)
        self.assertIn('try budget.requireInjected()', consumer)
        self.assertIn('typedRejected, report?.actualSFTPConnects == 0', consumer)
        self.assertIn('service.cancel(); await service.close()', consumer)
        for forbidden in ('SFTPAuthRoundTrip', 'service.open(', 'service.mkdir(', 'service.write(', 'service.read(', 'DirectSSHSession(', 'startProbe('):
            self.assertNotIn(forbidden, consumer)
        policy = (HERE / 'Sources/RealIntegrationCore/SFTPOTPNegativePolicy.swift').read_text()
        self.assertIn('expiry > wall, expiry <= wall + 75', policy)
        self.assertIn('wall >= expiresAt + 0.05 && uptime >= cReadUptime + (expiresAt - cReadWall) + 0.05', policy)
        self.assertIn('kind == "authentication" && operation == "authenticate" && code == nil', policy)
        report = policy.split('public struct SFTPOTPNegativeReport:', 1)[1]
        for forbidden in ('answer:', 'response:', 'password:', 'privateKey:', 'responseHash:', 'responseSHA'):
            self.assertNotIn(forbidden, report)
        reader = (HERE / 'Sources/RealIntegrationCore/OpenSSHManagementPolicy.swift').read_text()
        self.assertIn("time.time()<value['expires_at']<=time.time()+75", reader)
    def test_saved_password_public_never_overrides_gate_or_reads_keychain(self):
        owner = (HERE / 'Consumer/SavedPasswordPublicOwner.swift').read_text()
        self.assertIn('SavedPasswordAuthorization(provider:', owner)
        self.assertIn('session.connect(configuration, savedPassword: authorization)', owner)
        self.assertIn('session.connect(configuration) // Deliberately NO authorization/provider.', owner)
        self.assertIn('budget.claimProviderRead(session:', owner)
        self.assertIn('budget.finishProvider(session:', owner)
        self.assertIn('try budget.requireExpected(connectedEvents: report.connectedEvents)', owner)
        self.assertIn('providerActive == 0 && manualTask == nil', owner)
        for forbidden in ('configureProbeSavedPassword', 'PasswordAutomationGate', 'eligible:', 'startProbe(', 'terminal.text', 'sendInput(', 'CredentialStore(', 'SystemCredentials(', 'Keychain'):
            self.assertNotIn(forbidden, owner)
        consumer = (HERE / 'Consumer/SavedPasswordPublicConsumer.swift').read_text()
        self.assertIn('authentication: SSHAuthentication(method: .passwordOnly)', consumer)
        self.assertNotIn('savedPassword:', consumer)
        contract = (HERE / 'Sources/RealIntegrationCore/SavedPasswordPublicContract.swift').read_text()
        load = contract.split('public static func load(path:', 1)[1].split('public func password()', 1)[0]
        self.assertNotIn('/password.txt', load)
        self.assertIn('PrivateInput.read(contract.credentialDirectory + "/password.txt"', contract)
        policy = (HERE / 'Sources/RealIntegrationCore/SavedPasswordPublicPolicy.swift').read_text()
        self.assertIn('gateNotCovered = true; throw SavedPasswordPublicError.gateNotCovered', policy)
        report = policy.split('public struct SavedPasswordPublicReport:', 1)[1]
        self.assertIn('keychainAccess = false', report)
        self.assertIn('persistenceVerified = false', report)
        for forbidden in ('password:', 'secret:', 'prompt:', 'answer:', 'secretHash:'):
            self.assertNotIn(forbidden, report)
    def test_public_credential_lifecycle_is_live_gated_exact_and_recovery_first(self):
        consumer = (HERE / 'Consumer/CredentialStorePublicConsumer.swift').read_text()
        self.assertLess(consumer.index('try persist("prepared")'), consumer.index('CredentialStore(testNamespace: namespace)'))
        self.assertLess(consumer.index('try persist("save-attempted")'), consumer.index('currentStore.save('))
        self.assertIn('authorization: .granted', consumer)
        self.assertIn('if state.mayAttemptExactDelete && connectionCleanupDrained {', consumer)
        self.assertIn('store.deleteExact(reference)', consumer)
        self.assertIn('try await store.close()', consumer)
        self.assertIn('state.recordClose(restored: false)', consumer)
        for forbidden in ('SecItem', 'SecKeychainSetDefault', 'SecKeychainSetSearchList', '.replace(', 'SecAccessCreate', 'AXUIElement', 'NSAppleScript'):
            self.assertNotIn(forbidden, consumer.split('@MainActor enum', 1)[1])
        owner = (HERE / 'Consumer/CredentialStorePublicOwner.swift').read_text()
        self.assertIn('await store.read(reference)', owner)
        self.assertIn('session.connect(configuration, savedPassword: authorization)', owner)
        for forbidden in ('fixturePasswordForExplicitSave', 'configureProbeSavedPassword', 'eligible:', 'terminal.text', 'sendInput('):
            self.assertNotIn(forbidden, owner)
        recovery = (HERE / 'Consumer/CredentialStorePublicRecovery.swift').read_text()
        self.assertIn('PrivateInput.writeExclusive', recovery)
        self.assertIn('fsync(self.runFD) == 0', recovery)
        self.assertIn('fsync(self.parentFD) == 0', recovery)
        self.assertIn('CredentialStorePublicDurability.commit', recovery)
        self.assertIn('validateIdentity()', recovery)
        self.assertNotIn('FileManager.default.remove', recovery)
        options = (HERE / 'Sources/RealIntegrationCore/CredentialStorePublicContract.swift').read_text()
        self.assertIn('local && ready && keychain', options)
        self.assertIn('--authorized-test-keychain', options)
        state = (HERE / 'Sources/RealIntegrationCore/CredentialStorePublicState.swift').read_text()
        self.assertIn('automaticRecoveryDeletionAllowed = false', state)
        self.assertIn('physicalKeychainIsolation = false', state)
        builder = (HERE / 'build_host.py').read_text()
        self.assertIn("builder.c_module('SecurityPOSIX'", builder)
        self.assertIn("('OpenLXSSHSecurity', ROOT / 'Packages/OpenLXSSHSecurity/Sources/OpenLXSSHSecurity'", builder)
        # Offline graph must stay dependency-free: pure state tests never open a store.
        self.assertNotIn('OpenLXSSHSecurity', (HERE / 'Package.swift').read_text())
        tests = (HERE / 'Tests/RealIntegrationCoreTests/CredentialStorePublicTests.swift').read_text()
        self.assertNotIn('try CredentialStore(', tests)
        self.assertNotIn('import OpenLXSSHSecurity', tests)


if __name__ == '__main__':
    unittest.main()
