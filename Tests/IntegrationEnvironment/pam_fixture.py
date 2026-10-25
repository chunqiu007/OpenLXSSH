"""Test-only PAM policy loaded by Ubuntu libpam-python, not an SSH server.

Never log responses or exceptions: pam_python logs uncaught Python exceptions.
OpenSSH 9.6 serializes a multi-Message PAM conversation into SSH prompt rounds;
this exercises PAM's two-message API, NOT a single SSH packet with two prompts.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import time

RUN = Path('/run/openlxssh-fixture')
TTL = 75


def _conversation(pamh, texts, style=None):
    if style is None:
        style = pamh.PAM_PROMPT_ECHO_OFF
    messages = [pamh.Message(style, text) for text in texts]
    responses = pamh.conversation(messages)
    if len(responses) != len(messages):
        return None
    return [response.resp for response in responses]


def _notify(pamh, text):
    # One informational PAM message, zero password/OTP prompts. Do not use an
    # empty PAM list: libpam-python returns it without calling OpenSSH at all.
    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, text))


def _password(pamh):
    responses = _conversation(pamh, ['Fixture account password: '])
    if responses is None or not isinstance(responses[0], str):
        return pamh.PAM_AUTH_ERR
    record = json.loads((RUN / 'private' / 'password-record.json').read_text())
    digest = hashlib.scrypt(responses[0].encode(), salt=bytes.fromhex(record['salt']),
                            n=16384, r=8, p=1).hex()
    return pamh.PAM_SUCCESS if hmac.compare_digest(digest, record['digest']) else pamh.PAM_AUTH_ERR


def _save_challenge(identifier, payload):
    path = RUN / 'sessions' / (identifier + '.json')
    temporary = RUN / 'sessions' / ('.pending-' + identifier)
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(payload, stream)
    os.replace(str(temporary), str(path))
    return path


def _delete_challenge(path):
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    # Export snapshots are short-lived too, even when the auth is cancelled.
    exported = RUN / 'export' / ('challenge-' + path.name)
    try:
        exported.unlink()
    except FileNotFoundError:
        pass


def _sweep_expired():
    for path in (RUN / 'sessions').glob('*.json'):
        try:
            if json.loads(path.read_text())['expires_at'] <= time.time():
                _delete_challenge(path)
        except FileNotFoundError:
            pass  # another concurrent authentication consumed its own value


def _interactive(pamh, config):
    _sweep_expired()
    identifier = secrets.token_hex(12)  # non-secret, safe to display in UI
    started = time.time()
    expiry = started + TTL
    scenario = config['scenario']
    if scenario == 'multi':
        # Per-authentication, independent one-time challenges; no fixed OTP.
        answers = ['{:08d}'.format(secrets.randbelow(100000000)) for _ in range(3)]
        challenge = _save_challenge(identifier, {'session': identifier, 'expires_at': expiry,
                                    'scenario': scenario, 'responses': answers})
        try:
            responses = _conversation(pamh, [
                'One-time response A [{}]: '.format(identifier),
                'Unclassified verification B [{}]: '.format(identifier)])
            if time.time() >= expiry or responses is None:
                return pamh.PAM_AUTH_ERR
            if not all(isinstance(given, str) and hmac.compare_digest(given, expected)
                       for given, expected in zip(responses, answers[:2])):
                return pamh.PAM_AUTH_ERR
            final = _conversation(pamh, ['Next-round response C [{}]: '.format(identifier)])
            if time.time() >= expiry or final is None or not isinstance(final[0], str):
                return pamh.PAM_AUTH_ERR
            return pamh.PAM_SUCCESS if hmac.compare_digest(final[0], answers[2]) else pamh.PAM_AUTH_ERR
        finally:
            _delete_challenge(challenge)
    if scenario == 'zero':
        _notify(pamh, 'Fixture information-only authentication; no response requested.')
        return pamh.PAM_SUCCESS
    if scenario in ('approval', 'reject', 'cancel'):
        # Controlled waiting, not a real push provider. LoginGraceTime plus the
        # fixed <=60s wait bounds a disappeared client's server-side PAM work.
        _notify(pamh, 'Fixture approval simulation: waiting; cancel the connection to abort.')
        deadline = time.monotonic() + config['delay']
        while time.monotonic() < deadline:
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))
        if scenario == 'approval':
            _notify(pamh, 'Fixture approval simulation: approved.')
            return pamh.PAM_SUCCESS
        _notify(pamh, 'Fixture approval simulation: rejected or cancelled.')
        return pamh.PAM_AUTH_ERR
    return pamh.PAM_AUTH_ERR


def pam_sm_authenticate(pamh, flags, args):
    try:
        if pamh.get_user() != 'fixture' or pamh.service != 'sshd':
            return pamh.PAM_AUTH_ERR
        config = json.loads((RUN / 'config.json').read_text())
        mode = config['mode']
        # OpenSSH populates this only after successfully completing preceding
        # AuthenticationMethods steps. No text/prompt guessing or OTP detection.
        prior = {line.split()[0].split('/')[0]
                 for line in pamh.env.get('SSH_AUTH_INFO_0', '').splitlines() if line.split()}
        if mode == 'passwordonly' and not prior:
            return _password(pamh)
        if mode == 'password-kbd':
            if not prior:
                return _password(pamh)
            if 'password' in prior:
                return _interactive(pamh, config)
        if mode == 'key-kbd' and 'publickey' in prior:
            return _interactive(pamh, config)
        return pamh.PAM_AUTH_ERR
    except Exception:
        # Fail closed without allowing pam_python to print sensitive tracebacks.
        return pamh.PAM_AUTH_ERR


def pam_sm_setcred(pamh, flags, args):
    return pamh.PAM_SUCCESS
