"""Generate the one fixed, non-secret outer-PTY -> system-ssh wrapper; never run it."""
import base64
import hashlib
import re

INNER_SHA256 = 'a21f1e2931b873d75274da3e86b8723513d6ee7bc852dff1a9ca93e2a47f4391'
FROZEN = {
    'Core.swift': '2e9a75d09add80142bbf75e89d1d23c7942d925e79109a8dc5df69393a2de953',
    'Main.swift': '6e5acbdac1f193f613e79ff072acd251b60f77c119f53cb56ba77010972d4255',
    'LiveInput.swift': '5a83ce95aa2c72006bbf95660b4b83024d473f5f46a4e659a0978a2618f20ea4',
    'remote_probe.py': INNER_SHA256,
}


def wrapper(inner, case_nonce):
    if re.fullmatch('[0-9a-f]{32}', case_nonce) is None or hashlib.sha256(inner).hexdigest() != INNER_SHA256:
        raise ValueError('fixed-nested-probe-input')
    encoded = base64.b64encode(inner).decode('ascii')
    source = '''import base64,hashlib,os,re,shlex,sys
nonce=sys.argv[1] if len(sys.argv)==2 else ''
if re.fullmatch('[0-9a-f]{32}',nonce) is None or os.getuid()!=10000 or not os.isatty(0) or 'SSH_TTY' not in os.environ:raise SystemExit(64)
inner=base64.b64decode(INNER_BASE64,validate=True)
if hashlib.sha256(inner).hexdigest()!=INNER_HASH:raise SystemExit(65)
launcher='import base64,hashlib,sys;source=base64.b64decode('+repr(INNER_BASE64)+',validate=True);assert hashlib.sha256(source).hexdigest()=='+repr(INNER_HASH)+';exec(compile(source,"<fixed-nested-inner-probe>","exec"),{"__name__":"__main__"})'
command='/usr/bin/python3 -c '+shlex.quote(launcher)+' '+nonce
argv=['/usr/bin/ssh','-F','/dev/null','-tt','-p','2222','-l','fixture','-i',KEY_PATH]
for option in ('BatchMode=yes','PreferredAuthentications=publickey','PasswordAuthentication=no','KbdInteractiveAuthentication=no','IdentitiesOnly=yes','IdentityAgent=none','StrictHostKeyChecking=yes','UserKnownHostsFile=/fixture/home/.ssh/known_hosts','GlobalKnownHostsFile=/dev/null','UpdateHostKeys=no','ForwardAgent=no','ForwardX11=no','ClearAllForwardings=yes','ProxyCommand=none','ProxyJump=none','ControlMaster=no','ControlPath=none','EscapeChar=none','ConnectionAttempts=1','ConnectTimeout=8','ServerAliveInterval=5','ServerAliveCountMax=1'):
 argv+=['-o',option]
argv+=['--','127.0.0.1',command]
os.execv('/usr/bin/ssh',argv)
'''
    # The original OUTER shell owns `; r=$?; printf ... returned ...`; neither the
    # wrapper nor inner command emits returned. execv preserves this exact boundary.
    prefix = 'INNER_BASE64=' + repr(encoded) + '\nINNER_HASH=' + repr(INNER_SHA256) + '\nKEY_PATH=' + repr(
        '/fixture/home/.openlxssh-nested-' + case_nonce + '/id_ed25519') + '\n'
    result = (prefix + source).encode('ascii')
    if not 0 < len(result) <= 32768:
        raise ValueError('outer-loader-source-budget')
    return result
