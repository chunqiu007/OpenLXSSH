#!/usr/bin/env python3
"""Explicit finite supervisor for exactly normal-A then blackhole-B. Default never opens descriptors or processes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import time
import uuid

from core import Refused, binding, encoded, exact_json, identity, lsof_connection, verdict

HERE = Path(__file__).absolute().parent


def frozen():
    record = json.loads((HERE / 'frozen-inputs.json').read_bytes())
    for entry in record['dependencyObjects']:
        if hashlib.sha256(Path(entry['path']).read_bytes()).hexdigest() != entry['sha256']: raise Refused('dependency-changed')
    for path, expected in {**record['moduleSHA256'], **record['frozenRelaySHA256']}.items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected: raise Refused('readonly-input-changed')
    return record


def save(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')


def read_frame(process, seconds):
    deadline = time.monotonic() + seconds
    data = bytearray()
    os.set_blocking(process.stdout.fileno(), False)
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(min(.05, max(0, deadline-time.monotonic()))):
                if process.poll() is not None: raise Refused('child-ended-before-control-frame')
                continue
            try: block = os.read(process.stdout.fileno(), 2048-len(data))
            except (BlockingIOError, InterruptedError): continue
            if not block: raise Refused('private-pipe-eof')
            data.extend(block)
            if len(data) >= 2048: raise Refused('private-pipe-bounds')
            if data.endswith(b'\n'):
                if data.count(10) != 1: raise Refused('private-pipe-frame')
                return exact_json(bytes(data))
    raise Refused('private-pipe-deadline')


def send(process, value):
    if process.poll() is not None: raise Refused('child-ended-before-command')
    process.stdin.write(encoded(value)); process.stdin.flush()


def query(relay, value, seconds=10):
    sent = time.monotonic()
    send(relay, value); result = read_frame(relay, seconds)
    if result.get('ok') is not True: raise Refused('relay-command-refused')
    if value.get('op')=='arm':
        result['supervisorArmSentAt']=sent;result['supervisorArmReceivedAt']=time.monotonic()
    return result


def process_identity(tool, pid):
    result = subprocess.run([str(tool), str(pid)], stdin=subprocess.DEVNULL, capture_output=True, timeout=3)
    if result.returncode: raise Refused('owned-pid-metadata')
    return identity(exact_json(result.stdout))


def exact_owned_tcp(tool, consumer, birth):
    if birth['ppid'] != consumer.pid or birth['uid'] != os.getuid(): raise Refused('owned-ssh-parent-uid')
    before = process_identity(tool, birth['pid'])
    if before != birth: raise Refused('owned-ssh-birth-before')
    args = ['/usr/sbin/lsof','-nP','-a','-p',str(birth['pid']),'-iTCP:22221','-sTCP:ESTABLISHED','-F','pufnPT']
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=3)
    if result.returncode: raise Refused('owned-ssh-tcp')
    row = lsof_connection(result.stdout,birth['pid'])
    if row['uid'] != os.getuid() or process_identity(tool,birth['pid']) != birth: raise Refused('owned-ssh-birth-after')
    return row


def stop_child(child, grace=10):
    if child is None: return None
    outcome = {'pid':child.pid,'terminated':False,'killed':False}
    if child.poll() is None:
        child.terminate(); outcome['terminated'] = True
        try: child.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            child.kill(); outcome['killed'] = True; child.wait(timeout=3)
    outcome['exitCode'] = child.wait()
    for handle in (child.stdin,child.stdout,child.stderr):
        if handle is not None: handle.close()
    return outcome


def failed_consumer_cleanup(consumer, role, run, result, ack_sent):
    """Failure remains failure; give the owned consumer its result ACK and full close budget before signals."""
    cleanup={'resultAckSent':ack_sent,'closedFrameReceived':'closedReport' in result,'stage':'not-started'}
    result['failureCleanup']=cleanup
    if consumer is None: cleanup['stage']='no-consumer';return
    try:
        if 'closedReport' not in result and 'preCloseReport' in result:
            if not ack_sent:
                send(consumer,{'op':'result-recorded','run':run,'role':role,'ok':True})
                cleanup['resultAckSent']=True
            cleanup['stage']='waiting-owned-close'
            closed=read_frame(consumer,30)
            if set(closed)!={'op','run','role','report'} or closed['op']!='closed' or closed['run']!=run or closed['role']!=role or not isinstance(closed['report'],dict):
                raise Refused('failure-close-frame')
            result['closedReport']=closed['report'];cleanup['closedFrameReceived']=True
        result['consumerExitCode']=consumer.wait(timeout=30)
        cleanup['stage']='owned-consumer-exited'
    except Exception:
        cleanup['stage']='control-unavailable-gentle-stop-required'
        # stop_child below records actual TERM/KILL and waits >=10s control +12s close +3s FD drain.


def run_case(role, run, app, tool, contract, work):
    relay = consumer = None
    result_ack_sent = False
    result = {'role':role,'run':run,'status':'running','startedAt':time.monotonic(),'secretReadBySupervisor':False}
    # No inherited Docker/SSH/loader state. Only selected local Unix Docker endpoint is used by frozen bridge.
    environment = {'PATH':'/Applications/Docker.app/Contents/Resources/bin:/usr/bin:/bin:/usr/sbin:/sbin',
        'HOME':str(Path.home()),'LANG':'C','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'}
    stderr = (work/(role+'-stderr.log')).open('xb')
    try:
        relay = subprocess.Popen([sys.executable,'-B',str(HERE/'relay_control.py'),'--live-test-only','--role',role,'--run',run,'--owner-pid',str(os.getpid())],
            cwd=HERE,env=environment,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr,bufsize=0,close_fds=True)
        ready = read_frame(relay,60)
        if ready != {'event':'ready','run':run,'role':role,'pid':relay.pid,'port':22221}: raise Refused('relay-readiness')
        consumer = subprocess.Popen([str(app/'Contents/MacOS/OpenLXSSHKeepalive'),'--live-test-only','--contract',str(contract),
            '--role',role,'--run',run,'--authorized-local-fixture','--primary-reviewed'],cwd=HERE,env=environment,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr,bufsize=0,close_fds=True)
        event = read_frame(consumer,100)
        if set(event) != {'op','run','role','session','generation','ssh'} or event['op']!='shell-ready' or event['run']!=run or event['role']!=role:
            raise Refused('consumer-shell-control')
        birth = identity(event['ssh'])
        row = exact_owned_tcp(tool,consumer,birth)
        found = query(relay,{'op':'lookup','run':run,'role':role,'sourcePort':row['sourcePort']})
        value = binding({'run':run,'role':role,'token':found['token'],'sourcePort':row['sourcePort'],
            'session':event['session'],'generation':event['generation'],'ssh':birth})
        bound = query(relay,{'op':'bind','run':run,'role':role,'binding':value})
        result['binding'] = value; result['ownedTCPBeforeArm'] = row; result['bound'] = bound
        if role=='normal':
            send(consumer,{'op':'normal-ready','run':run,'role':role,'ok':True})
        else:
            # PID birth and exact established tuple are checked again immediately before arming.
            if exact_owned_tcp(tool,consumer,birth) != row: raise Refused('ssh-tuple-changed-before-arm')
            arm = query(relay,{'op':'arm','run':run,'role':role,'binding':value})
            if arm.get('mode')!='drop' or not arm.get('establishedAtArm') or not arm.get('bridgeAliveAtArm'): raise Refused('drop-not-confirmed')
            result['arm'] = arm
            send(consumer,{'op':'drop-confirmed','run':run,'role':role,'ok':True,'mode':'drop',
                'armedAt':arm['armedAt'],'armedWall':arm['armedWall'],'relayNow':arm['relayNow'],'relayWall':arm['relayWall']})
        outcome = read_frame(consumer,35 if role=='normal' else 22)
        outcome_received_at = time.monotonic()
        result['outcomeReceivedAt'] = outcome_received_at
        if set(outcome) != {'op','run','role','report'} or outcome['op']!='case-result' or outcome['run']!=run or outcome['role']!=role:
            raise Refused('consumer-result-control')
        report = outcome['report']
        result['preCloseReport'] = report
        if report.get('failure') is not None: raise Refused('pre-close-case-failure')
        if role=='blackhole':
            # Conservative natural-result bound includes arm validation/ACK transit, never later management or cleanup.
            bound = outcome_received_at-result['arm']['supervisorArmSentAt']
            result['conservativeArmRequestToOutcomeSeconds'] = bound
            if not 0 < bound <= 15:raise Refused('blackhole-conservative-15second-budget')
        # Outcome is real public DirectSSHSession natural pre-close status, not a supervisor-induced timeout.
        relay_result = query(relay,{'op':'result','run':run,'role':role,'binding':value})
        result['relayAtResult'] = relay_result
        result['coreVerdict'] = False # Final closed report and post-cleanup relay snapshot are both required.
        send(consumer,{'op':'result-recorded','run':run,'role':role,'ok':True})
        result_ack_sent = True
        closed = read_frame(consumer,20)
        if closed.get('op')!='closed' or closed.get('run')!=run or closed.get('role')!=role: raise Refused('consumer-close-control')
        result['closedReport'] = closed['report']
        result['consumerExitCode'] = consumer.wait(timeout=5)
        if report.get('failure') is not None or result['consumerExitCode']!=0 or closed['report'].get('failure') is not None or not all(closed['report'].get(k) for k in ('closed','pidGone','fdReturnedToBaseline')):
            raise Refused('case-verdict-or-cleanup')
        finished = query(relay,{'op':'finish','run':run,'role':role,'binding':value})
        result['relayAfterFinish'] = finished
        # DROP result snapshot is taken before owned bridge cleanup; A needs full frozen-pump completion metadata.
        result['coreVerdict'] = verdict(role,closed['report'], finished if role=='normal' else relay_result)
        if not result['coreVerdict']: raise Refused('combined-keepalive-verdict')
        query(relay,{'op':'stop','run':run,'role':role})
        result['relayExitCode'] = relay.wait(timeout=30)
        if result['relayExitCode']!=0: raise Refused('relay-cleanup')
        result['status']='passed-real-limited-case'
    except Exception:
        result['status']='failed-retain-no-retry';result['failure']='closed-supervisor-refusal'
        failed_consumer_cleanup(consumer,role,run,result,result_ack_sent)
    finally:
        result['consumerDrain']=stop_child(consumer,grace=30) if result['status']=='failed-retain-no-retry' else stop_child(consumer)
        result['relayDrain']=stop_child(relay)
        if result['status']=='passed-real-limited-case' and any(outcome and (outcome['terminated'] or outcome['killed']) for outcome in (result['consumerDrain'],result['relayDrain'])):
            result['status']='failed-retain-no-retry';result['failure']='external-signal-required'
        stderr.close();result['endedAt']=time.monotonic();save(work/(role+'-result.json'),result)
    return result


def prior_normal_proof(path, cleanup_path, signed_path, *, new_run, current_consumer_hash):
    """B-only reuses only exact accepted A bytes and unchanged signed Swift consumer sources."""
    expected='ff0542b43ec30a399b4f6ef3477ba181af1d89135ee2800c4d80d8ed1b08bd83'
    if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise Refused('prior-normal-result-changed')
    accepted=json.loads(path.read_bytes())
    if accepted.get('role')!='normal' or accepted.get('status')!='passed-real-limited-case' or accepted.get('coreVerdict') is not True:
        raise Refused('prior-normal-not-passed')
    if accepted['run']==new_run or not verdict('normal',accepted['closedReport'],accepted['relayAfterFinish']):raise Refused('prior-normal-config-or-nonce')
    for key in ('consumerDrain','relayDrain'):
        if accepted[key]['exitCode']!=0 or accepted[key]['terminated'] or accepted[key]['killed']:raise Refused('prior-normal-forced-drain')
    ledger=path.parent/'evidence-sha256.json'
    if hashlib.sha256(ledger.read_bytes()).hexdigest()!='752cc84ec7920bb88bb36c61e7010afd46bc620973dcf56ae485e6d35b501e27':raise Refused('original-campaign-ledger-changed')
    hashes=json.loads(ledger.read_bytes())
    if hashes.get(str(cleanup_path))!=hashlib.sha256(cleanup_path.read_bytes()).hexdigest():raise Refused('prior-local-cleanup-proof-changed')
    cleanup=json.loads(cleanup_path.read_bytes())
    if cleanup.get('run')!=accepted['run'] or cleanup.get('normalAndBlackholeRunRootsAbsent') is not True or cleanup.get('unknownEntriesRejected') is not True:
        raise Refused('prior-local-cleanup-not-proven')
    if hashlib.sha256(signed_path.read_bytes()).hexdigest()!='795a52e1ae7fcb1222ddd04cca60c7a98d15da0816f750809b7f0145be9b95f0':raise Refused('prior-signed-result-changed')
    signed=json.loads(signed_path.read_bytes())
    for name in ('Main.swift','Core.swift','LiveInput.swift'):
        if hashlib.sha256((HERE/name).read_bytes()).hexdigest()!=signed['sourceSHA256'][name]:raise Refused('prior-normal-consumer-source-changed')
    if signed['driverSHA256']!=current_consumer_hash:raise Refused('prior-normal-consumer-binary-changed')
    return {'result':str(path),'resultSHA256':expected,'run':accepted['run'],'reusedNotRerun':True,'cleanup':str(cleanup_path)}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('help','campaign','blackhole-only'),nargs='?',default='help')
    parser.add_argument('--prior-normal-result',type=Path);parser.add_argument('--prior-cleanup-proof',type=Path);parser.add_argument('--prior-signed-result',type=Path)
    parser.add_argument('--approved-signed-build',type=Path);parser.add_argument('--contract',type=Path)
    parser.add_argument('--primary-reviewed-live',action='store_true')
    args=parser.parse_args(argv)
    if args.action=='help':parser.print_help();return 0
    if not args.primary_reviewed_live or args.approved_signed_build is None or args.contract is None:return 64
    # Source/offline stage intentionally cannot create an approved signed receipt. Live remains a separate gate.
    record=frozen();receipt=json.loads((args.approved_signed_build/'keepalive-approved-build.json').read_bytes())
    app=Path(receipt['app']);tool=Path(receipt['identityTool'])
    expected_keys={'app','identityTool','consumerSHA256','identityToolSHA256','sourceSHA256','appFilesSHA256','signedStaticReview','fixturePreflight','fixturePreflightSHA256'}
    if set(receipt)!=expected_keys or receipt['signedStaticReview'] is not True: raise Refused('approved-build-schema')
    own={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in HERE.iterdir() if p.is_file() and p.name not in {'.gitignore'}}
    if own!=receipt['sourceSHA256']:raise Refused('own-source-changed')
    app_files={str(p.relative_to(app)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(app.rglob('*')) if p.is_file()}
    if app_files!=receipt['appFilesSHA256'] or hashlib.sha256((app/'Contents/MacOS/OpenLXSSHKeepalive').read_bytes()).hexdigest()!=receipt['consumerSHA256'] or hashlib.sha256(tool.read_bytes()).hexdigest()!=receipt['identityToolSHA256']:
        raise Refused('approved-build-changed')
    if app_files.get('Contents/Helpers/openlxssh-askpass')!=record['helperSHA256']:
        raise Refused('frozen-helper-changed')
    preflight=Path(receipt['fixturePreflight'])
    if preflight.is_symlink() or not preflight.is_file() or hashlib.sha256(preflight.read_bytes()).hexdigest()!=receipt['fixturePreflightSHA256']:
        raise Refused('missing-public-fixture-preflight-binding')
    public=json.loads(preflight.read_bytes())
    if (set(public)!={'containerID','fingerprint','imageID','networkID','checkedAt','healthy','capabilityMask'} or
        public['containerID']!='1253a29501483eb71f80e39b9af5c85e10c3a49329d5e93700fecd3f00f334f2' or
        public['fingerprint']!='SHA256:MHUel445tN/gQtcvZikLZVE1mlWZf7U38C0zZTTru+Q' or public['healthy'] is not True or
        public['imageID']!='sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363' or
        public['networkID']!='b949645e158058f7484e21b758459f8d0e6a284f0d2bb641879faf67f2b50ed1' or
        public['capabilityMask']!='200400eb' or not 0<=time.time()-public['checkedAt']<=120):
        raise Refused('public-fixture-preflight-refused')
    if args.action=='blackhole-only':
        if any(p is None for p in (args.prior_normal_result,args.prior_cleanup_proof,args.prior_signed_result)):raise Refused('prior-normal-proof-required')
        if args.contract.is_symlink():raise Refused('fresh-contract-path')
        fresh_contract=json.loads(args.contract.read_bytes())
        if fresh_contract.get('collectedAt',0)<=Path(args.prior_normal_result).stat().st_mtime:raise Refused('fresh-post-A-collect-required')
        if Path(receipt['fixturePreflight']).stat().st_mtime<=Path(args.prior_normal_result).stat().st_mtime:raise Refused('fresh-B-preflight-required')
    os.umask(0o077);work=HERE/'.runtime'/('campaign-'+uuid.uuid4().hex);work.mkdir(mode=0o700,parents=True)
    run=uuid.uuid4().hex
    if args.action=='blackhole-only':
        proof=prior_normal_proof(args.prior_normal_result,args.prior_cleanup_proof,args.prior_signed_result,
            new_run=run,current_consumer_hash=receipt['consumerSHA256'])
        save(work/'prior-normal-reuse.json',proof)
        b=run_case('blackhole',run,app,tool,args.contract,work)
        save(work/'campaign.json',{'run':run,'normalReused':proof,'blackhole':b['status'],'blackholeOnly':True})
        return 0 if b['status']=='passed-real-limited-case' else 1
    a=run_case('normal',run,app,tool,args.contract,work)
    if a['status']!='passed-real-limited-case':return 1
    if own!={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in HERE.iterdir() if p.is_file() and p.name!='.gitignore'}:
        raise Refused('own-source-changed-between-cases')
    if app_files!={str(p.relative_to(app)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(app.rglob('*')) if p.is_file()}:
        raise Refused('signed-app-changed-between-cases')
    b=run_case('blackhole',run,app,tool,args.contract,work)
    save(work/'campaign.json',{'run':run,'normal':a['status'],'blackhole':b['status'],'rolesSerial':True})
    return 0 if b['status']=='passed-real-limited-case' else 1


if __name__=='__main__':
    try:sys.exit(main())
    except Exception:sys.stderr.write('Keepalive campaign refused; no private details.\n');sys.exit(2)
