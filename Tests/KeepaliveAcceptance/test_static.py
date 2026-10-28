#!/usr/bin/env python3
"""No sockets, ports, Docker, credentials or linking: pure fakes plus readonly API typecheck."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE=Path(__file__).absolute().parent
sys.path.insert(0,str(HERE))
import core
import relay_control
import supervise


def bind(role='blackhole'):
    return {'run':'a'*32,'role':role,'token':'b'*32,'sourcePort':54321,'session':'12345678-1234-1234-1234-123456789abc',
        'generation':1,'ssh':{'pid':111,'ppid':99,'uid':501,'startSeconds':100,'startMicroseconds':1}}


def report(role):
    return {'role':role,'serverAliveInterval':2,'serverAliveCountMax':2,'shellACK':True,'freshACK':True,
        'authenticationRequests':0,'trustRequests':0,'quietSeconds':12.01,'quietSamples':240,'sameTokenPIDDuringQuiet':True,
        'quietApplicationOutputEvents':0,'lastExitCode':0 if role=='normal' else 255,
        'naturalState':'disconnected0' if role=='normal' else 'failed-launchFailed','dropToExitSeconds':5.5,
        'stopBeforeResult':False,'cancelBeforeResult':False,'deadlineBeforeResult':False,'failure':None,
        'closed':True,'pidGone':True,'fdReturnedToBaseline':True}


def relay(role):
    return {'mode':'forward' if role=='normal' else 'drop','pumpImplementation':'frozen-normal' if role=='normal' else 'bounded-local',
        'reason':'complete','finished':True,'armedAt':None if role=='normal' else 10,'failure':None,'cleanupFailed':False,
        'firstEOFDirection':'client','clientResultAt':16,'establishedAtArm':True,'bridgeAliveAtArm':True,
        'tcpSnapshotCount':4,'droppedBytes':[100,200],'cancelBeforeResult':False,'deadlineBeforeResult':False,
        'remoteBridgeAtArm':{'pid':123,'startTicks':10,'pidfdAlive':True},'remoteBridgeAtResult':{'pid':123,'startTicks':10,'pidfdAlive':True}}


class Pure(unittest.TestCase):
    def test_json_closed_bounds_duplicate_and_wrong_types(self):
        self.assertEqual(core.exact_json(core.encoded({'op':'bind'})),{'op':'bind'})
        for value in [b'',b'{}',b'[]\n',b'{"x":1,"x":2}\n',b'x'*2048+b'\n']:
            with self.assertRaises(core.Refused):core.exact_json(value)
        for field,value in [('generation',True),('sourcePort',22221+99999),('session','not-a-session'),('role','scan'),('run',1)]:
            data=bind();data[field]=value
            with self.assertRaises(core.Refused):core.binding(data)
        extra=bind();extra['extra']=1
        with self.assertRaises(core.Refused):core.binding(extra)

    def test_exact_lsof_own_pid_fd_established_tuple_not_accept_order(self):
        raw=b'p111\nu501\nf7\nPTCP\nn127.0.0.1:54321->127.0.0.1:22221\nTST=ESTABLISHED\n'
        self.assertEqual(core.lsof_connection(raw,111)['sourcePort'],54321)
        reverse=b'p99\nu501\nf8\nPTCP\nn127.0.0.1:22221->127.0.0.1:54321\nTST=ESTABLISHED\n'
        self.assertEqual(core.lsof_connection(reverse,99,fd=8,server=True)['sourcePort'],54321)
        for data in [raw.replace(b'ESTABLISHED',b'CLOSE_WAIT'),raw.replace(b'p111',b'p112'),raw+raw,
                     raw.replace(b'127.0.0.1:54321',b'10.0.0.1:54321'),raw.replace(b':22221',b':22222')]:
            with self.assertRaises(core.Refused):core.lsof_connection(data,111)
        with self.assertRaises(core.Refused):core.lsof_connection(raw,111,fd=9)

    def test_atomic_arm_discards_real_queues_before_clock_and_refuses_replay(self):
        flow=core.Flow();flow.bound=bind();flow.receive(0,b'public-dummy',0);flow.receive(1,b'other-dummy',0)
        def clock():
            self.assertEqual(flow.mode,'drop');self.assertEqual([len(q) for q in flow.queues],[0,0]);return 10
        result=flow.arm(bind(),clock,tcp_established=True,bridge_alive=True,safe_remaining=35)
        self.assertEqual(result['discardedAtArm'],[12,11]);self.assertEqual(result['armedAt'],10)
        flow.receive(0,b'x'*65536,11);self.assertEqual(flow.dropped,[65536,0]);self.assertFalse(any(flow.queues))
        with self.assertRaises(core.Refused):flow.wrote(0,1)
        with self.assertRaises(core.Refused):flow.arm(bind(),clock,tcp_established=True,bridge_alive=True,safe_remaining=35)
        for key,value in [('token','c'*32),('sourcePort',54322),('role','normal')]:
            bad=bind();bad[key]=value;new=core.Flow();new.bound=bind()
            with self.assertRaises(core.Refused):new.arm(bad,lambda:1,tcp_established=True,bridge_alive=True,safe_remaining=35)
        for established,alive,remaining in [(False,True,35),(True,False,35),(True,True,34.99)]:
            new=core.Flow();new.bound=bind()
            with self.assertRaises(core.Refused):new.arm(bind(),lambda:1,tcp_established=established,bridge_alive=alive,safe_remaining=remaining)

    def test_partial_write_eagain_bounds_and_drop_stale_write_readiness(self):
        flow=core.Flow();flow.receive(0,b'abcdef',0);flow.wrote(0,2);self.assertEqual(bytes(flow.queues[0]),b'cdef')
        with self.assertRaises(core.Refused):flow.receive(0,b'x'*65536,1)
        def blocked(*_):raise BlockingIOError()
        relay_control.forward_step(flow,[(1,2),(3,4)],[(2,selectors.EVENT_WRITE)],write=blocked)
        self.assertEqual(len(flow.queues[0]),4)
        flow.bound=bind();flow.arm(bind(),lambda:2,tcp_established=True,bridge_alive=True,safe_remaining=35)
        write=mock.Mock(side_effect=AssertionError('write after drop'))
        relay_control.forward_step(flow,[(1,2),(3,4)],[(2,selectors.EVENT_WRITE),(1,selectors.EVENT_READ)],
            read=lambda *_:b'xyz',write=write,now=lambda:3)
        write.assert_not_called();self.assertEqual(flow.dropped,[3,0])

    def test_forward_scan_eof_drains_each_direction_not_immediate_close(self):
        flow=core.Flow();flow.receive(0,b'abc',0);flow.eof('client',1);callbacks=[mock.Mock(),mock.Mock()]
        flow.drain_eof(callbacks);callbacks[0].assert_not_called();self.assertIsNone(flow.refused)
        flow.wrote(0,3);flow.drain_eof(callbacks);callbacks[0].assert_called_once();callbacks[1].assert_not_called()
        flow.receive(1,b'final',2);flow.eof('backend',3);flow.drain_eof(callbacks);callbacks[1].assert_not_called()
        flow.wrote(1,5);flow.drain_eof(callbacks);self.assertEqual(flow.half_closed,[True,True])
        self.assertEqual(flow.eof_times,[1,3])
        with self.assertRaises(core.Refused):flow.arm(bind(),lambda:4,tcp_established=True,bridge_alive=True,safe_remaining=35)

    def test_drop_never_halfcloses_and_proxy_eof_first_refuses(self):
        for side in ['client','backend']:
            flow=core.Flow();flow.bound=bind();flow.arm(bind(),lambda:1,tcp_established=True,bridge_alive=True,safe_remaining=35)
            flow.eof(side,2);callbacks=[mock.Mock(),mock.Mock()];flow.drain_eof(callbacks)
            self.assertFalse(any(c.called for c in callbacks))
            if side=='backend':
                with self.assertRaises(core.Refused):flow.result(3)
            else:flow.result(3);flow.eof('backend',4);self.assertIsNone(flow.refused)
        flow=core.Flow();flow.bound=bind();flow.eof('backend',0)
        with self.assertRaises(core.Refused):flow.arm(bind(),lambda:1,tcp_established=True,bridge_alive=True,safe_remaining=35)

    def test_verdict_never_passes_255_or_success_flags_alone(self):
        for role in ['normal','blackhole']:
            good=report(role);proxy=relay(role);self.assertTrue(core.verdict(role,good,proxy))
            for key,value in [('failure','cleanup'),('closed',False),('pidGone',False),('stopBeforeResult',True),('cancelBeforeResult',True),('deadlineBeforeResult',True),('shellACK',False)]:
                bad=dict(good);bad[key]=value;self.assertFalse(core.verdict(role,bad,proxy))
        for key,value in [('firstEOFDirection','backend'),('failure','read-error'),('bridgeAliveAtArm',False),('remoteBridgeAtResult',None),('tcpSnapshotCount',1),('deadlineBeforeResult',True),('droppedBytes',[0,0])]:
            bad=relay('blackhole');bad[key]=value;self.assertFalse(core.verdict('blackhole',report('blackhole'),bad))
        for seconds in [0,15.0001]:
            bad=report('blackhole');bad['dropToExitSeconds']=seconds;self.assertFalse(core.verdict('blackhole',bad,relay('blackhole')))
        bad=report('normal');bad['quietSeconds']=11.99;self.assertFalse(core.verdict('normal',bad,relay('normal')))
        bad=report('normal');bad['quietApplicationOutputEvents']=1;self.assertFalse(core.verdict('normal',bad,relay('normal')))

    def test_arm_boundary_detects_prequeued_backend_eof_and_accounts_pending_data(self):
        for blocks in [(b'x',b''),(b'',b'y')]:
            flow=core.Flow();flow.bound=bind();reader=mock.Mock(side_effect=blocks)
            relay_control.drain_pending_arm(flow,(1,3),read=reader,clock=lambda:2)
            with self.assertRaises(core.Refused):flow.arm(bind(),lambda:3,tcp_established=True,bridge_alive=True,safe_remaining=35)
        flow=core.Flow();flow.bound=bind()
        relay_control.drain_pending_arm(flow,(1,3),read=mock.Mock(side_effect=[b'client',b'backend']),clock=lambda:2)
        flow.arm(bind(),lambda:3,tcp_established=True,bridge_alive=True,safe_remaining=35)
        self.assertEqual(flow.discarded_at_arm,[6,7])

    def test_final_buffered_control_frame_is_read_before_child_exit_check(self):
        child=mock.Mock();child.stdout.fileno.return_value=90;child.poll.return_value=0
        selector=mock.MagicMock();selector.__enter__.return_value=selector;selector.select.return_value=[(mock.Mock(),1)]
        with mock.patch.object(supervise.selectors,'DefaultSelector',return_value=selector),mock.patch.object(supervise.os,'set_blocking'),mock.patch.object(supervise.os,'read',return_value=b'{"op":"closed"}\n'):
            self.assertEqual(supervise.read_frame(child,1),{'op':'closed'})
            child.poll.assert_not_called()

    def test_natural_result_bound_excludes_delayed_cleanup_but_cleanup_failure_still_fails(self):
        def execute(cleanup_failure=False,preclose_failure=False):
            clock=[100.0];run='a'*32
            proxy=mock.Mock(pid=201);consumer=mock.Mock(pid=202);proxy.wait.return_value=0;consumer.wait.return_value=0
            birth={'pid':111,'ppid':202,'uid':501,'startSeconds':100,'startMicroseconds':1}
            tcp={'sourcePort':54321,'state':'ESTABLISHED'}
            before=report('blackhole');before.update(closed=False,pidGone=False,fdReturnedToBaseline=False)
            if preclose_failure:before['failure']='connection'
            after=report('blackhole')
            if cleanup_failure:after['failure']='cleanup'
            events=[{'event':'ready','run':run,'role':'blackhole','pid':201,'port':22221},
                {'op':'shell-ready','run':run,'role':'blackhole','session':bind()['session'],'generation':1,'ssh':birth},
                {'op':'case-result','run':run,'role':'blackhole','report':before},
                {'op':'closed','run':run,'role':'blackhole','report':after}]
            def frame(*_):
                event=events.pop(0)
                if event.get('op')=='case-result':clock[0]=110.0
                elif event.get('op')=='closed':clock[0]+=30.0 # FD drain/close is after the natural result.
                return event
            queries=[]
            def query(_process,value,**_):
                op=value['op'];queries.append(op)
                if op=='lookup':return {'ok':True,'token':'b'*32,'sourcePort':54321}
                if op=='arm':return {'ok':True,'mode':'drop','establishedAtArm':True,'bridgeAliveAtArm':True,
                    'armedAt':100.1,'armedWall':1000.0,'relayNow':100.2,'relayWall':1000.1,'supervisorArmSentAt':100.0}
                if op=='result':clock[0]+=20.0 # Remote bridge result query is not detection time.
                return {'ok':True,**relay('blackhole')}
            drains={'exitCode':0,'terminated':False,'killed':False}
            with mock.patch.object(supervise.subprocess,'Popen',side_effect=[proxy,consumer]),mock.patch.object(supervise,'read_frame',side_effect=frame),\
                 mock.patch.object(supervise,'query',side_effect=query),mock.patch.object(supervise,'send'),\
                 mock.patch.object(supervise,'exact_owned_tcp',return_value=tcp),mock.patch.object(supervise,'stop_child',return_value=drains),\
                 mock.patch.object(supervise,'save'),mock.patch.object(supervise.Path,'open',return_value=io.BytesIO()),\
                 mock.patch.object(supervise.time,'monotonic',side_effect=lambda:clock[0]):
                result=supervise.run_case('blackhole',run,Path('/fake.app'),Path('/fake-tool'),Path('/fake-contract'),Path('/fake-work'))
            return result,queries
        good,_=execute();self.assertEqual(good['status'],'passed-real-limited-case')
        self.assertEqual(good['outcomeReceivedAt'],110.0);self.assertEqual(good['conservativeArmRequestToOutcomeSeconds'],10.0)
        self.assertGreater(good['endedAt']-100.0,15.0);self.assertTrue(good['coreVerdict'])
        bad,_=execute(cleanup_failure=True);self.assertEqual(bad['status'],'failed-retain-no-retry')
        self.assertEqual(bad['conservativeArmRequestToOutcomeSeconds'],10.0);self.assertFalse(bad['coreVerdict'])
        early,queries=execute(preclose_failure=True);self.assertEqual(early['status'],'failed-retain-no-retry')
        self.assertNotIn('result',queries)

    def test_fresh_ack_nonce_flip_is_always_distinct_lower_hex_including_palindrome(self):
        swift=(HERE/'Core.swift').read_text();consumer=(HERE/'Main.swift').read_text()
        self.assertIn('return (first == "0" ? "1" : "0") + previous.dropFirst()',swift)
        self.assertIn('ack(KeepaliveNonce.fresh(from:run))',consumer)
        self.assertNotIn('run.reversed()',consumer)
        for nonce in ['a'*32,'0'*32,'0123456789abcdeffedcba9876543210']+[n+'b'*31 for n in '0123456789abcdef']:
            fresh=('1' if nonce[0]=='0' else '0')+nonce[1:]
            self.assertNotEqual(fresh,nonce);self.assertRegex(fresh,r'^[0-9a-f]{32}$')

    def test_actual_relay_clock_origin_is_preserved_not_supervisor_origin(self):
        item=mock.Mock();item.metadata.return_value={'armedAt':22.534011875,'armedWall':1793156827.9269881}
        with mock.patch.object(relay_control.time,'monotonic',return_value=22.5574),mock.patch.object(relay_control.time,'time',return_value=1793156827.950376):
            actual=relay_control.arm_ack(item)
        child=mock.Mock()
        with mock.patch.object(supervise,'send'),mock.patch.object(supervise,'read_frame',return_value=actual),mock.patch.object(supervise.time,'monotonic',side_effect=[51.07501325,54.225535916]):
            forwarded=supervise.query(child,{'op':'arm'})
        self.assertEqual(forwarded['relayNow'],22.5574);self.assertEqual(forwarded['supervisorArmReceivedAt'],54.225535916)
        # Mirrors unchanged Main's strict arithmetic with independent Swift uptime (not assumed equal).
        def accepts(frame,local_wall,local_now=7000):
            transit=local_wall-frame['relayWall'];wall_elapsed=local_wall-frame['armedWall']
            delta=frame['relayNow']-frame['armedAt'];disagreement=abs((frame['relayWall']-frame['armedWall'])-delta)
            return transit>=0 and transit<2 and wall_elapsed>=0 and wall_elapsed<10 and delta>=0 and delta<=wall_elapsed+.2 and disagreement<.2
        localwall=1793156827.97
        self.assertTrue(accepts(forwarded,localwall))
        old=dict(forwarded,relayNow=54.225535916);self.assertFalse(accepts(old,localwall))
        self.assertFalse(accepts(dict(forwarded,relayWall=forwarded['armedWall']+1),localwall))
        source=(HERE/'supervise.py').read_text();self.assertIn("'relayNow':arm['relayNow'],'relayWall':arm['relayWall']",source)
        self.assertNotIn("'relayNow':time.monotonic()",source)

    def test_control_failure_ack_allows_owned_close_exit1_without_kill(self):
        child=mock.Mock(pid=123);child.poll.return_value=1;child.wait.return_value=1
        closed={'op':'closed','run':'a'*32,'role':'blackhole','report':dict(report('blackhole'),failure='control')}
        result={'status':'failed-retain-no-retry','preCloseReport':dict(report('blackhole'),failure='control')}
        with mock.patch.object(supervise,'send') as sent,mock.patch.object(supervise,'read_frame',return_value=closed):
            supervise.failed_consumer_cleanup(child,'blackhole','a'*32,result,False)
        sent.assert_called_once_with(child,{'op':'result-recorded','run':'a'*32,'role':'blackhole','ok':True})
        self.assertEqual(result['consumerExitCode'],1);self.assertEqual(result['closedReport']['failure'],'control')
        self.assertEqual(result['status'],'failed-retain-no-retry');self.assertTrue(result['failureCleanup']['closedFrameReceived'])
        drain=supervise.stop_child(child,grace=30);self.assertFalse(drain['terminated']);self.assertFalse(drain['killed'])
        child.kill.assert_not_called();child.terminate.assert_not_called()

    def test_broken_failure_control_uses_full_gentle_budget_then_records_last_resort(self):
        child=mock.Mock(pid=123);result={'preCloseReport':{'failure':'control'}}
        with mock.patch.object(supervise,'send',side_effect=BrokenPipeError()):
            supervise.failed_consumer_cleanup(child,'blackhole','a'*32,result,False)
        self.assertEqual(result['failureCleanup']['stage'],'control-unavailable-gentle-stop-required')
        child.poll.return_value=None;child.wait.side_effect=[subprocess.TimeoutExpired('owned',30),-9,-9]
        drain=supervise.stop_child(child,grace=30)
        self.assertEqual(child.wait.call_args_list,[mock.call(timeout=30),mock.call(timeout=3),mock.call()])
        self.assertTrue(drain['terminated']);self.assertTrue(drain['killed']);self.assertEqual(drain['exitCode'],-9)

    def test_blackhole_only_reuses_exact_A_and_unchanged_consumer_never_old_nonce(self):
        h=hashlib.sha256
        accepted={'role':'normal','status':'passed-real-limited-case','coreVerdict':True,'run':'a'*32,
            'closedReport':report('normal'),'relayAfterFinish':relay('normal'),
            'consumerDrain':{'exitCode':0,'terminated':False,'killed':False},'relayDrain':{'exitCode':0,'terminated':False,'killed':False}}
        cleanup={'run':'a'*32,'normalAndBlackholeRunRootsAbsent':True,'unknownEntriesRejected':True}
        signed={'sourceSHA256':{name:h((HERE/name).read_bytes()).hexdigest() for name in ['Main.swift','Core.swift','LiveInput.swift']},'driverSHA256':'c'*64}
        ap=Path('/fake/A.json');cp=Path('/fake/cleanup.json');sp=Path('/fake/signed.json');lp=ap.parent/'evidence-sha256.json'
        rawA=json.dumps(accepted).encode();rawC=json.dumps(cleanup).encode();rawS=json.dumps(signed).encode();rawL=json.dumps({str(cp):h(rawC).hexdigest()}).encode()
        class Hash:
            def __init__(self,raw):self.raw=raw
            def hexdigest(self):
                if self.raw==rawA:return 'ff0542b43ec30a399b4f6ef3477ba181af1d89135ee2800c4d80d8ed1b08bd83'
                if self.raw==rawL:return '752cc84ec7920bb88bb36c61e7010afd46bc620973dcf56ae485e6d35b501e27'
                if self.raw==rawS:return '795a52e1ae7fcb1222ddd04cca60c7a98d15da0816f750809b7f0145be9b95f0'
                return h(self.raw).hexdigest()
        read=Path.read_bytes
        def fake_read(path):return {ap:rawA,cp:rawC,sp:rawS,lp:rawL}.get(path) or read(path)
        # Only fake fixture evidence. No credentials, network or runtime case calls.
        with mock.patch.object(Path,'read_bytes',fake_read),mock.patch.object(supervise.hashlib,'sha256',side_effect=Hash):
            proof=supervise.prior_normal_proof(ap,cp,sp,new_run='b'*32,current_consumer_hash='c'*64)
            self.assertTrue(proof['reusedNotRerun'])
            with self.assertRaises(core.Refused):supervise.prior_normal_proof(ap,cp,sp,new_run='a'*32,current_consumer_hash='c'*64)
            with self.assertRaises(core.Refused):supervise.prior_normal_proof(ap,cp,sp,new_run='b'*32,current_consumer_hash='d'*64)

    def test_default_import_and_help_do_not_open_sockets_or_processes(self):
        with mock.patch('socket.socket',side_effect=AssertionError('socket')),mock.patch('subprocess.Popen',side_effect=AssertionError('process')):
            with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(relay_control.main([]),64)

    def test_source_no_payload_logging_or_production_mutation(self):
        source=(HERE/'relay_control.py').read_text();consumer=(HERE/'Main.swift').read_text()
        for forbidden in ['shell=True','startProbe','configureProbe','session.respond','savedPassword','CredentialStore','SecItem','NSPasteboard']:
            self.assertNotIn(forbidden,source+consumer)
        self.assertIn('serverAliveInterval:2,serverAliveCountMax:2',consumer)
        self.assertIn('FD_CLOEXEC',consumer);self.assertIn("self.bridge.pump(",source)
        self.assertNotIn('TCP_CONNECTION_INFO',source) # Exact own-FD lsof, no raw struct offsets.
        for path in HERE.glob('*.py'):ast.parse(path.read_text())


if __name__=='__main__':unittest.main(verbosity=2)
