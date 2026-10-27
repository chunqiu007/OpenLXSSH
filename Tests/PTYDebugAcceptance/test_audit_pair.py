#!/usr/bin/env python3
"""Pure A/B plan/identity tests; no Docker, container, key or network work."""
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

sys.dont_write_bytecode=True
HERE=Path(__file__).absolute().parent
sys.path.insert(0,str(HERE))
import audit_pair as pair
RUN='a'*32
NETWORK='c'*64


def container(case):
    name,volume=pair.names(RUN,case)
    return {'Id':('a' if case=='A' else 'b')*64,'Name':'/'+name,'Image':pair.IMAGE,'State':{'Status':'running'},
        'Config':{'Labels':pair.labels(RUN,case),'Entrypoint':['python3','/opt/openlxssh-fixture/server.py'],'Cmd':['serve','--authorized-run','--mode','keyonly']},
        'HostConfig':{'CapAdd':['CAP_'+cap for cap in pair.caps(case)],'CapDrop':['ALL'],'Privileged':False,'ReadonlyRootfs':True,'SecurityOpt':['no-new-privileges:true'],'Init':True,
            'Memory':402653184,'MemorySwap':402653184,'NanoCpus':500000000,'PidsLimit':128,'ShmSize':67108864,'LogConfig':{'Type':'none'},'PortBindings':{},'PublishAllPorts':False,
            'RestartPolicy':{'Name':'no'},'Tmpfs':pair.TMPFS,'NetworkMode':pair.names(RUN),'Ulimits':[{'Name':'nofile','Soft':1024,'Hard':1024}]},
        'NetworkSettings':{'Networks':{'own':{'NetworkID':NETWORK}}},'Mounts':[{'Type':'volume','Name':volume,'Destination':'/fixture','RW':True}]}


class Tests(unittest.TestCase):
    def test_01_syntax_default_plan_no_io_and_guards(self):
        compile((HERE/'audit_pair.py').read_bytes(),'audit_pair.py','exec')
        for args in ([],['--help'],['plan']):
            with mock.patch.object(pair,'live',side_effect=AssertionError('live')),mock.patch.object(pair.os,'open',side_effect=AssertionError('I/O')),mock.patch('sys.stdout',io.StringIO()):
                try:result=pair.main(args)
                except SystemExit as error:result=error.code
                self.assertEqual(result,0)
        for args in (['live'],['live','--authorized-isolated-pair']):
            with mock.patch('sys.stderr',io.StringIO()),self.assertRaises(SystemExit):pair.main(args)

    def test_02_single_capability_difference(self):
        self.assertEqual(set(pair.caps('B'))-set(pair.caps('A')),{'AUDIT_WRITE'})
        self.assertEqual(pair.expected_mask('B')^pair.expected_mask('A'),1<<29)
        for forbidden in ('AUDIT_CONTROL','AUDIT_READ','SYS_TTY_CONFIG','SYS_ADMIN','NET_ADMIN'):self.assertNotIn(forbidden,pair.caps('B'))

    def test_03_fixed_create_recipe_no_ports_binds_original_volume_or_build(self):
        args=pair.create_args(RUN,'A',pair.names(RUN))
        self.assertEqual(args[-5:],[pair.IMAGE,'serve','--authorized-run','--mode','keyonly'])
        self.assertIn('--read-only',args);self.assertIn('no-new-privileges:true',args);self.assertIn('nofile=1024:1024',args)
        self.assertNotIn('--health-cmd',args)
        self.assertIn('384m',args);self.assertIn('128',args);self.assertIn('0.5',args)
        self.assertNotIn('--publish',args);self.assertNotIn('--privileged',args);self.assertNotIn('--network=host',args)
        self.assertFalse(any('key-data' in value or 'docker.sock' in value for value in args))
        self.assertIn('type=volume,source='+pair.names(RUN,'A')[1]+',target=/fixture',args)

    def test_04_exact_id_labels_names_and_network(self):
        for case in ('A','B'):pair.verify_container(container(case),RUN,case,NETWORK)
        base=container('A')
        for field,value in [('Id','short'),('Image','mutable:tag'),('Name','/foreign')]:
            wrong=copy.deepcopy(base);wrong[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):pair.verify_container(wrong,RUN,'A',NETWORK)
        wrong=copy.deepcopy(base);wrong['Config']['Labels'][pair.LABEL+'.run']='b'*32
        with self.assertRaises(ValueError):pair.verify_container(wrong,RUN,'A',NETWORK)
        wrong=copy.deepcopy(base);wrong['NetworkSettings']['Networks']['own']['NetworkID']='d'*64
        with self.assertRaises(ValueError):pair.verify_container(wrong,RUN,'A',NETWORK)

    def test_05_foreign_mount_privilege_resource_drift_rejected(self):
        base=container('B')
        for field,value in [('Privileged',True),('ReadonlyRootfs',False),('Memory',1),('PidsLimit',1024),('LogConfig',{'Type':'json-file'}),('PortBindings',{'2222/tcp':[{'HostIp':'0.0.0.0','HostPort':'2222'}]}),('CapAdd',['CAP_SYS_ADMIN'])]:
            wrong=copy.deepcopy(base);wrong['HostConfig'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):pair.verify_container(wrong,RUN,'B',NETWORK)
        wrong=copy.deepcopy(base);wrong['Mounts'][0]['Type']='bind'
        with self.assertRaises(ValueError):pair.verify_container(wrong,RUN,'B',NETWORK)
        for state in ('created','exited'):
            value=copy.deepcopy(base);value['State']['Status']=state;value['NetworkSettings']['Networks']={};pair.verify_container(value,RUN,'B',NETWORK)

    def test_06_actual_root_monitor_masks_nnp_and_no_egress(self):
        for case in ('A','B'):
            status={'Uid':'0 0 0 0','CapEff':hex(pair.expected_mask(case)),'CapPrm':hex(pair.expected_mask(case)),'CapBnd':hex(pair.expected_mask(case)),'NoNewPrivs':'1'}
            value={'sshdStatus':status,'noDefaultRoute':True,'shmTotal':67108864}
            pair.verify_status(value,case)
            wrong=copy.deepcopy(value);wrong['sshdStatus']['CapEff']='0'
            with self.assertRaises(ValueError):pair.verify_status(wrong,case)
            wrong=copy.deepcopy(value);wrong['noDefaultRoute']=False
            with self.assertRaises(ValueError):pair.verify_status(wrong,case)

    def test_07_outcomes_reject_generic_failures_and_falsepositive_ack(self):
        value={'exit':0,'ackLF':True,'ackCRLF':False,'boundedFailure':None,'rawLogged':False,'childReaped':True,'pipesClosed':True}
        self.assertTrue(pair.expected_result(value,'A','T'))
        self.assertFalse(pair.expected_result(value,'A','TT'))
        failed=dict(value,exit=255,ackLF=False)
        self.assertTrue(pair.expected_result(failed,'A','TT'));self.assertFalse(pair.expected_result(failed,'B','TT'))
        success=dict(value,ackLF=False,ackCRLF=True)
        self.assertTrue(pair.expected_result(success,'B','TT'))
        for key,changed in [('exit',-15),('boundedFailure','execution-deadline'),('rawLogged',True),('childReaped',False)]:
            wrong=dict(success,**{key:changed});self.assertFalse(pair.expected_result(wrong,'B','TT'))

    def test_08_cleanup_fixed_exact_stop_then_rm_and_no_global_prune(self):
        text=(HERE/'audit_pair.py').read_text()
        self.assertLess(text.index("cli(['stop','--time','5',identifier]"),text.index("cli(['rm',identifier]"))
        self.assertIn("if stopped['State']['Running']:raise",text)
        self.assertIn("require_labels(item,run,case)",text)
        self.assertIn("require_labels(network,run,'network')",text)
        self.assertNotIn("['rm','-f'",text);self.assertNotIn('prune',text)
        self.assertIn("for case in ('A','B'):",text)
        self.assertIn('finally:\n                results.append(case_result)',text)
        self.assertIn("remove_case(case,min(end,time.monotonic()+25))",text)
        self.assertIn("entry['exit']=0",text);self.assertIn("entry['exit']='unknown_or_failure'",text)
        self.assertIn("'failedStage':stage if failure else None",text);self.assertIn('os.fsync(stream.fileno())',text)
        for filename in ('run-owned.json','network-created.json','-volume-created.json','-container-created.json'):self.assertIn(filename,text)
        self.assertIn("ready_limit=min(deadline-60,time.monotonic()+60)",text)
        self.assertIn("'/opt/openlxssh-fixture/server.py','health','--authorized-run'",text)
        for token in ('bad','a'*33):
            with self.assertRaises(ValueError):pair.names(token)


    def test_09_preflight_timeout_is_recorded_without_creating_or_adopting_resources(self):
        source=(HERE/'audit_pair.py').read_text()
        source=source.replace("FIXTURE=HERE.parent/'IntegrationEnvironment'", "FIXTURE=ORIGINAL_FIXTURE")
        calls=[]
        def bounded(command,environment,deadline,cancel,limit):
            calls.append(command)
            self.assertEqual(command[3:],['inspect']+list(pair.ROOT_IDS))
            self.assertGreater(deadline-time.monotonic(),19)
            raise TimeoutError('synthetic metadata deadline')
        with tempfile.TemporaryDirectory(prefix='openlxssh-audit-preflight-') as temporary:
            module=types.ModuleType('audit_pair_under_test');module.__file__=str(Path(temporary).resolve()/'audit_pair.py')
            Path(module.__file__).write_text(source)
            module.__dict__['ORIGINAL_FIXTURE']=pair.FIXTURE
            exec(compile(source,'audit-pair-preflight-test','exec'),module.__dict__)
            old_path=list(sys.path)
            try:
                with mock.patch.object(module.Path,'read_text',return_value=(HERE/'client_helper.py').read_text()), \
                        mock.patch.object(module.importlib.util,'spec_from_file_location',return_value=object()), \
                        mock.patch.object(module.importlib.util,'module_from_spec',return_value=types.SimpleNamespace(_bounded_stdout=bounded)), \
                        mock.patch('sys.stdout',io.StringIO()):
                    module.importlib.util.spec_from_file_location=mock.Mock(return_value=types.SimpleNamespace(name='fake_relay',loader=types.SimpleNamespace(exec_module=lambda _:None)))
                    self.assertEqual(module.live(),2)
            finally:
                sys.path[:]=old_path
                sys.modules.pop('fake_relay',None)
            result=json.loads(next((Path(temporary)/'.build').glob('audit-pair-*/result.json')).read_bytes())
            self.assertEqual(result['failedStage'],'preflight-original')
            self.assertEqual(result['failure'],'TimeoutError');self.assertIsNone(result['originalUnchanged'])
            self.assertTrue(result['cleanupComplete']);self.assertEqual(result['results'],[])
            self.assertEqual(len(calls),1)
            prepared=list((Path(temporary)/'.build').glob('audit-pair-*/prepared.json'))
            self.assertEqual(len(prepared),1)
            commands=json.loads(next((Path(temporary)/'.build').glob('audit-pair-*/commands.json')).read_bytes())
            self.assertEqual(commands[0]['exit'],'unknown_or_failure')
            self.assertEqual(commands[0]['expectedExit'],0)


if __name__=='__main__':unittest.main(verbosity=2)
