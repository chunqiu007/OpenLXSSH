#!/usr/bin/env python3
"""No Docker/socket/SSH. Pure config/classification and own Python child fakes."""
import importlib.util
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.dont_write_bytecode=True
HERE=Path(__file__).absolute().parent
sys.path.insert(0,str(HERE))
import server_helper as server

CONFIG='Port 2222\nListenAddress 0.0.0.0\nHostKey /run/openlxssh-fixture/current/host_ed25519\nPidFile /run/openlxssh-fixture/sshd.pid\nLogLevel ERROR\nAuthenticationMethods publickey\nUsePAM yes\n'


class Tests(unittest.TestCase):
    def test_01_syntax_size_inert_and_argv(self):
        compile((HERE/'server_helper.py').read_bytes(),'server_helper.py','exec')
        self.assertLessEqual(len((HERE/'server_helper.py').read_text().splitlines()),220)
        for args in ([],['--help']):
            with mock.patch.object(server,'execute',side_effect=AssertionError('runtime')),mock.patch('sys.stdout',io.StringIO()):self.assertEqual(server.main(args),0)
        for args in (['--authorized-server-case','bad'],['--port','2223']):
            with self.assertRaises(ValueError):server.main(args)

    def test_02_exact_four_config_changes_and_refusals(self):
        result=server.configuration(CONFIG,'/tmp/owned')
        before=CONFIG.splitlines();after=result.splitlines()
        self.assertEqual(sum(a!=b for a,b in zip(before,after)),4)
        self.assertIn('HostKey /run/openlxssh-fixture/current/host_ed25519',result)
        self.assertIn('AuthenticationMethods publickey',result)
        for raw in (CONFIG+'Port 2222\n',CONFIG.replace('Port 2222','Port 22'),CONFIG.replace('LogLevel ERROR\n','')):
            with self.assertRaises(ValueError):server.configuration(raw,'/tmp/owned')

    def test_03_static_classification_never_returns_dynamic_data(self):
        raw=b'fatal: linux_audit_write_entry failed: Operation not permitted\nchown(/SECRET-PATH, 10000, 5) failed: Permission denied\nlogin_write: Read-only file system\n'
        value=server.classify(raw)
        self.assertIn('audit-fatal',value['classes']);self.assertIn('pty-owner-chown',value['classes']);self.assertIn('login-accounting',value['classes'])
        self.assertEqual(value['errnos'],[1,13,30]);self.assertTrue(value['permissionDeniedOrReadonly'])
        self.assertNotIn('SECRET',str(value))
        self.assertEqual(server.classify(b'UNKNOWN PRIVATE LINE')['classes'],[])

    def test_04_workspace_only_held_config_and_empty_root(self):
        with tempfile.TemporaryDirectory(prefix='openlxssh-serverworkspace-') as raw:
            token='a'*32
            real_mkdir=server.os.mkdir;real_open=server.os.open;real_lstat=server.os.lstat;real_rmdir=server.os.rmdir
            target=Path(raw)/'owned'
            def mapped(path):return str(target) if path=='/tmp/openlxssh-server-pty-'+token else path
            with mock.patch.object(server.os,'mkdir',side_effect=lambda path,mode:real_mkdir(mapped(path),mode)), \
                    mock.patch.object(server.os,'open',side_effect=lambda path,*args,**kw:real_open(mapped(path),*args,**kw)), \
                    mock.patch.object(server.os,'lstat',side_effect=lambda path:real_lstat(mapped(path))), \
                    mock.patch.object(server.os,'rmdir',side_effect=lambda path:real_rmdir(mapped(path))):
                owner=server.Workspace(token,CONFIG)
                self.assertEqual((target/'sshd_config').stat().st_mode&0o777,0o600)
                (target/'unknown').write_text('PUBLIC_BYSTANDER')
                owner.close()
                self.assertFalse((target/'sshd_config').exists());self.assertTrue((target/'unknown').exists())

    def run_capture(self,mode):
        real_popen=subprocess.Popen;children=[]
        def spawn(args,**kwargs):
            if args==['server']:
                code="import os,time;os.write(2,b'Server listening on 127.0.0.1 port 2223.\\n');time.sleep(.03)"
                if mode=='overflow':code="import os,time;os.write(2,b'x'*70000);time.sleep(30)"
                if mode=='timeout':code='import time;time.sleep(30)'
            else:code="import os;os.write(1,b'PUBLIC_ACK\\n')"
            p=real_popen([sys.executable,'-u','-c',code],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0);children.append(p);return p
        class Tree:
            def add(self,p):pass
            def discover(self):pass
        try:
            with mock.patch.object(server.subprocess,'Popen',side_effect=spawn):
                first=spawn(['server']);peer,data,failure=server.capture(Tree(),first,['client'],time.monotonic()+(.08 if mode=='timeout' else 1))
            return len(children),data,failure
        finally:
            for p in children:
                if p.poll() is None:p.terminate()
                try:p.wait(timeout=1)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=1)
                p.stdout.close();p.stderr.close()
                with self.assertRaises(ChildProcessError):os.waitpid(p.pid,os.WNOHANG)

    def test_05_ready_log_only_launches_one_client(self):
        count,data,failure=self.run_capture('normal')
        self.assertEqual(count,2);self.assertIsNone(failure);self.assertEqual(bytes(data[2]),b'PUBLIC_ACK\n')
        count,data,failure=self.run_capture('timeout');self.assertEqual(count,1);self.assertEqual(failure,'execution-deadline')
        self.assertNotIn('socket.',(HERE/'server_helper.py').read_text())

    def test_06_combined_output_limit(self):
        count,data,failure=self.run_capture('overflow')
        self.assertEqual(count,1);self.assertEqual(failure,'combined-output-limit');self.assertLessEqual(sum(map(len,data)),65537)

    def test_07_pidfd_open_failure_fallback_reaps_root_and_closes_pipes(self):
        process=subprocess.Popen([sys.executable,'-u','-c','import time;time.sleep(30)'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        tree=server.OwnedTree.__new__(server.OwnedTree);tree.roots={};tree.owned={};tree.libc=mock.Mock();tree.previous=0
        try:
            with mock.patch.object(server.os,'pidfd_open',side_effect=OSError(24,'controlled'),create=True):
                with self.assertRaises(OSError):tree.add(process)
            with mock.patch.object(tree,'discover',side_effect=OSError(5,'controlled discovery')),mock.patch.object(tree,'children',side_effect=lambda parent:[process.pid] if process.poll() is None else []):
                self.assertFalse(tree.close())
            self.assertIsNotNone(process.poll());self.assertTrue(process.stdout.closed and process.stderr.closed)
            with self.assertRaises(ChildProcessError):os.waitpid(process.pid,os.WNOHANG)
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=2)
            process.stdout.close();process.stderr.close()

    def test_08_exact_descendant_identity_and_normal_exit_during_discovery(self):
        tree=server.OwnedTree.__new__(server.OwnedTree);tree.owned={};tree.roots={}
        with mock.patch.object(server.os,'pidfd_open',return_value=987654,create=True),mock.patch.object(tree,'metadata',return_value=(100,200,0)),mock.patch.object(server.os,'close'):
            tree.capture(300,100);self.assertEqual(tree.owned,{300:(987654,200,0)})
            with mock.patch.object(server.signal,'pidfd_send_signal',create=True) as send:
                tree.send(300,signal.SIGTERM);send.assert_called_once_with(987654,signal.SIGTERM)
            with mock.patch.object(tree,'metadata',return_value=(100,201,0)),mock.patch.object(server.signal,'pidfd_send_signal',create=True) as send:
                with self.assertRaises(ValueError):tree.send(300,signal.SIGTERM)
                send.assert_not_called()
        tree.owned={}
        with mock.patch.object(tree,'children',return_value=[300]),mock.patch.object(tree,'capture',side_effect=FileNotFoundError):tree.discover()
        with mock.patch.object(tree,'children',return_value=[300]),mock.patch.object(tree,'capture',side_effect=ProcessLookupError):tree.discover()
        with mock.patch.object(server.os,'pidfd_open',return_value=987654,create=True),mock.patch.object(tree,'metadata',return_value=(999,200,0)),mock.patch.object(server.os,'close') as close:
            with self.assertRaises(ValueError):tree.capture(300,100)
            close.assert_called_once_with(987654)


if __name__=='__main__':unittest.main(verbosity=2)
