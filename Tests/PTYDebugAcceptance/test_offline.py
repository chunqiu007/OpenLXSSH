#!/usr/bin/env python3
"""Pure/fake diagnostic tests; no socket, SSH, Docker or credential reads."""
import importlib.util
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest import mock

sys.dont_write_bytecode=True
HERE=Path(__file__).absolute().parent
spec=importlib.util.spec_from_file_location('client_helper',HERE/'client_helper.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)


class Tests(unittest.TestCase):
    def test_syntax_size_default_guards(self):
        compile((HERE/'client_helper.py').read_bytes(),'client_helper.py','exec')
        self.assertLessEqual(len((HERE/'client_helper.py').read_text().splitlines()),100)
        for args in ([],['--help']):
            with mock.patch.object(helper,'gate',side_effect=AssertionError('gate called')),mock.patch.object(helper.subprocess,'Popen',side_effect=AssertionError('child')),mock.patch('sys.stdout',io.StringIO()):self.assertEqual(helper.main(args),0)
        for args in (['--authorized-container-case','bad'],['--host','other'],['--authorized-container-case','a'*32,'extra']):
            with self.assertRaises(ValueError):helper.main(args)

    def test_fixed_linux_argv_and_no_darwin_or_arbitrary_address(self):
        args=helper.argv('a'*32)
        self.assertEqual(args[:9],['/usr/bin/ssh','-F','/dev/null','-vv','-tt','-p','2222','-l','fixture'])
        self.assertEqual(args[-3:-1],['--','127.0.0.1'])
        self.assertIn('HostKeyAlias=[127.0.0.1]:22221',args)
        self.assertIn('UserKnownHostsFile=/run/openlxssh-fixture/host_known_hosts',args)
        self.assertNotIn('UseKeychain=no',args)
        self.assertIn('/run/openlxssh-fixture/client/id_ed25519',args)
        self.assertIn('BatchMode=yes',args);self.assertIn('IdentityAgent=none',args)
        self.assertIn('ServerAliveInterval=5',args);self.assertIn('ServerAliveCountMax=1',args)

    def invoke_fake(self,code,timeout=1):
        real_popen=subprocess.Popen;children=[];signals=[]
        def spawn(*args,**kwargs):
            process=real_popen([sys.executable,'-u','-c',code],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            children.append(process);return process
        def send(handle,value):
            self.assertEqual(handle,987654);signals.append(value)
            children[0].send_signal(value)
        original_close=os.close
        def close(fd):
            if fd!=987654:original_close(fd)
        with mock.patch.object(helper.subprocess,'Popen',side_effect=spawn),mock.patch.object(helper.os,'pidfd_open',return_value=987654,create=True), \
                mock.patch.object(helper.signal,'pidfd_send_signal',side_effect=send,create=True),mock.patch.object(helper.os,'close',side_effect=close):
            result=helper.run_owned(['fixed-not-executed'],time.monotonic()+timeout)
        self.assertEqual(len(children),1);self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)
        with self.assertRaises(ChildProcessError):os.waitpid(children[0].pid,os.WNOHANG)
        return result,signals

    def test_fake_success_partial_capture_reap(self):
        (code,out,err,failure),signals=self.invoke_fake("import os; os.write(1,b'PUBLIC_ACK\\n');os.write(2,b'debug1: PTY allocation request accepted on channel 0\\n')")
        self.assertEqual((code,out,failure),(0,b'PUBLIC_ACK\n',None));self.assertEqual(signals,[])
        self.assertTrue(any(__import__('re').fullmatch(helper.STAGES['pty-accepted'],line) for line in err.splitlines()))

    def test_fake_deadline_term_ignoring_child_kill_and_wait(self):
        (code,out,err,failure),signals=self.invoke_fake('import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)',.1)
        self.assertEqual(failure,'execution-deadline');self.assertEqual(signals,[signal.SIGTERM,signal.SIGKILL]);self.assertEqual(code,-signal.SIGKILL)

    def test_fake_combined_output_limit(self):
        (code,out,err,failure),signals=self.invoke_fake("import os,time;os.write(1,b'x'*70000);time.sleep(30)")
        self.assertEqual(failure,'combined-output-limit');self.assertLessEqual(len(out)+len(err),65537)

    def exceptional_child(self,kind):
        real_popen=subprocess.Popen;children=[]
        def spawn(*args,**kwargs):
            p=real_popen([sys.executable,'-u','-c',"import os,time;os.write(1,b'PUBLIC');time.sleep(30)"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            children.append(p);return p
        original_close=os.close;original_read=os.read
        def read_error(fd,size):
            if any(fd==p.stdout.fileno() for p in children):raise OSError(5,'controlled read failure')
            return original_read(fd,size)
        def close(fd):
            if fd!=987654:original_close(fd)
        try:
            with mock.patch.object(helper.subprocess,'Popen',side_effect=spawn), \
                    mock.patch.object(helper.os,'pidfd_open',side_effect=OSError(24,'fd limit') if kind=='pidfd' else None,return_value=987654,create=True), \
                    mock.patch.object(helper.signal,'pidfd_send_signal',side_effect=lambda handle,sig:children[0].send_signal(sig),create=True), \
                    mock.patch.object(helper.os,'close',side_effect=close):
                if kind=='read':
                    with mock.patch.object(helper.os,'read',side_effect=read_error):
                        with self.assertRaises(OSError):helper.run_owned(['not-executed'],time.monotonic()+1)
                else:
                    with self.assertRaises(OSError):helper.run_owned(['not-executed'],time.monotonic()+1)
            self.assertIsNotNone(children[0].poll(),'owned child leaked after '+kind+' failure')
            self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)
            with self.assertRaises(ChildProcessError):os.waitpid(children[0].pid,os.WNOHANG)
        finally:
            for p in children:
                if p.poll() is None:p.kill();p.wait(timeout=2)
                p.stdout.close();p.stderr.close()

    def test_pidfd_open_failure_reaps_and_closes_owned_child(self):self.exceptional_child('pidfd')
    def test_read_failure_reaps_and_closes_owned_child(self):self.exceptional_child('read')

    def test_only_static_classification_no_raw_response(self):
        token='a'*32
        raw=b'PUBLIC_DIAGNOSTIC_OMITTED\n';err=b'debug1: Sending command: SECRETLIKE_NOT_REPORTED\nother PRIVATE_NOT_REPORTED\n'
        with mock.patch.object(helper,'gate'),mock.patch.object(helper,'run_owned',return_value=(255,raw,err,None)),mock.patch('sys.stdout',io.StringIO()) as output:
            helper.execute(token)
        text=output.getvalue();self.assertNotIn('PUBLIC_DIAGNOSTIC_OMITTED',text);self.assertNotIn('PRIVATE_NOT_REPORTED',text);self.assertNotIn('SECRETLIKE_NOT_REPORTED',text)
        self.assertIn('exec-sent',text)


if __name__=='__main__':unittest.main(verbosity=2)
