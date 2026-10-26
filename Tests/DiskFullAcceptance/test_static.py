#!/usr/bin/env python3
"""Pure offline tests; local tiny controlled writes only, never fill host storage."""
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.dont_write_bytecode=True
HERE=Path(__file__).absolute().parent


def load(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result


class Tests(unittest.TestCase):
    def test_syntax_and_inert_defaults(self):
        for source in HERE.glob('*.py'):compile(source.read_bytes(),str(source),'exec')
        for name in ('management','build_host'):
            module=load(name)
            for args in ([],['--help'],['validate'] if name=='build_host' else ['validate','--case',module.OWN+'/.runtime/enospc-12345678-1234-1234-1234-123456789abc/case.json']):
                with mock.patch.object(module.os,'open',side_effect=AssertionError('default I/O')), \
                     mock.patch.object(module.subprocess,'Popen',side_effect=AssertionError('default child')),mock.patch('sys.stdout',io.StringIO()):
                    try:
                        result=module.main(args)
                    except SystemExit as exit_value:
                        result=exit_value.code
                    self.assertEqual(result,0)

    def owner(self,base):
        module=load('management_helper')
        owner=module.Owner('12345678-1234-1234-1234-123456789abc')
        owner.parent=os.open(base,os.O_RDONLY|os.O_DIRECTORY)
        name='openlxssh-enospc-'+owner.case_id
        os.mkdir(name,0o700,dir_fd=owner.parent)
        owner.directory=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=owner.parent)
        info=os.fstat(owner.directory);owner.directory_identity=(info.st_dev,info.st_ino)
        owner.filler=os.open('filler.bin',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=owner.directory)
        info=os.fstat(owner.filler);owner.filler_identity=(info.st_dev,info.st_ino)
        owner.phase='ready'
        return module,owner,Path(base)/name

    def fake_uid_stat(self,module):
        real=module.os.stat
        def result(*args,**kwargs):
            info=real(*args,**kwargs)
            return type('Info',(),{'st_mode':info.st_mode,'st_uid':10000,'st_nlink':info.st_nlink,
                'st_size':info.st_size,'st_dev':info.st_dev,'st_ino':info.st_ino})()
        return mock.patch.object(module.os,'stat',side_effect=result)

    def test_small_owned_fd_release_and_no_unknown_delete(self):
        with tempfile.TemporaryDirectory(prefix='openlxssh-enospc-mechanism-') as raw:
            module,owner,directory=self.owner(raw)
            with mock.patch.object(module.os,'getuid',return_value=10000),self.fake_uid_stat(module):
                os.write(owner.filler,b'public-small-mechanism'*8)
                fd=owner.filler
                owner.release()
                self.assertEqual(os.fstat(fd).st_size,0)
                (directory/'unknown').write_text('public-bystander')
                owner.close()
                self.assertFalse((directory/'filler.bin').exists())
                self.assertTrue((directory/'unknown').exists())
                self.assertTrue(directory.is_dir())

    def test_replacement_preserved_and_original_inode_freed(self):
        with tempfile.TemporaryDirectory(prefix='openlxssh-enospc-replacement-') as raw:
            module,owner,directory=self.owner(raw)
            original=os.dup(owner.filler)
            try:
                os.write(owner.filler,b'public-small-mechanism')
                (directory/'filler.bin').unlink()
                (directory/'filler.bin').write_text('PUBLIC_REPLACEMENT')
                with mock.patch.object(module.os,'getuid',return_value=10000):owner.close()
                self.assertEqual(os.fstat(original).st_size,0)
                self.assertEqual((directory/'filler.bin').read_text(),'PUBLIC_REPLACEMENT')
            finally:os.close(original)

    def test_fill_limit_once_real_small_write_and_ttl_refusal(self):
        with tempfile.TemporaryDirectory(prefix='openlxssh-enospc-smallfill-') as raw:
            module,owner,directory=self.owner(raw)
            (directory/'target.bin').write_bytes(b'x'*65536)
            (directory/'target.bin').chmod(0o600)
            original_stat=module.os.stat
            def targetstat(*args,**kwargs):
                value=original_stat(*args,**kwargs)
                if args[0]=='target.bin':
                    return type('Info',(),{'st_mode':value.st_mode,'st_uid':10000,'st_nlink':1,'st_size':65536})()
                return value
            with mock.patch.object(module,'FILL',4096),mock.patch.object(module.os,'stat',side_effect=targetstat), \
                    mock.patch.object(owner,'fs',return_value={'totalBytes':module.TOTAL,'availableBytes':module.TOTAL-4096,'blockBytes':4096}), \
                    mock.patch.object(module.os,'getuid',return_value=10000):
                self.assertEqual(owner.fill()['filledBytes'],4096)
                self.assertGreaterEqual(os.fstat(owner.filler).st_blocks*512,4096)
                with self.assertRaises(ValueError):owner.fill()
                owner.deadline=0
                with self.assertRaises(TimeoutError):owner.check()
                owner.close()

    def test_sample_errno_is_only_real_oserror_and_once(self):
        with tempfile.TemporaryDirectory(prefix='openlxssh-enospc-sample-') as raw:
            module,owner,directory=self.owner(raw)
            owner.phase='filled';owner.filled=4096
            with mock.patch.object(owner,'fs',return_value={'totalBytes':module.TOTAL,'availableBytes':0,'blockBytes':4096}), \
                    mock.patch.object(module.os,'write',side_effect=OSError(28,'synthetic-interface-not-live')),mock.patch.object(module.os,'getuid',return_value=10000):
                event=owner.sample();self.assertTrue(event['realENOSPC']);self.assertEqual(event['errno'],28)
                with self.assertRaises(ValueError):owner.sample()
            with mock.patch.object(module.os,'getuid',return_value=10000):owner.close()
            # This was an offline interface injection, never a real ENOSPC claim.

    def test_serve_eof_and_deadline_always_release_held_fd(self):
        for ending in ('eof','ttl','bad-command'):
            with self.subTest(ending=ending),tempfile.TemporaryDirectory(prefix='openlxssh-enospc-serve-') as raw:
                module,owner,directory=self.owner(raw)
                os.write(owner.filler,b'public-small-mechanism')
                original=os.dup(owner.filler)
                class Selector:
                    def __enter__(self):return self
                    def __exit__(self,*_):pass
                    def register(self,*_):pass
                    def select(self,*_):return [] if ending=='ttl' else [True]
                parts=iter(b'{"caseID":"wrong","action":"fill"}\n')
                def read(*_):return b'' if ending=='eof' else bytes([next(parts)])
                try:
                    with mock.patch.object(module,'Owner',return_value=owner),mock.patch.object(owner,'prepare',return_value={}), \
                            mock.patch.object(module,'emit'),mock.patch.object(module.signal,'signal'),mock.patch.object(module.signal,'setitimer'), \
                            mock.patch.object(module.selectors,'DefaultSelector',return_value=Selector()),mock.patch.object(module.os,'read',side_effect=read), \
                            mock.patch.object(module.os,'getuid',return_value=10000),self.fake_uid_stat(module):
                        if ending=='eof':module.serve(owner.case_id)
                        else:
                            with self.assertRaises((TimeoutError,ValueError)):module.serve(owner.case_id)
                    self.assertEqual(os.fstat(original).st_size,0)
                    self.assertFalse(directory.exists())
                finally:os.close(original)

    def test_fill_partial_error_release_and_existing_refusal(self):
        with tempfile.TemporaryDirectory(prefix='openlxssh-enospc-fillerror-') as raw:
            module,owner,directory=self.owner(raw)
            (directory/'target.bin').write_bytes(b'x'*65536);(directory/'target.bin').chmod(0o600)
            write=module.os.write;calls=[]
            def partial(fd,data):
                calls.append(len(data))
                if len(calls)==1:return write(fd,data[:7])
                raise OSError(5,'controlled-write-error')
            original=os.dup(owner.filler)
            try:
                with mock.patch.object(module,'FILL',4096),self.fake_uid_stat(module),mock.patch.object(module.os,'write',side_effect=partial), \
                        mock.patch.object(module.os,'getuid',return_value=10000):
                    with self.assertRaises(OSError):owner.fill()
                    self.assertEqual(os.fstat(original).st_size,7)
                    owner.close()
                self.assertEqual(os.fstat(original).st_size,0)
                self.assertTrue((directory/'target.bin').exists())
            finally:os.close(original)

    def test_pipe_metadata_oversize_eof_timeout(self):
        host=load('management')
        for payload in (b'x'*33+b'\n',b'',b'partial'):
            readfd,writefd=os.pipe()
            try:
                if payload:os.write(writefd,payload)
                os.close(writefd);writefd=-1
                with self.assertRaises((ValueError,EOFError)):host.line(readfd,__import__('time').monotonic()+.1,32)
            finally:
                os.close(readfd)
                if writefd>=0:os.close(writefd)
        readfd,writefd=os.pipe()
        try:
            with self.assertRaises(TimeoutError):host.line(readfd,__import__('time').monotonic()+.01,32)
        finally:os.close(readfd);os.close(writefd)

    def test_helper_fixed_entry_no_arbitrary_path_or_shell(self):
        text=(HERE/'management_helper.py').read_text()
        self.assertIn("os.open('/dev/shm'",text)
        self.assertIn('os.ftruncate(self.filler, 0)',text)
        self.assertIn('signal.setitimer(signal.ITIMER_REAL, TTL)',text)
        self.assertNotIn('shell=True',text)
        self.assertNotIn('/tmp/',text)
        host=load('management')
        for path in ('/etc/case.json',host.OWN+'/.runtime/enospc-latest/case.json',host.OWN+'/.runtime/enospc-12345678-1234-1234-1234-123456789abc/case.json/extra'):
            with self.assertRaises(ValueError):host.syntax(path)

    def test_private_reader_real_delayed_first_read_allows_atime_only_change(self):
        host=load('management')
        with tempfile.TemporaryDirectory(prefix='openlxssh-private-atime-') as raw:
            path=Path(raw).resolve()/'case.json'
            payload=b'{"public":"delayed-first-read-not-a-credential"}\n'
            path.write_bytes(payload);path.chmod(0o600)
            created=path.stat()
            # Set a real old atime and wait past the filesystem's coarse second
            # boundary. No stat/read mocking: the actual first read updates it.
            os.utime(path,ns=(created.st_mtime_ns-10_000_000_000,created.st_mtime_ns))
            before=path.stat()
            time.sleep(1.05)
            try:
                actual=host.read_private(path,1024)
            except ValueError as error:
                actual=error
            after=path.stat()
            self.assertGreater(after.st_atime_ns,before.st_atime_ns,'filesystem did not provide real atime update')
            for name in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'):
                self.assertEqual(getattr(before,name),getattr(after,name),name+' changed during read-only test')
            self.assertIsInstance(actual,bytes,'real delayed first read incorrectly refused atime-only change')
            self.assertEqual(actual,payload)

    def test_private_reader_real_same_second_ctime_and_size_mutations_refused(self):
        host=load('management')
        for change in ('ctime','size'):
            with self.subTest(change=change),tempfile.TemporaryDirectory(prefix='openlxssh-private-mutation-') as raw:
                path=Path(raw).resolve()/'case.json'
                payload=b'{"public":"stable-original"}\n'
                # Start near the beginning of a real wall second; mutation is
                # performed synchronously within the actual os.read boundary.
                while time.time()%1>.3:time.sleep(.01)
                path.write_bytes(payload);path.chmod(0o600)
                before=path.stat();original_read=host.os.read;facts=[]
                def read_then_mutate(fd,maximum):
                    content=original_read(fd,maximum)
                    if change=='ctime':
                        os.chmod(path,0o400);os.chmod(path,0o600)
                    else:
                        writer=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
                        try:os.write(writer,b'x')
                        finally:os.close(writer)
                    facts.append(os.stat(path))
                    return content
                with mock.patch.object(host.os,'read',side_effect=read_then_mutate):
                    with self.assertRaises(ValueError):host.read_private(path,1024)
                self.assertEqual(len(facts),1)
                after=facts[0]
                if change=='ctime':
                    self.assertEqual(before.st_size,after.st_size)
                    self.assertEqual(before.st_mtime_ns,after.st_mtime_ns)
                    self.assertEqual(before.st_mode,after.st_mode)
                    self.assertEqual(int(before.st_ctime),int(after.st_ctime),'mutation crossed wall-second boundary')
                    self.assertNotEqual(before.st_ctime_ns,after.st_ctime_ns)
                else:self.assertEqual(after.st_size,before.st_size+1)

    def test_private_reader_preserves_nofollow_mode_singlelink_gates(self):
        host=load('management')
        with tempfile.TemporaryDirectory(prefix='openlxssh-private-gates-') as raw:
            parent=Path(raw).resolve();path=parent/'case.json'
            path.write_bytes(b'public-only');path.chmod(0o600)
            self.assertEqual(host.read_private(path,64),b'public-only')
            path.chmod(0o644)
            with self.assertRaises(ValueError):host.read_private(path,64)
            path.chmod(0o600)
            os.link(path,parent/'hard')
            with self.assertRaises(ValueError):host.read_private(path,64)
            (parent/'hard').unlink()
            (parent/'alias').symlink_to(path)
            with self.assertRaises(OSError):host.read_private(parent/'alias',64)
            (parent/'parent-alias').symlink_to(parent,target_is_directory=True)
            with self.assertRaises(OSError):host.read_private(parent/'parent-alias'/'case.json',64)

    def test_management_cli_exact_snapshot_route(self):
        text=(HERE/'management.py').read_text()
        self.assertIn("os.environ['PATH']='/Applications/Docker.app/Contents/Resources/bin:/usr/bin:/bin:/usr/sbin:/sbin'",text)
        self.assertIn("Path(__file__).absolute().parent.parent/'IntegrationEnvironment'",text)
        self.assertIn("actions=set()",text)
        self.assertIn("if command['action'] in actions:",text)
        builder=(HERE/'build_host.py').read_text()
        self.assertIn("for name in ('Contract.swift','PrivateInput.swift')",builder)
        self.assertNotIn("b.sources(accepted.CORE/'RealIntegrationCore')",builder)

    def test_wrapper_preserves_error_and_samples_before_engine_unwind(self):
        text=(HERE/'DiskCase.swift').read_text()
        first=text.index('sampled = try await helper.command("sample")')
        second=text.index('released = try await helper.command("release")')
        thrown=text.index('throw error // original production error')
        self.assertLess(first,second);self.assertLess(second,thrown)
        self.assertIn('return try await base.write(h,data:data,token:token)',text)
        self.assertNotIn('throw FileServiceError(',text)
        self.assertIn('token.cancel()',text)  # finite watchdog only, never a fault trigger
        self.assertIn('Task.sleep(for:.seconds(DiskFixed.seconds))',text)


if __name__=='__main__':unittest.main(verbosity=2)
