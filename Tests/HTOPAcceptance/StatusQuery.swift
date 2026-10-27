import Foundation
import COpenLXSSHAskpass
import HTOPCore
import RemoteTerminalCore

/// Fixed read-only Docker management channel; never SSH or TUI input. No raw output retained.
enum HStatusQuery {
    private static let reader = #"""
import fcntl,json,os,re,stat,sys
nonce,expected_pid,expected_start,ddev,dino,sdev,sino=sys.argv[1:]
if not re.fullmatch('[0-9a-f]{32}',nonce) or os.getuid()!=10000 or any(not value.isdigit() for value in (expected_pid,expected_start,ddev,dino,sdev,sino)):raise SystemExit(64)
parent=os.open('/tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
directory=fd=None
try:
 directory=os.open('openlxssh-htop-'+nonce,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
 info=os.fstat(directory)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=10000 or stat.S_IMODE(info.st_mode)!=0o700 or (info.st_dev,info.st_ino)!=(int(ddev),int(dino)):raise SystemExit(65)
 fd=os.open('status.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
 fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
 before=os.fstat(fd);named=os.stat('status.json',dir_fd=directory,follow_symlinks=False)
 if not stat.S_ISREG(before.st_mode) or before.st_uid!=10000 or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or (before.st_dev,before.st_ino)!=(int(sdev),int(sino)) or (before.st_dev,before.st_ino)!=(named.st_dev,named.st_ino) or not 0<before.st_size<=2048:raise SystemExit(65)
 raw=os.read(fd,2049);after=os.fstat(fd);named_after=os.stat('status.json',dir_fd=directory,follow_symlinks=False)
 identity=lambda info:(info.st_dev,info.st_ino,info.st_uid,info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
 if len(raw)!=before.st_size or identity(before)!=identity(after) or (named_after.st_dev,named_after.st_ino)!=(before.st_dev,before.st_ino):raise SystemExit(65)
 value=json.loads(raw)
 if set(value)!={'schema','stage','parent','htop','child','rows','cols','failure','configPresent'} or type(value['schema']) is not int or value['schema']!=1 or value['stage'] not in ('initialized','ready','sized','failed') or type(value['configPresent']) is not bool:raise SystemExit(65)
 for name in ('parent','htop','child'):
  ident=value[name]
  if ident is None:
   if name=='parent':raise SystemExit(65)
  elif set(ident)!={'pid','startTicks'} or type(ident['pid']) is not int or ident['pid']<=1 or type(ident['startTicks']) is not int or ident['startTicks']<=0:raise SystemExit(65)
 if value['parent']!={'pid':int(expected_pid),'startTicks':int(expected_start)}:raise SystemExit(65)
 process='/proc/'+expected_pid
 with open(process+'/stat') as stream:fields=stream.read().rsplit(')',1)[1].split()
 with open(process+'/status') as stream:uids=stream.read().split('Uid:',1)[1].splitlines()[0].split()
 if int(fields[19])!=int(expected_start) or uids!=['10000']*4:raise SystemExit(65)
 for name in ('rows','cols'):
  if value[name] is not None and (type(value[name]) is not int or not 1<=value[name]<=65535):raise SystemExit(65)
 failure=value['failure']
 if failure is not None and (set(failure)!={'stage','kind','errno'} or failure['stage'] not in ('preflight','launch','readiness','resize','exit','cleanup') or failure['kind'] not in ('refused','deadline','os-error','source-error') or failure['errno'] not in ('none','enoent','eacces','eperm','eio','other')):raise SystemExit(65)
 print(json.dumps(value,sort_keys=True,separators=(',',':')))
finally:
 if fd is not None:os.close(fd)
 if directory is not None:os.close(directory)
 os.close(parent)
"""#
    static func read(_ contract: TerminalContract, nonce: String, binding: HBinding) throws -> HStatus {
        guard Syntax.hex(nonce, 32), contract.containerID == "1253a29501483eb71f80e39b9af5c85e10c3a49329d5e93700fecd3f00f334f2", contract.endpoint == "unix:///Users/liuwenshuo/.docker/run/docker.sock" else { throw TerminalCheckError.contract }
        let executable = "/Applications/Docker.app/Contents/Resources/bin/docker"
        let values = [executable, "--host", contract.endpoint, "exec", "--user", "10000:10000", contract.containerID, "/usr/bin/python3", "-c", reader, nonce,
                      String(binding.parent.pid), String(binding.parent.startTicks), String(binding.directoryDevice), String(binding.directoryInode), String(binding.statusDevice), String(binding.statusInode)]
        let environment = ["PATH=/usr/bin:/bin", "LC_ALL=C", "DOCKER_CONFIG=" + NSHomeDirectory() + "/.docker"]
        let argv = values.map { strdup($0) } + [nil], env = environment.map { strdup($0) } + [nil]
        defer { (argv + env).forEach { free($0) } }
        guard let cancel = ap_cancel_create() else { throw TerminalCheckError.provenance }
        defer { ap_cancel_free(cancel) }
        var output = Data(count: 4096), count = 0, status: Int32 = -1
        let rc = argv.withUnsafeBufferPointer { a in env.withUnsafeBufferPointer { e in output.withUnsafeMutableBytes { bytes in
            ap_tool(executable, UnsafeMutablePointer(mutating: a.baseAddress!), UnsafeMutablePointer(mutating: e.baseAddress!), cancel, 5, 0, bytes.baseAddress, bytes.count, &count, &status)
        } } }
        guard rc == 0, status == 0 else { throw TerminalCheckError.remoteFailure }
        output.count = count
        return try HStatus.decode(output)
    }
}
