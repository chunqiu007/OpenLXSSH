import Darwin
import Foundation
import OpenLXSSHTrust
import RealIntegrationCore
import RealIntegrationPOSIX

/// Test-only bounded child for a disposable key pair; only the PUBLIC key is
/// retained. No passphrase/private content crosses argv, stdout, environment or reports.
func makePublicMismatchKey(directory:String)throws {
    let temporary=directory+"/keygen"
    guard mkdir(temporary,0o700)==0 else {throw AuthFailureError.tool}
    let parent=ri_open_private(temporary,1)
    guard parent>=0 else {throw AuthFailureError.tool}
    defer {Darwin.close(parent)}
    let privatePath=temporary+"/disposable"
    var owned:[String:(UInt64,UInt64)]=[:]
    defer {
        // No running child can survive the bounded waiter below. Cleanup does
        // not discover/signal any process, and never follows an unexpected name.
        for name in ["disposable","disposable.pub"] {
            let fd=openat(parent,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
            if fd>=0 {
                var before=stat(),current=stat()
                if let identity=owned[name],fstat(fd,&before)==0,before.st_uid==getuid(),before.st_nlink==1,
                   before.st_mode & mode_t(S_IFMT)==mode_t(S_IFREG),identity.0==UInt64(before.st_dev),identity.1==UInt64(before.st_ino),
                   fstatat(parent,name,&current,AT_SYMLINK_NOFOLLOW)==0,before.st_dev==current.st_dev,before.st_ino==current.st_ino {
                    _=unlinkat(parent,name,0) // ordinary deletion, not forensic erasure
                }
                Darwin.close(fd)
            }
        }
        _=rmdir(temporary) // only exact empty directory; unknown entries retain it
    }
    let process=Process()
    process.executableURL=URL(fileURLWithPath:"/usr/bin/ssh-keygen")
    process.arguments=["-q","-t","ed25519","-N","","-C","OpenLXSSH disposable public mismatch","-f",privatePath]
    process.environment=["PATH":"/usr/bin:/bin","LC_ALL":"C"]
    process.standardInput=FileHandle.nullDevice;process.standardOutput=FileHandle.nullDevice;process.standardError=FileHandle.nullDevice
    try process.run()
    let deadline=ProcessInfo.processInfo.systemUptime+8
    while process.isRunning && ProcessInfo.processInfo.systemUptime<deadline {Thread.sleep(forTimeInterval:0.01)}
    if process.isRunning {
        process.terminate()
        let end=ProcessInfo.processInfo.systemUptime+0.5
        while process.isRunning && ProcessInfo.processInfo.systemUptime<end {Thread.sleep(forTimeInterval:0.01)}
        if process.isRunning {_=Darwin.kill(process.processIdentifier,SIGKILL)}
        process.waitUntilExit();throw AuthFailureError.tool
    }
    process.waitUntilExit();guard process.terminationStatus==0 else {throw AuthFailureError.tool}
    for name in ["disposable","disposable.pub"] {
        let fd=openat(parent,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)
        guard fd>=0 else {throw AuthFailureError.tool};defer {Darwin.close(fd)}
        var value=stat();guard fstat(fd,&value)==0,value.st_uid==getuid(),value.st_nlink==1,
            value.st_mode & mode_t(S_IFMT)==mode_t(S_IFREG) else {throw AuthFailureError.tool}
        owned[name]=(UInt64(value.st_dev),UInt64(value.st_ino))
        if name=="disposable" {
            var current=stat()
            guard fstatat(parent,name,&current,AT_SYMLINK_NOFOLLOW)==0,current.st_dev==value.st_dev,current.st_ino==value.st_ino,
                  unlinkat(parent,name,0)==0 else {throw AuthFailureError.cleanup}
        }
    }
    // ssh-keygen's .pub can be0644 inside the private0700 parent. Normalize only
    // this exact owned public entry before using the shared strict reader.
    guard fchmodat(parent,"disposable.pub",0o600,0)==0 else {throw AuthFailureError.tool}
    let bytes=try PrivateInput.read(privatePath+".pub",limit:4096)
    let line=try PrivateInput.text(bytes).trimmingCharacters(in:.newlines)
    let key=try HostPublicKey(openSSHPublicKey:line)
    guard key.algorithm=="ssh-ed25519",key.fingerprint != AuthFixed.fingerprint,owned.count==2 else {throw AuthFailureError.tool}
    try PrivateInput.writeExclusive(Data((key.openSSH+"\n").utf8),to:directory+"/mismatch-public.txt")
    // Remove the pair now rather than waiting for normal function return, then
    // prove the public-only retention boundary before publishing its metadata.
    for name in ["disposable.pub"] {
        var info=stat();guard fstatat(parent,name,&info,AT_SYMLINK_NOFOLLOW)==0,
            owned[name]?.0==UInt64(info.st_dev),owned[name]?.1==UInt64(info.st_ino),unlinkat(parent,name,0)==0 else {throw AuthFailureError.cleanup}
    }
    guard rmdir(temporary)==0 else {throw AuthFailureError.cleanup}
}

func cleanupOwnedTrust(directory:String,knownHostsSHA256:String)throws {
    let fd=ri_open_private(directory,1);guard fd>=0 else {throw AuthFailureError.cleanup};defer {Darwin.close(fd)}
    var originals:[String:(UInt64,UInt64)]=[:],heldChildren:[Int32]=[]
    defer {for child in heldChildren {Darwin.close(child)}}
    let copy=openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
    guard copy>=0,let stream=fdopendir(copy) else {throw AuthFailureError.cleanup}
    var names:Set<String>=[]
    while let entry=readdir(stream) {let name=String(cString:withUnsafePointer(to:&entry.pointee.d_name){UnsafeRawPointer($0).assumingMemoryBound(to:CChar.self)})
        if name != "." && name != ".." {names.insert(name)}}
    closedir(stream)
    guard names==["known_hosts","trust.lock"],try PrivateInput.sha256(PrivateInput.read(directory+"/known_hosts",limit:16384))==knownHostsSHA256 else {throw AuthFailureError.cleanup}
    for name in names {
        let child=ri_open_private(directory+"/"+name,0);guard child>=0 else {throw AuthFailureError.cleanup};heldChildren.append(child)
        var info=stat();guard fstat(child,&info)==0 else {throw AuthFailureError.cleanup}
        originals[name]=(UInt64(info.st_dev),UInt64(info.st_ino))
    }
    for name in names {var value=stat();guard fstatat(fd,name,&value,AT_SYMLINK_NOFOLLOW)==0,originals[name]?.0==UInt64(value.st_dev),originals[name]?.1==UInt64(value.st_ino),unlinkat(fd,name,0)==0 else {throw AuthFailureError.cleanup}}
    let parent=ri_open_private(String(directory.dropLast("/trust".count)),1);guard parent>=0 else {throw AuthFailureError.cleanup};defer {Darwin.close(parent)}
    var held=stat(),current=stat();guard fstat(fd,&held)==0,fstatat(parent,"trust",&current,AT_SYMLINK_NOFOLLOW)==0,held.st_dev==current.st_dev,held.st_ino==current.st_ino,unlinkat(parent,"trust",AT_REMOVEDIR)==0 else {throw AuthFailureError.cleanup}
}
