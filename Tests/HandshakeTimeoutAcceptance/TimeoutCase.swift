import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTrust
import RealIntegrationCore
import RemoteFileMetrics
import StressMetrics

struct TimeoutReport:Encodable {
    let schema=1,taskID=TimeoutFixed.task,testOnlyHostMinimum="15.0",productAcceptance=false
    let caseID:String,status:String,host=TimeoutFixed.host,port=TimeoutFixed.port
    let connectSeconds=TimeoutFixed.connectSeconds,operationSeconds=TimeoutFixed.operationSeconds
    let elapsedSeconds:Double,failure:TimeoutFacts?,sftpReturned:Int,peer:PeerSnapshot,callbacks:CallbackSnapshot
    let connectFailureCloseAwaited:Bool,trustRootRemoved:Bool
    let fdBefore:Int32,fdAfter:Int32,ownedRootFDsAfter:Int32,fixtureSocketsBefore:Int32,fixtureSocketsAfter:Int32
    let limitation="Local accepted TCP peer remains completely silent; real production SSH handshake timeout only. No Docker/server/credentials, auth exchange, wire reads/logs, SYN timeout, product GUI/min26/performance or external-network claim. Public connect failure awaits native close; aggregate self FD counts can include runtime warmup and are recorded, not fabricated."
}
func removeEmptyTrust(_ directory:String)throws {
    let fd=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);guard fd>=0 else {throw TimeoutFailure.cleanup};defer{Darwin.close(fd)}
    var held=stat();guard fstat(fd,&held)==0,held.st_uid==getuid(),held.st_mode&0o777==0o700 else {throw TimeoutFailure.cleanup}
    let entries=try FileManager.default.contentsOfDirectory(atPath:directory)
    guard Set(entries)==["known_hosts","trust.lock"] else {throw TimeoutFailure.cleanup}
    let known=try PrivateInput.text(PrivateInput.read(directory+"/known_hosts",limit:4096))
    guard known.hasPrefix("# OpenLXSSH-host-trust-v1 "),known.split(separator:"\n").count==1 else {throw TimeoutFailure.cleanup}
    var owned:[String:(Int32,stat)]=[:]
    defer{for value in owned.values{Darwin.close(value.0)}}
    for name in entries {let child=openat(fd,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);guard child>=0 else {throw TimeoutFailure.cleanup};var info=stat();guard fstat(child,&info)==0,info.st_uid==getuid(),info.st_nlink==1,info.st_mode&0o777==0o600,info.st_mode&mode_t(S_IFMT)==mode_t(S_IFREG) else {Darwin.close(child);throw TimeoutFailure.cleanup};owned[name]=(child,info)}
    for(name,value)in owned{var now=stat();guard fstatat(fd,name,&now,AT_SYMLINK_NOFOLLOW)==0,now.st_dev==value.1.st_dev,now.st_ino==value.1.st_ino,unlinkat(fd,name,0)==0 else {throw TimeoutFailure.cleanup}}
    var path=stat();guard lstat(directory,&path)==0,path.st_dev==held.st_dev,path.st_ino==held.st_ino,rmdir(directory)==0 else {throw TimeoutFailure.cleanup}
}
enum TimeoutRun {
    static func execute(_ contract:TimeoutContract,path:String)async throws->Int32 {
        let directory=String(path.dropLast("/contract.json".count))
        try PrivateInput.checkDirectory(directory)
        try PrivateInput.writeExclusive(Data("one silent handshake attempt\n".utf8),to:directory+"/run.claim")
        let trust=try await Task.detached{try HostTrustStore(directory:AbsolutePath(directory+"/trust"))}.value
        // Load pure crypto/native metadata before baseline; no socket or key material.
        _=NativeDiagnostics.libssh2;_=NativeDiagnostics.openssl
        let before=stress_sample(directory),socketsBefore=remote_file_fixture_sockets()
        guard before.fd_count>=0,socketsBefore==0 else {throw TimeoutFailure.resource}
        let peer=SilentPeer(),gate=CallbackGate()
        var failure:TimeoutFacts?,sftpReturned=0,service:LibSSH2FileService?
        try peer.startOnce()
        let watchdog=Task.detached{do{try await Task.sleep(for:.seconds(TimeoutFixed.outerSeconds))}catch{return};gate.outerTimeout()}
        let start=DispatchTime.now().uptimeNanoseconds
        do{
            let host=HostIdentity(address:try HostAddress(TimeoutFixed.host),port:try SSHPort(Int(TimeoutFixed.port)))
            service=try await LibSSH2FileService.connect(configuration:SSHConnection(host:host,user:try SSHUser("fixture")),
                authentication:[.keyboardInteractive({_,reply in gate.auth(reply)})],trustStore:trust,
                trustHandler:{_,reply in gate.trustEvent(reply)},connectionTimeout:TimeoutFixed.connectSeconds,
                operationTimeout:TimeoutFixed.operationSeconds,token:gate.token)
            sftpReturned=1
        }catch let error as FileServiceError{failure=TimeoutFacts(error)}
        catch{watchdog.cancel();await watchdog.value;_=await peer.stopAndWait();throw error}
        let elapsed=Double(DispatchTime.now().uptimeNanoseconds-start)/1e9
        if let service{await service.close()}
        watchdog.cancel();await watchdog.value
        let snapshot=await peer.stopAndWait(),callbacks=gate.snapshot()
        let after=stress_sample(directory),socketsAfter=remote_file_fixture_sockets()
        var cleanup=true
        do{try removeEmptyTrust(directory+"/trust")}catch{cleanup=false}
        let valid=expectedHandshakeTimeout(failure,elapsed:elapsed,peer:snapshot,callbacks:callbacks,sftpReturned:sftpReturned) && cleanup && before.fd_count==after.fd_count && socketsAfter==0
        let report=TimeoutReport(caseID:contract.id,status:valid ? "verified-local-real-handshake-timeout":"failed-not-accepted",
            elapsedSeconds:elapsed,failure:failure,sftpReturned:sftpReturned,peer:snapshot,callbacks:callbacks,
            connectFailureCloseAwaited:true,trustRootRemoved:cleanup,fdBefore:before.fd_count,fdAfter:after.fd_count,
            ownedRootFDsAfter:after.owned_fd_count,fixtureSocketsBefore:socketsBefore,fixtureSocketsAfter:socketsAfter)
        let encoder=JSONEncoder();encoder.outputFormatting=[.prettyPrinted,.sortedKeys]
        try PrivateInput.writeExclusive(encoder.encode(report),to:directory+"/result.json")
        print(report.status+" result="+directory+"/result.json");return valid ? 0:1
    }
}
