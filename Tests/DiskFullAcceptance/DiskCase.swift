import CryptoKit
import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTrust
import RealIntegrationCore
import RealIntegrationPOSIX
import RemoteFileMetrics
import StressMetrics

/// Forwards the real backend unchanged. The only extra action occurs AFTER a
/// real write throws and BEFORE that same error returns to engine cleanup.
actor FullObserved: RemoteFileService {
    nonisolated let base: ObservedService
    nonisolated var capabilities: FileServiceCapabilities { base.capabilities }
    nonisolated var serverBinding: UUID? { base.serverBinding }
    let helper: DiskManagement
    private(set) var sampled: HelperEvent?
    private(set) var released: HelperEvent?
    private(set) var originalWriteFailure: FileServiceError?
    private(set) var managementFailure = false
    init(_ base: ObservedService, helper: DiskManagement) { self.base=base; self.helper=helper }
    func list(_ p: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { try await base.list(p,token:token) }
    func lstat(_ p: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await base.lstat(p,token:token) }
    func fstat(_ h: FileHandleID, token: CancellationToken) async throws -> FileAttributes? { try await base.fstat(h,token:token) }
    func open(_ p: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await base.open(p,mode:mode,token:token) }
    func read(_ h: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await base.read(h,maxBytes:maxBytes,token:token) }
    func write(_ h: FileHandleID, data: Data, token: CancellationToken) async throws -> Int {
        do { return try await base.write(h,data:data,token:token) }
        catch {
            if originalWriteFailure == nil {
                originalWriteFailure = error as? FileServiceError
                do { sampled = try await helper.command("sample") } catch { managementFailure=true }
                do { released = try await helper.command("release") } catch { managementFailure=true }
            }
            throw error // original production error, no substitution/simulation
        }
    }
    func finish(_ h: FileHandleID, token: CancellationToken) async throws { try await base.finish(h,token:token) }
    func closeHandle(_ h: FileHandleID) async throws { try await base.closeHandle(h) }
    func mkdir(_ p: RemotePath, token: CancellationToken) async throws { try await base.mkdir(p,token:token) }
    func rename(_ a: RemotePath, to b: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await base.rename(a,to:b,mode:mode,token:token) }
    func commit(_ a: RemotePath, to b: RemotePath, request: CommitRequest, token: CancellationToken) async throws { try await base.commit(a,to:b,request:request,token:token) }
    func remove(_ p: RemotePath, directory: Bool, token: CancellationToken) async throws { try await base.remove(p,directory:directory,token:token) }
    nonisolated func cancel() { base.cancel() }
    func close() async { await base.close() }
}

func diskSource(_ owner: OwnedLocal) throws -> (String, UInt64) {
    let fd=open(owner.path+"/source.bin",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600)
    guard fd>=0 else { throw DiskError.contract }; defer { Darwin.close(fd) }
    var hash=SHA256(), total: UInt64=0
    let seed=Data(SHA256.hash(data:raw("OpenLXSSH PUBLIC 8MiB ENOSPC source")))
    var block=Data(); for _ in 0..<(Fixed.chunk/seed.count) { block+=seed }
    while total<DiskFixed.sourceBytes {
        var offset=0
        while offset<block.count {
            let count=block.withUnsafeBytes { Darwin.write(fd,$0.baseAddress!.advanced(by:offset),$0.count-offset) }
            if count<0 && errno==EINTR { continue }
            guard count>0 else { throw DiskError.contract }; offset+=count
        }
        total+=UInt64(block.count); hash.update(data:block)
    }
    var allocated: UInt64=0
    guard fsync(fd)==0,remote_file_allocated(fd,&allocated)==0,allocated>=total,total==DiskFixed.sourceBytes else { throw DiskError.contract }
    return (hex(hash.finalize()),allocated)
}
@MainActor func diskConnect(_ contract: DiskContract, _ input: PublicMaterial, directory: String) async throws -> LibSSH2FileService {
    let path=directory+"/trust"
    try require(mkdir(path,0o700)==0);try PrivateInput.checkDirectory(path)
    let key=try await Task.detached { try HostPublicKey(openSSHPublicKey:input.hostKeyLine) }.value
    guard key.fingerprint==Fixed.fingerprint else { throw DiskError.contract }
    let trust=try HostTrustStore(directory:AbsolutePath(path))
    let host=HostIdentity(address:try HostAddress("127.0.0.1"),port:try SSHPort(22221))
    guard case .pending(let pending)=try await trust.evaluate(host:host,key:key) else { throw DiskError.contract }
    _=try await trust.confirm(pending,displayedFingerprint:Fixed.fingerprint)
    var privateKey=try PrivateInput.read(contract.generation+"/id_ed25519",limit:32768)
    defer { privateKey.resetBytes(in:0..<privateKey.count);privateKey.removeAll() }
    let publicKey=try PrivateInput.read(contract.generation+"/id_ed25519.pub",limit:4096)
    return try await LibSSH2FileService.connect(configuration:SSHConnection(host:host,user:try SSHUser("fixture")),
        authentication:[.publicKey(publicKey:publicKey,privateKey:privateKey,passphrase:nil)],trustStore:trust,
        trustHandler:{ _,reply in reply.resolve(.reject) },connectionTimeout:20,operationTimeout:20,token:CancellationToken())
}
struct DiskResult: Encodable {
    let schema=1,taskID=DiskFixed.task,testOnlyHostMinimum="15.0",productAcceptance=false
    let caseID:String,status:String
    let sourceBytes:UInt64,sourceSHA256:String,allocatedSourceBytes:UInt64
    let targetBefore:DiskAttributes?,targetAfter:DiskAttributes?
    let targetSHA256Before:String?,targetSHA256After:String?
    let errorKind:String?,operation:String?,code:Int64?
    let ready:HelperEvent?,sampled:HelperEvent?,released:HelperEvent?
    let originalWriteErrorMatched:Bool
    let ownedLedger:[OwnedPath],observedTemporaryPathsBase64:[String]
    let remoteCleanup:String,localCleanup:String,helperStopped:Bool,managerDrained:Bool
    let resources:APICounters,fixtureSocketsAfterClose:Int32
    let failure:String?
    let boundary="One real upload ENOSPC only, no host disk fill, OOM, cancellation fault, product GUI/min26/performance/24h acceptance. Exact ledger retained on any verification/dispose failure; no automatic reconnection. Helper releases filler independently before close."
}
@MainActor enum DiskRun {
    static func run(contract:DiskContract,input:PublicMaterial,directory:String,path:String) async throws -> Int32 {
        try PrivateInput.writeExclusive(raw("one finite disk-full attempt\n"),to:directory+"/run.claim")
        let owner=try OwnedLocal(parentPath:directory),ledger=Ledger()
        let source=ObservedService(try owner.service(),ledger:ledger,ownsLocalRoot:true)
        let generated=try diskSource(owner)
        try diskJSON(["root":owner.path,"device":String(owner.identity.0),"inode":String(owner.identity.1),"sourceSHA256":generated.0],directory:directory,name:"local-owned.json")
        let root=try DiskFixed.root(contract.id),target=try join(root,"target.bin")
        let helper=try DiskManagement(path:path,id:contract.id)
        let scheduler=TransferScheduler(maxConcurrentChunks:2),manager=TransferManager(maxConcurrentJobs:1,idleTimeout:nil)
        let engine=SafeTransferEngine(scheduler:scheduler,chunkSize:Fixed.chunk)
        var remote:ObservedService?,wrapped:FullObserved?,before:DiskAttributes?,after:DiskAttributes?,beforeHash:String?,afterHash:String?
        var report:TransferReport?,typed:FileServiceError?,failure:String?,remoteCleanup="not-attempted",localCleanup="retained"
        var owned:[OwnedPath]=[],history:[String]=[],released:HelperEvent?,ready:HelperEvent?
        let token = CancellationToken()
        let watchdog = Task { @MainActor in
            do { try await Task.sleep(for:.seconds(DiskFixed.seconds)) } catch { return }
            token.cancel()
        }
        defer { watchdog.cancel() }
        do {
            ready=try await helper.ready()
            let native=try await diskConnect(contract,input,directory:directory)
            let observed=ObservedService(native,ledger:ledger,remoteRoot:root);remote=observed
            // Management owns root. The consumer owns only its real successful
            // exclusive target/temp creations; never claims helper's filler.
            try await inspect(observed,root)
            let entries=try await observed.list(root,token:CancellationToken())
            guard entries.count==1,entries[0].name.bytes==raw("filler.bin"),entries[0].attributes.kind == .regular else { throw DiskError.ledger }
            try await put(observed,target,bytes:DiskFixed.original(contract.id))
            before=DiskAttributes(try await observed.lstat(target,token:CancellationToken()))
            beforeHash=try await digest(observed,target,relative:"target.bin",expected:DiskFixed.sentinelBytes).sha256
            guard beforeHash==PrivateInput.sha256(DiskFixed.original(contract.id)) else { throw DiskError.originalChanged }
            _=try await helper.command("fill") // only after real target create+hash
            let full=FullObserved(observed,helper:helper);wrapped=full
            let remoteID=try await manager.registerService(full,hostID:"fixture-enospc")
            _=try await manager.registerService(source)
            report=try await manager.withServiceOperation(serviceID:remoteID,hostID:"fixture-enospc",scheduling:.callerScheduled) { service,_leaseToken in
                let policy=TransferPolicy(confirmRisk:{ risk in
                    switch risk {
                    case .remotePathChecksAreNotAtomic(let p):return p==target
                    case .overwriteIsAtomicButNotCompareAndSwap(let p):return p==target
                    default:return false
                    }
                })
                return try await engine.copy(hostID:"fixture-enospc",source:source,sourcePath:rp("/source.bin"),
                    destination:service,destinationPath:target,conflict:.overwrite,token:token,policy:policy)
            }
            if let report,report.items.count==1,case .failed(let error)=report.items[0].state { typed=error }
            // Release FIRST on every path, even unexpected successful commit.
            released=await full.released
            if released==nil { released=try await helper.command("release") }
            guard let typed,diskFailureAccepted(typed,sample:await full.sampled),
                  await full.originalWriteFailure==typed, !(await full.managementFailure),
                  report?.items[0].retainedTemporary==nil else { throw DiskError.evidence }
            after=DiskAttributes(try await observed.lstat(target,token:CancellationToken()))
            afterHash=try await digest(observed,target,relative:"target.bin",expected:DiskFixed.sentinelBytes).sha256
            guard before==after,beforeHash==afterHash else { throw DiskError.originalChanged }
            owned=await observed.ownedMetadata();try diskLedger(owned,root:root)
            history=await observed.temporaryPaths()
            guard history.count==1 else { throw DiskError.ledger }
            let remaining=try await observed.list(root,token:CancellationToken())
            guard Set(remaining.map{$0.name.bytes})==Set([raw("filler.bin"),raw("target.bin")]),
                  remaining.allSatisfy({$0.attributes.kind == .regular}) else { throw DiskError.cleanup }
            try await observed.remove(target,directory:false,token:CancellationToken())
            remoteCleanup="exact-target-removed-engine-temp-absent-root-left-for-helper"
        } catch {
            failure=(error as? DiskError)?.rawValue ?? (error as? FileServiceError)?.kind.rawValue ?? "setup-or-pipe-refused"
            if released==nil { released=try? await helper.command("release") }
        }
        if let remote { owned=await remote.ownedMetadata();history=await remote.temporaryPaths() }
        // Never assumes disposed original service is usable. Retain exact ledger;
        // independent pre-held management EOF/TTL still frees memory.
        let helperStopped=await helper.stop()
        await manager.cancelAllAndWait()
        if let remote { await remote.close() }
        await source.close()
        let state=await manager.snapshot(),api=await ledger.snapshot()
        // Source is exact owned file; remove through its retained descriptor only
        // after actual size/hash proof. No unknown recursive discovery.
        do {
            let fd=ri_open_private(owner.path+"/source.bin",0)
            guard fd>=0 else { throw DiskError.cleanup };defer{Darwin.close(fd)}
            var info=stat();guard fstat(fd,&info)==0,UInt64(info.st_size)==DiskFixed.sourceBytes else { throw DiskError.cleanup }
            var hash=SHA256(),count:UInt64=0,chunk=[UInt8](repeating:0,count:Fixed.chunk)
            while true {
                let n=Darwin.read(fd,&chunk,chunk.count)
                if n<0 && errno==EINTR { continue }
                guard n>=0 else { throw DiskError.cleanup };if n==0 { break }
                count+=UInt64(n);guard count<=DiskFixed.sourceBytes else { throw DiskError.cleanup }
                hash.update(data:Data(chunk.prefix(n)))
            }
            guard count==DiskFixed.sourceBytes,hex(hash.finalize())==generated.0 else { throw DiskError.cleanup }
            let parent=ri_open_private(owner.path,1);guard parent>=0 else { throw DiskError.cleanup };defer{Darwin.close(parent)}
            var current=stat();guard fstatat(parent,"source.bin",&current,AT_SYMLINK_NOFOLLOW)==0,current.st_ino==info.st_ino,current.st_dev==info.st_dev,
                unlinkat(parent,"source.bin",0)==0 else { throw DiskError.cleanup }
            try owner.close(removeEmpty:true);localCleanup="exact-source-and-held-root-removed"
        }catch{try? owner.close(removeEmpty:false);failure=failure ?? "local-cleanup"}
        let sample=await wrapped?.sampled,original=await wrapped?.originalWriteFailure
        let accepted=failure==nil && helperStopped && ready != nil && released != nil && memorySafe(ready!,released!) && state.isClosed && !state.hasActiveWork && state.serviceOperations.isEmpty && api.openHandles==0 && remote_file_fixture_sockets()==0
        let result=DiskResult(caseID:contract.id,status:accepted ? "verified-real-ENOSPC-original-preserved" : "failed-not-accepted-retain-exact-ledger",
            sourceBytes:DiskFixed.sourceBytes,sourceSHA256:generated.0,allocatedSourceBytes:generated.1,
            targetBefore:before,targetAfter:after,targetSHA256Before:beforeHash,targetSHA256After:afterHash,
            errorKind:typed?.kind.rawValue,operation:typed?.operation,code:typed?.code,ready:ready,sampled:sample,released:released,
            originalWriteErrorMatched:original==typed,ownedLedger:owned,observedTemporaryPathsBase64:history,
            remoteCleanup:remoteCleanup,localCleanup:localCleanup,helperStopped:helperStopped,
            managerDrained:state.isClosed && !state.hasActiveWork && state.serviceOperations.isEmpty,
            resources:api,fixtureSocketsAfterClose:remote_file_fixture_sockets(),failure:failure)
        try diskJSON(result,directory:directory,name:"result.json")
        print(result.status+" result="+directory+"/result.json")
        return accepted ? 0:1
    }
}
