import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTrust
import RealIntegrationCore
import RemoteFileMetrics

final class TrustEvents:@unchecked Sendable {
    private let lock=NSLock()
    private var changes:[ChangedFacts]=[]
    private var pending=0
    func callback(_ event:FileHostTrustEvent,_ reply:ChallengeReply<FileHostTrustAnswer>) {
        lock.lock()
        switch event {
        case .pending:pending+=1
        case .changed(let value):changes.append(ChangedFacts(host:value.host.address.value,port:value.host.port.value,algorithm:value.algorithm,expected:value.expectedFingerprint,presented:value.presentedFingerprint))
        }
        lock.unlock();reply.resolve(.reject) // never confirm or replace in callback
    }
    func snapshot()->([ChangedFacts],Int) {lock.lock();defer{lock.unlock()};return(changes,pending)}
    func waitForChanged()async {for _ in 0..<100 {if !snapshot().0.isEmpty{return};try? await Task.sleep(for:.milliseconds(5))}}
}
struct AttemptReport:Codable {
    let label:String,sftpReturned:Int,directoryLists:Int,fileWrites:Int,kbiPlans:Int,closeAwaited:Bool,socketsAfterClose:Int32
    let failure:FailureFacts?
}
struct AuthReport:Codable {
    let schema:Int,caseID:String,scenario:AuthFailureCase,phase:String,status:String
    let attempts:[AttemptReport],changed:[ChangedFacts]
    let pendingTrustEvents:Int,oldFingerprint:String?,presentedFingerprint:String,knownHostsSHA256Before:String,knownHostsSHA256After:String
    let oldRecordUnchanged:Bool,replacementExplicit:Bool,trustCleanup:String,sessionCleanup:String
    let boundaries:[String]
}
func publicMismatch(_ directory:String)throws->HostPublicKey {
    let text=try PrivateInput.text(PrivateInput.read(directory+"/mismatch-public.txt",limit:4096)).trimmingCharacters(in:.newlines)
    let value=try HostPublicKey(openSSHPublicKey:text)
    guard value.algorithm=="ssh-ed25519",value.fingerprint != AuthFixed.fingerprint else {throw AuthFailureError.contract};return value
}
func authTrust(_ directory:String)throws->HostTrustStore {try HostTrustStore(directory:AbsolutePath(directory+"/trust"))}
func seedTrust(_ trust:HostTrustStore,key:HostPublicKey)async throws {
    let host=HostIdentity(address:try HostAddress("127.0.0.1"),port:try SSHPort(22221))
    guard case .pending(let pending)=try await trust.evaluate(host:host,key:key) else {throw AuthFailureError.contract}
    _=try await trust.confirm(pending,displayedFingerprint:key.fingerprint)
}
func knownHash(_ directory:String)throws->String {try PrivateInput.sha256(PrivateInput.read(directory+"/trust/known_hosts",limit:16384))}
func ensureSessionDirectory(_ directory:String)throws {
    guard mkdir(directory+"/sessions",0o700)==0 else {throw AuthFailureError.cleanup};try PrivateInput.checkDirectory(directory+"/sessions")
}
func cleanupSessionDirectory(_ directory:String)throws {
    // Files owns no PTY/session transcript. This intentionally empty exact root
    // proves the test does not retain a terminal or authentication log.
    guard rmdir(directory+"/sessions")==0 else {throw AuthFailureError.cleanup}
}
func mutatePassphraseOnce(_ bytes:Data)throws->Data {
    guard !bytes.isEmpty,bytes.count<=1024,!bytes.contains(0) else {throw AuthFailureError.keyMaterial}
    var changed=bytes
    changed[changed.startIndex]=changed[changed.startIndex]==65 ? 66:65
    return changed
}
func attempt(_ label:String,contract:AuthContract,trust:HostTrustStore,events:TrustEvents,encrypted:Bool,wrong:Bool,positive:Bool)async throws->AttemptReport {
    let host=HostIdentity(address:try HostAddress("127.0.0.1"),port:try SSHPort(22221))
    let name=encrypted ? "id_ed25519_encrypted":"id_ed25519"
    var privateKey=try PrivateInput.read(contract.generation+"/"+name,limit:32768)
    let publicKey=try PrivateInput.read(contract.generation+"/"+name+".pub",limit:4096)
    var phrase:Data?=encrypted ? try PrivateInput.secretLine(PrivateInput.read(contract.generation+"/key-passphrase.txt",limit:1024)):nil
    if wrong {guard let value=phrase else {throw AuthFailureError.keyMaterial};phrase=try mutatePassphraseOnce(value)}
    defer {privateKey.resetBytes(in:0..<privateKey.count);privateKey.removeAll();if phrase != nil {phrase!.resetBytes(in:0..<phrase!.count);phrase!.removeAll()}}
    var service:LibSSH2FileService?,failure:FailureFacts?,returned=0,listed=0
    do {
        service=try await LibSSH2FileService.connect(configuration:SSHConnection(host:host,user:try SSHUser("fixture")),
            authentication:[.publicKey(publicKey:publicKey,privateKey:privateKey,passphrase:phrase)],trustStore:trust,
            trustHandler:{event,reply in events.callback(event,reply)},connectionTimeout:20,operationTimeout:20,token:CancellationToken())
        returned=1
        if positive,let service {_=try await service.list(RemotePath("/fixture/home"),token:CancellationToken());listed=1}
    }catch let error as FileServiceError {failure=FailureFacts(error)}
    catch {if let service {await service.close()};throw error}
    if let service {await service.close()}
    // Product connect's failure path awaits close before throwing. This bool is
    // that public contract plus observed zero self peer sockets, not wire count.
    return AttemptReport(label:label,sftpReturned:returned,directoryLists:listed,fileWrites:0,kbiPlans:0,closeAwaited:true,socketsAfterClose:remote_file_fixture_sockets(),failure:failure)
}
func requirePositive(_ value:AttemptReport)throws {guard value.sftpReturned==1,value.directoryLists==1,value.failure==nil,value.closeAwaited,value.socketsAfterClose==0 else {throw AuthFailureError.unexpectedSuccess}}
let authBoundaries=["Host15 TEST ONLY, not shipping App/macOS26 acceptance.","No remote writes. Positive control observes actual authenticated SFTP connect return and one directory list.","No keyboard-interactive authentication plan is supplied; no KBI wire counter is exposed by public Files API.","Authentication-before-SFTP and trust-before-auth ordering is production control-flow evidence, not fabricated server counters.","Bad phrase authentication may represent local libssh2 decrypt/sign failure folded to -19, not server credential rejection.","Existing-record mismatch is not a real server host-key rotation. Explicit replacement is a separate operator-invoked step.","Swift/Data/libssh2 secret copies cannot all be guaranteed zeroized; no credential values or hashes are reported."]

enum AuthRun {
    static func negative(_ contract:AuthContract,input:AuthPublic,directory:String)async throws->Int32 {
        try PrivateInput.writeExclusive(Data("one negative attempt\n".utf8),to:directory+"/negative.claim")
        try ensureSessionDirectory(directory)
        let trust=try authTrust(directory),events=TrustEvents()
        var budget=AuthBudget(),reports:[AttemptReport]=[],old:String?,passed=false,cleanup="retained-for-review"
        if contract.scenario == .badKeyPassphrase {try await seedTrust(trust,key:input.key)}
        else {let key=try publicMismatch(directory);old=key.fingerprint;try await seedTrust(trust,key:key)}
        let before=try knownHash(directory)
        try authJSON(["caseID":contract.id,"scenario":contract.scenario.rawValue,"trustDirectory":directory+"/trust","knownHostsSHA256":before,"status":"owned-before-network"],directory:directory,name:"trust-owned.json")
        if contract.scenario == .badKeyPassphrase {
            try budget.claimPositive()
            let control=try await attempt("correct-encrypted-key-passphrase-control",contract:contract,trust:trust,events:events,encrypted:true,wrong:false,positive:true)
            reports.append(control)
            if control.sftpReturned != 1 || control.directoryLists != 1 || control.failure != nil || !control.closeAwaited || control.socketsAfterClose != 0 {
                try authJSON(AuthReport(schema:1,caseID:contract.id,scenario:contract.scenario,phase:"negative",status:"positive-control-failed-negative-not-attempted",attempts:reports,changed:events.snapshot().0,pendingTrustEvents:events.snapshot().1,oldFingerprint:nil,presentedFingerprint:input.key.fingerprint,knownHostsSHA256Before:before,knownHostsSHA256After:try knownHash(directory),oldRecordUnchanged:before == (try knownHash(directory)),replacementExplicit:false,trustCleanup:"retained-exact-owned-trust",sessionCleanup:"retained-empty-own-root",boundaries:authBoundaries),directory:directory,name:"negative-result.json")
                return 1
            }
            try budget.claimNegative()
            let negative=try await attempt("one-byte-wrong-key-passphrase",contract:contract,trust:trust,events:events,encrypted:true,wrong:true,positive:false)
            reports.append(negative)
            passed=badPhraseAccepted(negative.failure,sftpReturned:negative.sftpReturned,fileOps:negative.directoryLists,positivePassed:true,kbi:negative.kbiPlans) && negative.closeAwaited && negative.socketsAfterClose==0 && events.snapshot().0.isEmpty && events.snapshot().1==0
        }else {
            try budget.claimNegative()
            let negative=try await attempt("existing-record-host-key-mismatch",contract:contract,trust:trust,events:events,encrypted:false,wrong:false,positive:false)
            reports.append(negative);await events.waitForChanged()
            passed=mismatchAccepted(negative.failure,changed:events.snapshot().0,old:old!,presented:input.key.fingerprint,sftpReturned:negative.sftpReturned,fileOps:negative.directoryLists,recordUnchanged:before == (try knownHash(directory))) && negative.closeAwaited && negative.socketsAfterClose==0 && events.snapshot().1==0
        }
        let after=try knownHash(directory)
        try cleanupSessionDirectory(directory)
        if contract.scenario == .badKeyPassphrase && passed {try cleanupOwnedTrust(directory:directory+"/trust",knownHostsSHA256:after);cleanup="exact-trust-knownhosts-lock-root-removed"}
        let output=AuthReport(schema:1,caseID:contract.id,scenario:contract.scenario,phase:"negative",status:passed ? "expected-negative-observed":"failed-not-accepted",
            attempts:reports,changed:events.snapshot().0,pendingTrustEvents:events.snapshot().1,oldFingerprint:old,presentedFingerprint:input.key.fingerprint,
            knownHostsSHA256Before:before,knownHostsSHA256After:after,oldRecordUnchanged:before==after,replacementExplicit:false,trustCleanup:cleanup,sessionCleanup:"empty-own-root-removed",boundaries:authBoundaries)
        try authJSON(output,directory:directory,name:"negative-result.json")
        print(output.status+" result="+directory+"/negative-result.json");return passed ? 0:1
    }
    static func replacement(_ contract:AuthContract,input:AuthPublic,directory:String)async throws->Int32 {
        guard contract.scenario == .knownHostMismatch,contract.replacementStep==AuthFixed.replacementStep else {throw AuthFailureError.contract}
        let negative=try JSONDecoder().decode(AuthReport.self,from:PrivateInput.read(directory+"/negative-result.json",limit:16384))
        guard negative.schema==1,negative.caseID==contract.id,negative.scenario==contract.scenario,negative.phase=="negative",negative.status=="expected-negative-observed",
              !negative.replacementExplicit,negative.oldRecordUnchanged,negative.attempts.count==1,negative.attempts[0].closeAwaited,negative.attempts[0].socketsAfterClose==0,
              let old=negative.oldFingerprint,mismatchAccepted(negative.attempts[0].failure,changed:negative.changed,old:old,presented:input.key.fingerprint,sftpReturned:negative.attempts[0].sftpReturned,fileOps:negative.attempts[0].directoryLists,recordUnchanged:true),
              try knownHash(directory)==negative.knownHostsSHA256After else {throw AuthFailureError.contract}
        try PrivateInput.writeExclusive(Data("one explicit management replacement after negative fully closed\n".utf8),to:directory+"/replacement.claim")
        var budget=AuthBudget();try budget.claimReplacement(negativePassed:true,explicitStep:true)
        let trust=try authTrust(directory),host=HostIdentity(address:try HostAddress("127.0.0.1"),port:try SSHPort(22221))
        let decision=try await trust.prepareReplacement(host:host,key:input.key,expectedCurrentFingerprint:old)
        guard decision.fingerprint==AuthFixed.fingerprint,decision.reason == .manuallyVerifiedReplacement(previousFingerprint:old) else {throw AuthFailureError.contract}
        _=try await trust.confirm(decision,displayedFingerprint:AuthFixed.fingerprint)
        try ensureSessionDirectory(directory)
        let events=TrustEvents(),control=try await attempt("explicit-replacement-new-connection-control",contract:contract,trust:trust,events:events,encrypted:false,wrong:false,positive:true)
        try requirePositive(control)
        let after=try knownHash(directory)
        guard after != negative.knownHostsSHA256After,events.snapshot().0.isEmpty,events.snapshot().1==0 else {throw AuthFailureError.trustEvent}
        try cleanupSessionDirectory(directory);try cleanupOwnedTrust(directory:directory+"/trust",knownHostsSHA256:after)
        let output=AuthReport(schema:1,caseID:contract.id,scenario:contract.scenario,phase:"explicit-replacement",status:"explicit-replacement-positive-control-observed",attempts:[control],changed:[],pendingTrustEvents:0,
            oldFingerprint:old,presentedFingerprint:input.key.fingerprint,knownHostsSHA256Before:negative.knownHostsSHA256After,knownHostsSHA256After:after,
            oldRecordUnchanged:false,replacementExplicit:true,trustCleanup:"exact-trust-knownhosts-lock-root-removed",sessionCleanup:"empty-own-root-removed",boundaries:authBoundaries)
        try authJSON(output,directory:directory,name:"replacement-result.json")
        print(output.status+" result="+directory+"/replacement-result.json");return 0
    }
}
