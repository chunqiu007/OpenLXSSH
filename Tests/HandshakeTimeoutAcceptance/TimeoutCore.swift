import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTrust
import RealIntegrationCore

// One deliberately silent LOCAL TCP peer, not a mock SSH implementation.
enum TimeoutFixed {
    static let task="REAL-HANDSHAKE-TIMEOUT-PREP-A"
    static let host="127.0.0.1",port:UInt16=22221
    static let connectSeconds=1.0,operationSeconds=2.0,outerSeconds=10.0,peerSeconds=8.0
    static let minimumElapsed=1.5,maximumElapsed=8.0
}
enum TimeoutFailure:String,Error {case arguments,authorization,contract,listener,resource,unexpectedSFTP,wrongFailure,cleanup}
struct TimeoutOptions {
    enum Action {case help,validate,live}
    let action:Action,path:String?
    static func parse(_ args:[String])throws->Self {
        if args.isEmpty || args == ["--help"] {return Self(action:.help,path:nil)}
        guard let first=args.first,["validate","--live"].contains(first) else {throw TimeoutFailure.arguments}
        var path:String?,authorized=false,reviewed=false,i=1
        while i<args.count {
            switch args[i] {
            case "--contract":guard path==nil,i+1<args.count else {throw TimeoutFailure.arguments};i+=1;path=args[i];try PrivateInput.validateSyntax(args[i])
            case "--authorized-local-test":guard !authorized else {throw TimeoutFailure.arguments};authorized=true
            case "--primary-reviewed":guard !reviewed else {throw TimeoutFailure.arguments};reviewed=true
            default:throw TimeoutFailure.arguments
            };i+=1
        }
        guard let path,path.hasSuffix("/contract.json") else {throw TimeoutFailure.arguments}
        if first=="validate" {guard !authorized && !reviewed else {throw TimeoutFailure.arguments};return Self(action:.validate,path:path)}
        guard authorized && reviewed else {throw TimeoutFailure.authorization};return Self(action:.live,path:path)
    }
    static let help="""
    OpenLXSSH host15 TEST ONLY strict handshake timeout, NOT App/macOS26/remote-server acceptance.
    Default/--help or validate --contract /not/opened/contract.json: syntax only; NO I/O, socket or child.
    Future ONLY after primary runtime release and explicit approval:
      --live --contract /exact/own/.runtime/handshake-<uuid>/contract.json --authorized-local-test --primary-reviewed
    Fixed 127.0.0.1:22221 ONLY. One self-owned silent TCP listener accepts once; never sends banner/data
    and NEVER reads/logs received SSH bytes. No Docker/relay/real SSH server/generation/credentials/Keychain.
    Public LibSSH2FileService.connect TCP1s, handshake operation2s; outer10s/peer8s finite bounds.
    Success requires actual accept1 + original timeout/handshake/-10002, monotonic >=1.5 and <8s,
    no SFTP/trust/auth callbacks, no watchdog cancellation, and all own descriptors/tasks closed.
    Port collision/refused/transport/cancelled/wrong timeout is failure. No retries, alternative ports or budgets.
    """
}
struct TimeoutContract:Codable {
    let schema:Int,id:String,host:String,port:UInt16
    let connectSeconds:Double,operationSeconds:Double,outerSeconds:Double,peerSeconds:Double
    static let keys:Set<String>=["schema","id","host","port","connectSeconds","operationSeconds","outerSeconds","peerSeconds"]
    static func path(_ value:String,ownRoot:String)throws->String {
        let prefix=ownRoot+"/.runtime/handshake-",suffix="/contract.json"
        guard value.hasPrefix(prefix),value.hasSuffix(suffix),let id=UUID(uuidString:String(value.dropFirst(prefix.count).dropLast(suffix.count))),
              value==prefix+id.uuidString.lowercased()+suffix else {throw TimeoutFailure.contract};return id.uuidString.lowercased()
    }
    func validate(path:String,ownRoot:String)throws {
        guard try Self.path(path,ownRoot:ownRoot)==id,schema==1,host==TimeoutFixed.host,port==TimeoutFixed.port,
              connectSeconds==TimeoutFixed.connectSeconds,operationSeconds==TimeoutFixed.operationSeconds,
              outerSeconds==TimeoutFixed.outerSeconds,peerSeconds==TimeoutFixed.peerSeconds else {throw TimeoutFailure.contract}
    }
}
struct TimeoutFacts:Codable {
    let kind:String,operation:String,code:Int64?
    init(_ value:FileServiceError){kind=value.kind.rawValue;operation=value.operation;code=value.code}
    init(kind:String,operation:String,code:Int64?){self.kind=kind;self.operation=operation;self.code=code}
}
struct PeerSnapshot:Codable,Sendable {
    let accepted:Int,sentBytes:Int,readCalls:Int,openOwnedFDs:Int
    let listenerClosed:Bool,acceptedClosed:Bool,taskCompleted:Bool,expired:Bool
    let elapsedSeconds:Double
}
struct CallbackSnapshot:Codable,Sendable {let authentication:Int,trust:Int,outerCancelled:Bool}
func expectedHandshakeTimeout(_ failure:TimeoutFacts?,elapsed:Double,peer:PeerSnapshot,callbacks:CallbackSnapshot,sftpReturned:Int)->Bool {
    failure?.kind=="timeout" && failure?.operation=="handshake" && failure?.code == -10002 && elapsed.isFinite && elapsed>=TimeoutFixed.minimumElapsed && elapsed<TimeoutFixed.maximumElapsed && peer.accepted==1 && peer.sentBytes==0 && peer.readCalls==0 && peer.openOwnedFDs==0 && peer.listenerClosed && peer.acceptedClosed && peer.taskCompleted && !peer.expired && callbacks.authentication==0 && callbacks.trust==0 && !callbacks.outerCancelled && sftpReturned==0
}
final class CallbackGate:@unchecked Sendable {
    private let lock=NSLock()
    private var authentication=0,trust=0,cancelled=false
    let token=CancellationToken()
    func auth(_ reply:ChallengeReply<[Data]>) {lock.lock();authentication+=1;lock.unlock();token.cancel();reply.resolve([])}
    func trustEvent(_ reply:ChallengeReply<FileHostTrustAnswer>) {lock.lock();trust+=1;lock.unlock();token.cancel();reply.resolve(.reject)}
    func outerTimeout(){lock.lock();cancelled=true;lock.unlock();token.cancel()}
    func snapshot()->CallbackSnapshot{lock.lock();defer{lock.unlock()};return CallbackSnapshot(authentication:authentication,trust:trust,outerCancelled:cancelled)}
}
