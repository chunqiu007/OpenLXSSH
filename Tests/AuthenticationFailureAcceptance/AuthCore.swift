import CryptoKit
import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTrust
import RealIntegrationCore

enum AuthFixed {
    static let task="REAL-AUTH-FAILURE-PREP-A"
    static let base="docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d"
    static let image="sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363"
    static let project="openlxssh-fixture-61ed25328c13"
    static let container="2db5bbb3cb75a3253d9b02af5ca52cbdc8095230464f82c18d37eca9ac1fc837"
    static let fingerprint="SHA256:oCBbJaAjOZMzrKEnj+Z4iHSn74Qc+0tTu9bOzfpwJ5w"
    static let replacementStep="explicit-after-negative-closed-and-record-unchanged-v1"
}
enum AuthFailureCase:String,Codable,Sendable {case badKeyPassphrase="bad-key-passphrase",knownHostMismatch="known-host-mismatch"}
enum AuthFailureError:String,Error {case arguments,authorization,contract,provenance,trustEvent,unexpectedSuccess,negativeUnclassified,budget,cleanup,tool,keyMaterial}
struct AuthOptions {
    enum Action {case help,validate,prepare,runNegative,replaceAndControl}
    let action:Action,path:String?,testCase:AuthFailureCase?
    static func parse(_ args:[String])throws->Self {
        if args.isEmpty || args == ["--help"] {return Self(action:.help,path:nil,testCase:nil)}
        guard let first=args.first,["validate","prepare","--run-negative","--replace-and-control"].contains(first) else {throw AuthFailureError.arguments}
        var path:String?,testCase:AuthFailureCase?,authorized=false,reviewed=false,i=1
        while i<args.count {
            switch args[i] {
            case first=="prepare" ? "--generation":"--case":
                guard path==nil,i+1<args.count else {throw AuthFailureError.arguments};i+=1;path=args[i];try PrivateInput.validateSyntax(args[i])
            case "--scenario":guard testCase==nil,i+1<args.count,let value=AuthFailureCase(rawValue:args[i+1]) else {throw AuthFailureError.arguments};i+=1;testCase=value
            case "--authorized-local-fixture":guard !authorized else {throw AuthFailureError.arguments};authorized=true
            case "--primary-reviewed":guard !reviewed else {throw AuthFailureError.arguments};reviewed=true
            default:throw AuthFailureError.arguments
            };i+=1
        }
        guard let path else {throw AuthFailureError.arguments}
        if first=="validate" {guard !authorized && !reviewed && testCase==nil && path.hasSuffix("/case.json") else {throw AuthFailureError.arguments};return Self(action:.validate,path:path,testCase:nil)}
        guard authorized && reviewed else {throw AuthFailureError.authorization}
        guard (first=="prepare") == (testCase != nil) else {throw AuthFailureError.arguments}
        return Self(action:first=="prepare" ? .prepare:first=="--run-negative" ? .runNegative:.replaceAndControl,path:path,testCase:testCase)
    }
    static let help="""
    OpenLXSSH host15 TEST ONLY fixed SFTP authentication negatives; NOT App/macOS26 acceptance.
    Default/--help and validate --case /not/opened/case.json: syntax only, no filesystem/child/network I/O.
    Future only after primary independent review, fresh exact keyonly generation and exclusive finite relay:
      prepare --scenario bad-key-passphrase|known-host-mismatch --generation /exact/new/keyonly/credentials-<12hex> --authorized-local-fixture --primary-reviewed
      --run-negative --case /exact/own/.runtime/auth-<uuid>/case.json --authorized-local-fixture --primary-reviewed
    Known-host replacement is NEVER automatic. Only AFTER failed negative fully closed and record unchanged:
      --replace-and-control --case <same case> --authorized-local-fixture --primary-reviewed
    Fixed fixture@127.0.0.1:22221, CID/project/image/base and independently exported fingerprint.
    No passwords/passphrases in argv/env/report/hash, no KBI plan, Keychain, user SSH config or remote writes.
    Bad passphrase may fail locally inside libssh2 decrypt/sign and fold to authentication: not proof server rejected it.
    Known-host case is an existing-record mismatch, NOT a real server-key rotation. No live work in offline build.
    """
}
func authRequire(_ value:Bool,_ error:AuthFailureError = .contract)throws {if !value {throw error}}
func authJSON<T:Encodable>(_ value:T,directory:String,name:String)throws {
    let encoder=JSONEncoder();encoder.outputFormatting=[.prettyPrinted,.sortedKeys]
    try PrivateInput.writeExclusive(encoder.encode(value),to:directory+"/"+name)
}
func authObject(_ bytes:Data,keys:Set<String>)throws->[String:Any] {
    guard let object=try JSONSerialization.jsonObject(with:bytes) as? [String:Any],Set(object.keys)==keys else {throw AuthFailureError.contract};return object
}
struct AuthPublic:Sendable {
    let key:HostPublicKey,collectedAt:Double,hashes:[String:String]
    static func generation(_ value:String)throws {
        try PrivateInput.validateSyntax(value)
        let prefix=BuildLocation.fixtureRoot+"/.runtime/keyonly/credentials-"
        guard value.hasPrefix(prefix),Contract.hex(String(value.dropFirst(prefix.count)),count:12) else {throw AuthFailureError.contract}
    }
    static func load(_ value:String,now:Double,fresh:Bool)throws->Self {
        try generation(value)
        for parent in [BuildLocation.fixtureRoot+"/.runtime",BuildLocation.fixtureRoot+"/.runtime/keyonly",value] {try PrivateInput.checkDirectory(parent)}
        let state=try authObject(PrivateInput.read(BuildLocation.fixtureRoot+"/.runtime/state.json",limit:4096),keys:["version","project","image"])
        guard state["version"] as? Int==1,state["project"] as? String==AuthFixed.project,state["image"] as? String==AuthFixed.base else {throw AuthFailureError.provenance}
        let names=["provenance.json","known_hosts","fingerprint.txt","packages.txt"]
        var bytes:[String:Data]=[:];for name in names {bytes[name]=try PrivateInput.read(value+"/"+name,limit:name=="packages.txt" ? 32768:4096)}
        let p=try authObject(bytes["provenance.json"]!,keys:["base_image","built_image_id","service","collected_at"])
        guard p["base_image"] as? String==AuthFixed.base,p["built_image_id"] as? String==AuthFixed.image,p["service"] as? String=="keyonly",
              let time=p["collected_at"] as? Double,time.isFinite,now.isFinite,time>=BuildLocation.builtAt,now>=time,!fresh || now-time<=900 else {throw AuthFailureError.provenance}
        let text=try PrivateInput.text(bytes["known_hosts"]!),parts=text.dropLast().split(separator:" ",omittingEmptySubsequences:false)
        guard text.hasSuffix("\n"),!text.dropLast().contains("\n"),parts.count==3,parts[0]=="[127.0.0.1]:22221",parts[1]=="ssh-ed25519" else {throw AuthFailureError.provenance}
        let key=try HostPublicKey(algorithm:String(parts[1]),base64:String(parts[2]))
        let exported=try PrivateInput.text(bytes["fingerprint.txt"]!).split(whereSeparator:{$0.isWhitespace})
        guard key.fingerprint==AuthFixed.fingerprint,exported.count>=2,exported[1]==Substring(AuthFixed.fingerprint),!(bytes["packages.txt"]?.isEmpty ?? true) else {throw AuthFailureError.provenance}
        return Self(key:key,collectedAt:time,hashes:bytes.mapValues(PrivateInput.sha256))
    }
}
struct AuthContract:Codable,Sendable {
    let schema:Int,id:String,scenario:AuthFailureCase,generation:String,project:String,container:String,image:String,base:String,fingerprint:String
    let collectedAt:Double,preparedAt:Double,publicHashes:[String:String]
    let replacementStep:String
    static func path(_ value:String)throws->String {
        let prefix=BuildLocation.ownRoot+"/.runtime/auth-",suffix="/case.json"
        guard value.hasPrefix(prefix),value.hasSuffix(suffix),let id=UUID(uuidString:String(value.dropFirst(prefix.count).dropLast(suffix.count))),
              value==prefix+id.uuidString.lowercased()+suffix else {throw AuthFailureError.contract};return id.uuidString.lowercased()
    }
    static let keys:Set<String>=["schema","id","scenario","generation","project","container","image","base","fingerprint","collectedAt","preparedAt","publicHashes","replacementStep"]
    func validate(path:String,now:Double)throws {
        guard try Self.path(path)==id,schema==1,project==AuthFixed.project,container==AuthFixed.container,image==AuthFixed.image,base==AuthFixed.base,fingerprint==AuthFixed.fingerprint,
              collectedAt.isFinite,preparedAt.isFinite,now.isFinite,collectedAt>=BuildLocation.builtAt,preparedAt>=collectedAt,preparedAt-collectedAt<=900,now>=preparedAt,now-preparedAt<=900,
              Set(publicHashes.keys)==["provenance.json","known_hosts","fingerprint.txt","packages.txt"],publicHashes.values.allSatisfy({Contract.hex($0,count:64)}),
              replacementStep==(scenario == .knownHostMismatch ? AuthFixed.replacementStep:"not-applicable") else {throw AuthFailureError.contract}
        try AuthPublic.generation(generation)
    }
    func check(_ input:AuthPublic)throws {try authRequire(input.collectedAt==collectedAt && input.hashes==publicHashes,.provenance)}
}
struct AuthBudget:Sendable {
    private(set) var positive=0,negative=0,replacement=0
    mutating func claimPositive()throws {guard positive==0 else {throw AuthFailureError.budget};positive+=1}
    mutating func claimNegative()throws {guard negative==0 else {throw AuthFailureError.budget};negative+=1}
    mutating func claimReplacement(negativePassed:Bool,explicitStep:Bool)throws {guard negative==0,positive==0,replacement==0,negativePassed,explicitStep else {throw AuthFailureError.budget};replacement+=1}
}
struct FailureFacts:Codable,Equatable {
    let kind:String,operation:String,code:Int64?
    init(_ error:FileServiceError) {kind=error.kind.rawValue;operation=error.operation;code=error.code}
    init(kind:String,operation:String,code:Int64?) {self.kind=kind;self.operation=operation;self.code=code}
}
func badPhraseAccepted(_ facts:FailureFacts?,sftpReturned:Int,fileOps:Int,positivePassed:Bool,kbi:Int)->Bool {
    positivePassed && facts?.kind=="authentication" && facts?.operation=="authenticate" && sftpReturned==0 && fileOps==0 && kbi==0
}
struct ChangedFacts:Codable,Equatable,Sendable {let host:String,port:UInt16,algorithm:String,expected:String,presented:String}
func mismatchAccepted(_ facts:FailureFacts?,changed:[ChangedFacts],old:String,presented:String,sftpReturned:Int,fileOps:Int,recordUnchanged:Bool)->Bool {
    facts?.kind=="untrusted" && facts?.operation=="host-key" && changed.count==1 && changed[0]==ChangedFacts(host:"127.0.0.1",port:22221,algorithm:"ssh-ed25519",expected:old,presented:presented) && old != presented && presented==AuthFixed.fingerprint && sftpReturned==0 && fileOps==0 && recordUnchanged
}
