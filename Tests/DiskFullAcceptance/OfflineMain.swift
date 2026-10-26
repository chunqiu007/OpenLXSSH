import Darwin
import Foundation
import OpenLXSSHFiles
import RealIntegrationCore

@main enum OfflineMain {
    static func main() {
        var checks=0
        func check(_ value:Bool) throws { guard value else { throw DiskError.evidence };checks+=1 }
        func refuses(_ body:() throws -> Void) throws { do {try body()}catch{checks+=1;return};throw DiskError.evidence }
        do {
            try check(try DiskOptions.parse([]).action == .help)
            try check(try DiskOptions.parse(["--help"]).action == .help)
            try check(try DiskOptions.parse(["validate","--case","/not/opened/case.json"]).action == .validate)
            for args in [["--live","--case","/not/opened/case.json"],
                ["--live","--authorized-local-fixture","--case","/not/opened/case.json"],
                ["validate","--primary-reviewed","--case","/not/opened/case.json"],
                ["--live","--host","example.com"],["prepare","--generation","/a/../b"]] {
                try refuses{_=try DiskOptions.parse(args)}
            }
            let id="12345678-1234-1234-1234-123456789abc",root=try DiskFixed.root(id)
            try check(String(decoding:root.bytes,as:UTF8.self)=="/dev/shm/openlxssh-enospc-"+id)
            let path=BuildLocation.ownRoot+"/.runtime/enospc-"+id+"/case.json"
            try check(try DiskContract.validatePath(path,ownRoot:BuildLocation.ownRoot)==id)
            for bad in ["/etc/case.json",path.replacingOccurrences(of:id,with:"latest"),path+"/extra"] {
                try refuses{_=try DiskContract.validatePath(bad,ownRoot:BuildLocation.ownRoot)}
            }
            let ready=HelperEvent(schema:1,caseID:id,event:"ready",uid:10000,filledBytes:0,totalBytes:DiskFixed.capacity,
                availableBytes:DiskFixed.capacity,blockBytes:4096,errno:nil,realENOSPC:nil,beforeAvailableBytes:nil,afterAvailableBytes:nil)
            try ready.validate(id:id,event:"ready");checks+=1
            try refuses{try ready.validate(id:"other",event:"ready")}
            try refuses{try ready.validate(id:id,event:"filled")}
            let sample=HelperEvent(schema:1,caseID:id,event:"sampled",uid:10000,filledBytes:DiskFixed.maxFill-4096,totalBytes:DiskFixed.capacity,
                availableBytes:0,blockBytes:4096,errno:28,realENOSPC:true,beforeAvailableBytes:0,afterAvailableBytes:0)
            try sample.validate(id:id,event:"sampled");try check(sample.provesFull)
            let real=FileServiceError(.protocolFailure,operation:"write",code:4)
            try check(diskFailureAccepted(real,sample:sample))
            for error in [FileServiceError(.transport,operation:"write",code:4),FileServiceError(.cancelled,operation:"write",code:4),
                FileServiceError(.timeout,operation:"write",code:4),FileServiceError(.protocolFailure,operation:"open",code:4),
                FileServiceError(.protocolFailure,operation:"write",code:3)] {
                try check(!diskFailureAccepted(error,sample:sample))
            }
            let release=HelperEvent(schema:1,caseID:id,event:"released",uid:10000,filledBytes:0,totalBytes:nil,
                availableBytes:DiskFixed.maxFill-4096,blockBytes:nil,errno:nil,realENOSPC:nil,beforeAvailableBytes:nil,afterAvailableBytes:nil)
            try release.validate(id:id,event:"released");checks+=1
            try check(!diskFailureAccepted(real,sample:nil))
            let target=try join(root,"target.bin"),temp=try join(root,".openlxssh-transfer."+UUID().uuidString+".part")
            let paths=[OwnedPath(pathBase64:target.bytes.base64EncodedString(),directory:false),OwnedPath(pathBase64:temp.bytes.base64EncodedString(),directory:false)]
            try diskLedger(paths,root:root);checks+=1
            try refuses{try diskLedger(paths+paths,root:root)}
            try refuses{try diskLedger([OwnedPath(pathBase64:raw("/tmp/bystander").base64EncodedString(),directory:false)],root:root)}
            try refuses{try diskLedger([OwnedPath(pathBase64:try join(root,"unknown").bytes.base64EncodedString(),directory:false)],root:root)}
            try check(DiskFixed.original(id).count==65536)
            print("Disk-full offline checks passed: \(checks). Synthetic schema/evidence only; NO credentials, sockets, Docker or disk-full.")
        } catch { fputs("Disk-full offline checks failed after \(checks); no secret details.\n",stderr);exit(1) }
    }
}
