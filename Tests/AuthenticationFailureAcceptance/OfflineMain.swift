import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTrust
import RealIntegrationCore

@main enum OfflineMain {
    static func main()async {
        var checks=0
        func check(_ value:Bool)throws{guard value else {throw AuthFailureError.contract};checks+=1}
        func refuses(_ body:()throws->Void)throws{do{try body()}catch{checks+=1;return};throw AuthFailureError.contract}
        do {
            try check(try AuthOptions.parse([]).action == .help);try check(try AuthOptions.parse(["--help"]).action == .help)
            try check(try AuthOptions.parse(["validate","--case","/not/opened/case.json"]).action == .validate)
            for args in [["--run-negative","--case","/not/opened/case.json"],["--replace-and-control","--authorized-local-fixture","--case","/not/opened/case.json"],
                ["prepare","--scenario","other","--generation","/not/opened"],["validate","--scenario","known-host-mismatch","--case","/a/case.json"],
                ["prepare","--generation","/a/../b","--scenario","bad-key-passphrase"],["--run-negative","--host","example.com"]] {try refuses{_=try AuthOptions.parse(args)}}
            var budget=AuthBudget();try budget.claimPositive();try budget.claimNegative();checks+=2
            try refuses{try budget.claimPositive()};try refuses{try budget.claimNegative()};try refuses{try budget.claimReplacement(negativePassed:true,explicitStep:true)}
            var replacement=AuthBudget();try refuses{try replacement.claimReplacement(negativePassed:false,explicitStep:true)}
            try replacement.claimReplacement(negativePassed:true,explicitStep:true);checks+=1
            try refuses{try replacement.claimReplacement(negativePassed:true,explicitStep:true)}
            let correct=Data("PUBLIC_NOT_A_REAL_PASSPHRASE".utf8),wrong=try mutatePassphraseOnce(correct)
            try check(correct.count==wrong.count && zip(correct,wrong).filter{$0 != $1}.count==1)
            let auth=FailureFacts(kind:"authentication",operation:"authenticate",code:-19)
            try check(badPhraseAccepted(auth,sftpReturned:0,fileOps:0,positivePassed:true,kbi:0))
            for facts in [FailureFacts(kind:"transport",operation:"authenticate",code:-19),FailureFacts(kind:"timeout",operation:"authenticate",code:-19),FailureFacts(kind:"authentication",operation:"handshake",code:-19)] {
                try check(!badPhraseAccepted(facts,sftpReturned:0,fileOps:0,positivePassed:true,kbi:0))}
            try check(!badPhraseAccepted(auth,sftpReturned:1,fileOps:0,positivePassed:true,kbi:0));try check(!badPhraseAccepted(auth,sftpReturned:0,fileOps:0,positivePassed:false,kbi:0))
            try check(!badPhraseAccepted(auth,sftpReturned:0,fileOps:0,positivePassed:true,kbi:1))
            let old="SHA256:PUBLIC_SYNTHETIC_OLD",untrusted=FailureFacts(kind:"untrusted",operation:"host-key",code:-10004)
            let changed=ChangedFacts(host:"127.0.0.1",port:22221,algorithm:"ssh-ed25519",expected:old,presented:AuthFixed.fingerprint)
            try check(mismatchAccepted(untrusted,changed:[changed],old:old,presented:AuthFixed.fingerprint,sftpReturned:0,fileOps:0,recordUnchanged:true))
            for values in [[],[changed,changed],[ChangedFacts(host:"example.com",port:22221,algorithm:"ssh-ed25519",expected:old,presented:AuthFixed.fingerprint)],
                [ChangedFacts(host:"127.0.0.1",port:22221,algorithm:"ssh-rsa",expected:old,presented:AuthFixed.fingerprint)]] {
                try check(!mismatchAccepted(untrusted,changed:values,old:old,presented:AuthFixed.fingerprint,sftpReturned:0,fileOps:0,recordUnchanged:true))}
            try check(!mismatchAccepted(untrusted,changed:[changed],old:old,presented:AuthFixed.fingerprint,sftpReturned:0,fileOps:0,recordUnchanged:false))
            let now=BuildLocation.builtAt+20,id="12345678-1234-1234-1234-123456789abc"
            let generation=BuildLocation.fixtureRoot+"/.runtime/keyonly/credentials-012345abcdef"
            let contract=AuthContract(schema:1,id:id,scenario:.knownHostMismatch,generation:generation,project:AuthFixed.project,container:AuthFixed.container,image:AuthFixed.image,base:AuthFixed.base,fingerprint:AuthFixed.fingerprint,collectedAt:BuildLocation.builtAt+1,preparedAt:now,publicHashes:Dictionary(uniqueKeysWithValues:["provenance.json","known_hosts","fingerprint.txt","packages.txt"].map{($0,String(repeating:"a",count:64))}),replacementStep:AuthFixed.replacementStep)
            let path=BuildLocation.ownRoot+"/.runtime/auth-"+id+"/case.json"
            try contract.validate(path:path,now:now);checks+=1
            for time in [now-1,now+901,Double.nan] {try refuses{try contract.validate(path:path,now:time)}}
            try refuses{try contract.validate(path:path.replacingOccurrences(of:id,with:"latest"),now:now)}
            var encoded=try JSONSerialization.jsonObject(with:JSONEncoder().encode(contract)) as! [String:Any]
            for (field,value) in [("project","foreign"),("container",String(repeating:"b",count:64)),("fingerprint","SHA256:other"),("replacementStep","automatic"),("scenario","generic-auth")] {
                var bad=encoded;bad[field]=value
                try refuses{let mutated=try JSONDecoder().decode(AuthContract.self,from:JSONSerialization.data(withJSONObject:bad));try mutated.validate(path:path,now:now)}
            }
            encoded["extra"]="refuse";try refuses{_=try authObject(JSONSerialization.data(withJSONObject:encoded),keys:AuthContract.keys)}
            // Valid pre-existing PUBLIC test fixtures, parsed by mature ssh-keygen.
            let first=try HostPublicKey(openSSHPublicKey:"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE7UT0nd6jwWZVEVSodMrNLwfp8wralbSFtJ5vUAuvqg")
            let second=try HostPublicKey(openSSHPublicKey:"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICVjCQeOke+c616gj3L7T3Xi0vvxcnF4wNs5FYMv6g3C")
            let directory=BuildLocation.offlineRoot+"/unit-"+UUID().uuidString.lowercased();try check(mkdir(directory,0o700)==0)
            let store=try authTrust(directory);try await seedTrust(store,key:first)
            let before=try knownHash(directory),host=HostIdentity(address:try HostAddress("127.0.0.1"),port:try SSHPort(22221))
            guard case .rejected(let observed)=try await store.evaluate(host:host,key:second) else {throw AuthFailureError.trustEvent};checks+=1
            try check(observed.expectedFingerprint==first.fingerprint && observed.presentedFingerprint==second.fingerprint && observed.algorithm=="ssh-ed25519")
            try check(try knownHash(directory)==before)
            try PrivateInput.writeExclusive(Data("PUBLIC_BYSTANDER".utf8),to:directory+"/trust/bystander")
            var cleanupRejected=false;do{try cleanupOwnedTrust(directory:directory+"/trust",knownHostsSHA256:before)}catch{cleanupRejected=true}
            try check(cleanupRejected && access((directory+"/trust/known_hosts"),F_OK)==0 && access((directory+"/trust/bystander"),F_OK)==0)
            try check(unlink(directory+"/trust/bystander")==0)
            var refused=false;do{_=try await store.prepareReplacement(host:host,key:second,expectedCurrentFingerprint:second.fingerprint)}catch{refused=true};try check(refused)
            let request=try await store.prepareReplacement(host:host,key:second,expectedCurrentFingerprint:first.fingerprint)
            try check(request.reason == .manuallyVerifiedReplacement(previousFingerprint:first.fingerprint))
            _=try await store.confirm(request,displayedFingerprint:second.fingerprint);checks+=1
            refused=false;do{_=try await store.confirm(request,displayedFingerprint:second.fingerprint)}catch{refused=true};try check(refused)
            let after=try knownHash(directory);try check(before != after)
            try cleanupOwnedTrust(directory:directory+"/trust",knownHostsSHA256:after);try check(access((directory+"/trust"),F_OK) != 0)
            try check(rmdir(directory)==0)
            print("Authentication negative offline checks passed: \(checks). Public/synthetic contracts and real local Trust API only; no credentials, network, Docker or actual generation.")
        }catch{fputs("Authentication negative offline failure after \(checks) checks; no secret details.\n",stderr);exit(1)}
    }
}
