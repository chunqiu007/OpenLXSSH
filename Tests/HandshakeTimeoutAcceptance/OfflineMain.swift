import Darwin
import Foundation
import OpenLXSSHFiles
import RealIntegrationCore

@main enum OfflineMain {
    static func main()async {
        var checks=0
        func check(_ value:Bool)throws{guard value else{throw TimeoutFailure.contract};checks+=1}
        func refuses(_ body:()throws->Void)throws{do{try body()}catch{checks+=1;return};throw TimeoutFailure.contract}
        do{
            try check(try TimeoutOptions.parse([]).action == .help);try check(try TimeoutOptions.parse(["--help"]).action == .help)
            try check(try TimeoutOptions.parse(["validate","--contract","/not/opened/contract.json"]).action == .validate)
            for args in [["--live","--contract","/not/opened/contract.json"],["--live","--authorized-local-test","--contract","/not/opened/contract.json"],
                ["validate","--primary-reviewed","--contract","/a/contract.json"],["--live","--host","example.com"],["--live","--port","22222"],
                ["validate","--contract","/a/../contract.json"],["--live","--operation-seconds","2"],
                ["validate","--contract","/a/contract.json","--contract","/b/contract.json"]]{try refuses{_=try TimeoutOptions.parse(args)}}
            let id="12345678-1234-1234-1234-123456789abc",path=BuildLocation.ownRoot+"/.runtime/handshake-"+id+"/contract.json"
            let contract=TimeoutContract(schema:1,id:id,host:"127.0.0.1",port:22221,connectSeconds:1,operationSeconds:2,outerSeconds:10,peerSeconds:8)
            try contract.validate(path:path,ownRoot:BuildLocation.ownRoot);checks+=1
            var object=try JSONSerialization.jsonObject(with:JSONEncoder().encode(contract)) as! [String:Any]
            for(field,value)in [("host","0.0.0.0" as Any),("host","localhost"),("port",22222),("operationSeconds",3),("outerSeconds",0),("peerSeconds",9),("schema",2)]{
                var changed=object;changed[field]=value
                try refuses{let parsed=try JSONDecoder().decode(TimeoutContract.self,from:JSONSerialization.data(withJSONObject:changed));try parsed.validate(path:path,ownRoot:BuildLocation.ownRoot)}
            }
            object["extra"]="reject";try check(Set(object.keys) != TimeoutContract.keys)
            try refuses{_=try TimeoutContract.path(path.replacingOccurrences(of:id,with:"latest"),ownRoot:BuildLocation.ownRoot)}
            let peer=PeerSnapshot(accepted:1,sentBytes:0,readCalls:0,openOwnedFDs:0,listenerClosed:true,acceptedClosed:true,taskCompleted:true,expired:false,elapsedSeconds:2.1)
            let callbacks=CallbackSnapshot(authentication:0,trust:0,outerCancelled:false)
            let timeout=TimeoutFacts(kind:"timeout",operation:"handshake",code:-10002)
            try check(expectedHandshakeTimeout(timeout,elapsed:2.1,peer:peer,callbacks:callbacks,sftpReturned:0))
            for error in [TimeoutFacts(kind:"cancelled",operation:"handshake",code:-10001),TimeoutFacts(kind:"transport",operation:"connect",code:61),
                TimeoutFacts(kind:"timeout",operation:"connect",code:-10002),TimeoutFacts(kind:"timeout",operation:"handshake",code:nil),TimeoutFacts(kind:"untrusted",operation:"host-key",code:-10004)]{
                try check(!expectedHandshakeTimeout(error,elapsed:2.1,peer:peer,callbacks:callbacks,sftpReturned:0))}
            for seconds in [0.0,1.49,8.0,Double.nan,Double.infinity]{try check(!expectedHandshakeTimeout(timeout,elapsed:seconds,peer:peer,callbacks:callbacks,sftpReturned:0))}
            for callback in [CallbackSnapshot(authentication:1,trust:0,outerCancelled:false),CallbackSnapshot(authentication:0,trust:1,outerCancelled:false),CallbackSnapshot(authentication:0,trust:0,outerCancelled:true)]{
                try check(!expectedHandshakeTimeout(timeout,elapsed:2.1,peer:peer,callbacks:callback,sftpReturned:0))}
            try check(!expectedHandshakeTimeout(timeout,elapsed:2.1,peer:peer,callbacks:callbacks,sftpReturned:1))
            for other in [PeerSnapshot(accepted:0,sentBytes:0,readCalls:0,openOwnedFDs:0,listenerClosed:true,acceptedClosed:true,taskCompleted:true,expired:false,elapsedSeconds:2),
                PeerSnapshot(accepted:1,sentBytes:1,readCalls:0,openOwnedFDs:0,listenerClosed:true,acceptedClosed:true,taskCompleted:true,expired:false,elapsedSeconds:2),
                PeerSnapshot(accepted:1,sentBytes:0,readCalls:1,openOwnedFDs:0,listenerClosed:true,acceptedClosed:true,taskCompleted:true,expired:false,elapsedSeconds:2),
                PeerSnapshot(accepted:1,sentBytes:0,readCalls:0,openOwnedFDs:1,listenerClosed:false,acceptedClosed:true,taskCompleted:true,expired:false,elapsedSeconds:2),
                PeerSnapshot(accepted:1,sentBytes:0,readCalls:0,openOwnedFDs:0,listenerClosed:true,acceptedClosed:true,taskCompleted:true,expired:true,elapsedSeconds:8)]{
                try check(!expectedHandshakeTimeout(timeout,elapsed:2.1,peer:other,callbacks:callbacks,sftpReturned:0))}
            // FD cleanup mechanism uses pipes only: never socket/bind/connect.
            var pipes:[Int32]=[-1,-1];try check(pipe(&pipes)==0)
            let owner=PeerDescriptors();try owner.ownListener(pipes[0]);try owner.ownAccepted(pipes[1]);try check(owner.count()==2)
            owner.closeAll();try check(owner.count()==0)
            for fd in pipes{try check(fcntl(fd,F_GETFD) == -1 && errno==EBADF)}
            var reused:[Int32]=[-1,-1];try check(pipe(&reused)==0)
            owner.closeAll() // must NOT close a recycled numeric fd
            for fd in reused{try check(fcntl(fd,F_GETFD)>=0);Darwin.close(fd)}
            let gate=CallbackGate();gate.auth(ChallengeReply<[Data]>());try check(gate.token.isCancelled && gate.snapshot().authentication==1)
            print("Handshake timeout offline checks passed: \(checks). Synthetic classification/contracts and pipe-FD cleanup only; NO socket, credentials or handshake.")
        }catch{fputs("Handshake timeout offline failure after \(checks) checks; no wire/private details.\n",stderr);exit(1)}
    }
}
