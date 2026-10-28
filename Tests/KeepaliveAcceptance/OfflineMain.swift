import Foundation
import RemoteTerminalCore
import KeepaliveCore

// Executes only pure ACK/nonce functions. No AppKit/session/file/socket/control descriptors.
@main enum OfflineMain {
    static func main() throws {
        var passed = 0
        func require(_ value: Bool, _ name: String) throws {
            guard value else { throw NSError(domain:"KeepaliveOffline",code:1,userInfo:[NSLocalizedDescriptionKey:name]) }
            passed += 1
        }
        func rejected(_ body: () throws -> Void, _ name: String) throws {
            do { try body() }
            catch { passed += 1; return }
            throw NSError(domain:"KeepaliveOffline",code:2,userInfo:[NSLocalizedDescriptionKey:name])
        }
        let run = String(repeating:"a",count:32)
        func data(_ object: [String:Any]) throws -> Data {
            try JSONSerialization.data(withJSONObject:object,options:[.sortedKeys]) + Data([10])
        }
        let goodNormal: [String:Any] = ["op":"normal-ready","run":run,"role":"normal","ok":true]
        let decodedNormal = try KeepaliveControl.decode(data(goodNormal),op:"normal-ready",run:run,role:.normal)
        try require(decodedNormal["ok"] as? Bool == true,"valid-normal")
        let goodDrop: [String:Any] = ["op":"drop-confirmed","run":run,"role":"blackhole","ok":true,
            "mode":"drop","armedAt":100.0,"armedWall":1000.0,"relayNow":100.5,"relayWall":1000.5]
        let decodedDrop = try KeepaliveControl.decode(data(goodDrop),op:"drop-confirmed",run:run,role:.blackhole)
        try require(decodedDrop["mode"] as? String == "drop","valid-drop")
        let result = try KeepaliveControl.decode(data(["op":"result-recorded","run":run,"role":"blackhole","ok":true]),
            op:"result-recorded",run:run,role:.blackhole)
        try require(result["role"] as? String == "blackhole","valid-result-ack")
        let duplicate = Data(("{\"op\":\"normal-ready\",\"run\":\""+run+"\",\"role\":\"normal\",\"ok\":true,\"ok\":true}\n").utf8)
        try rejected({ _ = try KeepaliveControl.decode(duplicate,op:"normal-ready",run:run,role:.normal) },"duplicate-key")
        for (name, change) in [("extra",["extra":1] as [String:Any]),("wrong-role",["role":"blackhole"]),
                               ("wrong-run",["run":String(repeating:"b",count:32)]),("wrong-op",["op":"result-recorded"]),
                               ("nested",["ok":["nested":true]]),("array",["ok":[true]]),("numeric-ok",["ok":1]),
                               ("false-ok",["ok":false])] {
            let invalid = goodNormal.merging(change) { _,new in new }
            try rejected({ _ = try KeepaliveControl.decode(data(invalid),op:"normal-ready",run:run,role:.normal) },name)
        }
        let escaped = Data(("{\"op\":\"normal-ready\",\"run\":\""+run+"\",\"role\":\"normal\",\"o\\u006b\":true}\n").utf8)
        try rejected({ _ = try KeepaliveControl.decode(escaped,op:"normal-ready",run:run,role:.normal) },"escaped-key")
        for key in ["armedAt","armedWall","relayNow","relayWall"] {
            for invalid in [true as Any,"100",0,-1,NSNull()] {
                var object = goodDrop;object[key] = invalid
                try rejected({ _ = try KeepaliveControl.decode(data(object),op:"drop-confirmed",run:run,role:.blackhole) },"invalid-time-"+key)
            }
        }
        var wrongMode = goodDrop;wrongMode["mode"] = "forward"
        try rejected({ _ = try KeepaliveControl.decode(data(wrongMode),op:"drop-confirmed",run:run,role:.blackhole) },"wrong-mode")
        var missing = goodDrop;missing.removeValue(forKey:"armedAt")
        try rejected({ _ = try KeepaliveControl.decode(data(missing),op:"drop-confirmed",run:run,role:.blackhole) },"missing-time")
        for invalid in [Data(),Data(repeating:120,count:2048),Data("{}\n\n".utf8),try data(goodNormal).dropLast()] {
            try rejected({ _ = try KeepaliveControl.decode(Data(invalid),op:"normal-ready",run:run,role:.normal) },"frame-bounds")
        }
        let palindrome = "0123456789abcdeffedcba9876543210"
        try require(String(palindrome.reversed()) == palindrome,"palindrome-test-input")
        for previous in [String(repeating:"0",count:32),String(repeating:"a",count:32),palindrome] + "0123456789abcdef".map({ String($0)+String(repeating:"b",count:31) }) {
            let fresh = try KeepaliveNonce.fresh(from:previous)
            try require(fresh != previous && Syntax.hex(fresh,32),"nonce-distinct-lowerhex")
            try require(fresh.dropFirst() == previous.dropFirst(),"nonce-only-first-nibble")
        }
        for invalid in ["",String(repeating:"a",count:31),String(repeating:"a",count:33),String(repeating:"A",count:32),String(repeating:"g",count:32)] {
            try rejected({ _ = try KeepaliveNonce.fresh(from:invalid) },"invalid-nonce")
        }
        print("Keepalive Swift pure assertions passed: \(passed)")
    }
}
