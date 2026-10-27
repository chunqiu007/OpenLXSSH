import Foundation
import HTOPCore
import RemoteTerminalCore

@main enum OfflineMain {
    static func main() throws {
        var checks = 0
        func check(_ value: Bool) throws { guard value else { throw TerminalCheckError.integrity }; checks += 1 }
        func rejects(_ operation: () throws -> Void) throws { do { try operation() } catch { checks += 1; return }; throw TerminalCheckError.integrity }
        let nonce = String(repeating: "a", count: 32), hash = String(repeating: "b", count: 64)
        func frame(_ name: String, _ fields: String) -> String { "RT1|" + nonce + "|" + name + "|" + fields + "|END" }
        var budget = try HBudget(nonce: nonce, count: 10, sourceHash: hash, start: 100)
        let frames: [(String, HAction)] = [(frame("load-ready", "10," + hash), .source), (frame("hello", "10000,321,1000,113,10,113,11"), .start), (frame("exited", "0"), .none), (frame("done", "1"), .none), (frame("returned", "0"), .complete)]
        var history = ""
        for (index, item) in frames.enumerated() {
            history += item.0
            try check(budget.inspect(history, now: Double(index + 101)) == item.1)
            try check(budget.inspect(history, now: Double(index + 101)) == .none)
            if index < 4 { try rejects { try budget.requireComplete() } }
        }
        try budget.requireComplete(); checks += 1
        try check(budget.binding?.parent == HIdentity(pid: 321, startTicks: 1000))
        try check(budget.events == 5 && budget.normalExit && budget.cleanup)
        for bad in [frame("hello", "10000,321"), frame("exited", "0"), frame("done", "1"), frame("failed", "readiness,private-error,none")] {
            try rejects { var value = try HBudget(nonce: nonce, count: 10, sourceHash: hash, start: 100); _ = try value.inspect(bad, now: 101) }
        }
        var object: [String: Any] = ["schema": 1, "stage": "initialized", "parent": ["pid": 321, "startTicks": 1000], "htop": NSNull(), "child": NSNull(), "rows": NSNull(), "cols": NSNull(), "failure": NSNull(), "configPresent": false]
        func status() throws -> HStatus { try HStatus.decode(JSONSerialization.data(withJSONObject: object)) }
        var states = HStatusBudget(parent: HIdentity(pid: 321, startTicks: 1000))
        try states.inspect(status()); try check(!states.readyObserved && !states.sizeObserved)
        object["stage"] = "ready"; object["htop"] = ["pid": 322, "startTicks": 1001]; object["child"] = ["pid": 323, "startTicks": 1002]
        try states.inspect(status()); try check(states.readyObserved && !states.sizeObserved)
        try states.inspect(status()); checks += 1
        object["stage"] = "sized"; object["rows"] = 31; object["cols"] = 93
        try states.inspect(status()); try check(states.sizeObserved)
        var premature = HStatusBudget(parent: HIdentity(pid: 321, startTicks: 1000))
        try rejects { try premature.inspect(status()) }
        object["cols"] = 92
        try rejects { try states.inspect(status()) }
        object["cols"] = 93; object["parent"] = ["pid": 321, "startTicks": 2000]
        try rejects { try states.inspect(status()) }
        object["parent"] = ["pid": 321, "startTicks": 1000]; object["htop"] = ["pid": 322, "startTicks": 2001]
        try rejects { try states.inspect(status()) }
        object["htop"] = ["pid": 322, "startTicks": 1001]; object["unknown"] = "private"
        try rejects { _ = try status() }
        object.removeValue(forKey: "unknown"); object["failure"] = ["stage": "readiness", "kind": "private", "errno": "none"]
        try rejects { _ = try status() }
        object["failure"] = NSNull(); object["rows"] = 65536
        try rejects { _ = try status() }
        try check(HPlan.quit == Data([113]) && HPlan.start == Data("H\r".utf8))
        let report = HReport()
        try check(!report.readinessVerified && !report.remoteSizeMatched && !report.quitEnqueued)
        try check(!report.pixelsVerified && !report.internalStateVerified && !report.productAcceptance && !report.imeTested)
        print("HTOP pure core checks passed: \(checks); no live/readiness/pixels claim.")
    }
}
