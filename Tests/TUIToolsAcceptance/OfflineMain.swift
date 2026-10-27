import Foundation
import RemoteTerminalCore
import TUIToolsCore

@main enum OfflineMain {
    static func main() throws {
        var checks = 0
        func check(_ condition: Bool) throws { guard condition else { throw TerminalCheckError.integrity }; checks += 1 }
        func rejects(_ operation: () throws -> Void) throws {
            do { try operation() } catch { checks += 1; return }; throw TerminalCheckError.integrity
        }
        let nonce = String(repeating: "a", count: 32), hash = String(repeating: "b", count: 64)
        func frame(_ event: String, _ fields: String = "") -> String { "RT1|" + nonce + "|" + event + "|" + fields + "|END" }
        func fresh() throws -> TUIBudget { try TUIBudget(nonce: nonce, sourceCount: 10, sourceHash: hash, start: 100) }
        let frames: [(String, TUIAction)] = [
            (frame("load-ready", "10," + hash), .source), (frame("hello", "10000,321"), .start),
            (frame("tmux-ready", "10000,322," + String(TmuxPlan.input.count)), .sample),
            (frame("input", String(TmuxPlan.input.count) + "," + Syntax.hash(TmuxPlan.input)), .prepareResize),
            (frame("resize-ready"), .resize), (frame("size", "31,93"), .allowDetach), (frame("detach-ready"), .detach),
            (frame("detached", "1,323"), .none), (frame("done", "1"), .none), (frame("returned", "0"), .complete)]
        var budget = try fresh(), history = "ordinary rendered screen"
        for (index, value) in frames.enumerated() {
            history += value.0
            try check(budget.inspect(history, now: Double(101 + index)) == value.1)
            try check(budget.inspect(history, now: Double(101 + index)) == .none)
            if index < 9 { try rejects { try budget.requireComplete() } }
        }
        try budget.requireComplete(); checks += 1
        try check(budget.events == 10 && budget.remotePID == 321 && budget.panePID == 322 && budget.serverPID == 323)
        try check(budget.inputMatched && budget.sizeMatched && budget.detached && budget.cleaned)
        try check(TmuxPlan.detach == Data([2, 100]) && TmuxPlan.start == Data("T\r".utf8))
        try check(TmuxPlan.resize == Data([82]) && TmuxPlan.allowDetach == Data([68]))
        for bad in [frame("tmux-ready", "10000,322,1"), frame("size", "31,93"), frame("returned", "0"), frame("failed", "private text"), frame("unknown", "private")] {
            var value = try fresh(); try rejects { _ = try value.inspect(bad, now: 101) }
            try check(value.events == 0 && !value.sizeMatched && !value.cleaned)
        }
        var wrongSize = try fresh()
        for value in frames.prefix(5) { _ = try wrongSize.inspect(value.0, now: 101) }
        try rejects { _ = try wrongSize.inspect(frame("size", "30,93"), now: 102) }
        try check(!wrongSize.sizeMatched && wrongSize.events == 5)
        var wrongHash = try fresh()
        for value in frames.prefix(3) { _ = try wrongHash.inspect(value.0, now: 101) }
        try rejects { _ = try wrongHash.inspect(frame("input", "1," + hash), now: 102) }
        try check(!wrongHash.inputMatched && wrongHash.events == 3)
        var coalesced = try fresh()
        try rejects { _ = try coalesced.inspect(frames[0].0 + frames[1].0, now: 101) }
        try check(coalesced.events == 1)
        var remoteFailure = try fresh()
        try rejects { _ = try remoteFailure.inspect(frame("failed", "cleanup,os-error,eacces"), now: 101) }
        try check(remoteFailure.remoteFailure?.errno == .eacces && remoteFailure.unexpected == .failed && remoteFailure.events == 0)
        var report = TUIReport(); report.recordProbe(remoteFailure)
        let text = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
        try check(text.contains("eacces") && !text.contains("private"))
        var unknown = try fresh()
        try rejects { _ = try unknown.inspect(frame("/private/unknown", "private"), now: 101) }
        report.recordProbe(unknown)
        try check(unknown.unexpected == .unrecognized)
        try check(!String(decoding: try JSONEncoder().encode(report), as: UTF8.self).contains("private"))
        var timeout = try fresh(); try rejects { _ = try timeout.inspect("", now: 200) }
        var oversized = try fresh(); try rejects { _ = try oversized.inspect(String(repeating: "x", count: 65537), now: 101) }
        var unrelated = try fresh()
        try check(unrelated.inspect("RT1|" + String(repeating: "c", count: 32) + "|hello|10000,321|END", now: 101) == .none)
        var wrapped = try fresh()
        try check(wrapped.inspect(frames[0].0.replacingOccurrences(of: "load-ready", with: "load-\nready"), now: 101) == .source)
        try check(!report.productAcceptance && !report.pixelsVerified && !report.imeTested && !report.htopTested)
        guard checks == 61 else { throw TerminalCheckError.integrity } // Original58 plus three new resize-ready frame checks.
        func beforeInput() throws -> TUIBudget {
            var value = try fresh()
            for stage in frames.prefix(3) { _ = try value.inspect(stage.0, now: 101) }
            return value
        }
        let count = String(TmuxPlan.input.count), inputHash = Syntax.hash(TmuxPlan.input)
        for (bad, reason, bucket, length, hashMatch): (String, TUIRejectReason, TUIFieldCount, Bool?, Bool?) in [
            (frame("input", count + "," + inputHash + "|extra"), .envelope, .two, true, true),
            (frame("input", count), .fieldCount, .one, true, nil),
            (frame("input", count + "," + inputHash + ",extra"), .fieldCount, .three, true, true),
            (frame("input", count + "," + inputHash + ",extra,more"), .fieldCount, .other, true, true),
            (frame("input", "0," + inputHash), .integrity, .two, false, true),
            (frame("input", count + "," + String(repeating: "0", count: 64)), .integrity, .two, true, false)] {
            var value = try beforeInput()
            try rejects { _ = try value.inspect(bad, now: 102) }
            try check(value.rejectReason == reason && value.rejectFieldCount == bucket)
            try check(value.inputLengthMatch == length && value.inputHashMatch == hashMatch)
            try check(value.events == 3 && !value.inputMatched && !value.sizeMatched)
            var diagnostic = TUIReport(); diagnostic.recordProbe(value)
            let encoded = try JSONEncoder().encode(diagnostic)
            let object = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
            try check(object["rejectReason"] as? String == reason.rawValue)
            try check(object["rejectFieldCount"] as? String == bucket.rawValue)
            let safe = String(decoding: encoded, as: UTF8.self)
            try check(!safe.contains(inputHash) && !safe.contains("extra") && !safe.contains("RT1|"))
        }
        var sequence = try beforeInput()
        _ = try sequence.inspect(frames[3].0, now: 102)
        try check(sequence.inspect(frames[3].0, now: 103) == .none)
        try check(sequence.rejectReason == nil && sequence.rejectFieldCount == nil && sequence.inputLengthMatch == nil && sequence.inputHashMatch == nil)
        try rejects { _ = try sequence.inspect(frame("input", count + "," + String(repeating: "0", count: 64)), now: 104) }
        try check(sequence.rejectReason == .sequence && sequence.rejectFieldCount == .two)
        try check(sequence.inputLengthMatch == true && sequence.inputHashMatch == false && sequence.events == 4 && sequence.inputMatched)
        var envelope = try fresh()
        try rejects { _ = try envelope.inspect("RT1|" + nonce + "|input|END", now: 101) }
        try check(envelope.rejectReason == .envelope && envelope.rejectFieldCount == .zero && envelope.inputLengthMatch == nil)
        try check(wrongSize.rejectReason == .size && wrongSize.rejectFieldCount == .two)
        try check(coalesced.rejectReason == .actions)
        try check(timeout.rejectReason == .deadline && oversized.rejectReason == .renderLimit)
        try check(TUIRejectReason(rawValue: "/private/reason") == nil && TUIFieldCount(rawValue: "17") == nil)
        guard checks == 114 else { throw TerminalCheckError.integrity } // Original111 retained, plus three new-frame checks.
        var resize = try beforeInput()
        try check(resize.inspect(frames[3].0, now: 102) == .prepareResize)
        try check(TmuxPlan.prepareResize == Data([67]))
        try check(resize.inspect(frames[3].0, now: 103) == .none)
        try check(resize.inspect(frame("resize-ready"), now: 104) == .resize)
        try check(resize.inspect(frame("resize-ready"), now: 105) == .none)
        try check(resize.events == 5 && resize.inputMatched && !resize.sizeMatched)
        try check(resize.inspect(frame("size", "31,93"), now: 106) == .allowDetach)
        try check(resize.sizeMatched && resize.events == 6)
        var missingReady = try beforeInput()
        _ = try missingReady.inspect(frames[3].0, now: 102)
        try rejects { _ = try missingReady.inspect(frame("size", "31,93"), now: 103) }
        try check(missingReady.rejectReason == .sequence && !missingReady.sizeMatched)
        var earlyReady = try beforeInput()
        try rejects { _ = try earlyReady.inspect(frame("resize-ready"), now: 102) }
        try check(earlyReady.events == 3)
        var combined = try beforeInput()
        try rejects { _ = try combined.inspect(frames[3].0 + frame("resize-ready"), now: 102) }
        try check(combined.rejectReason == .actions && combined.events == 4)
        var paneError = try fresh()
        try rejects { _ = try paneError.inspect(frame("failed", "resize,deadline,none,24,80"), now: 102) }
        try check(paneError.remoteFailure?.stage == .resize && paneError.remoteFailure?.seenRows == 24 && paneError.remoteFailure?.seenCols == 80)
        for fields in ["resize,deadline,none,65536,80", "resize,deadline,none,0,80", "resize,deadline,none,-1,80", "input,refused,none,24,80"] {
            var value = try fresh()
            try rejects { _ = try value.inspect(frame("failed", fields), now: 102) }
            try check(value.remoteFailure == nil)
        }
        print("TUITools pure core checks passed: \(checks); original111 retained; no live TUI/pixels/IME claim.")
    }
}
