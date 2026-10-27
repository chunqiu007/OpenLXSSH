import Foundation
import RemoteTerminalCore

@main enum OfflineMain {
    static func main() throws {
        var checks = 0
        func check(_ condition: Bool) throws {
            guard condition else { throw TerminalCheckError.integrity }; checks += 1
        }
        func rejects(_ operation: () throws -> Void) throws {
            do { try operation() } catch { checks += 1; return }
            throw TerminalCheckError.integrity
        }
        try check(TerminalOptions.parse([]).action == .help)
        try check(TerminalOptions.parse(["validate", "--contract", "/not/opened/remote-terminal.json"]).action == .validate)
        try rejects { _ = try TerminalOptions.parse(["--live", "--contract", "/not/opened/remote-terminal.json"]) }
        try rejects { _ = try TerminalOptions.parse(["validate", "--host", "example.com"]) }
        let id = String(repeating: "a", count: 32)
        var budget = try ProbeBudget(nonce: id, sourceCount: 10, sourceSHA256: String(repeating: "c", count: 64), start: 100)
        func frame(_ event: String, _ fields: String = "") -> String { "RT1|" + id + "|" + event + "|" + fields + "|END" }
        let stages: [(String, ProbeAction)] = [
            (frame("load-ready", "10," + String(repeating: "c", count: 64)), .source),
            (frame("hello", "10000,321"), .none), (frame("input-ready", String(ProbePlan.input.count)), .sample),
            (frame("input", String(ProbePlan.input.count) + "," + Syntax.hash(ProbePlan.input)), .none),
            (frame("interrupt-ready"), .interrupt), (frame("interrupt", "1"), .none), (frame("resize-ready"), .resize),
            (frame("size", "31,93"), .vimStart), (frame("vim-ready"), .vimKeys),
            (frame("vim", String(ProbePlan.document.count) + "," + Syntax.hash(ProbePlan.document)), .none), (frame("done", "1"), .none), (frame("returned", "0"), .complete)]
        var screen = "ordinary shell text without test acknowledgements"
        for (index, stage) in stages.enumerated() {
            screen += "\r\n" + stage.0
            try check(budget.inspect(screen, now: Double(101 + index)) == stage.1)
            try check(budget.inspect(screen, now: Double(101 + index)) == .none)
            if index == 10 {
                try check(budget.cleanupAcknowledged)
                try rejects { try budget.requireComplete() } // done is cleanup only, not return-to-outer proof.
            }
        }
        try check(budget.events == 12)
        try budget.requireComplete(); checks += 1
        var wrapped = try ProbeBudget(nonce: id, sourceCount: 10, sourceSHA256: String(repeating: "c", count: 64), start: 100)
        _ = try wrapped.inspect(frame("load-ready", "10," + String(repeating: "c", count: 64)), now: 101)
        try check(wrapped.inspect("RT1|" + id + "|hel\nlo|10000,321|END", now: 102) == .none)
        try check(wrapped.remotePID == 321)
        for bad in [frame("hello", "0,321"), frame("vim-ready"), frame("failed", "1"), frame("hello", "10000,0"),
                    frame("hello", "10000,321|extra"), frame("hello", "10000,321") + frame("done", "1")] {
            try rejects { var value = try ProbeBudget(nonce: id, sourceCount: 10, sourceSHA256: String(repeating: "c", count: 64), start: 100); _ = try value.inspect(bad, now: 101) }
        }
        try rejects { var value = try ProbeBudget(nonce: id, sourceCount: 10, sourceSHA256: String(repeating: "c", count: 64), start: 100); _ = try value.inspect("", now: 225) }
        try rejects { var value = try ProbeBudget(nonce: id, sourceCount: 10, sourceSHA256: String(repeating: "c", count: 64), start: 100); _ = try value.inspect(String(repeating: "x", count: 65537), now: 101) }
        var unrelated = try ProbeBudget(nonce: id, sourceCount: 10, sourceSHA256: String(repeating: "c", count: 64), start: 100)
        try check(unrelated.inspect("Password: RT1|" + String(repeating: "b", count: 32) + "|input-ready|1|END", now: 101) == .none)
        let source = Data("public fixed source".utf8)
        let command = try ProbePlan.command(source: source, nonce: id)
        try check(command.last == 13)
        try check(!String(decoding: command, as: UTF8.self).contains("Password"))
        try rejects { _ = try ProbePlan.command(source: source, nonce: id + ";id") }
        try rejects { _ = try ProbePlan.command(source: Data(), nonce: id) }
        try check(ProbePlan.input == Data([65,83,67,73,73,32,47,32,228,184,173,230,150,135,32,47,32,101,204,129]))
        let fingerprint = "SHA256:" + Data(repeating: 1, count: 32).base64EncodedString().dropLast()
        var object: [String: Any] = ["schema": 1, "taskID": "REAL-OUTER-PTY-TUI-PREP-A", "service": "keyonly", "host": "127.0.0.1", "port": 22221,
                                   "user": "fixture", "key": "edplain", "credentialDirectory": "/fixture/.runtime/keyonly/credentials-012345abcdef",
                                   "expectedFingerprint": String(fingerprint), "baseImage": TerminalContract.base, "imageID": "sha256:" + String(repeating: "a", count: 64),
                                   "containerID": String(repeating: "b", count: 64), "project": "openlxssh-fixture-012345abcdef", "networkID": String(repeating: "c", count: 64),
                                   "context": "desktop-linux", "endpoint": "unix:///Users/test/.docker/run/docker.sock", "collectedAt": 90.0, "expiresAt": 200.0]
        func validate(_ value: [String: Any]) throws {
            let data = try JSONSerialization.data(withJSONObject: value)
            _ = try Syntax.object(data, keys: TerminalContract.keys)
            let contract = try JSONDecoder().decode(TerminalContract.self, from: data)
            try contract.validate(path: "/own/.runtime/case-012345abcdef/remote-terminal.json", ownRoot: "/own", fixtureRoot: "/fixture", home: "/Users/test", now: 100)
        }
        try validate(object); checks += 1
        let contract = try JSONDecoder().decode(TerminalContract.self, from: JSONSerialization.data(withJSONObject: object))
        let volume = contract.project + "_key-data"
        let binds = [volume + ":/fixture:rw"]
        let mount: [String: Any] = ["Type": "volume", "Name": volume, "Source": "/var/lib/docker/volumes/" + volume + "/_data", "Destination": "/fixture", "Driver": "local", "Mode": "rw", "RW": true, "Propagation": ""]
        // Actual public Docker shape: Binds includes the owned named volume, not a host bind.
        try Syntax.validateMounts(binds: binds, mounts: [mount], project: contract.project); checks += 1
        for badBinds: Any in [NSNull(), ["/Users/host:/fixture:rw"], ["/var/run/docker.sock:/fixture:rw"], binds + ["other:/tmp:rw"], [volume + ":/fixture:ro"]] {
            try rejects { try Syntax.validateMounts(binds: badBinds, mounts: [mount], project: contract.project) }
        }
        for (field, value): (String, Any) in [("Type", "bind"), ("Name", "other"), ("Source", "/Users/host"), ("Destination", "/tmp"), ("Driver", "other"), ("RW", false), ("RW", 1), ("Mode", "ro"), ("Propagation", "rshared")] {
            var bad = mount; bad[field] = value
            try rejects { try Syntax.validateMounts(binds: binds, mounts: [bad], project: contract.project) }
        }
        try rejects { try Syntax.validateMounts(binds: binds, mounts: [mount, mount], project: contract.project) }
        try rejects { try Syntax.validateMounts(binds: binds, mounts: [], project: contract.project) }
        let image: [String: Any] = ["Id": contract.imageID, "Architecture": "arm64", "Os": "linux", "Config": ["Labels": ["org.openlxssh.fixture": "env-fixture-a", "org.openlxssh.fixture.base": TerminalContract.base]]]
        try Syntax.validateImage(JSONSerialization.data(withJSONObject: [image]), contract: contract); checks += 1 // direct-build image has no compose.project label.
        for field in ["Id", "Architecture", "Os", "Config"] {
            var bad = image; bad[field] = "wrong"
            try rejects { try Syntax.validateImage(JSONSerialization.data(withJSONObject: [bad]), contract: contract) }
        }
        for label in ["org.openlxssh.fixture", "org.openlxssh.fixture.base"] {
            var bad = image
            var labels = ["org.openlxssh.fixture": "env-fixture-a", "org.openlxssh.fixture.base": TerminalContract.base]
            labels[label] = "wrong"; bad["Config"] = ["Labels": labels]
            try rejects { try Syntax.validateImage(JSONSerialization.data(withJSONObject: [bad]), contract: contract) }
        }
        for (name, value): (String, Any) in [("host", "localhost"), ("port", 22225), ("service", "passwordonly"), ("key", "edencrypted"),
                                            ("endpoint", "tcp://127.0.0.1:2375"), ("expiresAt", 100.0), ("collectedAt", 101.0),
                                            ("credentialDirectory", "/fixture/.runtime/keyonly/credentials-latest"), ("command", "unreviewed")] {
            var bad = object; bad[name] = value; try rejects { try validate(bad) }
        }
        object.removeValue(forKey: "containerID"); try rejects { try validate(object) }
        try check(checks == 83) // Original complete Core gate remains, before new post-auth tests.
        let shortFrame = "RTS1|" + id + "|shell-ready|1|END"
        var short = try ShortShellACK(nonce: id, start: 100)
        let shortCommand = try short.command()
        try check(shortCommand.count <= 256 && shortCommand.allSatisfy { $0 < 128 })
        try check(shortCommand.last == 13)
        try check(!String(decoding: shortCommand, as: UTF8.self).contains("RTS1|")) // echoed command cannot satisfy ACK.
        try check(!String(decoding: shortCommand, as: UTF8.self).contains("RT1|"))
        try rejects { _ = try short.inspect(rendered: shortFrame, now: 101) }
        try rejects { try short.requireAcknowledged() }
        try short.didEnqueue(now: 101)
        try rejects { try short.didEnqueue(now: 101.1) }
        try check(short.inspect(rendered: String(decoding: shortCommand, as: UTF8.self), now: 102) == false)
        try check(short.inspect(rendered: "unrelated Password text RTS1|" + String(repeating: "b", count: 32) + "|shell-ready|1|END", now: 102) == false)
        try check(short.inspect(rendered: "RTS1|" + id + "|shell-\nready|1|END", now: 103))
        try short.requireAcknowledged(); checks += 1
        try check(short.inspect(rendered: shortFrame, now: 104) == false)
        for value in ["RTS1|" + id + "|shell-ready|0|END", "RTS1|" + id + "|shell-ready|1,extra|END",
                      shortFrame + shortFrame, "RT1|" + id + "|load-ready|10," + String(repeating: "c", count: 64) + "|END"] {
            try rejects {
                var state = try ShortShellACK(nonce: id, start: 100)
                try state.didEnqueue(now: 101); _ = try state.inspect(rendered: value, now: 102)
            }
        }
        try rejects { _ = try ShortShellACK(nonce: id + ";id", start: 100) }
        try rejects { var state = try ShortShellACK(nonce: id, start: 100); try state.didEnqueue(now: 101); _ = try state.inspect(rendered: "", now: 112) }
        try rejects { var state = try ShortShellACK(nonce: id, start: 100); try state.didEnqueue(now: 101); _ = try state.inspect(rendered: String(repeating: "x", count: 65537), now: 102) }
        var diagnostics = try PostAuthDiagnostics(start: 100)
        diagnostics.stage = .waitingShortACK; diagnostics.failureStage = .waitingShortACK
        diagnostics.failureSession = SessionObservation(state: .failed, failure: .launchFailed, lastExitCode: 255, inputError: nil, pendingInputBytes: 0, ownedPID: nil)
        diagnostics.preCloseSession = diagnostics.failureSession
        diagnostics.terminalFailure = .launchFailed; diagnostics.stopRequested = false
        diagnostics.firstInputBefore = SessionObservation(state: .connected, failure: nil, lastExitCode: nil, inputError: nil, pendingInputBytes: 0, ownedPID: 321)
        diagnostics.firstInputAfter = SessionObservation(state: .connected, failure: nil, lastExitCode: nil, inputError: .inputFull, pendingInputBytes: 80, ownedPID: 321)
        diagnostics.inputAttempts = 1; diagnostics.inputReturns = 1; diagnostics.lastInputByteCount = shortCommand.count
        try diagnostics.mark(.connectRequested, now: 100)
        try diagnostics.mark(.connected, now: 101)
        try diagnostics.mark(.firstInputAttempt, now: 102)
        try diagnostics.mark(.firstInputReturned, now: 102.1)
        try diagnostics.mark(.shortACKEnqueued, now: 102.1)
        try diagnostics.mark(.sessionEnded, now: 103)
        try diagnostics.mark(.connected, now: 104) // First occurrence remains the only recorded time.
        try check(diagnostics.relativeTimes.count == 6)
        try check(diagnostics.relativeTimes.first(where: { $0.event == .connected })?.seconds == 1)
        try rejects { try diagnostics.mark(.cleanupEnded, now: .infinity) }
        try rejects { try diagnostics.mark(.cleanupEnded, now: 99) }
        try rejects { try diagnostics.mark(.cleanupEnded, now: 281) }
        let encodedDiagnostics = try JSONEncoder().encode(diagnostics)
        let diagnosticText = String(decoding: encodedDiagnostics, as: UTF8.self)
        let diagnosticObject = try JSONSerialization.jsonObject(with: encodedDiagnostics) as! [String: Any]
        try check(diagnosticObject["remotePID"] is NSNull)
        try check(diagnosticObject["remotePIDConfirmed"] as? Bool == false)
        try check(diagnosticObject["remoteStarted"] as? Bool == false)
        try check(diagnosticObject["failureStage"] as? String == "waitingShortACK")
        try check(diagnosticText.contains("launchFailed") && diagnosticText.contains("255"))
        try check(!diagnosticText.contains("authenticationFailed")) // Generic exit never becomes an auth refusal.
        for forbidden in ["Password", "remote_probe.py", "RTS1|", "prompt", "terminalText", "inputData", "errorDescription", "key-passphrase", "password.txt"] {
            try check(!diagnosticText.contains(forbidden))
        }
        diagnostics.remoteStarted = true
        try check(diagnostics.remotePIDConfirmed == false) // enqueue is explicitly NOT remote process proof.
        diagnostics.remotePID = 456
        try check(diagnostics.remotePIDConfirmed)
        try check(ObservedSessionState(rawValue: "secret arbitrary state") == nil)
        try check(ObservedSessionFailure(rawValue: "unknown failure details") == nil)
        try check(ObservedInputError(rawValue: "raw error string") == nil)
        guard checks == 128 else { throw TerminalCheckError.integrity }
        print("RemoteTerminal original 128-check baseline passed; no gates removed.")
        func beforeSize() throws -> ProbeBudget {
            var value = try ProbeBudget(nonce: id, sourceCount: 10, sourceSHA256: String(repeating: "c", count: 64), start: 100)
            for stage in stages.prefix(7) { _ = try value.inspect(stage.0, now: 101) }
            return value
        }
        try check(ProbePlan.vimStart == Data("V\r".utf8))
        var start = try beforeSize()
        try check(start.events == 7 && !start.remoteSizeMatched)
        try check(start.inspect("ordinary rendered text", now: 102) == .none)
        try check(!start.remoteSizeMatched && start.events == 7)
        try check(start.inspect(frame("size", "31,93"), now: 103) == .vimStart)
        try check(start.events == 8 && start.remoteSizeMatched)
        for retained in [frame("size", "31,93"), stages.prefix(8).map(\.0).joined(), frame("size", "31,93") + frame("size", "31,93")] {
            try check(start.inspect(retained, now: 104) == .none)
            try check(start.events == 8 && start.remoteSizeMatched)
        }
        try check(start.inspect(frame("vim-ready"), now: 105) == .vimKeys)
        try check(start.events == 9)
        try check(start.inspect(frame("size", "31,93") + frame("vim-ready"), now: 106) == .none)
        try rejects { try start.requireComplete() }
        for bad in [frame("size", "31,94"), frame("size", "0,93"), frame("size", "31,93,extra"), frame("vim-ready")] {
            var value = try beforeSize()
            try rejects { _ = try value.inspect(bad, now: 102) }
            try check(value.events == 7 && !value.remoteSizeMatched)
        }
        var noSizeOrder = try ProbeBudget(nonce: id, sourceCount: 10, sourceSHA256: String(repeating: "c", count: 64), start: 100)
        try rejects { _ = try noSizeOrder.inspect(frame("size", "31,93"), now: 101) }
        try check(!noSizeOrder.remoteSizeMatched && noSizeOrder.events == 0)
        var partial = try beforeSize()
        try check(partial.inspect("RT1|" + id + "|size|31,93|EN", now: 102) == .none)
        try check(!partial.remoteSizeMatched && partial.events == 7)
        try check(partial.inspect(frame("size", "31,93"), now: 103) == .vimStart)
        var duplicate = try beforeSize()
        try check(duplicate.inspect(frame("size", "31,93") + frame("size", "31,93"), now: 102) == .vimStart)
        try check(duplicate.events == 8)
        var coalesced = try beforeSize()
        try rejects { _ = try coalesced.inspect(frame("size", "31,93") + frame("vim-ready"), now: 102) }
        try check(coalesced.events == 8 && coalesced.remoteSizeMatched) // No combined start/keys action is returned.
        var precedingAction = try ProbeBudget(nonce: id, sourceCount: 10, sourceSHA256: String(repeating: "c", count: 64), start: 100)
        for stage in stages.prefix(6) { _ = try precedingAction.inspect(stage.0, now: 101) }
        try rejects { _ = try precedingAction.inspect(frame("resize-ready") + frame("size", "31,93"), now: 102) }
        try check(precedingAction.events == 7 && !precedingAction.remoteSizeMatched) // Conflicting action cannot fabricate size progress.
        print("RemoteTerminal offline core checks passed: \(checks); original128 retained; no files/generation/Docker/socket/live.")
    }
}
