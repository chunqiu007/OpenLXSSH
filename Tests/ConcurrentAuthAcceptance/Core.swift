import Foundation
import RealIntegrationCore

enum ConcurrentPolicy {
    enum Action: Equatable { case help, validate, offline, execute }
    static let help = "Concurrent auth TEST ONLY: --help | --validate | --offline-check | --execute --primary-release --contract ABSOLUTE_PATH. No builder; live execution requires separate primary review/release."
    static let primaryPrompt = "fixture@" + "[127.0.0.1]:22224" + "'s password: " // System OpenSSH user/HostKeyAlias template, NOT observed text.
    static var primaryHash: String { PrivateInput.sha256(Data(primaryPrompt.utf8)) }
    static func parse(_ args: [String]) throws -> (Action, String?) {
        if args.isEmpty || args == ["--help"] { return (.help, nil) }
        if args == ["--validate"] { return (.validate, nil) }
        if args == ["--offline-check"] { return (.offline, nil) }
        guard args.count == 4, args[0] == "--execute", args[1] == "--primary-release", args[2] == "--contract",
              args[3].hasPrefix("/"), !args[3].contains("//"), !args[3].split(separator: "/").contains(where: { $0 == "." || $0 == ".." }),
              !args[3].unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { throw OpenSSHError.invalidContract }
        return (.execute, args[3]) // Syntax only: no file, signature, AppKit, Docker or credential access.
    }
    static func check(_ input: OpenSSHInput) throws {
        let c = input.contract
        guard c.testCase == .positive, c.service == .passwordKbd, c.key == .none, c.primary == .password,
              c.port == 22224, c.primaryPromptSHA256 == primaryHash else { throw OpenSSHError.invalidContract }
    }
    static func offlineCheck() throws {
        func rejects(_ expected: OpenSSHError, _ operation: () throws -> Void) throws {
            do { try operation() } catch let actual as OpenSSHError where actual == expected { return }
            throw OpenSSHError.invalidContract
        }
        guard try parse([]).0 == .help, try parse(["--validate"]).0 == .validate,
              try parse(["--offline-check"]).0 == .offline, primaryPrompt.utf8.count == 38 else { throw OpenSSHError.invalidContract }
        try rejects(.invalidContract) { _ = try parse(["--execute", "--contract", "/not-read"]) }
        try rejects(.invalidContract) { _ = try parse(["--execute", "--primary-release", "--contract", "/a/../b"]) }
        guard try parse(["--execute", "--primary-release", "--contract", "/not-read"]).0 == .execute else { throw OpenSSHError.invalidContract }
        let first = UUID(), pending = UUID(), challengeA = String(repeating: "a", count: 24), challengeB = String(repeating: "b", count: 24)
        var a = try OpenSSHAnswerBudget(service: .passwordKbd, primary: .password, primaryHash: primaryHash, start: 10)
        _ = try a.claim(id: first, prompt: primaryPrompt, kind: "unknownMasked", hasHint: false, now: 11); try a.consume(id: first, now: 11)
        var unknown = a
        try rejects(.unknownRequest) { _ = try unknown.claim(id: UUID(), prompt: "unrecognized", kind: "unknownMasked", hasHint: false, now: 12) }
        _ = try a.claim(id: pending, prompt: OpenSSHAnswerBudget.otpPrompt(port: 22224, session: challengeA, index: 0), kind: "unknownMasked", hasHint: false, now: 12)
        var duplicate = a
        try rejects(.staleRequest) { _ = try duplicate.claim(id: pending, prompt: primaryPrompt, kind: "unknownMasked", hasHint: false, now: 12) }
        var b = a; try b.consume(id: pending, now: 12)
        try rejects(.wrongRound) { _ = try b.claim(id: UUID(), prompt: OpenSSHAnswerBudget.otpPrompt(port: 22224, session: challengeB, index: 1), kind: "unknownMasked", hasHint: false, now: 13) }
        a.close(); try rejects(.staleRequest) { try a.consume(id: pending, now: 13) }
        var survivor = try OpenSSHAnswerBudget(service: .passwordKbd, primary: .password, primaryHash: primaryHash, start: 10)
        let primaryID = UUID()
        _ = try survivor.claim(id: primaryID, prompt: primaryPrompt, kind: "unknownMasked", hasHint: false, now: 14)
        try survivor.consume(id: primaryID, now: 14)
        for index in 0..<3 {
            let id = UUID(), prompt = try OpenSSHAnswerBudget.otpPrompt(port: 22224, session: challengeB, index: index)
            _ = try survivor.claim(id: id, prompt: prompt, kind: "unknownMasked", hasHint: false, now: 15 + Double(index))
            try survivor.consume(id: id, now: 15 + Double(index))
        }
        try survivor.requireComplete()
        guard a.closed, a.otpAnswers == 0, survivor.sessionID == challengeB, survivor.sessionID != a.sessionID else { throw OpenSSHError.invalidContract }
        var expired = try OpenSSHAnswerBudget(service: .passwordKbd, primary: .password, primaryHash: primaryHash, start: 10)
        try rejects(.staleRequest) { _ = try expired.claim(id: UUID(), prompt: primaryPrompt, kind: "unknownMasked", hasHint: false, now: 70) }
    }
}

struct ConcurrentEvidence: Encodable {
    let sessionID: UUID; let generation: UInt64?; let challengeID: String?; let barrierPID: Int32?; let otpPendingUptime: Double?
    let requests: Int; let primaryAnswers: Int; let otpAnswers: Int; let primaryReads: Int; let otpReads: Int; let successfulSubmissions: Int
    let connectedEvents: Int; let closed: Bool; let ownedPIDReleased: Bool; let handlerDrained: Bool
}
struct ConcurrentRunReceipt: Encodable {
    let taskID = "REAL-CONCURRENT-AUTH-PREP-A"; let runID: UUID; let runDirectory: String
}
struct ConcurrentReport: Encodable {
    let taskID = "REAL-CONCURRENT-AUTH-PREP-A", productAcceptance = false, outerAuthenticationOnly = true, testOnlyHostMinimum = "15.0"
    var runID: UUID?, runDirectory: String?, receiptWritten = false
    var barrierUptime: Double?, aClosedUptime: Double?, bConnectedUptime: Double?
    var policyVerified = false, simultaneousPending = false, bPendingAfterAClose = false, lateReplyRejected = false
    var serverSessionsRemoved = 0
    var a: ConcurrentEvidence?, b: ConcurrentEvidence?, failure: OpenSSHError?
}
