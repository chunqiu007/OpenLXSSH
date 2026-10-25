import Foundation
import Darwin
import AskpassPOSIX

private func require(_ condition: @autoclosure () -> Bool) throws {
    guard condition() else { throw ProbeError.protocolViolation }
}
private func drive(_ broker: FixtureBroker, seconds: TimeInterval = 7,
                   decision: (FixtureBroker.Pending) -> Decision?) throws {
    let end = now() + seconds
    while !broker.allReaped && now() < end {
        broker.pump()
        for pending in broker.pending {
            if let response = decision(pending) {
                try broker.submit(response, session: pending.request.session, requestID: pending.request.id, generation: pending.request.generation)
            }
        }
    }
    try require(broker.allReaped)
    try require(broker.openRequests == 0)
    try require(broker.helpersReleased)
}
private func answer(_ request: Request, bytes: Data) -> Decision {
    switch request.kind {
    case .unknownMasked: .manual(bytes)
    case .confirmation: .confirm(true)
    case .notification: .acknowledge
    }
}

public func runSelfTest(image: String, adversary: String?) throws {
    signal(SIGPIPE, SIG_IGN)
    guard let adversary else { throw ProbeError.unavailable }
    let helper = URL(fileURLWithPath: image).deletingLastPathComponent().appendingPathComponent("openlxssh-askpass-helper").path
    var count = 0
    func passed(_ name: String) { count += 1; print("PASS \(name)") }
    // Every answer is generated at runtime. The value is never formatted into an
    // error, CLI/env, log, file, test snapshot or comparison diagnostic.
    let secretA = try randomBytes(24).base64EncodedData()
    let secretB = try randomBytes(24).base64EncodedData()
    do {
        var brokerIdentity = try identity(getpid())
        try require(ap_signed_keygen(&brokerIdentity) != 0)
        let broker = try FixtureBroker(image: image)
        let id = try broker.launchFixture(mode: "empty")
        guard let session = broker.sessions[id] else { throw ProbeError.unavailable }
        var fixtureIdentity = session.parent
        try require(ap_signed_keygen(&fixtureIdentity) != 0)
        try drive(broker) { _ in .manual(Data()) }
        try require(broker.fixturePassed(id))
    }
    passed("system-keygen policy refuses broker and fixture identities without widening parent trust")
    do {
        let broker = try FixtureBroker(image: image)
        let a = try broker.launchFixture(expectedAnswer: secretA)
        let b = try broker.launchFixture(expectedAnswer: secretB)
        try drive(broker) { pending in answer(pending.request, bytes: pending.request.session == a ? secretA : secretB) }
        if !broker.fixturePassed(a) || !broker.fixturePassed(b) {
            print("DIAGNOSTIC concurrent exitA=\(broker.exitCode(a) ?? -1) exitB=\(broker.exitCode(b) ?? -1) accepted=\(broker.acceptedKinds.count) rejected=\(broker.rejected)")
        }
        try require(broker.fixturePassed(a) && broker.fixturePassed(b))
        try require(broker.acceptedKinds.filter { $0 == .unknownMasked }.count == 4)
        try require(broker.acceptedKinds.filter { $0 == .confirmation }.count == 2)
        try require(broker.acceptedKinds.filter { $0 == .notification }.count == 2)
        try require(ap_mach_name_unknown(broker.serviceName) == 0)
    }
    passed("Mach concurrent sessions, unknown hints, confirm/none, stdin unread")
    do {
        let broker = try FixtureBroker(image: image)
        let id = try broker.launchFixture(mode: "empty", expectedAnswer: Data())
        try drive(broker) { _ in .manual(Data()) }
        try require(broker.fixturePassed(id))
    }
    passed("empty prompt and empty manual response")
    do {
        let boundaryAnswer = try randomBytes(768).base64EncodedData().prefix(Limits.answerBytes)
        let broker = try FixtureBroker(image: image)
        let id = try broker.launchFixture(mode: "max-prompt", expectedAnswer: boundaryAnswer)
        try drive(broker) { _ in .manual(boundaryAnswer) }
        try require(broker.fixturePassed(id))
    }
    passed("4096-byte prompt and 1023-byte random response survive real IPC without truncation")
    for mode in ["wrong-nonce", "wrong-generation", "wrong-session", "oversize", "complex", "ool", "budget", "nested", "bad-signature", "wrong-signer", "replay"] {
        let ports = ap_port_count()
        let broker = try FixtureBroker(image: image)
        let wrongSigner = URL(fileURLWithPath: image).deletingLastPathComponent().appendingPathComponent("openlxssh-askpass-wrong-signer").path
        let selected = mode == "bad-signature" ? adversary : (mode == "wrong-signer" ? wrongSigner : nil)
        let id = try broker.launchFixture(mode: mode == "wrong-signer" ? "bad-signature" : mode, helperImage: selected)
        try drive(broker) { _ in .manual(Data()) }
        try require(broker.fixturePassed(id))
        let category: ProbeError = mode == "complex" || mode == "ool" || mode == "oversize" ? .protocolViolation : (mode == "budget" ? .bounds : (["nested", "bad-signature", "wrong-signer"].contains(mode) ? .identity : (mode == "replay" ? .replay : .stale)))
        try require(broker.rejected[category, default: 0] == 1)
        try require(ap_port_count() == ports + 1) // only broker receive remains
        passed("reject \(mode)")
    }
    do {
        let broker = try FixtureBroker(image: image)
        let a = try broker.launchFixture(mode: "hold", expectedAnswer: secretA)
        guard let grant = broker.sessions[a]?.state.grant else { throw ProbeError.unavailable }
        let b = try broker.launchFixture(mode: "bad-signature", presentedGrant: grant)
        let end = now() + 2
        while broker.exitCode(b) == nil && now() < end { broker.pump() }
        try require(broker.fixturePassed(b) && broker.rejected[.stale, default: 0] == 1)
        try require(broker.pending.count == 1 && broker.pending[0].request.session == a)
        broker.cancel(a); try drive(broker) { _ in nil }
    }
    passed("registered session B cannot replay session A grant even with genuine helper signature")
    do {
        let broker = try FixtureBroker(image: image)
        broker.queuedExecFixture = true
        let id = try broker.launchFixture(mode: "queued-exec")
        let end = now() + 2
        while broker.rejected.isEmpty && now() < end { broker.pump() }
        try require(broker.queuedExecRejected && broker.rejected[.identity, default: 0] == 1)
        try require(broker.pending.isEmpty && broker.acceptedKinds.isEmpty)
        broker.cancel(id); try drive(broker) { _ in nil }
    }
    passed("queued pre-exec request keeps frozen audit identity and cannot authorize the new image")
    do {
        let broker = try FixtureBroker(image: image)
        // Genuine signed helper, correct leaked nonce, but direct child of broker,
        // not of the registered session parent. It cannot enter the coordinator.
        let registered = try broker.launchFixture(mode: "hold", expectedAnswer: secretA)
        guard let session = broker.sessions[registered] else { throw ProbeError.unavailable }
        let child = try spawn(path: helper, arguments: ["fixture challenge"], environment: broker.environment(session.state.grant))
        Darwin.close(child.1)
        var status: Int32 = 0, reaped = false, output = Data()
        defer { Darwin.close(child.2); if !reaped { _ = ap_signal_group(child.0, SIGKILL); for _ in 0..<100 { if ap_wait(child.0, &status) == 1 { break }; usleep(5_000) } } }
        let end = now() + 2
        while now() < end {
            broker.pump()
            if ap_wait(child.0, &status) == 1 { reaped = true; break }
        }
        try readAvailable(child.2, into: &output)
        try require(reaped && ap_exit_status(status) != 0 && output.isEmpty)
        try require(broker.rejected[.identity, default: 0] == 1)
        broker.cancel(registered); try drive(broker) { _ in nil }
    }
    passed("same-UID signed helper with leaked nonce but unregistered parent")
    do {
        let broker = try FixtureBroker(image: image)
        let id = try broker.launchFixture(mode: "hold", expectedAnswer: secretA)
        let end = now() + 1
        while broker.pending.isEmpty && now() < end { broker.pump() }
        guard let pending = broker.pending.first else { throw ProbeError.unavailable }
        broker.cancel(id)
        do { try broker.submit(.manual(secretA), session: id, requestID: pending.request.id, generation: pending.request.generation); throw ProbeError.protocolViolation }
        catch ProbeError.stale { }
        try drive(broker) { _ in nil }
        try require(broker.phase(id) == .closed(.cancelled))
    }
    passed("cancel revokes request, rejects late answer, reaps parent/helper")
    do {
        let broker = try FixtureBroker(image: image)
        let id = try broker.launchFixture(mode: "hold", expectedAnswer: secretA)
        try drive(broker, seconds: 4) { _ in nil }
        try require(broker.phase(id) == .closed(.timeout))
    }
    passed("bounded request timeout terminates and reaps controlled parent/helper")
    do {
        let broker = try FixtureBroker(image: image)
        let id = try broker.launchFixture(mode: "hold", expectedAnswer: secretA)
        let end = now() + 1
        while broker.pending.isEmpty && now() < end { broker.pump() }
        guard let pending = broker.pending.first else { throw ProbeError.unavailable }
        try drive(broker, seconds: 4) { _ in nil }
        do { try broker.submit(.manual(secretA), session: id, requestID: pending.request.id, generation: pending.request.generation); throw ProbeError.protocolViolation }
        catch ProbeError.stale { }
    }
    passed("timed-out generation cannot deliver a late random answer")
    do {
        let broker = try FixtureBroker(image: image)
        let id = try broker.launchFixture(mode: "hold")
        let end = now() + 1
        while broker.pending.isEmpty && now() < end { broker.pump() }
        guard let internalSession = broker.sessions[id], let pending = internalSession.pending else { throw ProbeError.unavailable }
        // Force destruction of helper reply receive rights after request acceptance.
        // Actual Mach send must fail and consume its send-once right exactly once.
        let ports = ap_port_count()
        _ = kill(pending.2.pid, SIGKILL)
        let deadline = now() + 0.5
        while ap_mach_reply_alive(pending.1.raw) != 0 && now() < deadline { usleep(5_000) }
        do { try pending.1.send(Reply(request: pending.0, decision: .manual(Data()))); throw ProbeError.protocolViolation }
        catch ProbeError.unavailable { }
        internalSession.pending = nil
        broker.cancel(id); try drive(broker) { _ in nil }
        try require(ap_port_count() == ports - 1)
    }
    passed("dead helper receive right makes response send fail without leaking send-once rights")
    do {
        let broker = try FixtureBroker(image: image)
        let id = try broker.launchFixture(mode: "crash")
        try drive(broker) { _ in nil }
        try require(broker.phase(id) == .closed(.helperFailed))
        try require(broker.exitCode(id) == 128 + SIGKILL)
    }
    passed("helper crash cancels without retry and escalates stubborn parent to SIGKILL")
    for bad in [Data([0]), Data([10]), Data([13]), Data(repeating: 65, count: Limits.answerBytes + 1)] {
        let broker = try FixtureBroker(image: image)
        let id = try broker.launchFixture(mode: "hold")
        let end = now() + 1
        while broker.pending.isEmpty && now() < end { broker.pump() }
        guard let pending = broker.pending.first else { throw ProbeError.unavailable }
        do { try broker.submit(.manual(bad), session: id, requestID: pending.request.id, generation: pending.request.generation); throw ProbeError.protocolViolation }
        catch ProbeError.bounds { }
        try drive(broker) { _ in nil }
        try require(broker.phase(id) == .closed(.bounds))
    }
    passed("NUL CR LF oversized answers rejected without truncation or output")
    do {
        let child = try spawn(path: adversary, arguments: ["--fake-broker"], environment: ["AP_HELPER": helper, "PATH": "/usr/bin:/bin"])
        Darwin.close(child.1)
        var status: Int32 = 0, reaped = false, output = Data()
        defer { Darwin.close(child.2); if !reaped { _ = ap_signal_group(child.0, SIGKILL); for _ in 0..<100 { if ap_wait(child.0, &status) == 1 { break }; usleep(5_000) } } }
        let end = now() + 3
        while now() < end {
            try readAvailable(child.2, into: &output, limit: 64)
            if ap_wait(child.0, &status) == 1 { reaped = true; try readAvailable(child.2, into: &output, limit: 64); break }
            usleep(5_000)
        }
        try require(reaped && ap_exit_status(status) == 0 && output == Data("fake-rejected".utf8))
    }
    passed("helper authenticates frozen broker reply and writes no stdout for a fake broker")
    do {
        var broker: FixtureBroker? = try FixtureBroker(image: image)
        let env = broker!.environment(SessionGrant(generation: 1, nonce: try nonce()))
        broker = nil
        let child = try spawn(path: helper, arguments: ["fixture challenge"], environment: env)
        Darwin.close(child.1)
        var status: Int32 = 0, reaped = false, bytes = Data()
        defer { Darwin.close(child.2); if !reaped { _ = ap_signal_group(child.0, SIGKILL); for _ in 0..<100 { if ap_wait(child.0, &status) == 1 { break }; usleep(5_000) } } }
        let end = now() + 1
        while now() < end {
            if ap_wait(child.0, &status) == 1 { reaped = true; break }; usleep(5_000)
        }
        try readAvailable(child.2, into: &bytes)
        try require(reaped && ap_exit_status(status) != 0 && bytes.isEmpty)
    }
    passed("disconnected broker fails helper promptly with no stdout or retry")
    do {
        let broker = try FixtureBroker(image: image)
        let a = try broker.launchFixture(mode: "hold", expectedAnswer: secretA)
        let b = try broker.launchFixture(mode: "empty")
        let end = now() + 1
        while broker.pending.count < 2 && now() < end { broker.pump() }
        try require(broker.pending.count == 2)
        broker.cancel(a)
        try drive(broker) { pending in pending.request.session == b ? .manual(Data()) : nil }
        try require(broker.phase(a) == .closed(.cancelled) && broker.fixturePassed(b))
    }
    passed("cancelling one concurrent session does not cancel or answer another")
    do {
        let before = ap_fd_count(), ports = ap_port_count()
        try require(before > 0 && ports > 0)
        for _ in 0..<6 {
            let broker = try FixtureBroker(image: image)
            let id = try broker.launchFixture(mode: "empty")
            try drive(broker) { _ in .manual(Data()) }
            try require(broker.fixturePassed(id))
        }
        try require(ap_fd_count() == before && ap_port_count() == ports)
    }
    passed("six launch/close cycles release children, descriptors and Mach rights")
    do {
        var broker: FixtureBroker? = try FixtureBroker(image: image)
        let service = broker!.serviceName
        _ = try broker!.launchFixture(mode: "hold")
        let end = now() + 1
        while broker!.pending.isEmpty && now() < end { broker!.pump() }
        broker = nil
        try require(ap_mach_name_unknown(service) == 1)
        print("POSTEXIT_SERVICE \(service)")
    }
    passed("broker disposal cancels children, releases Mach rights and removes temporary name")
    print("SELF-TEST PASS scenarios=\(count) transport=frozen-Mach-audit signing=Apple-Development-distinct-images fixture-only")
    print("NOT VERIFIED by this fixture: SSH server auth/MFA, macOS26, Sandbox, DeveloperID or distribution; bundle/readpass uses verify-app.py")
}

public func runFakeBrokerFixture(environment: [String: String]) -> Int32 {
    guard let helper = environment["AP_HELPER"] else { return 90 }
    do {
        let own = try identity(getpid())
        var name = [CChar](repeating: 0, count: 128), port: UInt32 = 0
        guard ap_mach_start(&name, name.count, &port) == 0 else { return 91 }
        let service = String(decoding: name.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        defer { _ = ap_mach_stop(port, service) }
        let grant = SessionGrant(generation: 1, nonce: try nonce())
        let env = ["AP_SERVICE": service, "AP_BROKER_PID": String(own.pid), "AP_BROKER_SECONDS": String(own.seconds),
                   "AP_BROKER_MICROS": String(own.microseconds), "AP_SESSION": grant.session.uuidString,
                   "AP_GENERATION": "1", "AP_NONCE": grant.nonce, "PATH": "/usr/bin:/bin"]
        let child = try spawn(path: helper, arguments: ["fixture challenge"], environment: env, newGroup: false)
        Darwin.close(child.1)
        var status: Int32 = 0, reaped = false
        defer { Darwin.close(child.2); if !reaped { _ = kill(child.0, SIGKILL); for _ in 0..<100 { if ap_wait(child.0, &status) == 1 { break }; usleep(5_000) } } }
        let envelope = try receiveMach(port, reply: false, timeout: 1000)
        let request = try envelope.decode(Request.self)
        guard let right = envelope.reply else { return 92 }
        // Fake broker deliberately skips trust checks; the genuine helper must
        // validate the response's own frozen trailer before touching stdout.
        try right.send(Reply(request: request, decision: .manual(Data())))
        for _ in 0..<100 { if ap_wait(child.0, &status) == 1 { reaped = true; break }; usleep(5_000) }
        var output = Data(); try readAvailable(child.2, into: &output)
        guard reaped, ap_exit_status(status) != 0, output.isEmpty else { return 95 }
        try writePipe(Data("fake-rejected".utf8), fd: STDOUT_FILENO); return 0
    } catch { return 96 }
}
