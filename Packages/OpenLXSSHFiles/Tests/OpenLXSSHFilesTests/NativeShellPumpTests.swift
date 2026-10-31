import COpenLXSSHFiles
import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHFiles

private final class PumpClock: @unchecked Sendable {
    let origin = ContinuousClock.now
    private let lock = NSLock()
    private var offset: Double = 0
    var now: ContinuousClock.Instant { lock.withLock { origin.advanced(by: .seconds(offset)) } }
    func set(_ seconds: Double) { lock.withLock { precondition(seconds >= offset); offset = seconds } }
}
private final class PumpCompletions: @unchecked Sendable {
    private let lock = NSLock()
    private var counts: [String: Int] = [:]
    func finish(_ id: String) { lock.withLock { counts[id, default: 0] += 1 } }
    var total: Int { lock.withLock { counts.values.reduce(0, +) } }
    var exactlyOnce: Bool { lock.withLock { !counts.isEmpty && counts.values.allSatisfy { $0 == 1 } } }
}
private enum PumpCall: String, Sendable { case write, read, exit, eof, resize, sendEOF, probeOpen, probeClose, probeFree, poll }
private enum PumpAnswer: Sendable {
    case code(Int32, directions: Int32 = 0), writeAll, bytes(Data), exit(Int32)
    static func again(_ directions: Int32) -> Self { .code(Int32(LIBSSH2_ERROR_EAGAIN), directions: directions) }
}
private struct PumpEvent: Sendable {
    let call: PumpCall
    let pointer: UInt
    let length: Int
    let bytes: Data
    let columns: Int32
    let rows: Int32
    let code: Int32
}
/// A bounded result script, not SSH packets or another pump. Unexpected callbacks fail the test.
/// No callback sleeps, awaits, drives the pump or changes its queue/rotation.
private final class PumpScript: @unchecked Sendable {
    private struct Rule { var answers: [PumpAnswer]; let repeating: PumpAnswer? }
    private let lock = NSLock()
    private var rules: [PumpCall: Rule] = [:]
    private var events: [PumpEvent] = []
    private var errors: [String] = []
    private var pollDirections: Int32?
    private var owner: UInt?
    private var token: UInt?
    func install(_ call: PumpCall, _ answers: [PumpAnswer] = [], repeating: PumpAnswer? = nil) {
        lock.withLock { rules[call] = Rule(answers: answers, repeating: repeating) }
    }
    var trace: [PumpEvent] { lock.withLock { events } }
    var failures: [String] { lock.withLock { errors } }
    func count(_ call: PumpCall) -> Int { lock.withLock { events.filter { $0.call == call }.count } }
    var written: Data {
        lock.withLock { events.filter { $0.call == .write && $0.code > 0 }.reduce(into: Data()) { $0.append($1.bytes.prefix(Int($1.code))) } }
    }
    private func invoke(_ call: PumpCall, connection: OpaquePointer, cancellation: OpaquePointer,
                        pointer: UInt = 0, length: Int = 0, bytes: Data = Data(),
                        columns: Int32 = 0, rows: Int32 = 0) -> (Int32, PumpAnswer) {
        lock.withLock {
            let c = UInt(bitPattern: UnsafeRawPointer(connection)), t = UInt(bitPattern: UnsafeRawPointer(cancellation))
            if let owner, owner != c { errors.append("connection-owner-changed") }; owner = c
            if let token, token != t { errors.append("pump-token-changed") }; token = t
            let answer: PumpAnswer
            if call == .poll {
                if let directions = pollDirections { answer = .code(directions); pollDirections = nil }
                else { errors.append("unexpected-poll"); answer = .code(Int32(RF_INVALID)) }
            } else {
                if pollDirections != nil { errors.append("missing-poll-before-" + call.rawValue); pollDirections = nil }
                if var rule = rules[call], !rule.answers.isEmpty {
                    answer = rule.answers.removeFirst(); rules[call] = rule
                } else if let repeated = rules[call]?.repeating { answer = repeated }
                else { errors.append("unexpected-" + call.rawValue); answer = .code(Int32(RF_INVALID)) }
            }
            let code: Int32
            if !errors.isEmpty { return (Int32(RF_INVALID), .code(Int32(RF_INVALID))) }
            switch answer {
            case .code(let value, let directions):
                code = value
                if call != .poll && (value == Int32(LIBSSH2_ERROR_EAGAIN) || (call == .write && value == 0)) && call != .resize && call != .sendEOF {
                    pollDirections = directions
                }
            case .writeAll: code = Int32(length)
            case .bytes(let data): code = Int32(data.count); if data.count > length { errors.append("read-script-overflow") }
            case .exit: code = 0
            }
            if events.count < 4096 {
                events.append(PumpEvent(call: call, pointer: pointer, length: length, bytes: bytes,
                                        columns: columns, rows: rows, code: code))
            } else { errors.append("script-event-limit") }
            return (code, answer)
        }
    }
    func steps(clock: PumpClock) -> NativeShellPumpSteps {
        NativeShellPumpSteps(now: { clock.now },
            poll: { self.invoke(.poll, connection: $0, cancellation: $1).0 },
            write: { c, p, length, token in
                self.invoke(.write, connection: c, cancellation: token, pointer: UInt(bitPattern: p), length: length,
                            bytes: Data(bytes: p, count: length)).0
            }, read: { c, p, length, token in
                let (code, answer) = self.invoke(.read, connection: c, cancellation: token, pointer: UInt(bitPattern: p), length: length)
                if case .bytes(let data) = answer, data.count <= length { data.copyBytes(to: UnsafeMutableRawBufferPointer(start: p, count: length)) }
                return code
            }, exit: { c, result, token in
                let (code, answer) = self.invoke(.exit, connection: c, cancellation: token)
                if case .exit(let status) = answer { result.pointee = rf_shell_exit(); result.pointee.status = status }
                return code
            }, eof: { self.invoke(.eof, connection: $0, cancellation: $1).0 },
            resize: { self.invoke(.resize, connection: $0, cancellation: $3, columns: $1, rows: $2).0 },
            sendEOF: { self.invoke(.sendEOF, connection: $0, cancellation: $1).0 },
            probeOpen: { self.invoke(.probeOpen, connection: $0, cancellation: $1).0 },
            probeClose: { self.invoke(.probeClose, connection: $0, cancellation: $1).0 },
            probeFree: { self.invoke(.probeFree, connection: $0, cancellation: $1).0 })
    }
}
private final class PumpFixture: @unchecked Sendable {
    let session: LibSSH2ShellSession
    let script: PumpScript
    let clock = PumpClock()
    let done = PumpCompletions()
    private var descriptors: [Int32] = [-1, -1]
    init(script: PumpScript, policy: NativeShellLivenessCandidate?, timeout: Double = 10) throws {
        self.script = script
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else { throw NativeShellError(.transport, operation: "pump-socketpair") }
        do {
            session = try LibSSH2ShellSession(offlinePumpSocket: descriptors[0],
                options: NativeShellOptions(size: NativeShellSize(columns: 80, rows: 24), operationTimeout: timeout, liveness: policy),
                steps: script.steps(clock: clock))
        } catch { descriptors.forEach { Darwin.close($0) }; throw error }
    }
    func write(_ data: Data, id: String = "write") -> Task<Void, any Error> {
        Task { defer { done.finish(id) }; try await session.write(data, token: CancellationToken()) }
    }
    func read(_ limit: Int = 65536, wait: Double = 0.25, id: String = "read") -> Task<NativeShellReceive, any Error> {
        Task { defer { done.finish(id) }; return try await session.receive(maxBytes: limit, wait: wait, token: CancellationToken()) }
    }
    func control(eof: Bool = false) -> Task<Void, any Error> {
        Task {
            defer { done.finish("control") }
            if eof { try await session.sendEOF(token: CancellationToken()) }
            else { try await session.resize(NativeShellSize(columns: 113, rows: 37), token: CancellationToken()) }
        }
    }
    func close() async {
        await session.close()
        let snapshot = await session.pumpSnapshot()
        XCTAssertEqual(snapshot.queuedWrites, 0); XCTAssertFalse(snapshot.hasReader); XCTAssertFalse(snapshot.hasControl)
        XCTAssertEqual(snapshot.readBufferBytes, 0); XCTAssertFalse(snapshot.pendingOutbound); XCTAssertFalse(snapshot.nativePresent)
        XCTAssertEqual(session.pendingInputBytes, 0)
        XCTAssertEqual(snapshot.nativeDisposals, 1); XCTAssertTrue(session.interactionSnapshot().drained)
        XCTAssertTrue(script.failures.isEmpty, script.failures.joined(separator: ","))
        if descriptors[0] >= 0 {
            XCTAssertNotEqual(fcntl(descriptors[0], F_GETFD), -1, "Native owns a duplicate, never the caller FD")
            var byte: UInt8 = 0
            XCTAssertEqual(recv(descriptors[1], &byte, 1, MSG_DONTWAIT), 0, "Real native teardown shuts down the socket")
            for fd in descriptors { XCTAssertEqual(Darwin.close(fd), 0); XCTAssertEqual(fcntl(fd, F_GETFD), -1); XCTAssertEqual(errno, EBADF) }
            descriptors = [-1, -1]
        }
    }
}

/// Real Swift session pump/admission/continuations and native resource owner, scripted I/O results.
/// No SSH handshake, authenticated channel, network endpoint, credentials or interoperability claim.
final class NativeShellPumpTests: XCTestCase, @unchecked Sendable {
    private let inbound = Int32(RF_SHELL_POLL_INBOUND), outbound = Int32(RF_SHELL_POLL_OUTBOUND)
    private func fixture(_ script: PumpScript, policy: NativeShellLivenessCandidate? = nil, timeout: Double = 10) throws -> PumpFixture {
        let f = try PumpFixture(script: script, policy: policy, timeout: timeout)
        addTeardownBlock { await f.close() }; return f
    }
    private func wait(_ predicate: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !(await predicate()) {
            guard .now < deadline else { throw NativeShellError(.timeout, operation: "pump-test-event") }
            try await Task.sleep(for: .milliseconds(1))
        }
    }
    private func failed<T: Sendable>(_ task: Task<T, any Error>, kind: NativeShellError.Kind) async {
        do { _ = try await task.value; XCTFail("Expected " + kind.rawValue) }
        catch let error as NativeShellError { XCTAssertEqual(error.kind, kind) }
        catch { XCTFail("Unexpected error type") }
    }
    func testWriteEAGAINStableArgumentsAndOutboundExclusion() async throws {
        let script = PumpScript(); script.install(.write, repeating: .again(outbound))
        script.install(.read, [.bytes(Data([4, 5]))]); script.install(.resize, [.code(0)])
        let f = try fixture(script)
        do {
            try await f.session.establish(identity: ServerIdentity(host: "offline.invalid", port: 22), username: Data("fixture".utf8),
                plan: NativeShellAuthenticationPlan(primary: .password(Data()), keyboard: nil), hostKeyHandler: nil, token: CancellationToken())
            XCTFail("Offline pump must not establish")
        } catch let error as NativeShellError { XCTAssertEqual(error.operation, "offline-pump-establish") }
        let stages = await f.session.authenticationStages(); XCTAssertTrue(stages.isEmpty)
        let source = Data((0..<(70 * 1024)).map { UInt8(truncatingIfNeeded: $0) }), write = f.write(source)
        try await wait { script.count(.write) >= 3 }
        let read = f.read(), control = f.control(), start = script.trace.count, attempts = script.count(.write)
        try await wait { let s = await f.session.pumpSnapshot(); return s.hasReader && s.hasControl && script.count(.write) >= attempts + 3 }
        XCTAssertTrue(script.trace.dropFirst(start).allSatisfy { $0.call == .write || $0.call == .poll })
        let original = try XCTUnwrap(script.trace.first { $0.call == .write })
        XCTAssertEqual(original.length, 32768)
        for event in script.trace where event.call == .write {
            XCTAssertEqual(event.pointer, original.pointer); XCTAssertEqual(event.length, original.length); XCTAssertEqual(event.bytes, original.bytes)
        }
        script.install(.write, repeating: .again(inbound))
        try await wait { f.done.total == 2 }
        let output = try await read.value; XCTAssertEqual(output, .bytes(Data([4, 5]))); try await control.value
        script.install(.write, [.code(17)], repeating: .again(outbound))
        try await wait { script.trace.contains { $0.call == .write && $0.pointer == original.pointer + 17 && $0.code < 0 } }
        let advanced = try XCTUnwrap(script.trace.last { $0.call == .write })
        XCTAssertEqual(advanced.pointer, original.pointer + 17); XCTAssertEqual(advanced.length, 32768)
        XCTAssertEqual(advanced.bytes, Data(source.dropFirst(17).prefix(32768)))
        script.install(.write, repeating: .writeAll)
        try await wait { f.done.total == 3 }; try await write.value
        XCTAssertEqual(script.written, source); XCTAssertTrue(f.done.exactlyOnce)
    }
    func testReadAndExitOutboundContinuationKeepsOriginalAPI() async throws {
        for scenario in 0..<3 {
            let script = PumpScript(); script.install(.read, repeating: .again(outbound))
            script.install(.write, repeating: .writeAll); script.install(.resize, [.code(0)])
            let f = try fixture(script, timeout: 1)
            if scenario == 2 {
                script.install(.read, [.code(0)]); script.install(.eof, [.code(1)])
                let eof = f.read(id: "eof"); try await wait { f.done.total == 1 }
                let value = try await eof.value; XCTAssertEqual(value, .eof)
                script.install(.exit, repeating: .again(outbound))
            }
            let read = f.read(wait: 0.05), call: PumpCall = scenario == 2 ? .exit : .read
            try await wait { script.count(call) >= 3 }
            f.clock.set(0.1)
            let write = f.write(Data([1])), control = f.control(), start = script.trace.count, count = script.count(call)
            try await wait { let s = await f.session.pumpSnapshot(); return s.hasReader && s.hasControl && s.queuedWrites == 1 && script.count(call) >= count + 3 }
            XCTAssertTrue(script.trace.dropFirst(start).allSatisfy { $0.call == call || $0.call == .poll })
            if scenario != 2 {
                let reads = script.trace.filter { $0.call == .read }, first = try XCTUnwrap(script.trace.first { $0.call == .read })
                XCTAssertTrue(reads.allSatisfy { $0.pointer == first.pointer && $0.length == first.length })
            }
            if scenario == 1 {
                f.clock.set(1)
                try await wait { let s = await f.session.pumpSnapshot(); return s.failure != nil }
                await failed(read, kind: .timeout); await failed(write, kind: .timeout); await failed(control, kind: .timeout)
                let s = await f.session.pumpSnapshot(); XCTAssertEqual(s.failure?.operation, "read-window-adjust")
            } else {
                script.install(call, [scenario == 2 ? .exit(7) : .bytes(Data([8, 9]))])
                try await wait { f.done.total == (scenario == 2 ? 4 : 3) }
                let value = try await read.value
                if scenario == 2 {
                    guard case .exit(let exit) = value else { return XCTFail("Expected scripted exit result") }
                    XCTAssertEqual(exit.reportedStatus, 7); await failed(write, kind: .closed); await failed(control, kind: .closed)
                    let s = await f.session.pumpSnapshot(); XCTAssertFalse(s.nativePresent); XCTAssertEqual(s.nativeDisposals, 1)
                } else { XCTAssertEqual(value, .bytes(Data([8, 9]))); try await write.value; try await control.value }
            }
            XCTAssertTrue(f.done.exactlyOnce); await f.close()
        }
    }
    func testControlEAGAINAlwaysPinsQueue() async throws {
        for (eof, directions) in [(false, inbound), (false, outbound), (true, inbound), (true, outbound)] {
            let call: PumpCall = eof ? .sendEOF : .resize, script = PumpScript()
            script.install(call, repeating: .again(directions)); script.install(.read, [.bytes(Data([6]))])
            script.install(.write, [.writeAll]); script.install(.probeOpen, [.code(Int32(RF_SHELL_PROBE_REJECTED))])
            let f = try fixture(script, policy: NativeShellLivenessCandidate(interval: 0.05, maxUnresponsivePeriods: 2))
            let control = f.control(eof: eof); try await wait { script.count(call) >= 3 }
            let read = f.read(), write = eof ? nil : f.write(Data([2])), start = script.trace.count, count = script.count(call)
            f.clock.set(0.05)
            try await wait { let s = await f.session.pumpSnapshot(); return s.hasReader && script.count(call) >= count + 3 }
            XCTAssertTrue(script.trace.dropFirst(start).allSatisfy { $0.call == call }); XCTAssertEqual(script.count(.poll), 0)
            for event in script.trace where event.call == .resize { XCTAssertEqual(event.columns, 113); XCTAssertEqual(event.rows, 37) }
            script.install(call, [.code(0)])
            try await wait { f.done.total == (eof ? 2 : 3) }
            try await control.value; let value = try await read.value; XCTAssertEqual(value, .bytes(Data([6])))
            if let write { try await write.value }
            XCTAssertTrue(f.done.exactlyOnce); await f.close()
            let timeoutScript = PumpScript(); timeoutScript.install(call, repeating: .again(inbound))
            let timed = try fixture(timeoutScript, timeout: 1), pending = timed.control(eof: eof)
            try await wait { timeoutScript.count(call) >= 3 }; timed.clock.set(1)
            try await wait { let s = await timed.session.pumpSnapshot(); return s.failure != nil }
            await failed(pending, kind: .timeout)
            let failure = await timed.session.pumpSnapshot(); XCTAssertEqual(failure.failure?.operation, "control")
            XCTAssertTrue(timed.done.exactlyOnce)
        }
    }
    func testPendingProbeOutputCannotExtendDeadline() async throws {
        let script = PumpScript(); script.install(.read, repeating: .again(inbound)); script.install(.probeOpen, repeating: .again(outbound))
        let f = try fixture(script, policy: NativeShellLivenessCandidate(interval: 3600, maxUnresponsivePeriods: 10))
        let initial = f.read(id: "idle"); try await wait { script.count(.read) > 0 }; f.clock.set(3600)
        try await wait { script.count(.probeOpen) >= 3 && f.done.total == 1 }
        let idle = try await initial.value; XCTAssertEqual(idle, .wouldBlock)
        script.install(.read, repeating: .bytes(Data([7])))
        let read = f.read(id: "pending-output"), start = script.trace.count, attempts = script.count(.probeOpen)
        try await wait { let s = await f.session.pumpSnapshot(); return s.hasReader && script.count(.probeOpen) >= attempts + 3 }
        XCTAssertTrue(script.trace.dropFirst(start).allSatisfy { $0.call == .probeOpen || $0.call == .poll })
        script.install(.probeOpen, repeating: .again(inbound))
        try await wait { f.done.total == 2 }; let value = try await read.value; XCTAssertEqual(value, .bytes(Data([7])))
        for (index, time) in [7200.0, 35999, 39599.9].enumerated() {
            f.clock.set(time); let output = f.read(id: "output-\(index)")
            try await wait { f.done.total == index + 3 }; _ = try await output.value
            let snapshot = await f.session.pumpSnapshot(), facts = await f.session.livenessSnapshot()
            XCTAssertEqual(snapshot.probeDeadline, f.clock.origin.advanced(by: .seconds(39600)))
            XCTAssertEqual(facts?.probesStarted, 1); XCTAssertEqual(facts?.confirmations, 0); XCTAssertEqual(facts?.pending, true)
        }
        f.clock.set(39600)
        try await wait { let s = await f.session.pumpSnapshot(); return !s.nativePresent }
        let s = await f.session.pumpSnapshot(); XCTAssertEqual(s.failure?.kind, .timeout); XCTAssertEqual(s.failure?.operation, "ssh-round-trip")
        XCTAssertEqual(script.count(.probeClose), 0); XCTAssertEqual(script.count(.probeFree), 0); XCTAssertTrue(f.done.exactlyOnce)
    }
    func testFiniteMixedLoadMakesProgressAndSettlesHelper() async throws {
        let script = PumpScript(); script.install(.read, repeating: .again(inbound)); script.install(.probeOpen, repeating: .again(inbound))
        script.install(.write, [.again(inbound), .code(17)], repeating: .writeAll)
        script.install(.resize, [.again(inbound), .code(0)], repeating: .code(0))
        let f = try fixture(script, policy: NativeShellLivenessCandidate(interval: 0.05, maxUnresponsivePeriods: 10))
        let chunk = Data((0..<65536).map { UInt8(truncatingIfNeeded: $0) })
        let reader = Task { () throws -> [Data] in
            defer { f.done.finish("mixed-reader") }
            var result: [Data] = []
            for _ in 0..<6 {
                guard case .bytes(let data) = try await f.session.receive(token: CancellationToken()) else { throw NativeShellError(.protocolFailure, operation: "mixed-output") }
                result.append(data)
            }
            return result
        }
        try await wait { script.count(.read) > 0 }; f.clock.set(0.05)
        try await wait { script.count(.probeOpen) > 0 }
        let writers = (0..<4).map { f.write(chunk, id: "mixed-write-\($0)") }
        let controls = Task {
            defer { f.done.finish("mixed-controls") }
            for i in 0..<5 { try await f.session.resize(NativeShellSize(columns: 90 + i, rows: 30 + i), token: CancellationToken()) }
        }
        script.install(.read, repeating: .bytes(chunk))
        try await wait { script.count(.write) >= 3 && script.count(.read) >= 4 && script.count(.resize) >= 3 }
        script.install(.probeClose, [.again(outbound), .code(0)]); script.install(.probeFree, [.again(inbound), .code(0)])
        script.install(.probeOpen, [.code(Int32(RF_SHELL_PROBE_CONFIRMED)), .code(Int32(RF_SHELL_PROBE_REJECTED))])
        try await wait { let facts = await f.session.livenessSnapshot(); return f.done.total == 6 && facts?.helpersFreed == 1 }
        for task in writers { try await task.value }; try await controls.value
        let output = try await reader.value; XCTAssertEqual(output, Array(repeating: chunk, count: 6))
        XCTAssertEqual(script.written, chunk + chunk + chunk + chunk)
        let first = await f.session.livenessSnapshot(); XCTAssertEqual(first?.probesStarted, 1); XCTAssertEqual(first?.pending, false)
        f.clock.set(0.1)
        try await wait { let facts = await f.session.livenessSnapshot(); return facts?.remoteRejections == 1 }
        let facts = await f.session.livenessSnapshot()
        XCTAssertEqual(facts?.probesStarted, 2); XCTAssertEqual(facts?.confirmations, 1); XCTAssertEqual(facts?.helpersFreed, 1)
        XCTAssertEqual(facts?.helperChannels, 0); XCTAssertEqual(facts?.pending, false)
        XCTAssertEqual(script.count(.probeClose), 2); XCTAssertEqual(script.count(.probeFree), 2); XCTAssertTrue(f.done.exactlyOnce)
        await f.close()
        let cleanupScript = PumpScript(); cleanupScript.install(.read, repeating: .again(inbound))
        cleanupScript.install(.probeOpen, [.code(Int32(RF_SHELL_PROBE_CONFIRMED))])
        cleanupScript.install(.probeClose, repeating: .again(outbound))
        let cleanup = try fixture(cleanupScript, policy: NativeShellLivenessCandidate(interval: 0.05, maxUnresponsivePeriods: 10), timeout: 1)
        let pendingRead = cleanup.read(); try await wait { cleanupScript.count(.read) > 0 }; cleanup.clock.set(0.05)
        try await wait { cleanupScript.count(.probeClose) >= 3 }
        let pending = await cleanup.session.livenessSnapshot(); XCTAssertEqual(pending?.confirmations, 1); XCTAssertEqual(pending?.helperChannels, 1)
        cleanup.clock.set(1.05)
        try await wait { let s = await cleanup.session.pumpSnapshot(); return s.failure != nil }
        await failed(pendingRead, kind: .timeout)
        let snapshot = await cleanup.session.pumpSnapshot(); XCTAssertEqual(snapshot.failure?.operation, "ssh-probe-cleanup")
        let disposed = await cleanup.session.livenessSnapshot(); XCTAssertEqual(disposed?.helperChannels, 0); XCTAssertEqual(disposed?.pending, false)
        XCTAssertEqual(snapshot.nativeDisposals, 1); XCTAssertTrue(cleanup.done.exactlyOnce)
    }
    func testSaturatedCancellationCompletesOnceAndReleasesOwner() async throws {
        let script = PumpScript(); script.install(.write, repeating: .again(outbound))
        let f = try fixture(script)
        let firstWrite = f.write(Data(repeating: 0x41, count: 2048), id: "saturated-0")
        try await wait { script.count(.write) >= 3 }
        let writes = [firstWrite] + (1..<128).map { f.write(Data(repeating: 0x41, count: 2048), id: "saturated-\($0)") }
        let read = f.read(), control = f.control()
        try await wait {
            let s = await f.session.pumpSnapshot()
            return s.queuedWrites == 128 && s.hasReader && s.hasControl && s.pendingOutbound && s.readBufferBytes == 65536
        }
        XCTAssertEqual(f.session.pendingInputBytes, 256 * 1024)
        do { try await f.session.write(Data([1]), token: CancellationToken()); XCTFail("Full input accepted") }
        catch let error as NativeShellError { XCTAssertEqual(error.kind, .resourceLimit) }
        do { _ = try await f.session.receive(token: CancellationToken()); XCTFail("Second reader accepted") }
        catch let error as NativeShellError { XCTAssertEqual(error.kind, .busy) }
        do { try await f.session.sendEOF(token: CancellationToken()); XCTFail("Second control accepted") }
        catch let error as NativeShellError { XCTAssertEqual(error.kind, .busy) }
        let start = ContinuousClock.now
        f.session.cancel(); f.session.cancel()
        try await wait { f.done.total == 130 }
        for task in writes { await failed(task, kind: .cancelled) }; await failed(read, kind: .cancelled); await failed(control, kind: .cancelled)
        let elapsed = start.duration(to: .now)
        XCTAssertLessThan(elapsed, .milliseconds(500), "Real clock, never the virtual I/O clock")
        XCTAssertTrue(f.done.exactlyOnce); XCTAssertEqual(f.session.pendingInputBytes, 0)
        await f.session.close(); await f.session.close()
        let snapshot = await f.session.pumpSnapshot(); XCTAssertEqual(snapshot.nativeDisposals, 1)
        XCTAssertEqual(f.done.total, 130); XCTAssertTrue(f.done.exactlyOnce)
        print("Native pump saturated cancellation real duration=\(elapsed), completed=\(f.done.total), nativeDisposals=\(snapshot.nativeDisposals)")
    }
}
