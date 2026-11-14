import CNativeLivenessTest
import Darwin
import Foundation
import OpenLXSSHFiles
import OpenLXSSHTrust
import RealIntegrationCore
import UXNativeShellProbeSupport

private enum LivenessMaterial {
    static func contract(path: String) throws -> NativeLivenessContract {
        try NativeLivenessContract.checkPath(path, buildRoot: ShellProbeBuildContext.buildRoot)
        let folder = URL(fileURLWithPath: path).deletingLastPathComponent().path
        try StableFixtureFiles.checkMarker(directory: ShellProbeBuildContext.buildRoot,
            file: ".native-shell-probe-owner", expected: "OpenLXSSH-U0-NativeShellProbe-v1\n")
        try StableFixtureFiles.checkMarker(directory: folder, file: ".native-liveness-case-owner",
            expected: "NATIVE-LIVENESS-SUPERVISOR-R2\n")
        let bytes = try StableFixtureFiles.read(path, limit: 4096)
        _ = try NativeLivenessJSON.object(bytes, keys: NativeLivenessContract.keys)
        let value = try JSONDecoder().decode(NativeLivenessContract.self, from: bytes)
        try value.validate(path: path, buildRoot: ShellProbeBuildContext.buildRoot, now: Date().timeIntervalSince1970)
        return value
    }
    static func freshness(_ value: NativeLivenessContract, material: SFTPAuthContract) throws {
        let bytes = try StableFixtureFiles.read(material.credentialDirectory + "/provenance.json", limit: 4096)
        let object = try MinaJSON.object(bytes, keys: ["base_image", "built_image_id", "service", "collected_at"])
        guard object["service"] as? String == "keyonly", object["collected_at"] as? Double == value.collectedAt,
              Date().timeIntervalSince1970 - value.collectedAt <= 120 else { throw NativeLivenessControlError.schema }
    }
}
private func proof(_ snapshot: NativeShellLivenessSnapshot) -> NativeLivenessProof {
    NativeLivenessProof(started: snapshot.probesStarted, confirmed: snapshot.confirmations,
        rejected: snapshot.remoteRejections, freed: snapshot.helpersFreed, helpers: snapshot.helperChannels, pending: snapshot.pending)
}
private func publicObject<T: Encodable>(_ value: T) throws -> [String: Any] {
    guard let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any] else {
        throw NativeLivenessControlError.schema
    }
    return object
}
/// Test-only live entry. Called solely by the separately built liveness executable after all
/// explicit flags/private FIFO/marked-contract gates. Never reads primary material in supervisor.
public enum NativeLivenessFixtureConsumer {
    public static func execute(options: NativeLivenessOptions) async -> Int32 {
        guard let path = options.contractPath, let owner = options.ownerPID else { return 64 }
        var report: NativeLivenessReport?
        var controlOwner: NativeLivenessPrivateControl?
        var session: LibSSH2ShellSession?
        let started = ProcessInfo.processInfo.systemUptime
        let fullDeadline = started + 85.0, token = CancellationToken(), stop = NativeLivenessStop()
        defer { stop.close() }
        var watchdog: Task<Void, Never>?
        do {
            let control = try NativeLivenessPrivateControl(ownerPID: owner)
            controlOwner = control
            let contract = try await Task.detached { try LivenessMaterial.contract(path: path) }.value
            let instrumented = ns_test_instrumented() == 1
            guard instrumented == (contract.role == .maxSessions) else { throw NativeLivenessControlError.schema }
            report = NativeLivenessReport(run: contract.run, role: contract.role, instrumented: instrumented)
            let managementContract = try await Task.detached {
                try NativeShellMaterialContract.readPublic(path: contract.materialContractPath)
            }.value
            guard managementContract.service == .keyonly, managementContract.key == .edplain,
                  managementContract.port == 22221,
                  managementContract.context == "desktop-linux",
                  managementContract.endpoint == "unix:///Users/liuwenshuo/.docker/run/docker.sock",
                  managementContract.project == "openlxssh-fixture-61ed25328c13",
                  managementContract.containerID == "ed38148af68e2c6cdb70f18b9a716876754a393df2d530b168ddd2144d99021a",
                  managementContract.imageID == "sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363",
                  managementContract.networkID == "b949645e158058f7484e21b758459f8d0e6a284f0d2bb641879faf67f2b50ed1",
                  managementContract.expectedFingerprint == "SHA256:d2G+w7lBrjYDFHHd6c6GxIhk7qzFs6df1i7EVJfeUYs" else {
                throw NativeLivenessControlError.schema
            }
            let manager = try OpenSSHManagement(contract: managementContract.rootManagementIdentity(), deadline: min(started + 30, fullDeadline - 12))
            defer { manager.cancel() }
            // Independent exact context/image/network/readonly/capability policy BEFORE secrets.
            try await Task.detached { try manager.verify(); try LivenessMaterial.freshness(contract, material: managementContract) }.value
            let input = try await Task.detached {
                try NativeShellMaterialContract.selectedInput(path: contract.materialContractPath, contract: managementContract)
            }.value
            guard let privateKey = input.privateKey, let publicKey = input.publicKey else { throw NativeLivenessControlError.schema }
            report?.contractFresh = true; report?.prepareSeconds = ProcessInfo.processInfo.systemUptime - started
            guard report!.prepareSeconds <= 30 else { throw NativeLivenessControlError.deadline }
            let root = ShellProbeBuildContext.buildRoot + "/native-liveness-run-" + contract.run + "-" + contract.role.rawValue
            guard mkdir(root, 0o700) == 0 else { throw NativeLivenessControlError.schema }
            let store = try await Task.detached { try HostTrustStore(directory: AbsolutePath(root + "/trust")) }.value
            let actualKey = try await Task.detached { try HostPublicKey(openSSHPublicKey: input.hostKeyLine) }.value
            let host = HostIdentity(address: try HostAddress("127.0.0.1"), port: try SSHPort(22221))
            guard case .pending(let pending) = try await store.evaluate(host: host, key: actualKey) else { throw NativeLivenessControlError.schema }
            try await store.confirm(pending, displayedFingerprint: managementContract.expectedFingerprint)
            let baseline = ns_test_descriptor_count()
            guard baseline > 0 else { throw NativeLivenessControlError.evidence }
            let activeStart = ProcessInfo.processInfo.systemUptime, activeDeadline = min(activeStart + 45, fullDeadline - 12)
            watchdog = Task.detached {
                while !Task.isCancelled {
                    if stop.stopped || getppid() != owner || ProcessInfo.processInfo.systemUptime >= activeDeadline {
                        token.cancel(); return
                    }
                    do { try await Task.sleep(for: .milliseconds(5)) } catch { return }
                }
            }
            do {
                let policy = try NativeShellLivenessCandidate(interval: 2, maxUnresponsivePeriods: 2)
                let nativeOptions = try NativeShellOptions(size: NativeShellSize(columns: 80, rows: 24), operationTimeout: 10,
                    interactionTimeout: 15, authenticationTimeout: 45, liveness: policy)
                let connected = try await LibSSH2ShellSession.connect(configuration: SSHConnection(host: host, user: SSHUser("fixture")),
                    primaryMethod: .publicKey, primaryProvider: { request in
                        try request.token.check(); return .publicKey(publicKey: publicKey, privateKey: privateKey, passphrase: nil)
                    }, trustStore: store, trustHandler: { _, reply in reply.resolve(.reject) }, options: nativeOptions,
                    connectionTimeout: 5, token: token)
                session = connected
                let id = connected.sessionID.uuidString.lowercased(), source = ns_test_tcp_source_port()
                guard source >= 1024 else { throw NativeLivenessControlError.evidence }
                report?.session = id; report?.sourcePort = Int(source)
                var sequence = NativeLivenessControlSequence(run: contract.run, role: contract.role, session: id)
                try await ack(connected, nonce: contract.run, token: token)
                try await settleOutput(connected, token: token)
                report?.shellACK = true
                let quietStart = ProcessInfo.processInfo.systemUptime
                while ProcessInfo.processInfo.systemUptime - quietStart < 12 {
                    switch try await connected.receive(wait: 0.1, token: token) {
                    case .wouldBlock: break
                    case .bytes(let bytes): report?.quietOutputBytes += bytes.count; throw NativeLivenessControlError.evidence
                    default: throw NativeLivenessControlError.evidence
                    }
                }
                report?.quietSeconds = ProcessInfo.processInfo.systemUptime - quietStart
                try await awaitSettled(connected, token: token, seconds: 3)
                let fresh = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
                try await ack(connected, nonce: fresh, token: token)
                try await settleOutput(connected, token: token)
                try await awaitSettled(connected, token: token, seconds: 3)
                guard let before = await connected.livenessSnapshot(), proof(before).settled else { throw NativeLivenessControlError.evidence }
                report?.preArm = proof(before); report?.freshACK = true
                if instrumented {
                    guard before.remoteRejections >= 2, ns_test_extra_channels() == 7,
                          ns_test_real_open_code() == -21, ns_test_real_rejections() >= 2,
                          ns_test_thread_violation() == 0 else { throw NativeLivenessControlError.evidence }
                    report?.extraChannelsAtProof = 7
                }
                try control.send(["op": "native-ready", "sequence": 0, "run": contract.run, "role": contract.role.rawValue,
                    "session": id, "sourcePort": Int(source), "pid": Int(getpid()), "stamp": ProcessInfo.processInfo.systemUptime,
                    "proof": try publicObject(proof(before)), "freshACK": true])
                _ = try await control.receive(op: "binding-confirmed", sequence: 1, contract: contract, session: id, seconds: 5, state: &sequence)
                // Suspend application reads so no idle-read callback can shift the next helper.
                // Report only a newly completed/freed proof, leaving nearly a full interval to arm.
                let boundaryStart = before.probesStarted
                let boundaryDeadline = ContinuousClock.now.advanced(by: .seconds(6))
                var boundary: NativeShellLivenessSnapshot?
                var proofLower: Double?
                var proofUpper: Double?
                while .now < boundaryDeadline {
                    try token.check()
                    let beforeSnapshot = ProcessInfo.processInfo.systemUptime
                    guard let value = await connected.livenessSnapshot() else { throw NativeLivenessControlError.evidence }
                    let afterSnapshot = ProcessInfo.processInfo.systemUptime
                    if value.probesStarted == boundaryStart + 1, proof(value).settled {
                        guard proofLower != nil else { throw NativeLivenessControlError.evidence }
                        boundary = value; proofUpper = afterSnapshot; break
                    }
                    guard value.probesStarted <= boundaryStart + 1 else { throw NativeLivenessControlError.evidence }
                    // This snapshot definitely precedes completion of the specific next proof.
                    // Use CALL START, not return time, as its conservative completion lower bound.
                    proofLower = beforeSnapshot
                    try await Task.sleep(for: .milliseconds(5))
                }
                guard let boundary, ns_test_tcp_source_port() == source else { throw NativeLivenessControlError.evidence }
                report?.preArm = proof(boundary)
                let armReadySent = ProcessInfo.processInfo.systemUptime
                var armReady: [String: Any] = ["op": "arm-ready", "sequence": 1, "run": contract.run, "role": contract.role.rawValue,
                    "session": id, "sourcePort": Int(source), "stamp": armReadySent,
                    "proof": try publicObject(proof(boundary)), "freshACK": true]
                if contract.role == .blackhole {
                    guard let proofLower, let proofUpper else { throw NativeLivenessControlError.evidence }
                    report?.proofLower = proofLower; report?.proofUpper = proofUpper; report?.armReadySent = armReadySent
                    armReady["proofLower"] = proofLower; armReady["proofUpper"] = proofUpper
                }
                try control.send(armReady)
                if contract.role == .blackhole {
                    let arm = try await control.receive(op: "drop-confirmed", sequence: 2, contract: contract,
                        session: id, seconds: 3, state: &sequence)
                    guard let armedAt = NativeLivenessJSON.finite(arm["armedAt"]), let armedWall = NativeLivenessJSON.finite(arm["armedWall"]),
                          let relayNow = NativeLivenessJSON.finite(arm["relayNow"]), let relayWall = NativeLivenessJSON.finite(arm["relayWall"]) else { throw NativeLivenessControlError.clock }
                    let local = ProcessInfo.processInfo.systemUptime
                    report?.dropACKReceived = local
                    guard let proofLower, let proofUpper else { throw NativeLivenessControlError.evidence }
                    report?.armAge = try NativeLivenessArmAge(proofLower: proofLower, proofUpper: proofUpper,
                        consumerSent: armReadySent, consumerACK: local, relayArmed: armedAt, relayReply: relayNow)
                    let clock = try NativeLivenessClockEvidence(armedAt: armedAt, armedWall: armedWall, relayNow: relayNow,
                        relayWall: relayWall, localNow: local, localWall: Date().timeIntervalSince1970)
                    report?.clock = clock
                    let deadline = local + max(0, 7 - clock.elapsedAtACK)
                    do {
                        while ProcessInfo.processInfo.systemUptime < deadline {
                            switch try await connected.receive(wait: 0.1, token: token) {
                            case .wouldBlock: break
                            default: throw NativeLivenessControlError.evidence
                            }
                        }
                        throw NativeLivenessControlError.deadline
                    } catch let error as NativeShellError {
                        let elapsed = clock.elapsedAtACK + ProcessInfo.processInfo.systemUptime - local
                        guard error.kind == .timeout, error.operation == "ssh-round-trip", !token.isCancelled,
                              elapsed >= 4, elapsed <= 7 else { throw error }
                        report?.nativeKind = error.kind.rawValue; report?.nativeOperation = error.operation
                        report?.dropToResultSeconds = elapsed
                    }
                } else {
                    _ = try await control.receive(op: "normal-ready", sequence: 2, contract: contract, session: id, seconds: 3, state: &sequence)
                    // A fresh actual shell ACK AFTER rejected helper proofs, including MaxSessions.
                    try await ack(connected, nonce: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(), token: token)
                    try await connected.write(Data("exit 7\n".utf8), token: token)
                    let exitDeadline = ContinuousClock.now.advanced(by: .seconds(5))
                    var exit: NativeShellExit?
                    while .now < exitDeadline, exit == nil {
                        switch try await connected.receive(wait: 0.1, token: token) {
                        case .bytes, .wouldBlock, .eof: break
                        case .exit(let value): exit = value
                        }
                    }
                    guard exit?.reportedStatus == 7, exit?.signal == nil else { throw NativeLivenessControlError.evidence }
                    report?.naturalExit = 7
                }
                try token.check()
                guard !stop.stopped, getppid() == owner else { throw NativeLivenessControlError.owner }
                report?.naturalResultBeforeCancel = true; report?.naturalResultAt = ProcessInfo.processInfo.systemUptime
                if let final = await connected.livenessSnapshot() { report?.final = proof(final) }
                watchdog?.cancel(); await watchdog?.value; watchdog = nil
                try control.send(["op": "case-result", "sequence": 2, "run": contract.run, "role": contract.role.rawValue,
                    "session": id, "stamp": ProcessInfo.processInfo.systemUptime, "report": try publicObject(report!)])
                _ = try await control.receive(op: "result-recorded", sequence: 3, contract: contract, session: id, seconds: 8, state: &sequence)
            } catch {
                report?.nativeKind = (error as? NativeShellError)?.kind.rawValue
                report?.nativeOperation = (error as? NativeShellError)?.operation
                report?.failure = (error as? NativeLivenessControlError)?.rawValue ?? "native-or-evidence-failure"
                let cancelledBeforeResult = report?.naturalResultBeforeCancel != true
                report?.cancelBeforeResult = cancelledBeforeResult
                report?.deadlineBeforeResult = ProcessInfo.processInfo.systemUptime >= activeDeadline || (error as? NativeLivenessControlError) == .deadline
                report?.ownerLostBeforeResult = getppid() != owner
                report?.stoppedBeforeResult = stop.stopped
                watchdog?.cancel(); await watchdog?.value; watchdog = nil
                if let final = report, let id = final.session, !final.naturalResultBeforeCancel {
                    try? control.send(["op": "failed", "sequence": -1, "run": contract.run, "role": contract.role.rawValue,
                        "session": id, "stamp": ProcessInfo.processInfo.systemUptime, "report": try publicObject(final)])
                }
            }
            if let session { await session.close(); report?.closed = true; report?.interactionsDrained = session.interactionSnapshot().drained }
            session = nil
            let fdDeadline = ContinuousClock.now.advanced(by: .seconds(3))
            while ns_test_descriptor_count() > baseline, .now < fdDeadline { try await Task.sleep(for: .milliseconds(10)) }
            report?.fdReturnedToBaseline = ns_test_descriptor_count() == baseline
            report?.extraChannelsAfterClose = Int(ns_test_extra_channels())
            report?.instrumentedRealOpenCode = Int(ns_test_real_open_code())
            report?.instrumentedRejections = Int(ns_test_real_rejections())
            report?.instrumentedSessionFreed = ns_test_session_freed() == 1
            report?.instrumentedThreadViolation = ns_test_thread_violation() != 0
            guard let final = report, let id = final.session else { throw NativeLivenessControlError.evidence }
            try control.send(["op": "closed", "sequence": 3, "run": contract.run, "role": contract.role.rawValue,
                "session": id, "stamp": ProcessInfo.processInfo.systemUptime, "report": try publicObject(final)])
            return final.failure == nil && final.closed && final.interactionsDrained && final.fdReturnedToBaseline ? 0 : 1
        } catch {
            watchdog?.cancel(); await watchdog?.value
            if let session { await session.close() }
            if var failed = report {
                failed.failure = "prepare-or-control-failure"; failed.cancelBeforeResult = !failed.naturalResultBeforeCancel
                if let controlOwner {
                    try? controlOwner.send(["op": "failed", "sequence": -1, "run": failed.run,
                        "role": failed.role.rawValue, "session": failed.session ?? "not-established",
                        "stamp": ProcessInfo.processInfo.systemUptime, "report": try publicObject(failed)])
                }
            }
            fputs("Native liveness fixture refused; no private details emitted.\n", stderr)
            return 1
        }
    }
    private static func ack(_ session: LibSSH2ShellSession, nonce: String, token: CancellationToken) async throws {
        try await session.write(Data(("n='" + nonce + "'; printf 'NATIVE_ACK_%s\\n' \"$n\"\n").utf8), token: token)
        let expected = Data(("NATIVE_ACK_" + nonce).utf8), deadline = ContinuousClock.now.advanced(by: .seconds(5))
        var tail = Data(), count = 0
        while .now < deadline {
            switch try await session.receive(wait: 0.1, token: token) {
            case .bytes(let bytes):
                count += bytes.count; guard count <= 65536 else { throw NativeLivenessControlError.evidence }
                tail.append(bytes); if tail.range(of: expected) != nil { return }
                if tail.count > 4096 { tail = Data(tail.suffix(4096)) }
            case .wouldBlock: break
            default: throw NativeLivenessControlError.evidence
            }
        }
        throw NativeLivenessControlError.deadline
    }
    private static func settleOutput(_ session: LibSSH2ShellSession, token: CancellationToken) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        var stable = ContinuousClock.now, count = 0
        while .now < deadline {
            switch try await session.receive(wait: 0.05, token: token) {
            case .bytes(let bytes): count += bytes.count; stable = .now
            case .wouldBlock: if stable.duration(to: .now) >= .milliseconds(200) { return }
            default: throw NativeLivenessControlError.evidence
            }
            guard count <= 65536 else { throw NativeLivenessControlError.evidence }
        }
        throw NativeLivenessControlError.deadline
    }
    private static func awaitSettled(_ session: LibSSH2ShellSession, token: CancellationToken, seconds: Double) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(seconds))
        while .now < deadline {
            try token.check()
            if let snapshot = await session.livenessSnapshot(), proof(snapshot).settled { return }
            try await Task.sleep(for: .milliseconds(5))
        }
        throw NativeLivenessControlError.deadline
    }
}
