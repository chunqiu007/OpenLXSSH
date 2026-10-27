import Darwin
import Foundation
import XCTest

final class AppRealIntegrationContractTests: XCTestCase {
    private let id = "12345678-1234-1234-1234-123456789abc"
    private var path: String { AppRealIntegrationContract.inputRoot + "/run-" + id + "/app-real-integration.json" }
    private func object() -> [String: Any] {
        ["schema": 1, "runID": id, "host": "127.0.0.1", "port": 22221, "user": "fixture", "service": "keyonly",
         "generation": AppRealIntegrationContract.fixtureRoot + "/.runtime/keyonly/credentials-012345abcdef",
         "expectedBase": AppRealIntegrationContract.base, "expectedImage": AppRealIntegrationContract.image,
         "expectedProject": AppRealIntegrationContract.project, "expectedContainer": AppRealIntegrationContract.container,
         "expectedFingerprint": AppRealIntegrationContract.fingerprint, "collectedAt": 1000.0, "preparedAt": 1100.0,
         "provenanceSHA256": String(repeating: "a", count: 64), "knownHostsSHA256": String(repeating: "b", count: 64),
         "generationPublicKeySHA256": String(repeating: "c", count: 64)]
    }
    private func decode(_ value: [String: Any]) throws -> AppRealIntegrationContract {
        try AppRealIntegrationContract.decodeStrict(JSONSerialization.data(withJSONObject: value))
    }
    func testClosedPhaseDefaultsToOldReadOnlyAndRejectsUnknownPhase() throws {
        XCTAssertEqual(try decode(object()).selectedPhase, .readOnly)
        for phase in ["read-only", "transfer-survives-close", "window-continue-cancel", "quit-continue-cancel", "file-operations", "terminal-search-paste"] {
            var value = object(); value["phase"] = phase
            XCTAssertEqual(try decode(value).selectedPhase.rawValue, phase)
        }
        let invalidValues: [Any] = ["quit-all", "arbitrary-command", NSNull(), 1]
        for invalid in invalidValues {
            var value = object(); value["phase"] = invalid
            XCTAssertThrowsError(try decode(value))
        }
        var remote = object(); remote["remotePath"] = "/arbitrary"
        XCTAssertThrowsError(try decode(remote))
    }
    func testTransferScopeIsFixedUUIDRootAndBounded16MiB() throws {
        let scope = try AppRealTransferScope(runID: id)
        XCTAssertEqual(scope.remoteDirectory, "/fixture/home/openlxssh-app-transfer-" + id)
        XCTAssertEqual(scope.remotePayload, scope.remoteDirectory + "/payload-16MiB.bin")
        XCTAssertEqual(AppRealTransferScope.sourceBytes, 16 * 1024 * 1024)
        XCTAssertEqual(AppRealTransferScope.chunkBytes, 65536)
        XCTAssertTrue(scope.permitsRemote(Data(scope.remoteDirectory.utf8)))
        XCTAssertTrue(scope.permitsRemote(Data(scope.remotePayload.utf8)))
        for path in ["/fixture/home", scope.remoteDirectory + "-other", scope.remoteDirectory + "/unknown", "/etc/passwd"] {
            XCTAssertFalse(scope.permitsRemote(Data(path.utf8)))
        }
        XCTAssertThrowsError(try AppRealTransferScope(runID: "latest"))
    }
    func testRealInflightGateRejectsCompletedZeroAndDecisionWaitStates() {
        XCTAssertTrue(AppRealTransferScope.isRealInflight(state: "running", transferred: 65536, sourceBytes: 16 * 1024 * 1024))
        for state in ["queued", "waitingRisk", "waitingConflict", "succeeded", "cancelled", "failed"] {
            XCTAssertFalse(AppRealTransferScope.isRealInflight(state: state, transferred: 65536, sourceBytes: 16 * 1024 * 1024))
        }
        for count: UInt64 in [0, 16 * 1024 * 1024, 16 * 1024 * 1024 + 1] {
            XCTAssertFalse(AppRealTransferScope.isRealInflight(state: "running", transferred: count, sourceBytes: 16 * 1024 * 1024))
        }
        XCTAssertFalse(AppRealTransferScope.isRealInflight(state: "running", transferred: 65536, sourceBytes: 32 * 1024 * 1024))
    }
    func testTransferDiagnosticsOnlyExportsKnownRawPathsAndClosedStates() throws {
        let scope = try AppRealTransferScope(runID: id), temp = Data((scope.remoteDirectory + "/.openlxssh-transfer.01234567-89AB-CDEF-0123-456789ABCDEF.part").utf8)
        let sample = AppRealTransferSnapshot(stage: .pendingDecision, scope: scope, jobID: UUID(), generation: UUID(), sourceServiceID: UUID(), destinationServiceID: UUID(),
            sourcePath: Data("/unrelated-secret-name".utf8), destinationPath: Data(scope.remotePayload.utf8), state: "untrusted-state-text", transferredBytes: 65536,
            pendingQuestion: .remotePathRisk, riskPath: Data("/unrelated-risk".utf8), ownedPaths: [Data(scope.remoteDirectory.utf8), temp, Data("/outside".utf8)],
            sshState: .connected, ownedSSHPIDPresent: true, serverBinding: UUID(), connectionAttempts: 1)
        let encoded = try JSONEncoder().encode(sample), text = String(decoding: encoded, as: UTF8.self)
        XCTAssertNil(sample.sourcePathBase64); XCTAssertNil(sample.riskPathBase64)
        XCTAssertEqual(sample.state, .unknown); XCTAssertEqual(sample.ownedPathsBase64.count, 2); XCTAssertEqual(sample.rejectedPaths, 3)
        for forbidden in ["unrelated-secret-name", "untrusted-state-text", "unrelated-risk", "password", "privateKey", "terminal", "errorDescription"] { XCTAssertFalse(text.contains(forbidden)) }
        XCTAssertEqual(try JSONDecoder().decode(AppRealTransferSnapshot.self, from: encoded).stage, .pendingDecision)
        XCTAssertFalse(scope.permitsDiagnosticPath(Data((scope.remoteDirectory + "/.openlxssh-transfer.latest.part").utf8)))
        XCTAssertFalse(scope.permitsDiagnosticPath(Data((scope.remoteDirectory + "/other").utf8)))
    }
    func testTransferDiagnosticRingKeepsAtMostEightNewestMetadataSnapshots() throws {
        let scope = try AppRealTransferScope(runID: id)
        var ring = AppRealTransferDiagnostics()
        for count in 0..<25 {
            let sample = AppRealTransferSnapshot(stage: .observeJob, scope: scope, jobID: nil, generation: nil, sourceServiceID: nil, destinationServiceID: nil,
                sourcePath: nil, destinationPath: nil, state: "running", transferredBytes: UInt64(count), pendingQuestion: .none, riskPath: nil, ownedPaths: [],
                sshState: .connected, ownedSSHPIDPresent: true, serverBinding: nil, connectionAttempts: 1)
            ring.record(sample)
        }
        ring.enter(.preCloseAction); ring.failed(.preCloseInflight)
        XCTAssertEqual(ring.snapshots.count, 8); XCTAssertEqual(ring.snapshots.first?.transferredBytes, 17); XCTAssertEqual(ring.snapshots.last?.transferredBytes, 24)
        XCTAssertEqual(ring.stage, .preCloseAction); XCTAssertEqual(ring.failedGuard, .preCloseInflight)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(ring)) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["stage", "failedGuard", "snapshots"])
    }
    func testFileOperationsScopeAndDeletePlansRejectUnknownLinksAndOverflow() throws {
        let scope = try AppRealFileScope(runID: id)
        XCTAssertEqual(scope.root, "/fixture/home/openlxssh-app-files-" + id)
        XCTAssertEqual(scope.payloads.count, 2); XCTAssertEqual(scope.payloads.reduce(0) { $0 + $1.1 }, 12288)
        XCTAssertFalse(AppRealIntegrationPhase.fileOperations.isTransfer)
        XCTAssertTrue(scope.exactDelete([(Data((scope.root + "/" + scope.renamed + "/" + scope.child).utf8), "file"),
            (Data((scope.root + "/" + scope.renamed).utf8), "directory")], name: scope.renamed, issues: 0))
        let expected = scope.expectedDelete(scope.renamed).map { ($0.key, $0.value) }
        XCTAssertFalse(scope.exactDelete(expected, name: scope.renamed, issues: 1))
        XCTAssertFalse(scope.exactDelete(expected + [(Data((scope.root + "/unknown").utf8), "file")], name: scope.renamed, issues: 0))
        XCTAssertFalse(scope.exactDelete([(Data((scope.root + "/" + scope.renamed).utf8), "link")], name: scope.renamed, issues: 0))
        XCTAssertFalse(scope.exactDelete([(Data("/outside".utf8), "directory")], name: "root", issues: 0))
        XCTAssertFalse(scope.exactDelete([], name: "unknown", issues: 0))
        XCTAssertFalse(scope.allowedRisk(Data((scope.root + "-outside").utf8)))
        XCTAssertFalse(scope.allowedRisk(Data((scope.root + "/../escape").utf8)))
        XCTAssertThrowsError(try AppRealFileScope(runID: "../escape"))
    }
    func testFileOperationManifestPreservesRawPOSIXNameBytes() throws {
        let scope = try AppRealFileScope(runID: id)
        let path = scope.folder + "/" + scope.child
        let digest = AppRealFileDigest(relativePathBase64: Data(path.utf8).base64EncodedString(), bytes: 8192, sha256: String(repeating: "a", count: 64))
        let copy = try JSONDecoder().decode(AppRealFileDigest.self, from: JSONEncoder().encode(digest))
        XCTAssertEqual(Data(base64Encoded: copy.relativePathBase64), Data(path.utf8))
        XCTAssertNotEqual(Data(path.precomposedStringWithCanonicalMapping.utf8), Data(path.utf8))
        XCTAssertEqual(copy, digest)
    }
    func testQuitHooksAreAbsentByDefaultAndOrderedOnceBeforeNativeReply() throws {
        var gate = AppRealQuitHookGate()
        XCTAssertFalse(gate.mayReplyToNativeQuit)
        XCTAssertThrowsError(try gate.after())
        XCTAssertThrowsError(try gate.committedReceipt())
        XCTAssertThrowsError(try gate.before(phase: .readOnly))
        XCTAssertThrowsError(try gate.before(phase: .windowContinueCancel))
        try gate.before(phase: .quitContinueCancel)
        XCTAssertThrowsError(try gate.before(phase: .quitContinueCancel))
        XCTAssertFalse(gate.mayReplyToNativeQuit)
        try gate.after()
        XCTAssertThrowsError(try gate.after())
        XCTAssertFalse(gate.mayReplyToNativeQuit)
        try gate.committedReceipt()
        XCTAssertTrue(gate.mayReplyToNativeQuit)
        XCTAssertThrowsError(try gate.committedReceipt())
        XCTAssertEqual(gate.beforeCalls, 1); XCTAssertEqual(gate.afterCalls, 1)
    }
    func testQuitCancelMustBeCancelledDrainedAndSameSingleConnection() {
        XCTAssertTrue(AppRealQuitTransferGate.cancelledAndDrained(state: "cancelled", managerClosed: true, activeWork: false, sshClosed: true,
            pidPresent: false, closedServices: 1, handles: 0, attempts: 1))
        for state in ["succeeded", "running", "failed"] {
            XCTAssertFalse(AppRealQuitTransferGate.cancelledAndDrained(state: state, managerClosed: true, activeWork: false, sshClosed: true,
                pidPresent: false, closedServices: 1, handles: 0, attempts: 1))
        }
        XCTAssertFalse(AppRealQuitTransferGate.cancelledAndDrained(state: "cancelled", managerClosed: false, activeWork: true, sshClosed: true,
            pidPresent: false, closedServices: 1, handles: 0, attempts: 1))
        XCTAssertFalse(AppRealQuitTransferGate.cancelledAndDrained(state: "cancelled", managerClosed: true, activeWork: false, sshClosed: false,
            pidPresent: true, closedServices: 1, handles: 1, attempts: 2))
    }
    func testWindowCancelRequiresCancelledWorkerServiceSSHAndWindowDrain() {
        func gate(_ state: String = "cancelled", _ closed: Bool = true, _ active: Bool = false, _ ssh: Bool = true,
                  _ pid: Bool = false, _ window: Bool = false, _ services: Int = 1, _ handles: Int = 0) -> Bool {
            AppRealWindowTransferGate.cancelledAndDrained(state: state, managerClosed: closed, activeWork: active, sshClosed: ssh,
                pidPresent: pid, windowPresent: window, closedServices: services, handles: handles)
        }
        XCTAssertTrue(gate())
        XCTAssertFalse(gate("succeeded")); XCTAssertFalse(gate("failed")); XCTAssertFalse(gate("running"))
        XCTAssertFalse(gate("cancelled", false)); XCTAssertFalse(gate("cancelled", true, true))
        XCTAssertFalse(gate("cancelled", true, false, false)); XCTAssertFalse(gate("cancelled", true, false, true, true))
        XCTAssertFalse(gate("cancelled", true, false, true, false, true)); XCTAssertFalse(gate("cancelled", true, false, true, false, false, 0))
        XCTAssertFalse(gate("cancelled", true, false, true, false, false, 1, 1))
    }
    func testWindowJobIdentityCannotChangeAcrossContinueAndCancel() {
        let values = [UUID(), UUID(), UUID(), UUID()], host = UUID().uuidString
        let expected = values.map(\.uuidString) + [host]
        XCTAssertTrue(AppRealWindowTransferGate.sameIdentity(jobID: values[0], generation: values[1], sourceServiceID: values[2], destinationServiceID: values[3], host: host, expected: expected))
        XCTAssertFalse(AppRealWindowTransferGate.sameIdentity(jobID: UUID(), generation: values[1], sourceServiceID: values[2], destinationServiceID: values[3], host: host, expected: expected))
        XCTAssertFalse(AppRealWindowTransferGate.sameIdentity(jobID: values[0], generation: UUID(), sourceServiceID: values[2], destinationServiceID: values[3], host: host, expected: expected))
        XCTAssertFalse(AppRealWindowTransferGate.sameIdentity(jobID: values[0], generation: values[1], sourceServiceID: values[2], destinationServiceID: UUID(), host: host, expected: expected))
        XCTAssertFalse(AppRealWindowTransferGate.sameIdentity(jobID: values[0], generation: values[1], sourceServiceID: values[2], destinationServiceID: values[3], host: "other", expected: expected))
    }
    func testWindowCheckpointOnlyContainsBoundedKnownMetadata() throws {
        let scope = try AppRealTransferScope(runID: id)
        let checkpoint = AppRealWindowCheckpoint(runID: id, event: "before-first-close", jobID: UUID(), generation: UUID(), serviceID: UUID(), hostID: UUID(),
            serverBinding: UUID().uuidString, sourceBytes: AppRealTransferScope.sourceBytes, progressBytes: 65536,
            remoteRootBase64: Data(scope.remoteDirectory.utf8).base64EncodedString(), payloadBase64: Data(scope.remotePayload.utf8).base64EncodedString(),
            temporaryBase64: Data((scope.remoteDirectory + "/.openlxssh-transfer.01234567-89AB-CDEF-0123-456789ABCDEF.part").utf8).base64EncodedString(), connectionAttempts: 1, retainedTemporaryPathsBase64: [])
        let data = try JSONEncoder().encode(checkpoint), value = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(value["phase"] as? String, "window-continue-cancel")
        let snapshot = AppRealTransferSnapshot(stage: .windowFirstClose, scope: scope, jobID: nil, generation: nil,
            sourceServiceID: nil, destinationServiceID: nil, sourcePath: nil, destinationPath: nil, state: "running", transferredBytes: 65536,
            pendingQuestion: .none, riskPath: nil, ownedPaths: [], sshState: .connected, ownedSSHPIDPresent: true,
            serverBinding: nil, connectionAttempts: 1, phase: .windowContinueCancel)
        XCTAssertEqual(snapshot.phase, .windowContinueCancel)
        XCTAssertLessThan(data.count, 4096)
        for forbidden in ["password", "privateKey", "terminal", "errorDescription"] { XCTAssertFalse(String(decoding: data, as: UTF8.self).contains(forbidden)) }
    }
    func testTerminalProtocolNonceFramesRejectDuplicatesOversizeAndWrongIntegrity() throws {
        let plan = try AppRealTerminalProtocol(nonce: String(repeating: "a", count: 32))
        XCTAssertThrowsError(try AppRealTerminalProtocol(nonce: "bad; command"))
        XCTAssertNil(try plan.frameValue("ordinary Password: or unrelated text", stage: .ready))
        XCTAssertNil(try plan.frameValue("AT1|" + String(repeating: "b", count: 32) + "|ready|ok|END", stage: .ready))
        let ready = "AT1|" + plan.nonce + "|ready|ok|END"
        XCTAssertEqual(try plan.frameValue(ready, stage: .ready), "ok")
        XCTAssertThrowsError(try plan.frameValue(ready + ready, stage: .ready))
        XCTAssertThrowsError(try plan.frameValue(String(repeating: "X", count: 65537), stage: .ready))
        XCTAssertFalse(plan.captureMatches("1,wronghash", expectedHash: String(repeating: "a", count: 64)))
        XCTAssertTrue(plan.captureMatches(String(plan.expectedPaste.count) + "," + String(repeating: "a", count: 64), expectedHash: String(repeating: "a", count: 64)))
        XCTAssertTrue(plan.expectedPaste.starts(with: Data("\u{1b}[200~".utf8)))
        XCTAssertTrue(plan.expectedPaste.suffix(6) == Data("\u{1b}[201~".utf8))
        XCTAssertLessThan(try plan.probeCommand().count, 4096)
        XCTAssertFalse(String(decoding: plan.shellCommand, as: UTF8.self).contains("AT1|"))
        XCTAssertFalse(AppRealIntegrationPhase.terminalSearchPaste.isTransfer)
    }
    func testTerminalCaptureParserReturnsActualFrameFields() throws {
        let plan = try AppRealTerminalProtocol(nonce: String(repeating: "a", count: 32))
        for hash in [String(repeating: "0123456789abcdef", count: 4), String(repeating: "f", count: 64)] {
            let value = String(plan.expectedPaste.count) + "," + hash
            let frame = "AT1|" + plan.nonce + "|captured|" + value + "|END"
            let captured = try plan.parseCapture(XCTUnwrap(plan.frameValue(frame, stage: .captured)), expectedHash: hash)
            XCTAssertEqual(captured.bytes, Int(value.split(separator: ",")[0]))
            XCTAssertEqual(captured.sha256, String(value.split(separator: ",")[1]))
            XCTAssertEqual(captured.bytes, plan.expectedPaste.count)
            XCTAssertEqual(captured.sha256, hash)
        }
    }
    func testTerminalCaptureParserRejectsNoncanonicalCountsAndMalformedFields() throws {
        let plan = try AppRealTerminalProtocol(nonce: String(repeating: "a", count: 32))
        let hash = String(repeating: "a", count: 64), count = String(plan.expectedPaste.count)
        let invalidCounts = ["", "0", "00", "01", "0" + count, "+" + count, "-1", " " + count, count + " ",
            count + ".0", "1e2", "1024", "999999999999999999999999999999", "５２", "1\n", "1\u{0}"]
        let invalidHashes = ["", String(hash.dropLast()), hash + "a", hash.uppercased(), String(repeating: "g", count: 64),
            " " + hash, hash + "\n", hash + "\u{0}"]
        let malformed = invalidCounts.map { $0 + "," + hash } + invalidHashes.map { count + "," + $0 }
            + ["", count, count + "," + hash + ",extra", count + ",," + hash, count + "," + hash + ","]
        for value in malformed {
            XCTAssertThrowsError(try plan.parseCapture(value, expectedHash: hash), value)
            XCTAssertFalse(plan.captureMatches(value, expectedHash: hash), value)
        }
    }
    func testTerminalCaptureParserRetainsExactExpectedCountAndHashGates() throws {
        let plan = try AppRealTerminalProtocol(nonce: String(repeating: "a", count: 32))
        let hash = String(repeating: "a", count: 64), otherHash = String(repeating: "b", count: 64)
        for count in [1, plan.expectedPaste.count - 1, plan.expectedPaste.count + 1, 1023] {
            let value = String(count) + "," + hash
            XCTAssertThrowsError(try plan.parseCapture(value, expectedHash: hash))
            XCTAssertFalse(plan.captureMatches(value, expectedHash: hash))
        }
        let wrongHash = String(plan.expectedPaste.count) + "," + otherHash
        XCTAssertThrowsError(try plan.parseCapture(wrongHash, expectedHash: hash))
        XCTAssertFalse(plan.captureMatches(wrongHash, expectedHash: hash))
        for malformedHash in [hash.uppercased(), "wronghash", ""] {
            let value = String(plan.expectedPaste.count) + "," + malformedHash
            XCTAssertThrowsError(try plan.parseCapture(value, expectedHash: malformedHash))
            XCTAssertFalse(plan.captureMatches(value, expectedHash: malformedHash))
        }
    }
    func testTerminalProbeRequiresReadbackMatchBeforeRestoredSuccessWithFakes() throws {
        let plan = try AppRealTerminalProtocol(nonce: String(repeating: "a", count: 32))
        let command = String(decoding: try plan.probeCommand(), as: UTF8.self)
        let start = try XCTUnwrap(command.range(of: "base64.b64decode(\""))
        let end = try XCTUnwrap(command.range(of: "\")", range: start.upperBound..<command.endIndex))
        let encoded = String(command[start.upperBound..<end.lowerBound])
        XCTAssertNotNil(Data(base64Encoded: encoded))
        // Executes the exact embedded probe with memory-only imports; no real PTY, shell,
        // network, credential store or clipboard. A process alarm bounds regressions.
        let harness = #"""
import base64,builtins,hashlib,json,signal,sys,types
signal.alarm(10)
source=base64.b64decode(sys.argv[1],validate=True)
nonce=sys.argv[2]
payload=base64.b64decode(sys.argv[3],validate=True)
def run(mode):
 events=[];frames=[];gets=0
 original=[1,2,3,4,5,6,[b'a',b'b']]
 def get(fd):
  nonlocal gets
  assert fd==0
  gets+=1;events.append('get-original' if gets==1 else 'get-restored')
  if gets>1 and mode=='get-error':raise OSError('fake readback refusal')
  value=original[:6]+[list(original[6])]
  if gets>1 and mode=='mismatch':value[3]^=1
  return value
 def set_(fd,when,value):
  assert fd==0 and when==0 and value==original
  events.append('set')
  if mode=='set-error':raise OSError('fake restore refusal')
 def raw(fd,when):
  assert fd==0 and when==0
  events.append('raw')
 def write(fd,value):
  assert fd==1 and value in (b'\x1b[?2004h',b'\x1b[?2004l')
  events.append('enable' if value.endswith(b'h') else 'disable')
  return len(value)
 def read(fd,size):
  assert fd==0 and size==1024
  events.append('read')
  return b'' if mode=='read-eof' else payload
 def print_(*values,**options):
  text=' '.join(str(value) for value in values)
  if 'AT1|' in text:frames.append(text)
  if '|restored|' in text:events.append('restored')
 modules={'hashlib':hashlib,'os':types.SimpleNamespace(read=read,write=write),
  'select':types.SimpleNamespace(select=lambda *args:([0],[],[])),
  'sys':types.SimpleNamespace(argv=['fixed-probe',nonce]),
  'termios':types.SimpleNamespace(TCSANOW=0,tcgetattr=get,tcsetattr=set_),
  'time':types.SimpleNamespace(monotonic=lambda:0), 'tty':types.SimpleNamespace(setraw=raw)}
 def imported(name,*args,**kwargs):return modules[name]
 namespace={'__builtins__':dict(vars(builtins),__import__=imported,print=print_)}
 status=0
 try:exec(compile(source,'<fixed-probe-with-fakes>','exec'),namespace)
 except SystemExit as error:status=error.code
 except OSError:status=1
 return {'exitCode':status,'frames':''.join(frames),'events':events}
print(json.dumps({'sha256':hashlib.sha256(payload).hexdigest(),
 'scenarios':{mode:run(mode) for mode in ['match','mismatch','get-error','set-error','read-eof']}}))
"""#
        let process = Process(), output = Pipe(), errors = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-I", "-B", "-c", harness, encoded, plan.nonce, plan.expectedPaste.base64EncodedString()]
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"]
        process.standardInput = FileHandle.nullDevice; process.standardOutput = output; process.standardError = errors
        try process.run(); process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        let errorText = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        XCTAssertEqual(process.terminationReason, .exit, errorText)
        XCTAssertEqual(process.terminationStatus, 0, errorText)
        let result = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let hash = try XCTUnwrap(result["sha256"] as? String)
        let scenarios = try XCTUnwrap(result["scenarios"] as? [String: [String: Any]])
        XCTAssertEqual(Set(scenarios.keys), ["match", "mismatch", "get-error", "set-error", "read-eof"])
        for (mode, expectedExit) in [("match", 0), ("mismatch", 66), ("get-error", 1), ("set-error", 1), ("read-eof", 65)] {
            let scenario = try XCTUnwrap(scenarios[mode])
            XCTAssertEqual(scenario["exitCode"] as? Int, expectedExit, mode)
            let frames = try XCTUnwrap(scenario["frames"] as? String), events = try XCTUnwrap(scenario["events"] as? [String])
            XCTAssertEqual(try plan.frameValue(frames, stage: .restored), mode == "match" ? "ok" : nil, mode)
            var expectedEvents = ["get-original", "raw", "enable", "read", "disable", "set"]
            if mode != "set-error" { expectedEvents.append("get-restored") }
            if mode == "match" { expectedEvents.append("restored") }
            XCTAssertEqual(events, expectedEvents, mode)
            if mode == "read-eof" { XCTAssertNil(try plan.frameValue(frames, stage: .captured)) }
            else {
                let value = try XCTUnwrap(plan.frameValue(frames, stage: .captured))
                let captured = try plan.parseCapture(value, expectedHash: hash)
                XCTAssertEqual(captured.bytes, plan.expectedPaste.count)
                XCTAssertEqual(captured.sha256, hash)
            }
        }
    }
    func testDefaultValidateAndHelpArePureParsingWithoutExistingFiles() throws {
        XCTAssertEqual(try AppRealIntegrationArguments.parse([], hostProbe: true).action, .none)
        XCTAssertEqual(try AppRealIntegrationArguments.parse([], hostProbe: false).action, .none)
        XCTAssertEqual(try AppRealIntegrationArguments.parse(["--real-fixture-help"], hostProbe: true).action, .help)
        let options = try AppRealIntegrationArguments.parse(["--real-fixture-validate", "--real-fixture-contract", "/does/not/exist/app-real-integration.json"], hostProbe: true)
        XCTAssertEqual(options.action, .validate)
        XCTAssertEqual(options.scanSeconds, 5)
    }
    func testShippingRejectsEveryRealFixtureFlagIncludingHelpValidateAndAuthorization() {
        for flag in AppRealIntegrationArguments.flagNames.union(["--real-fixture-unknown"]) {
            XCTAssertThrowsError(try AppRealIntegrationArguments.parse([flag], hostProbe: false))
        }
    }
    func testBothAuthorizationGatesRequiredAndNoUnknownOrMixedSmokeFlags() throws {
        let base = ["--real-fixture-test", "--real-fixture-contract", path]
        for suffix in [[], ["--authorized-local-fixture"], ["--primary-released"]] {
            XCTAssertThrowsError(try AppRealIntegrationArguments.parse(base + suffix, hostProbe: true))
        }
        let valid = base + ["--authorized-local-fixture", "--primary-released"]
        XCTAssertEqual(try AppRealIntegrationArguments.parse(valid, hostProbe: true).action, .live)
        XCTAssertEqual(try AppRealIntegrationArguments.parse(valid, hostProbe: true).scanSeconds, 5)
        XCTAssertEqual(try AppRealIntegrationArguments.parse(valid + ["--real-fixture-scan-seconds", "15"], hostProbe: true).scanSeconds, 15)
        for suffix in [["--self-test-data-dir", "/tmp/other"], ["--host", "example.com"], ["--password", "synthetic"],
                       ["--real-fixture-scan-seconds", "20"], ["--authorized-local-fixture"], ["--real-fixture-contract", path]] {
            XCTAssertThrowsError(try AppRealIntegrationArguments.parse(valid + suffix, hostProbe: true))
        }
    }
    func testStrictSchemaRejectsAdditionalAndMissingFields() throws {
        XCTAssertNoThrow(try decode(object()))
        var extra = object(); extra["password"] = "synthetic-not-used"
        XCTAssertThrowsError(try decode(extra))
        var missing = object(); missing["expectedFingerprint"] = nil
        XCTAssertThrowsError(try decode(missing))
    }
    func testExactBindingAndGenerationGate() throws {
        let value = try decode(object())
        XCTAssertNoThrow(try value.validate(path: path, now: 1200, buildEpoch: 999))
        for (key, wrong) in [("host", "example.com"), ("user", "root"), ("service", "passwordonly"), ("expectedImage", "sha256:unreviewed"),
                             ("expectedContainer", String(repeating: "0", count: 64)), ("expectedProject", "other"),
                             ("expectedFingerprint", "SHA256:unverified"), ("generation", AppRealIntegrationContract.fixtureRoot + "/.runtime/keyonly/credentials-latest"),
                             ("generation", AppRealIntegrationContract.fixtureRoot + "/.runtime/passwordonly/credentials-012345abcdef")] {
            var bad = object(); bad[key] = wrong
            XCTAssertThrowsError(try decode(bad).validate(path: path, now: 1200, buildEpoch: 999))
        }
        var port = object(); port["port"] = 22222
        XCTAssertThrowsError(try decode(port).validate(path: path, now: 1200, buildEpoch: 999))
    }
    func testFreshnessRunIDAndTraversalAreNotRelaxed() throws {
        let value = try decode(object())
        for (now, build) in [(1099.0, 999.0), (2900.1, 999), (1200, 1001), (.nan, 999)] {
            XCTAssertThrowsError(try value.validate(path: path, now: now, buildEpoch: build))
        }
        for bad in ["relative", "/a/../app-real-integration.json", "/a//b", "/a/./b", "/a/$b", "/a/\nb", path.replacingOccurrences(of: id, with: "latest"), "/etc/passwd"] {
            XCTAssertThrowsError(try AppRealIntegrationContract.validateContractPath(bad))
        }
    }
    func testTrustRequiresEndpointAlgorithmAndWholeFingerprint() throws {
        let value = try decode(object())
        XCTAssertTrue(value.matchesTrust(host: "127.0.0.1", port: 22221, algorithm: "ssh-ed25519", fingerprint: AppRealIntegrationContract.fingerprint))
        XCTAssertFalse(value.matchesTrust(host: "localhost", port: 22221, algorithm: "ssh-ed25519", fingerprint: AppRealIntegrationContract.fingerprint))
        XCTAssertFalse(value.matchesTrust(host: "127.0.0.1", port: 22222, algorithm: "ssh-ed25519", fingerprint: AppRealIntegrationContract.fingerprint))
        XCTAssertFalse(value.matchesTrust(host: "127.0.0.1", port: 22221, algorithm: "ssh-rsa", fingerprint: AppRealIntegrationContract.fingerprint))
        XCTAssertFalse(value.matchesTrust(host: "127.0.0.1", port: 22221, algorithm: "ssh-ed25519", fingerprint: String(AppRealIntegrationContract.fingerprint.dropLast())))
    }
    #if HOST_PROBE
    func testKnownSpecialLeafUsesHeldFDWithoutRelaxingGlobalDollarPathGuard() throws {
        let scope = try AppRealFileScope(runID: id)
        let temporary = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
        let root = temporary.appendingPathComponent("OpenLXSSH-AppTests-special-leaf-" + UUID().uuidString)
        XCTAssertEqual(mkdir(root.path, 0o700), 0)
        let parent = try AppRealPrivateInput.directory(root.path)
        defer { _ = unlinkat(parent, scope.child, 0); Darwin.close(parent); _ = rmdir(root.path) }
        let payload = Data(repeating: 37, count: 8192)
        try AppRealPrivateInput.write(payload, parent: parent, name: scope.child)
        XCTAssertThrowsError(try AppRealIntegrationContract.pathSyntax(root.appendingPathComponent(scope.child).path))
        let read = try AppRealPrivateInput.readKnownFileOperationLeaf(parent: parent, name: scope.child, scope: scope)
        XCTAssertEqual(read.bytes, payload)
        var named = stat(); XCTAssertEqual(fstatat(parent, scope.child, &named, AT_SYMLINK_NOFOLLOW), 0)
        XCTAssertEqual(read.device, named.st_dev); XCTAssertEqual(read.inode, named.st_ino)
        XCTAssertThrowsError(try AppRealPrivateInput.readKnownFileOperationLeaf(parent: parent, name: "unknown$leaf", scope: scope))
        XCTAssertEqual(chmod(root.appendingPathComponent(scope.child).path, 0o644), 0)
        XCTAssertThrowsError(try AppRealPrivateInput.readKnownFileOperationLeaf(parent: parent, name: scope.child, scope: scope))
        XCTAssertEqual(chmod(root.appendingPathComponent(scope.child).path, 0o600), 0)
        XCTAssertEqual(unlinkat(parent, scope.child, 0), 0)
        XCTAssertEqual(symlinkat("/does-not-exist", parent, scope.child), 0)
        XCTAssertThrowsError(try AppRealPrivateInput.readKnownFileOperationLeaf(parent: parent, name: scope.child, scope: scope))
    }
    func testPrivateMetadataRejectsPermissionLinksFIFOAndOversizeWithoutSecrets() throws {
        let temporary = try AppDataLocation.canonical(FileManager.default.temporaryDirectory)
        let root = temporary.appendingPathComponent("OpenLXSSH-AppTests-real-contract-" + UUID().uuidString)
        XCTAssertEqual(mkdir(root.path, 0o700), 0)
        let fd = try AppRealPrivateInput.directory(root.path)
        defer {
            for name in ["metadata", "hard", "link", "fifo"] { _ = unlinkat(fd, name, 0) }
            Darwin.close(fd); _ = rmdir(root.path)
        }
        try AppRealPrivateInput.write(Data("synthetic-only\n".utf8), parent: fd, name: "metadata")
        let path = root.appendingPathComponent("metadata").path
        XCTAssertEqual(try AppRealPrivateInput.read(path, limit: 128), Data("synthetic-only\n".utf8))
        XCTAssertThrowsError(try AppRealPrivateInput.read(path, limit: 2))
        XCTAssertEqual(chmod(path, 0o644), 0); XCTAssertThrowsError(try AppRealPrivateInput.read(path, limit: 128))
        XCTAssertEqual(chmod(path, 0o600), 0)
        XCTAssertEqual(linkat(fd, "metadata", fd, "hard", 0), 0); XCTAssertThrowsError(try AppRealPrivateInput.read(path, limit: 128)); XCTAssertEqual(unlinkat(fd, "hard", 0), 0)
        XCTAssertEqual(symlinkat("metadata", fd, "link"), 0); XCTAssertThrowsError(try AppRealPrivateInput.read(root.appendingPathComponent("link").path, limit: 128))
        XCTAssertEqual(mkfifoat(fd, "fifo", 0o600), 0); XCTAssertThrowsError(try AppRealPrivateInput.read(root.appendingPathComponent("fifo").path, limit: 128))
        var acl = acl_init(1), entry: acl_entry_t?
        XCTAssertNotNil(acl); defer { acl_free(UnsafeMutableRawPointer(acl!)) }
        XCTAssertEqual(acl_create_entry(&acl, &entry), 0)
        XCTAssertEqual(acl_set_tag_type(entry!, ACL_EXTENDED_ALLOW), 0)
        var identity = UUID().uuid
        XCTAssertEqual(acl_set_qualifier(entry!, &identity), 0) // Synthetic ACL principal only; never queries user/group directories.
        var permissions: acl_permset_t?; XCTAssertEqual(acl_get_permset(entry!, &permissions), 0)
        XCTAssertEqual(acl_add_perm(permissions!, ACL_READ_DATA), 0)
        XCTAssertEqual(acl_set_file(path, ACL_TYPE_EXTENDED, acl), 0)
        XCTAssertThrowsError(try AppRealPrivateInput.read(path, limit: 128))
    }
    #endif
}
