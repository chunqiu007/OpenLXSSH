import Darwin
import Foundation
import XCTest
#if HOST_PROBE
import OpenLXSSHFiles
import OpenLXSSHTrust
#endif

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
        for phase in ["read-only", "transfer-survives-close", "window-continue-cancel", "quit-continue-cancel", "file-operations", "terminal-search-paste", "sessions-reconnect", "batch-conflicts", "batch-overwrite", "transfer-survives-switch", "auth-ui-cancel", "trust-change-recover"] {
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
    func testSessionsReconnectIsClosedTerminalOnlyPhaseAndNonceIsStrict() throws {
        var value = object(); value["phase"] = "sessions-reconnect"
        XCTAssertEqual(try decode(value).selectedPhase, .sessionsReconnect)
        XCTAssertTrue(AppRealIntegrationPhase.sessionsReconnect.isTerminalOnly)
        XCTAssertTrue(AppRealIntegrationPhase.terminalSearchPaste.isTerminalOnly)
        for phase in [AppRealIntegrationPhase.readOnly, .fileOperations, .transferSurvivesClose, .windowContinueCancel, .quitContinueCancel] {
            XCTAssertFalse(phase.isTerminalOnly)
        }
        XCTAssertFalse(AppRealIntegrationPhase.sessionsReconnect.isTransfer)
        for nonce in ["", String(repeating: "a", count: 31), String(repeating: "a", count: 33), String(repeating: "A", count: 32), "bad; command"] {
            XCTAssertThrowsError(try AppRealSessionsProtocol(nonce: nonce))
        }
        XCTAssertNoThrow(try AppRealSessionsProtocol(nonce: String(repeating: "0", count: 32)))
        XCTAssertEqual(AppRealSessionsProtocol.keepaliveInterval, 7); XCTAssertEqual(AppRealSessionsProtocol.keepaliveCountMax, 2)
    }
    func testSessionsAckRolesAreCollisionFreeAndEchoCannotSupplyHistoryOrACK() throws {
        let plan = try AppRealSessionsProtocol(nonce: String(repeating: "a", count: 32))
        let commands = AppRealSessionsProtocol.Role.allCases.map { String(decoding: plan.ackCommand($0), as: UTF8.self) }
        XCTAssertEqual(Set(commands).count, 3)
        for (role, command) in zip(AppRealSessionsProtocol.Role.allCases, commands) {
            XCTAssertTrue(command.hasPrefix("printf '\\101\\1231|"))
            XCTAssertTrue(command.hasSuffix("\\n'\r")); XCTAssertLessThan(command.utf8.count, 128)
            XCTAssertFalse(command.contains("AS1|")); XCTAssertFalse(try plan.acknowledged(command, role: role))
            XCTAssertFalse(command.contains("AT1|")); XCTAssertFalse(command.contains("exit "))
        }
        let exitCommand = String(decoding: plan.naturalExitCommand, as: UTF8.self)
        XCTAssertEqual(exitCommand, "printf '\\117PENLX-SESS-HISTORY-" + plan.nonce + "\\n'; exit 0\r")
        XCTAssertFalse(exitCommand.contains(plan.historyMarker)); XCTAssertLessThan(exitCommand.utf8.count, 128)
        XCTAssertEqual(plan.historyMarker, "OPENLX-SESS-HISTORY-" + plan.nonce)
    }
    func testSessionsAckRejectsWrongRoleNonceDuplicateMalformedAndOversizeFrames() throws {
        let plan = try AppRealSessionsProtocol(nonce: String(repeating: "a", count: 32))
        let frame = "AS1|" + plan.nonce + "|a-first|ok|END"
        XCTAssertTrue(try plan.acknowledged("ordinary text\r\n" + frame, role: .aInitial))
        XCTAssertTrue(try plan.acknowledged(frame + String(repeating: "x", count: AppRealSessionsProtocol.maximumOutputBytes - frame.utf8.count), role: .aInitial))
        XCTAssertFalse(try plan.acknowledged(frame, role: .bInitial))
        XCTAssertFalse(try plan.acknowledged(frame, role: .aReconnected))
        XCTAssertFalse(try plan.acknowledged(frame.replacingOccurrences(of: plan.nonce, with: String(repeating: "b", count: 32)), role: .aInitial))
        XCTAssertFalse(try plan.acknowledged(String(frame.dropLast(4)), role: .aInitial))
        XCTAssertThrowsError(try plan.acknowledged(frame + frame, role: .aInitial))
        XCTAssertThrowsError(try plan.acknowledged(frame.replacingOccurrences(of: "|ok|", with: "|wrong|"), role: .aInitial))
        XCTAssertThrowsError(try plan.acknowledged(String(repeating: "x", count: AppRealSessionsProtocol.maximumOutputBytes + 1), role: .aInitial))
    }
    func testSessionsIdentityRequiresDistinctObjectsAndExactNextGenerationIncludingPIDReuse() throws {
        let tab = UUID(), session = UUID()
        func identity(tabID: UUID? = nil, sessionID: UUID? = nil, generation: UInt64 = 1, pid: Int32 = 111,
                      parent: Int32 = 50, seconds: UInt64 = 100, micros: UInt64 = 1) -> AppRealSessionsProtocol.Identity {
            .init(tabID: tabID ?? tab, sessionID: sessionID ?? session, generation: generation,
                process: .init(pid: pid, parentPID: parent, startSeconds: seconds, startMicroseconds: micros))
        }
        let old = identity(), b = identity(tabID: UUID(), sessionID: UUID(), pid: 222)
        XCTAssertTrue(AppRealSessionsProtocol.independent(old, b, distinctObjects: true))
        XCTAssertFalse(AppRealSessionsProtocol.independent(old, b, distinctObjects: false))
        XCTAssertFalse(AppRealSessionsProtocol.independent(old, identity(sessionID: UUID(), pid: 222), distinctObjects: true))
        XCTAssertFalse(AppRealSessionsProtocol.independent(old, identity(tabID: UUID(), pid: 222), distinctObjects: true))
        XCTAssertFalse(AppRealSessionsProtocol.independent(old, identity(tabID: UUID(), sessionID: UUID()), distinctObjects: true))
        let next = identity(generation: 2, pid: 333, seconds: 101)
        XCTAssertTrue(AppRealSessionsProtocol.reconnected(old, next, sameObjects: true, oldObservedGone: true))
        // A PID number can be reused only after old absence and a different birth identity.
        XCTAssertTrue(AppRealSessionsProtocol.reconnected(old, identity(generation: 2, seconds: 101), sameObjects: true, oldObservedGone: true))
        for wrong in [identity(generation: 1, pid: 333), identity(generation: 3, pid: 333), identity(generation: 2),
                      identity(tabID: UUID(), generation: 2, pid: 333), identity(sessionID: UUID(), generation: 2, pid: 333),
                      identity(generation: 2, pid: 0), identity(generation: 2, parent: 0), identity(generation: 2, seconds: 0),
                      identity(generation: 2, micros: 1_000_000)] {
            XCTAssertFalse(AppRealSessionsProtocol.reconnected(old, wrong, sameObjects: true, oldObservedGone: true))
        }
        XCTAssertFalse(AppRealSessionsProtocol.reconnected(old, next, sameObjects: false, oldObservedGone: true))
        XCTAssertFalse(AppRealSessionsProtocol.reconnected(old, next, sameObjects: true, oldObservedGone: false))
        XCTAssertFalse(AppRealSessionsProtocol.reconnected(identity(generation: .max), identity(generation: 0, pid: 333), sameObjects: true, oldObservedGone: true))
    }
    func testSessionsNaturalDisconnectCannotBeCancellationNilExitOrLivePID() {
        func gate(_ disconnected: Bool = true, _ exit: Int32? = 0, _ pid: Int32? = nil, _ reconnect: Bool = true, _ gone: Bool = true) -> Bool {
            AppRealSessionsProtocol.naturalDisconnect(disconnectedZero: disconnected, lastExitCode: exit, ownedPID: pid, canReconnect: reconnect, oldGone: gone)
        }
        XCTAssertTrue(gate()); XCTAssertFalse(gate(false)); XCTAssertFalse(gate(true, nil)); XCTAssertFalse(gate(true, 255))
        XCTAssertFalse(gate(true, 0, 123)); XCTAssertFalse(gate(true, 0, nil, false)); XCTAssertFalse(gate(true, 0, nil, true, false))
    }
    func testSessionsFiniteObservationIsMonotonicBoundedAndRejectsAnyReconnectSample() throws {
        func sample(_ value: inout AppRealSessionsProtocol.Observation, _ elapsed: Double, _ disconnected: Bool = true,
                    _ token: Bool = true, _ absent: Bool = true, _ gone: Bool = true, _ b: Bool = true) throws {
            try value.sample(elapsed: elapsed, disconnectedZero: disconnected, tokenUnchanged: token,
                ownedPIDAbsent: absent, oldProcessGone: gone, bUnchanged: b)
        }
        var value = AppRealSessionsProtocol.Observation(); XCTAssertFalse(value.complete)
        XCTAssertThrowsError(try sample(&value, 1)); try sample(&value, 0); XCTAssertFalse(value.complete)
        XCTAssertThrowsError(try sample(&value, 0)); XCTAssertThrowsError(try sample(&value, -.infinity))
        XCTAssertThrowsError(try sample(&value, .nan)); XCTAssertThrowsError(try sample(&value, 10.001))
        for flags in [(false, true, true, true, true), (true, false, true, true, true), (true, true, false, true, true),
                      (true, true, true, false, true), (true, true, true, true, false)] {
            XCTAssertThrowsError(try sample(&value, 0.5, flags.0, flags.1, flags.2, flags.3, flags.4))
        }
        try sample(&value, 1.999); XCTAssertFalse(value.complete)
        try sample(&value, 2); XCTAssertTrue(value.complete); XCTAssertEqual(value.samples, 3); XCTAssertEqual(value.elapsedSeconds, 2)
        XCTAssertThrowsError(try sample(&value, 1.5)); XCTAssertEqual(value.samples, 3)
        var bounded = AppRealSessionsProtocol.Observation(); try sample(&bounded, 0)
        for i in 1..<256 { try sample(&bounded, Double(i) / 1000) }
        XCTAssertEqual(bounded.samples, 256); XCTAssertThrowsError(try sample(&bounded, 0.256))
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any])
        XCTAssertEqual(Set(json.keys), ["samples", "elapsedSeconds"])
    }
    func testBatchClosedScopePayloadFormulaAndExactDeleteRejectsUnknowns() throws {
        var value = object(); value["phase"] = "batch-conflicts"
        XCTAssertEqual(try decode(value).selectedPhase, .batchConflicts)
        XCTAssertFalse(AppRealIntegrationPhase.batchConflicts.isTransfer); XCTAssertFalse(AppRealIntegrationPhase.batchConflicts.isTerminalOnly)
        let scope = try AppRealBatchScope(runID: id)
        XCTAssertEqual(scope.root, "/fixture/home/openlxssh-app-batch-" + id)
        XCTAssertThrowsError(try AppRealBatchScope(runID: "latest")); XCTAssertThrowsError(try AppRealBatchScope(runID: id.uppercased()))
        for (name, size) in [("a.bin", 4096), ("b.bin", 8192)] {
            let seed = try scope.payload(name, fresh: false), fresh = try scope.payload(name, fresh: true)
            XCTAssertEqual(seed.count, size); XCTAssertEqual(fresh.count, size); XCTAssertNotEqual(seed, fresh)
            let formula = Data(("OpenLXSSH batch " + id + " Seed/" + name + "\n").utf8)
            XCTAssertEqual(seed.prefix(formula.count), formula)
            XCTAssertEqual(seed, Data((0..<size).map { formula[$0 % formula.count] }))
        }
        XCTAssertThrowsError(try scope.payload("../outside", fresh: true))
        XCTAssertTrue(scope.allowsRisk(Data((scope.root + "/a.bin").utf8)))
        XCTAssertFalse(scope.allowsRisk(Data(scope.root.utf8))); XCTAssertFalse(scope.allowsRisk(Data((scope.root + "/unknown").utf8)))
        let expected = (AppRealBatchScope.names + [AppRealBatchScope.alternate]).map { (Data((scope.root + "/" + $0).utf8), "file") } + [(Data(scope.root.utf8), "directory")]
        XCTAssertTrue(scope.exactDelete(expected, issues: 0)); XCTAssertFalse(scope.exactDelete(expected, issues: 1))
        XCTAssertFalse(scope.exactDelete(expected + [expected[0]], issues: 0)); XCTAssertFalse(scope.exactDelete(Array(expected.dropLast()), issues: 0))
        XCTAssertFalse(scope.exactDelete([(Data("/outside".utf8), "file")] + Array(expected.dropFirst()), issues: 0))
    }
    #if HOST_PROBE
    private func batchJob(scope: AppRealBatchScope, host: UUID, service: UUID, local: UUID, batch: UUID, name: String,
                          jobID: UUID = UUID(), generation: UUID = UUID(), state: TransferJobState = .queued, bytes: UInt64 = 0,
                          pending: AppRealBatchGate.Decision? = nil, item: TransferItemResult? = nil) throws -> AppRealBatchGate.Snapshot {
        .init(id: jobID, generation: generation, retryOf: nil, request: .init(hostID: host.uuidString, batchID: batch,
            source: .init(serviceID: local, path: try RemotePath("/" + name)), destination: .init(serviceID: service, path: try RemotePath(scope.root + "/" + name))),
            state: state, transferredBytes: bytes, cancellationRequested: false, pendingDecision: pending, error: nil, items: item.map { [$0] } ?? [])
    }
    func testBatchAdmissionRejectsWrongBatchHostPathDuplicateAndStaleGeneration() throws {
        let scope = try AppRealBatchScope(runID: id), host = UUID(), service = UUID(), local = UUID(), batch = UUID()
        let a = try batchJob(scope: scope, host: host, service: service, local: local, batch: batch, name: "a.bin")
        let b = try batchJob(scope: scope, host: host, service: service, local: local, batch: batch, name: "b.bin")
        var gate = AppRealBatchGate(); try gate.admit([a,b], stage: .seed, scope: scope, hostID: host, serviceID: service)
        XCTAssertEqual(gate.jobs.count, 2); XCTAssertTrue(gate.current(a))
        XCTAssertThrowsError(try gate.admit([a,b], stage: .skip, scope: scope, hostID: host, serviceID: service))
        for values in [[a,a], [a], [a,try batchJob(scope: scope, host: host, service: service, local: local, batch: UUID(), name: "b.bin")],
                       [a,try batchJob(scope: scope, host: host, service: service, local: local, batch: batch, name: "unknown")]] {
            var fresh = AppRealBatchGate(); XCTAssertThrowsError(try fresh.admit(values, stage: .seed, scope: scope, hostID: host, serviceID: service))
        }
        var wrong = AppRealBatchGate(); XCTAssertThrowsError(try wrong.admit([a,b], stage: .seed, scope: scope, hostID: UUID(), serviceID: service))
        let stale = try batchJob(scope: scope, host: host, service: service, local: local, batch: batch, name: "a.bin", jobID: a.id)
        XCTAssertFalse(gate.current(stale))
    }
    func testBatchDecisionRejectsStaleDuplicateWrongTypeAndRiskDoesNotImplyConflict() throws {
        let scope = try AppRealBatchScope(runID: id), host = UUID(), service = UUID(), local = UUID(), batch = UUID(), jobID = UUID(), generation = UUID()
        let a = try batchJob(scope: scope, host: host, service: service, local: local, batch: batch, name: "a.bin", jobID: jobID, generation: generation)
        let b = try batchJob(scope: scope, host: host, service: service, local: local, batch: batch, name: "b.bin")
        var gate = AppRealBatchGate(); try gate.admit([a,b], stage: .skip, scope: scope, hostID: host, serviceID: service)
        let question = TransferDecisionQuestion.conflict(.init(source: a.request.source.path, destination: a.request.destination.path, existing: .init(kind: .regular, size: 4096)))
        let request = AppRealBatchGate.Decision(id: UUID(), jobID: jobID, generation: generation, question: question)
        let waiting = try batchJob(scope: scope, host: host, service: service, local: local, batch: batch, name: "a.bin", jobID: jobID, generation: generation, state: .waitingConflict, pending: request)
        XCTAssertThrowsError(try gate.decision(request, job: waiting, stage: .skip, scope: scope, risk: true))
        XCTAssertThrowsError(try gate.decision(request, job: waiting, stage: .rename, scope: scope, risk: false))
        let stale = AppRealBatchGate.Decision(id: UUID(), jobID: jobID, generation: UUID(), question: question)
        XCTAssertThrowsError(try gate.decision(stale, job: waiting, stage: .skip, scope: scope, risk: false))
        try gate.decision(request, job: waiting, stage: .skip, scope: scope, risk: false)
        XCTAssertThrowsError(try gate.decision(request, job: waiting, stage: .skip, scope: scope, risk: false))
        let risk = AppRealBatchGate.Decision(id: UUID(), jobID: jobID, generation: generation, question: .risk(.remotePathChecksAreNotAtomic(path: a.request.destination.path)))
        let riskJob = try batchJob(scope: scope, host: host, service: service, local: local, batch: batch, name: "a.bin", jobID: jobID, generation: generation, state: .waitingRisk, pending: risk)
        try gate.decision(risk, job: riskJob, stage: .skip, scope: scope, risk: true)
        XCTAssertEqual(gate.decisions.count, 2)
        let unknown = AppRealBatchGate.Decision(id: UUID(), jobID: jobID, generation: generation, question: .risk(.remotePathChecksAreNotAtomic(path: try RemotePath(scope.root + "/unknown"))))
        let unknownJob = try batchJob(scope: scope, host: host, service: service, local: local, batch: batch, name: "a.bin", jobID: jobID, generation: generation, state: .waitingRisk, pending: unknown)
        XCTAssertThrowsError(try gate.decision(unknown, job: unknownJob, stage: .skip, scope: scope, risk: true))
    }
    func testBatchTerminalSkipRequiresBothSkippedZeroBytesNoPendingOrRetainedTemp() throws {
        let scope = try AppRealBatchScope(runID: id), host = UUID(), service = UUID(), local = UUID(), batch = UUID()
        let original = try AppRealBatchScope.names.map { try batchJob(scope: scope, host: host, service: service, local: local, batch: batch, name: $0) }
        var gate = AppRealBatchGate(); try gate.admit(original, stage: .skip, scope: scope, hostID: host, serviceID: service)
        func ended(_ value: AppRealBatchGate.Snapshot, state: TransferJobState = .skipped, bytes: UInt64 = 0, retained: RemotePath? = nil) throws -> AppRealBatchGate.Snapshot {
            let item = TransferItemResult(source: value.request.source.path, destination: value.request.destination.path, state: .skipped, retainedTemporary: retained)
            return try batchJob(scope: scope, host: host, service: service, local: local, batch: batch,
                name: String(decoding: value.request.source.path.name!.bytes, as: UTF8.self), jobID: value.id, generation: value.generation, state: state, bytes: bytes, item: item)
        }
        let a = try ended(original[0]), b = try ended(original[1]); XCTAssertTrue(gate.terminal([a,b], stage: .skip, scope: scope))
        for state in [TransferJobState.succeeded, .failed, .cancelled, .completedWithSkips, .waitingConflict] {
            XCTAssertFalse(gate.terminal([try ended(original[0], state: state),b], stage: .skip, scope: scope))
        }
        XCTAssertFalse(gate.terminal([try ended(original[0], bytes: 1),b], stage: .skip, scope: scope))
        XCTAssertFalse(gate.terminal([try ended(original[0], retained: RemotePath(scope.root + "/.openlxssh-transfer.keep.part")),b], stage: .skip, scope: scope))
        XCTAssertFalse(gate.terminal([a,a], stage: .skip, scope: scope)); XCTAssertFalse(gate.terminal([a], stage: .skip, scope: scope))
        let pending = AppRealBatchGate.Decision(id: UUID(), jobID: a.id, generation: a.generation,
            question: .risk(.remotePathChecksAreNotAtomic(path: a.request.destination.path)))
        let withPending = try batchJob(scope: scope, host: host, service: service, local: local, batch: batch, name: "a.bin",
            jobID: a.id, generation: a.generation, state: .skipped, pending: pending, item: a.items[0])
        XCTAssertFalse(gate.terminal([withPending,b], stage: .skip, scope: scope))
    }
    func testBatchNewRenameBatchMustSucceedAtAlternateAndHaveDistinctBatchIdentity() throws {
        let scope = try AppRealBatchScope(runID: id), host = UUID(), service = UUID(), local = UUID()
        var gate = AppRealBatchGate()
        let seedBatch = UUID(), skipBatch = UUID(), renameBatch = UUID()
        let seed = try AppRealBatchScope.names.map { try batchJob(scope: scope, host: host, service: service, local: local, batch: seedBatch, name: $0) }
        let skip = try AppRealBatchScope.names.map { try batchJob(scope: scope, host: host, service: service, local: local, batch: skipBatch, name: $0) }
        try gate.admit(seed, stage: .seed, scope: scope, hostID: host, serviceID: service)
        try gate.admit(skip, stage: .skip, scope: scope, hostID: host, serviceID: service)
        let rename = try batchJob(scope: scope, host: host, service: service, local: local, batch: renameBatch, name: "a.bin")
        try gate.admit([rename], stage: .rename, scope: scope, hostID: host, serviceID: service)
        XCTAssertEqual(gate.jobs.count, 5); XCTAssertEqual(Set(gate.batches.values).count, 3)
        func result(_ destination: RemotePath, _ state: TransferJobState = .succeeded, _ bytes: UInt64 = 4096) throws -> AppRealBatchGate.Snapshot {
            let item = TransferItemResult(source: rename.request.source.path, destination: destination, state: .succeeded(bytes: bytes), retainedTemporary: nil)
            return try batchJob(scope: scope, host: host, service: service, local: local, batch: renameBatch, name: "a.bin",
                jobID: rename.id, generation: rename.generation, state: state, bytes: bytes, item: item)
        }
        let alternate = try RemotePath(scope.root + "/" + AppRealBatchScope.alternate)
        XCTAssertTrue(gate.terminal([try result(alternate)], stage: .rename, scope: scope))
        XCTAssertFalse(gate.terminal([try result(rename.request.destination.path)], stage: .rename, scope: scope))
        XCTAssertFalse(gate.terminal([try result(alternate, .skipped, 0)], stage: .rename, scope: scope))
        XCTAssertFalse(gate.terminal([try result(alternate, .succeeded, 4095)], stage: .rename, scope: scope))
        for fresh in [false, true] {
            for name in AppRealBatchScope.names {
                let data = try scope.payload(name, fresh: fresh)
                XCTAssertEqual(AppRealPrivateInput.sha(data), AppRealPrivateInput.sha(try scope.payload(name, fresh: fresh)))
                XCTAssertNotEqual(AppRealPrivateInput.sha(data), AppRealPrivateInput.sha(try scope.payload(name, fresh: !fresh)))
            }
        }
    }
    #endif
    func testOverwriteClosedPhaseAndExactThreePathCleanupDoNotAllowAlternate() throws {
        var value = object(); value["phase"] = "batch-overwrite"
        XCTAssertEqual(try decode(value).selectedPhase, .batchOverwrite)
        XCTAssertFalse(AppRealIntegrationPhase.batchOverwrite.isTransfer); XCTAssertFalse(AppRealIntegrationPhase.batchOverwrite.isTerminalOnly)
        let scope = try AppRealBatchScope(runID: id)
        let exact = AppRealBatchScope.names.map { (Data((scope.root + "/" + $0).utf8), "file") } + [(Data(scope.root.utf8), "directory")]
        XCTAssertTrue(scope.exactOverwriteDelete(exact, issues: 0)); XCTAssertFalse(scope.exactOverwriteDelete(exact, issues: 1))
        XCTAssertFalse(scope.exactOverwriteDelete(exact + [(Data((scope.root + "/" + AppRealBatchScope.alternate).utf8), "file")], issues: 0))
        XCTAssertFalse(scope.exactOverwriteDelete([exact[0],exact[0],exact[2]], issues: 0))
        XCTAssertFalse(scope.exactOverwriteDelete([(exact[0].0,"link"),exact[1],exact[2]], issues: 0))
        for name in AppRealBatchScope.names {
            XCTAssertEqual(try scope.payload(name, fresh: false).count, try scope.payload(name, fresh: true).count)
            XCTAssertNotEqual(try scope.payload(name, fresh: false), try scope.payload(name, fresh: true))
        }
    }
    #if HOST_PROBE
    func testOverwriteRequiresOneConflictButSeparateRiskPerJobWithFreshIDs() throws {
        let scope = try AppRealBatchScope(runID: id), host = UUID(), service = UUID(), local = UUID(), batch = UUID()
        let originals = try AppRealBatchScope.names.map { try batchJob(scope: scope, host: host, service: service, local: local, batch: batch, name: $0) }
        var gate = AppRealBatchGate(); try gate.admit(originals, stage: .overwrite, scope: scope, hostID: host, serviceID: service)
        func waiting(_ job: AppRealBatchGate.Snapshot, _ question: TransferDecisionQuestion, decisionID: UUID = UUID()) -> (AppRealBatchGate.Decision, AppRealBatchGate.Snapshot) {
            let decision = AppRealBatchGate.Decision(id: decisionID, jobID: job.id, generation: job.generation, question: question)
            let state: TransferJobState = { if case .conflict = question { return .waitingConflict }; return .waitingRisk }()
            return (decision,.init(id: job.id, generation: job.generation, retryOf: nil, request: job.request, state: state,
                transferredBytes: 0, cancellationRequested: false, pendingDecision: decision, error: nil, items: []))
        }
        let a = originals[0], b = originals[1]
        let early = waiting(a,.risk(.overwriteIsAtomicButNotCompareAndSwap(path: a.request.destination.path)))
        XCTAssertThrowsError(try gate.overwriteDecision(early.0, job: early.1, scope: scope))
        let pathA = waiting(a,.risk(.remotePathChecksAreNotAtomic(path: a.request.destination.path)))
        try gate.overwriteDecision(pathA.0, job: pathA.1, scope: scope)
        let conflict = waiting(a,.conflict(.init(source: a.request.source.path, destination: a.request.destination.path, existing: .init(kind: .regular,size: 4096))))
        try gate.overwriteDecision(conflict.0, job: conflict.1, scope: scope)
        XCTAssertEqual(gate.overwriteRiskJobs.count,0) // The conflict is not risk acceptance.
        let riskA = waiting(a,.risk(.overwriteIsAtomicButNotCompareAndSwap(path: a.request.destination.path)))
        try gate.overwriteDecision(riskA.0, job: riskA.1, scope: scope)
        XCTAssertThrowsError(try gate.overwriteDecision(riskA.0, job: riskA.1, scope: scope))
        let pathB = waiting(b,.risk(.remotePathChecksAreNotAtomic(path: b.request.destination.path)))
        try gate.overwriteDecision(pathB.0, job: pathB.1, scope: scope)
        let secondConflict = waiting(b,.conflict(.init(source: b.request.source.path, destination: b.request.destination.path, existing: .init(kind: .regular,size: 8192))))
        XCTAssertThrowsError(try gate.overwriteDecision(secondConflict.0, job: secondConflict.1, scope: scope))
        let repeatedID = waiting(b,.risk(.overwriteIsAtomicButNotCompareAndSwap(path: b.request.destination.path)),decisionID: riskA.0.id)
        XCTAssertThrowsError(try gate.overwriteDecision(repeatedID.0, job: repeatedID.1, scope: scope))
        let riskB = waiting(b,.risk(.overwriteIsAtomicButNotCompareAndSwap(path: b.request.destination.path)))
        try gate.overwriteDecision(riskB.0, job: riskB.1, scope: scope)
        XCTAssertEqual(gate.decisions.count,5); XCTAssertEqual(gate.overwriteRiskJobs,Set(originals.map(\.id)))
        func complete(_ job: AppRealBatchGate.Snapshot, includeRisks: Bool = true) throws -> AppRealBatchGate.Snapshot {
            let size = UInt64(try AppRealBatchScope.size(String(decoding: job.request.source.path.name!.bytes,as: UTF8.self)))
            let item = TransferItemResult(source: job.request.source.path,destination: job.request.destination.path,state: .succeeded(bytes: size),retainedTemporary: nil,
                acknowledgedRisks: includeRisks ? [.remotePathChecksAreNotAtomic(path: job.request.destination.path),.overwriteIsAtomicButNotCompareAndSwap(path: job.request.destination.path)] : [])
            return .init(id: job.id,generation: job.generation,retryOf: nil,request: job.request,state: .succeeded,transferredBytes: size,cancellationRequested: false,pendingDecision: nil,error: nil,items: [item])
        }
        XCTAssertTrue(try gate.terminal(originals.map { try complete($0) },stage: .overwrite,scope: scope))
        XCTAssertFalse(try gate.terminal([complete(a,includeRisks: false),complete(b)],stage: .overwrite,scope: scope))
    }
    func testOverwriteRiskRefusesWrongStagePathGenerationStateProgressAndTemporary() throws {
        let scope = try AppRealBatchScope(runID: id), host = UUID(), service = UUID(), local = UUID(), batch = UUID()
        let originals = try AppRealBatchScope.names.map { try batchJob(scope: scope,host: host,service: service,local: local,batch: batch,name: $0) }
        for stage in [AppRealBatchScope.Stage.seed,.skip,.rename,.overwrite] {
            var gate = AppRealBatchGate(); let values = stage == .rename ? [originals[0]] : originals
            try gate.admit(values,stage: stage,scope: scope,hostID: host,serviceID: service)
            let job = originals[0], risk = AppRealBatchGate.Decision(id: UUID(),jobID: job.id,generation: job.generation,
                question: .risk(.overwriteIsAtomicButNotCompareAndSwap(path: job.request.destination.path)))
            func snapshot(bytes: UInt64 = 0,state: TransferJobState = .waitingRisk,items: [TransferItemResult] = [],decision: AppRealBatchGate.Decision? = nil) -> AppRealBatchGate.Snapshot {
                .init(id: job.id,generation: job.generation,retryOf: nil,request: job.request,state: state,transferredBytes: bytes,
                    cancellationRequested: false,pendingDecision: decision ?? risk,error: nil,items: items)
            }
            if stage == .overwrite { XCTAssertNoThrow(try gate.decision(risk,job: snapshot(),stage: stage,scope: scope,risk: true)) }
            else { XCTAssertThrowsError(try gate.decision(risk,job: snapshot(),stage: stage,scope: scope,risk: true)) }
            var fresh = AppRealBatchGate(); try fresh.admit(values,stage: stage,scope: scope,hostID: host,serviceID: service)
            XCTAssertThrowsError(try fresh.decision(risk,job: snapshot(bytes: 1),stage: stage,scope: scope,risk: true))
            XCTAssertThrowsError(try fresh.decision(risk,job: snapshot(state: .running),stage: stage,scope: scope,risk: true))
            let item = TransferItemResult(source: job.request.source.path,destination: job.request.destination.path,state: .skipped,
                retainedTemporary: try RemotePath(scope.root + "/.openlxssh-transfer.retained.part"))
            XCTAssertThrowsError(try fresh.decision(risk,job: snapshot(items: [item]),stage: stage,scope: scope,risk: true))
            let wrong = AppRealBatchGate.Decision(id: UUID(),jobID: job.id,generation: UUID(),question: risk.question)
            XCTAssertThrowsError(try fresh.decision(wrong,job: snapshot(decision: wrong),stage: stage,scope: scope,risk: true))
            let wrongPath = AppRealBatchGate.Decision(id: UUID(),jobID: job.id,generation: job.generation,
                question: .risk(.overwriteIsAtomicButNotCompareAndSwap(path: try RemotePath(scope.root + "/unknown"))))
            XCTAssertThrowsError(try fresh.decision(wrongPath,job: snapshot(decision: wrongPath),stage: stage,scope: scope,risk: true))
        }
    }
    #endif
    func testSwitchClosedPhaseUsesTransferNotTerminalOnlyAndKeepsOtherPhaseSemantics() throws {
        var value = object(); value["phase"] = "transfer-survives-switch"
        XCTAssertEqual(try decode(value).selectedPhase, .transferSurvivesSwitch)
        XCTAssertTrue(AppRealIntegrationPhase.transferSurvivesSwitch.isTransfer); XCTAssertFalse(AppRealIntegrationPhase.transferSurvivesSwitch.isTerminalOnly)
        for phase in [AppRealIntegrationPhase.transferSurvivesClose,.windowContinueCancel,.quitContinueCancel] { XCTAssertTrue(phase.isTransfer) }
        for phase in [AppRealIntegrationPhase.batchConflicts,.batchOverwrite,.sessionsReconnect,.terminalSearchPaste,.readOnly] { XCTAssertFalse(phase.isTransfer) }
    }
    #if HOST_PROBE
    func testSwitchGateRequiresExactRunningJobRequestSessionsAndRealSelectionChange() throws {
        let scope = try AppRealBatchScope(runID: id), host = UUID(), service = UUID(), local = UUID(), batch = UUID()
        let jobID = UUID(), generation = UUID(), aID = UUID(), bID = UUID()
        let a = AppRealSessionsProtocol.Identity(tabID: aID,sessionID: aID,generation: 1,process: .init(pid: 111,parentPID: 99,startSeconds: 1,startMicroseconds: 0))
        let b = AppRealSessionsProtocol.Identity(tabID: bID,sessionID: bID,generation: 1,process: .init(pid: 222,parentPID: 99,startSeconds: 2,startMicroseconds: 0))
        func job(state: TransferJobState = .running, bytes: UInt64 = 65536, id: UUID? = nil, gen: UUID? = nil,
                 batchID: UUID? = nil, hostID: UUID? = nil, serviceID: UUID? = nil, name: String = "a.bin") throws -> AppRealBatchGate.Snapshot {
            try batchJob(scope: scope,host: hostID ?? host,service: serviceID ?? service,local: local,batch: batchID ?? batch,
                name: name,jobID: id ?? jobID,generation: gen ?? generation,state: state,bytes: bytes)
        }
        let first = try job(), gate = try AppRealSwitchGate(first: first,a: a,b: b)
        XCTAssertTrue(gate.before(first,a: a,b: b,bothConnectedAndSameObjects: true,selected: aID,target: bID))
        XCTAssertTrue(gate.before(try job(bytes: 131072),a: a,b: b,bothConnectedAndSameObjects: true,selected: bID,target: aID))
        for bad in [try job(state: .succeeded),try job(state: .queued),try job(state: .waitingRisk),try job(bytes: 0),
                    try job(bytes: AppRealTransferScope.sourceBytes),try job(bytes: AppRealTransferScope.sourceBytes+1),
                    try job(id: UUID()),try job(gen: UUID()),try job(batchID: UUID()),try job(hostID: UUID()),try job(serviceID: UUID()),try job(name: "b.bin")] {
            XCTAssertFalse(gate.before(bad,a: a,b: b,bothConnectedAndSameObjects: true,selected: aID,target: bID))
        }
        let newA = AppRealSessionsProtocol.Identity(tabID: aID,sessionID: aID,generation: 2,process: a.process)
        let newB = AppRealSessionsProtocol.Identity(tabID: bID,sessionID: bID,generation: 1,process: .init(pid: 223,parentPID: 99,startSeconds: 3,startMicroseconds: 0))
        XCTAssertFalse(gate.before(first,a: newA,b: b,bothConnectedAndSameObjects: true,selected: aID,target: bID))
        XCTAssertFalse(gate.before(first,a: a,b: newB,bothConnectedAndSameObjects: true,selected: aID,target: bID))
        XCTAssertFalse(gate.before(first,a: a,b: b,bothConnectedAndSameObjects: false,selected: aID,target: bID))
        XCTAssertFalse(gate.before(first,a: a,b: b,bothConnectedAndSameObjects: true,selected: aID,target: aID))
        XCTAssertFalse(gate.before(first,a: a,b: b,bothConnectedAndSameObjects: true,selected: nil,target: bID))
        XCTAssertTrue(gate.after(from: aID,selected: bID,target: bID)); XCTAssertTrue(gate.after(from: bID,selected: aID,target: aID))
        XCTAssertFalse(gate.after(from: aID,selected: aID,target: bID)); XCTAssertFalse(gate.after(from: aID,selected: bID,target: aID))
        XCTAssertFalse(gate.after(from: nil,selected: bID,target: bID)); XCTAssertFalse(gate.after(from: aID,selected: UUID(),target: bID))
    }
    func testSwitchGateRejectsCompletedFirstSamplePendingDecisionAndInvalidPair() throws {
        let scope = try AppRealBatchScope(runID: id), host = UUID(), service = UUID(), local = UUID(), batch = UUID()
        let aID = UUID(), bID = UUID()
        let a = AppRealSessionsProtocol.Identity(tabID: aID,sessionID: aID,generation: 1,process: .init(pid: 111,parentPID: 99,startSeconds: 1,startMicroseconds: 0))
        let b = AppRealSessionsProtocol.Identity(tabID: bID,sessionID: bID,generation: 1,process: .init(pid: 222,parentPID: 99,startSeconds: 2,startMicroseconds: 0))
        let first = try batchJob(scope: scope,host: host,service: service,local: local,batch: batch,name: "a.bin",state: .running,bytes: 65536)
        XCTAssertThrowsError(try AppRealSwitchGate(first: first,a: a,b: a))
        let completed = try batchJob(scope: scope,host: host,service: service,local: local,batch: batch,name: "a.bin",state: .succeeded,bytes: AppRealTransferScope.sourceBytes)
        XCTAssertThrowsError(try AppRealSwitchGate(first: completed,a: a,b: b))
        let pending = AppRealBatchGate.Decision(id: UUID(),jobID: first.id,generation: first.generation,question: .risk(.remotePathChecksAreNotAtomic(path: first.request.destination.path)))
        let waiting = AppRealBatchGate.Snapshot(id: first.id,generation: first.generation,retryOf: nil,request: first.request,state: .running,
            transferredBytes: 65536,cancellationRequested: false,pendingDecision: pending,error: nil,items: [])
        XCTAssertThrowsError(try AppRealSwitchGate(first: waiting,a: a,b: b))
        let gate = try AppRealSwitchGate(first: first,a: a,b: b)
        XCTAssertFalse(gate.before(waiting,a: a,b: b,bothConnectedAndSameObjects: true,selected: aID,target: bID))
    }
    #endif
    func testAuthUIClosedPhaseSelectsOnlyEncryptedKeyWithoutChangingOtherPhases() throws {
        var value = object(); value["phase"] = "auth-ui-cancel"
        XCTAssertEqual(try decode(value).selectedPhase, .authUICancel)
        XCTAssertTrue(AppRealIntegrationPhase.authUICancel.isTerminalOnly); XCTAssertFalse(AppRealIntegrationPhase.authUICancel.isTransfer)
        XCTAssertEqual(AppRealIntegrationPhase.authUICancel.fixturePrivateKeyName, "id_ed25519_encrypted")
        for phase in [AppRealIntegrationPhase.readOnly,.terminalSearchPaste,.sessionsReconnect,.fileOperations,.batchConflicts,.batchOverwrite,.transferSurvivesClose,.transferSurvivesSwitch,.windowContinueCancel,.quitContinueCancel] {
            XCTAssertEqual(phase.fixturePrivateKeyName, "id_ed25519")
        }
        value["phase"] = "auth-ui-any-key"; XCTAssertThrowsError(try decode(value))
        value = object(); value["encryptedPublicSHA256"] = String(repeating: "a", count: 64)
        XCTAssertThrowsError(try decode(value)) // Existing contract schema remains closed.
    }
    func testAuthUIFixturePhraseRemovesOnlyOneFinalLFAndRejectsMalformedPayload() throws {
        // Public synthetic dummy bytes only; never reads a fixture generation.
        let dummy = Data("synthetic-not-a-fixture-value".utf8)
        XCTAssertEqual(try AppRealAuthUIGate.phrasePayload(dummy + Data([10])), dummy)
        XCTAssertEqual(try AppRealAuthUIGate.phrasePayload(Data(" leading and trailing \n".utf8)), Data(" leading and trailing ".utf8))
        XCTAssertEqual(try AppRealAuthUIGate.phrasePayload(Data(repeating: 120,count: 1023) + Data([10])).count, 1023)
        for invalid in [Data(),Data([10]),dummy,dummy + Data([13,10]),dummy + Data([10,10]),Data([120,0,10]),
                        Data([120,10,121,10]),Data([255,10]),Data(repeating: 120,count: 1024) + Data([10])] {
            XCTAssertThrowsError(try AppRealAuthUIGate.phrasePayload(invalid))
        }
    }
    func testAuthUIChallengeCancelAndFreshRecoveryRequireActualBoundGenerationAndNoFirstAnswer() throws {
        let id = UUID(), oldProcess = AppRealSessionsProtocol.ProcessIdentity(pid: 111,parentPID: 99,startSeconds: 1,startMicroseconds: 0)
        let initial = AppRealSessionsProtocol.Identity(tabID: id,sessionID: id,generation: 1,process: oldProcess)
        let old = AppRealAuthUIGate.Challenge(requestID: UUID(),identity: initial)
        XCTAssertTrue(AppRealAuthUIGate.challenge(old,authenticating: true,unknownMasked: true,currentIdentity: initial))
        XCTAssertFalse(AppRealAuthUIGate.challenge(old,authenticating: false,unknownMasked: true,currentIdentity: initial))
        XCTAssertFalse(AppRealAuthUIGate.challenge(old,authenticating: true,unknownMasked: false,currentIdentity: initial))
        func cancelled(_ disconnected: Bool = true,_ pid: Int32? = nil,_ pending: Bool = true,_ reconnect: Bool = true,
                       _ gone: Bool = true,_ reads: Int = 0,_ answers: Int = 0) -> Bool {
            AppRealAuthUIGate.cancelled(disconnectedNil: disconnected,ownedPID: pid,pendingNil: pending,canReconnect: reconnect,
                oldGone: gone,manualReads: reads,submittedAnswers: answers)
        }
        XCTAssertTrue(cancelled()); XCTAssertFalse(cancelled(false)); XCTAssertFalse(cancelled(true,111))
        XCTAssertFalse(cancelled(true,nil,false)); XCTAssertFalse(cancelled(true,nil,true,false))
        XCTAssertFalse(cancelled(true,nil,true,true,false)); XCTAssertFalse(cancelled(true,nil,true,true,true,1))
        XCTAssertFalse(cancelled(true,nil,true,true,true,0,1))
        let next = AppRealSessionsProtocol.Identity(tabID: id,sessionID: id,generation: 2,
            process: .init(pid: 222,parentPID: 99,startSeconds: 2,startMicroseconds: 0))
        let new = AppRealAuthUIGate.Challenge(requestID: UUID(),identity: next)
        XCTAssertTrue(AppRealAuthUIGate.fresh(old,new,sameObjects: true,oldObservedGone: true))
        XCTAssertFalse(AppRealAuthUIGate.fresh(old,new,sameObjects: false,oldObservedGone: true))
        XCTAssertFalse(AppRealAuthUIGate.fresh(old,new,sameObjects: true,oldObservedGone: false))
        XCTAssertFalse(AppRealAuthUIGate.fresh(old,.init(requestID: old.requestID,identity: next),sameObjects: true,oldObservedGone: true))
        XCTAssertFalse(AppRealAuthUIGate.challenge(old,authenticating: true,unknownMasked: true,currentIdentity: next))
        XCTAssertFalse(AppRealAuthUIGate.fresh(old,.init(requestID: UUID(),identity: initial),sameObjects: true,oldObservedGone: true))
        let json = try JSONEncoder().encode(new), encoded = try XCTUnwrap(JSONSerialization.jsonObject(with: json) as? [String: Any])
        XCTAssertEqual(Set(encoded.keys),["requestID","identity"])
        for forbidden in ["prompt","answer","phrase","hash","length"] { XCTAssertFalse(String(decoding: json,as: UTF8.self).contains(forbidden)) }
    }
    func testAuthUIConnectedRequiresFreshACKAndExactlyOneNativeAnswerAndFiniteNoChallengeSamples() throws {
        XCTAssertTrue(AppRealAuthUIGate.completed(connected: true,shellACK: true,pendingNil: true,manualReads: 1,submittedAnswers: 1))
        for flags in [(false,true,true),(true,false,true),(true,true,false)] {
            XCTAssertFalse(AppRealAuthUIGate.completed(connected: flags.0,shellACK: flags.1,pendingNil: flags.2,manualReads: 1,submittedAnswers: 1))
        }
        for (reads,answers) in [(0,1),(1,0),(2,1),(1,2)] {
            XCTAssertFalse(AppRealAuthUIGate.completed(connected: true,shellACK: true,pendingNil: true,manualReads: reads,submittedAnswers: answers))
        }
        var observation = AppRealAuthUIGate.Observation()
        XCTAssertThrowsError(try observation.sample(elapsed: 1,connected: true,identityUnchanged: true,noChallenge: true))
        try observation.sample(elapsed: 0,connected: true,identityUnchanged: true,noChallenge: true)
        XCTAssertThrowsError(try observation.sample(elapsed: 0.5,connected: true,identityUnchanged: true,noChallenge: false))
        XCTAssertThrowsError(try observation.sample(elapsed: .nan,connected: true,identityUnchanged: true,noChallenge: true))
        XCTAssertThrowsError(try observation.sample(elapsed: 0.5,connected: false,identityUnchanged: true,noChallenge: true))
        XCTAssertThrowsError(try observation.sample(elapsed: 0.5,connected: true,identityUnchanged: false,noChallenge: true))
        try observation.sample(elapsed: 2,connected: true,identityUnchanged: true,noChallenge: true)
        XCTAssertTrue(observation.complete); XCTAssertEqual(observation.samples,2)
    }
    private func concurrentAuthChallenges() -> (AppRealAuthUIGate.Challenge, AppRealAuthUIGate.Challenge) {
        func challenge(_ pid: Int32, _ birth: UInt64) -> AppRealAuthUIGate.Challenge {
            .init(requestID: UUID(), identity: .init(tabID: UUID(), sessionID: UUID(), generation: 1,
                process: .init(pid: pid, parentPID: 99, startSeconds: birth, startMicroseconds: 1)))
        }
        return (challenge(111, 1), challenge(222, 2))
    }
    private func concurrentAuthSnapshot(_ value: AppRealAuthUIGate.Challenge, state: AppRealConcurrentAuthGate.State = .authenticating,
                                        tokenMatches: Bool = true, unknownMasked: Bool = true) -> AppRealConcurrentAuthGate.Snapshot {
        .init(tabID: value.identity.tabID, sessionID: value.identity.sessionID, generation: value.identity.generation,
            process: state == .disconnectedNil ? nil : value.identity.process, requestID: state == .authenticating ? value.requestID : nil,
            requestMatchesToken: tokenMatches, unknownMasked: unknownMasked, state: state, trustEmpty: true, canReconnect: state == .disconnectedNil)
    }
    func testConcurrentAuthClosedPhaseSharesOnlyTwoAuthPhasesEncryptedAndPhraseAllowlist() throws {
        var value = object(); value["phase"] = "concurrent-auth-ui"
        XCTAssertEqual(try decode(value).selectedPhase, .concurrentAuthUI)
        XCTAssertTrue(AppRealIntegrationPhase.concurrentAuthUI.isTerminalOnly); XCTAssertFalse(AppRealIntegrationPhase.concurrentAuthUI.isTransfer)
        for name in ["read-only", "transfer-survives-close", "window-continue-cancel", "quit-continue-cancel", "file-operations", "terminal-search-paste", "sessions-reconnect", "batch-conflicts", "batch-overwrite", "transfer-survives-switch", "auth-ui-cancel", "trust-change-recover", "concurrent-auth-ui"] {
            let phase = try XCTUnwrap(AppRealIntegrationPhase(rawValue: name))
            let auth = phase == .authUICancel || phase == .concurrentAuthUI
            XCTAssertEqual(phase.allowsFixturePhrase, auth)
            XCTAssertEqual(phase.fixturePrivateKeyName, auth ? "id_ed25519_encrypted" : "id_ed25519")
        }
        XCTAssertEqual(try AppRealAuthUIGate.phrasePayload(Data("synthetic-only\n".utf8)), Data("synthetic-only".utf8))
        XCTAssertThrowsError(try AppRealAuthUIGate.phrasePayload(Data("synthetic-only\r\n".utf8)))
        value["phase"] = "concurrent-auth-ui-other"; XCTAssertThrowsError(try decode(value))
        value["phase"] = "concurrent-auth-ui"; value["encryptedPublicSHA256"] = String(repeating: "a", count: 64)
        XCTAssertThrowsError(try decode(value))
    }
    func testConcurrentAuthBarrierRequiresDistinctPendingInitialRequestsAndZeroManualAnswers() {
        typealias Gate = AppRealConcurrentAuthGate
        let (a, b) = concurrentAuthChallenges(), currentA = concurrentAuthSnapshot(a), currentB = concurrentAuthSnapshot(b)
        let counts = Gate.Counts(importPhraseReads: 1, aManualPhraseReads: 0, bManualPhraseReads: 0, aSubmittedAnswers: 0, bSubmittedAnswers: 0)
        func barrier(_ second: AppRealAuthUIGate.Challenge, _ sa: Gate.Snapshot, _ sb: Gate.Snapshot, _ c: Gate.Counts, distinct: Bool = true, sameKey: Bool = true) -> Bool {
            Gate.barrier(a, second, currentA: sa, currentB: sb, distinctObjects: distinct, sameHostAndKey: sameKey, counts: c)
        }
        XCTAssertTrue(barrier(b, currentA, currentB, counts))
        XCTAssertFalse(barrier(b, currentA, currentB, counts, distinct: false)); XCTAssertFalse(barrier(b, currentA, currentB, counts, sameKey: false))
        let sameRequest = AppRealAuthUIGate.Challenge(requestID: a.requestID, identity: b.identity)
        XCTAssertFalse(barrier(sameRequest, currentA, concurrentAuthSnapshot(sameRequest), counts))
        let shared = AppRealAuthUIGate.Challenge(requestID: b.requestID, identity: a.identity)
        XCTAssertFalse(barrier(shared, currentA, concurrentAuthSnapshot(shared), counts))
        let sameBirth = AppRealAuthUIGate.Challenge(requestID: b.requestID, identity: .init(tabID: b.identity.tabID, sessionID: b.identity.sessionID,
            generation: 1, process: .init(pid: 222, parentPID: 99, startSeconds: 1, startMicroseconds: 1)))
        XCTAssertFalse(barrier(sameBirth, currentA, concurrentAuthSnapshot(sameBirth), counts))
        let later = AppRealAuthUIGate.Challenge(requestID: b.requestID, identity: .init(tabID: b.identity.tabID, sessionID: b.identity.sessionID, generation: 2, process: b.identity.process))
        XCTAssertFalse(barrier(later, currentA, concurrentAuthSnapshot(later), counts))
        XCTAssertFalse(barrier(b, concurrentAuthSnapshot(a, state: .connected), currentB, counts))
        XCTAssertFalse(barrier(b, currentA, concurrentAuthSnapshot(b, tokenMatches: false), counts))
        XCTAssertFalse(barrier(b, currentA, concurrentAuthSnapshot(b, unknownMasked: false), counts))
        var read = counts; read.bManualPhraseReads = 1
        var submitted = counts; submitted.aSubmittedAnswers = 1
        XCTAssertFalse(barrier(b, currentA, currentB, read)); XCTAssertFalse(barrier(b, currentA, currentB, submitted))
    }
    func testConcurrentAuthCancelARequiresBOriginalPendingAndSecureSheetCannotCrossToken() {
        typealias Gate = AppRealConcurrentAuthGate
        let (a, b) = concurrentAuthChallenges(), closedA = concurrentAuthSnapshot(a, state: .disconnectedNil), pendingB = concurrentAuthSnapshot(b)
        let counts = Gate.Counts(importPhraseReads: 1, aManualPhraseReads: 0, bManualPhraseReads: 0, aSubmittedAnswers: 0, bSubmittedAnswers: 0)
        XCTAssertTrue(Gate.cancelledA(a, b, currentA: closedA, currentB: pendingB, sameObjects: true, oldGone: true, counts: counts))
        XCTAssertFalse(Gate.cancelledA(a, b, currentA: closedA, currentB: pendingB, sameObjects: true, oldGone: false, counts: counts))
        XCTAssertFalse(Gate.cancelledA(a, b, currentA: concurrentAuthSnapshot(a), currentB: pendingB, sameObjects: true, oldGone: true, counts: counts))
        let replaced = AppRealAuthUIGate.Challenge(requestID: UUID(), identity: b.identity)
        XCTAssertFalse(Gate.cancelledA(a, b, currentA: closedA, currentB: concurrentAuthSnapshot(replaced), sameObjects: true, oldGone: true, counts: counts))
        XCTAssertTrue(Gate.sheetBound(b, current: pendingB, selectedTabID: b.identity.tabID, secureFieldEmpty: true))
        XCTAssertFalse(Gate.sheetBound(b, current: concurrentAuthSnapshot(a), selectedTabID: b.identity.tabID, secureFieldEmpty: true))
        XCTAssertFalse(Gate.sheetBound(b, current: concurrentAuthSnapshot(b, tokenMatches: false), selectedTabID: b.identity.tabID, secureFieldEmpty: true))
        XCTAssertFalse(Gate.sheetBound(b, current: pendingB, selectedTabID: a.identity.tabID, secureFieldEmpty: true))
        XCTAssertFalse(Gate.sheetBound(b, current: pendingB, selectedTabID: b.identity.tabID, secureFieldEmpty: false))
    }
    func testConcurrentAuthBCompletionRequiresUniqueAnswerFreshACKAndAStillOriginalDisconnected() throws {
        typealias Gate = AppRealConcurrentAuthGate
        let (a, b) = concurrentAuthChallenges(), closedA = concurrentAuthSnapshot(a, state: .disconnectedNil), connectedB = concurrentAuthSnapshot(b, state: .connected)
        let counts = Gate.Counts(importPhraseReads: 1, aManualPhraseReads: 0, bManualPhraseReads: 1, aSubmittedAnswers: 0, bSubmittedAnswers: 1)
        func completed(_ sa: Gate.Snapshot, _ sb: Gate.Snapshot, _ c: Gate.Counts, ack: Bool = true) -> Bool {
            Gate.completedB(a, b, currentA: sa, currentB: sb, sameObjects: true, oldGone: true, counts: c, freshACK: ack)
        }
        XCTAssertTrue(completed(closedA, connectedB, counts)); XCTAssertFalse(completed(closedA, connectedB, counts, ack: false))
        XCTAssertFalse(completed(concurrentAuthSnapshot(a, state: .connected), connectedB, counts))
        XCTAssertFalse(completed(closedA, concurrentAuthSnapshot(b), counts))
        let newA = AppRealAuthUIGate.Challenge(requestID: UUID(), identity: .init(tabID: a.identity.tabID, sessionID: a.identity.sessionID, generation: 2, process: a.identity.process))
        XCTAssertFalse(completed(concurrentAuthSnapshot(newA, state: .disconnectedNil), connectedB, counts))
        let newB = AppRealAuthUIGate.Challenge(requestID: UUID(), identity: .init(tabID: b.identity.tabID, sessionID: b.identity.sessionID, generation: 2,
            process: .init(pid: 333, parentPID: 99, startSeconds: 3, startMicroseconds: 1)))
        XCTAssertFalse(completed(closedA, concurrentAuthSnapshot(newB, state: .connected), counts))
        var duplicate = counts; duplicate.bSubmittedAnswers = 2
        var crossed = counts; crossed.aSubmittedAnswers = 1
        XCTAssertFalse(completed(closedA, connectedB, duplicate)); XCTAssertFalse(completed(closedA, connectedB, crossed))
        let encoded = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(connectedB)) as? [String: Any])
        XCTAssertEqual(Set(encoded.keys), ["tabID", "sessionID", "generation", "process", "requestMatchesToken", "unknownMasked", "state", "trustEmpty", "canReconnect"])
        let countFields = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(counts)) as? [String: Any])
        XCTAssertEqual(Set(countFields.keys), ["importPhraseReads", "aManualPhraseReads", "bManualPhraseReads", "aSubmittedAnswers", "bSubmittedAnswers"])
    }
    func testTrustChangeClosedTerminalOnlyPhaseUsesPlainFixtureKeyAndExactEndpoint() throws {
        var value = object(); value["phase"] = "trust-change-recover"
        XCTAssertEqual(try decode(value).selectedPhase,.trustChangeRecover)
        XCTAssertTrue(AppRealIntegrationPhase.trustChangeRecover.isTerminalOnly); XCTAssertFalse(AppRealIntegrationPhase.trustChangeRecover.isTransfer)
        XCTAssertEqual(AppRealIntegrationPhase.trustChangeRecover.fixturePrivateKeyName,"id_ed25519")
        let actual = AppRealIntegrationContract.fingerprint, wrong = "SHA256:" + String(repeating: "A",count: 43)
        XCTAssertTrue(AppRealTrustGate.distinctPublicRecords(host: "127.0.0.1",port: 22221,algorithm: "ssh-ed25519",wrongFingerprint: wrong,actualFingerprint: actual))
        XCTAssertFalse(AppRealTrustGate.distinctPublicRecords(host: "127.0.0.1",port: 22221,algorithm: "ssh-ed25519",wrongFingerprint: actual,actualFingerprint: actual))
        for (host,port,algorithm) in [("localhost",22221,"ssh-ed25519"),("127.0.0.1",22222,"ssh-ed25519"),("127.0.0.1",22221,"ssh-rsa")] {
            XCTAssertFalse(AppRealTrustGate.distinctPublicRecords(host: host,port: port,algorithm: algorithm,wrongFingerprint: wrong,actualFingerprint: actual))
        }
    }
    func testTrustRejectGateRequiresTypedFailureNoInteractivePIDOrPromptAndUnchangedPublicRecord() {
        let id = UUID(), token = AppRealTrustGate.Token(tabID: id,sessionID: id,generation: 1), hash = String(repeating: "a",count: 64)
        func gate(_ rejected: Bool = true,_ pid: Bool = false,_ auth: Bool = false,_ prompt: Bool = false,_ reconnect: Bool = true,
                  _ after: String? = nil,_ exact: Bool = true,_ generation: UInt64 = 1) -> Bool {
            AppRealTrustGate.rejected(trustRejected: rejected,ownedPIDSeen: pid,authSeen: auth,promptSeen: prompt,reconnectable: reconnect,
                token: .init(tabID: token.tabID,sessionID: token.sessionID,generation: generation),beforeHash: hash,afterHash: after ?? hash,exactOldRecord: exact)
        }
        XCTAssertTrue(gate()); XCTAssertFalse(gate(false)); XCTAssertFalse(gate(true,true)); XCTAssertFalse(gate(true,false,true))
        XCTAssertFalse(gate(true,false,false,true)); XCTAssertFalse(gate(true,false,false,false,false))
        XCTAssertFalse(gate(true,false,false,false,true,String(repeating: "b",count: 64)))
        XCTAssertFalse(gate(true,false,false,false,true,nil,false)); XCTAssertFalse(gate(true,false,false,false,true,nil,true,2))
    }
    func testTrustNativeReplacementDoesNotReconnectUntilExactNextGenerationAndACK() {
        let id = UUID(), old = AppRealTrustGate.Token(tabID: id,sessionID: id,generation: 1), oldHash = String(repeating: "a",count: 64), newHash = String(repeating: "b",count: 64)
        func replacement(current: AppRealTrustGate.Token? = nil,rejected: Bool = true,exact: Bool = true,count: Int = 1,
                         hash: String? = nil,native: Bool = true) -> Bool {
            AppRealTrustGate.replacement(before: old,current: current ?? old,stillRejected: rejected,recordsExactActual: exact,count: count,
                oldHash: oldHash,newHash: hash ?? newHash,nativeConfirmed: native)
        }
        XCTAssertTrue(replacement()); XCTAssertFalse(replacement(current: .init(tabID: id,sessionID: id,generation: 2)))
        XCTAssertFalse(replacement(rejected: false)); XCTAssertFalse(replacement(exact: false)); XCTAssertFalse(replacement(count: 2))
        XCTAssertFalse(replacement(hash: oldHash)); XCTAssertFalse(replacement(native: false)); XCTAssertFalse(replacement(hash: "not-a-hash"))
        let next = AppRealSessionsProtocol.Identity(tabID: id,sessionID: id,generation: 2,process: .init(pid: 111,parentPID: 99,startSeconds: 1,startMicroseconds: 0))
        XCTAssertTrue(AppRealTrustGate.recovered(before: old,after: next,sameObjects: true,connected: true,shellACK: true,noPrompts: true))
        for flags in [(false,true,true,true),(true,false,true,true),(true,true,false,true),(true,true,true,false)] {
            XCTAssertFalse(AppRealTrustGate.recovered(before: old,after: next,sameObjects: flags.0,connected: flags.1,shellACK: flags.2,noPrompts: flags.3))
        }
        let same = AppRealSessionsProtocol.Identity(tabID: id,sessionID: id,generation: 1,process: next.process)
        XCTAssertFalse(AppRealTrustGate.recovered(before: old,after: same,sameObjects: true,connected: true,shellACK: true,noPrompts: true))
    }
    #if HOST_PROBE
    func testTrustHostPublicKeyUsesMatureParserForPublicSyntheticKeyAndRejectsMalformed() throws {
        // Public RFC8032 test-vector key, not a fixture/server/private key.
        let raw: [UInt8] = [0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
                            0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a]
        let blob = Data([0,0,0,11]) + Data("ssh-ed25519".utf8) + Data([0,0,0,32]) + Data(raw)
        let line = "ssh-ed25519 " + blob.base64EncodedString(), key = try HostPublicKey(openSSHPublicKey: line)
        XCTAssertEqual(key.openSSH,line); XCTAssertEqual(key.algorithm,"ssh-ed25519"); XCTAssertNotEqual(key.fingerprint,AppRealIntegrationContract.fingerprint)
        for invalid in [line + "\n"," "+line,"ssh-ed25519 not-base64","ssh-ed25519 AAAA","ssh-rsa "+blob.base64EncodedString()] {
            XCTAssertThrowsError(try HostPublicKey(openSSHPublicKey: invalid))
        }
    }
    #endif
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
