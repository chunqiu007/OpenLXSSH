import Darwin
import Foundation
import OpenLXSSHFiles
import RealIntegrationCore

@main enum DisconnectOfflineMain {
    static func main() throws {
        var checks = 0
        func check(_ value: Bool) throws { try require(value); checks += 1 }
        func refuses(_ body: () throws -> Void) throws {
            do { try body() } catch { checks += 1; return }; throw GateError.integrity
        }
        try check(try DisconnectOptions.parse([]).action == .help)
        try check(try DisconnectOptions.parse(["--help"]).action == .help)
        try check(try DisconnectOptions.parse(["validate", "--case", "/not/opened/case.json"]).action == .validate)
        for action in ["--prepare-disconnect-case", "--disconnect-case", "--verify-disconnect-case"] {
            let pathArg = action == "--prepare-disconnect-case" ? "--generation" : "--case"
            try refuses { _ = try DisconnectOptions.parse([action, pathArg, "/not/opened/case.json"]) }
            try refuses { _ = try DisconnectOptions.parse([action, pathArg, "/not/opened/case.json", "--authorized-local-fixture"]) }
            try check(try DisconnectOptions.parse([action, pathArg, "/not/opened/case.json", "--authorized-local-fixture", "--primary-reviewed"]).path == "/not/opened/case.json")
        }
        for args in [["--disconnect-case", "--host", "example.com"], ["--disconnect-case", "--password", "synthetic"],
            ["validate", "--case", "/a/../case.json"], ["validate", "--case", "/a/case.json", "--authorized-local-fixture"],
            ["--disconnect-case", "--case", "/a/case.json", "--authorized-local-fixture", "--primary-reviewed", "--cleanup-owned-paths"]] {
            try refuses { _ = try DisconnectOptions.parse(args) }
        }
        let id = "12345678-1234-1234-1234-123456789abc", root = try DisconnectFixed.root(id), target = try join(root, "target.bin")
        let temp = try join(root, ".openlxssh-transfer.01234567-89AB-CDEF-0123-456789ABCDEF.part")
        func owned(_ p: RemotePath, dir: Bool = false) -> DisconnectOwnedPath { DisconnectOwnedPath(pathBase64: p.bytes.base64EncodedString(), directory: dir) }
        let ledger = [owned(root, dir: true), owned(target), owned(temp)]
        try check(try DisconnectLedger.validate(ledger, id: id) == [temp])
        try check(try DisconnectLedger.validate(Array(ledger.prefix(2)), id: id).isEmpty)
        for bad in [ledger + [owned(temp)], [owned(root), owned(target)], [owned(root, dir: true), owned(try join(root, "unknown"))],
            [owned(root, dir: true), owned(target), owned(try rp("/outside/.openlxssh-transfer.01234567-89AB-CDEF-0123-456789ABCDEF.part"))],
            [owned(root, dir: true), owned(target), owned(try join(root, ".openlxssh-transfer.latest.part"))]] {
            try refuses { _ = try DisconnectLedger.validate(bad, id: id) }
        }
        let targetEntry = DirectoryEntry(name: try FileName("target.bin"), attributes: FileAttributes(kind: .regular))
        let tempEntry = DirectoryEntry(name: temp.name!, attributes: FileAttributes(kind: .regular))
        try DisconnectLedger.checkListing([targetEntry, tempEntry], created: ledger, id: id); checks += 1
        try DisconnectLedger.checkListing([targetEntry], created: ledger, id: id); checks += 1
        for bad in [[tempEntry], [targetEntry, DirectoryEntry(name: try FileName("unknown"), attributes: FileAttributes(kind: .regular))],
            [targetEntry, DirectoryEntry(name: temp.name!, attributes: FileAttributes(kind: .symbolicLink))]] {
            try refuses { try DisconnectLedger.checkListing(bad, created: ledger, id: id) }
        }
        let ready = DisconnectReady(schema: 1, caseID: id, event: "upload-real-progress-ready-to-terminate-owned-relay",
            progressBytes: DisconnectFixed.quarter, sourceBytes: DisconnectFixed.bytes, at: 1000,
            serverBinding: UUID().uuidString, createdPaths: ledger)
        try ready.validate(id: id); checks += 1
        let readyBytes = try JSONEncoder().encode(ready)
        let roundTrip = try JSONDecoder().decode(DisconnectReady.self, from: readyBytes)
        try roundTrip.validate(id: id); checks += 1
        let receipt = RelayTermination(schema: 1, caseID: id, reason: "SIGTERM-exact-owned-relay-after-ready", readySHA256: PrivateInput.sha256(readyBytes),
            ownedRelayPID: 12345, requestedAt: 1001, completedAt: 1002, relayExitCode: 0, accepted: 1, finished: 1, rejected: 0, cleanupFailed: 0)
        try receipt.validate(ready: ready, readyData: readyBytes); checks += 1
        let item = TransferItemResult(source: try rp("/source.bin"), destination: target,
            state: .failed(FileServiceError(.transport, operation: "write", code: -43)), retainedTemporary: temp)
        let nativeError = DisconnectItem(item)
        let upload = DisconnectUploadResult(schema: 1, caseID: id, status: "typed-failure-await-external-proof-and-new-connection",
            sourceBytes: DisconnectFixed.bytes, sourceSHA256: String(repeating: "a", count: 64), sourceAllocatedBytes: DisconnectFixed.bytes,
            targetBefore: nil, targetSHA256Before: nil, progressBytes: DisconnectFixed.quarter,
            failureKind: "transport", failureOperation: "write", failureCode: -43, failureDetail: nil,
            items: [nativeError], ownedPaths: ledger, startedAt: 900, endedAt: 1002,
            firstServerBinding: ready.serverBinding, firstConnectionCloseAwaited: true, managerLeaseDrained: true,
            resourcesAfterClose: APICounters(openHandles: 0, peakHandles: 2, successfulOpens: 3, successfulCloses: 2,
                closedByServiceShutdown: 1, closeCallsFailed: 1, readBytes: 0, writtenBytes: DisconnectFixed.quarter,
                largestRead: Fixed.chunk, largestWrite: Fixed.chunk), fixtureSocketsAfterClose: 0)
        let uploadCopy = try JSONDecoder().decode(DisconnectUploadResult.self, from: JSONEncoder().encode(upload))
        try check(uploadCopy.items.first?.retainedTemporaryBase64 == temp.bytes.base64EncodedString())
        try check(uploadCopy.failureOperation == "write" && uploadCopy.failureCode == -43)
        try check(try DisconnectLedger.validate(uploadCopy.ownedPaths, id: id) == [temp])
        try refuses { try receipt.validate(ready: ready, readyData: raw("modified")) }
        let wrong = RelayTermination(schema: 1, caseID: id, reason: "token-cancel-is-not-network", readySHA256: PrivateInput.sha256(readyBytes),
            ownedRelayPID: 12345, requestedAt: 1001, completedAt: 1002, relayExitCode: 0, accepted: 1, finished: 1, rejected: 0, cleanupFailed: 0)
        try refuses { try wrong.validate(ready: ready, readyData: readyBytes) }
        for kind in [FileServiceError.Kind.transport, .closed] {
            try check(expectedDisconnectFailure(FileServiceError(kind, operation: "write", code: -43), progress: DisconnectFixed.quarter, sourceBytes: DisconnectFixed.bytes))
        }
        for kind in [FileServiceError.Kind.timeout, .cancelled, .permissionDenied, .integrity, .protocolFailure] {
            try check(!expectedDisconnectFailure(FileServiceError(kind, operation: "write"), progress: DisconnectFixed.quarter, sourceBytes: DisconnectFixed.bytes))
        }
        try check(!expectedDisconnectFailure(FileServiceError(.transport, operation: "write"), progress: DisconnectFixed.bytes, sourceBytes: DisconnectFixed.bytes))
        try check(!expectedDisconnectFailure(FileServiceError(.transport, operation: "write"), progress: 0, sourceBytes: DisconnectFixed.bytes))
        try check(DisconnectFixed.bytes == 16 * 1024 * 1024 && DisconnectFixed.quarter == 4 * 1024 * 1024)
        print("Disconnect offline checks passed: \(checks). Pure metadata/argument/error/ledger checks; no data generation, credential reads, sockets, relay or live connection.")
    }
}
