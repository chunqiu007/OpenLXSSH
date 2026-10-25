import Darwin
import Foundation
import GRDB
import OpenLXSSHCore

// These modes operate only on a caller-created 0700 temporary leaf. No server or user data is accessed.
// abrupt-* deliberately calls _exit in this child only, bypassing Swift/SQLite destructors.
let arguments = Array(CommandLine.arguments.dropFirst())
do {
    guard arguments.count >= 2 else { throw RepositoryError.invalidField("fixtureArguments") }
    let mode = arguments[0]
    let directory = URL(fileURLWithPath: arguments[1], isDirectory: true)
    guard directory.lastPathComponent.hasPrefix("openlxssh-core-test-"),
          directory.deletingLastPathComponent().resolvingSymlinksInPath() == FileManager.default.temporaryDirectory.resolvingSymlinksInPath() else {
        throw RepositoryError.unsafeDatabaseLocation
    }
    switch mode {
    case "write":
        guard arguments.count == 4, let count = Int(arguments[3]), (1...1000).contains(count) else { throw RepositoryError.invalidField("fixtureCount") }
        let database = try OpenLXSSHDatabase(directory: directory)
        for index in 0..<count {
            try database.addHost(HostConfiguration(name: "\(arguments[2])-\(index)", address: "test.invalid", username: "fixture"))
        }
        try database.close()
    case "hold-write":
        let database = try OpenLXSSHDatabase(directory: directory)
        try database.close()
        var config = Configuration()
        config.foreignKeysEnabled = true; config.journalMode = .wal; config.busyMode = .timeout(5)
        let queue = try DatabaseQueue(path: database.databaseURL.path, configuration: config)
        try queue.write { db in
            try db.execute(sql: "INSERT INTO hosts(id, name, address, username, authentication) VALUES (?, 'child-held-lock', 'test.invalid', 'fixture', 'password')", arguments: [UUID()])
            let readyURL = directory.appendingPathComponent("writer.ready")
            guard FileManager.default.createFile(atPath: readyURL.path, contents: Data(), attributes: [.posixPermissions: 0o600]) else {
                throw RepositoryError.unsafeDatabaseLocation
            }
            Thread.sleep(forTimeInterval: 0.4)
        }
        try queue.close()
    case "abrupt-commit":
        let database = try OpenLXSSHDatabase(directory: directory)
        try database.addHost(HostConfiguration(id: UUID(uuidString: "77777777-7777-4777-8777-777777777777")!, name: "committed", address: "test.invalid", username: "fixture"))
        // No close, deinit, or checkpoint: the committed row must recover from the WAL.
        _exit(71)
    case "abrupt-cleanup":
        let database = try OpenLXSSHDatabase(directory: directory)
        try database.apply([
            .deleteCredential(UUID(uuidString: "88888888-8888-4888-8888-888888888888")!),
            .scheduleOrphanCleanup(ExternalResource(kind: .privateKey, id: UUID(uuidString: "99999999-9999-4999-8999-999999999999")!))
        ])
        _exit(73)
    case "abrupt-transaction":
        let database = try OpenLXSSHDatabase(directory: directory)
        try database.close()
        var config = Configuration()
        config.foreignKeysEnabled = true; config.journalMode = .wal; config.busyMode = .timeout(5)
        let queue = try DatabaseQueue(path: database.databaseURL.path, configuration: config)
        try queue.writeWithoutTransaction { db in
            try db.execute(sql: "PRAGMA synchronous = FULL; PRAGMA cache_size = 5; PRAGMA cache_spill = 5")
            let walURL = directory.appendingPathComponent("OpenLXSSH.sqlite-wal")
            let beforeAttributes = try? FileManager.default.attributesOfItem(atPath: walURL.path)
            let before = (beforeAttributes?[.size] as? NSNumber)?.intValue ?? 0
            try db.execute(sql: "BEGIN IMMEDIATE")
            do {
                for index in 0..<300 {
                    try db.execute(sql: "INSERT INTO hosts(id, name, address, username, authentication) VALUES (?, ?, 'test.invalid', 'fixture', 'password')", arguments: [UUID(), "uncommitted-\(index)-" + String(repeating: "x", count: 160)])
                }
                let after = (try FileManager.default.attributesOfItem(atPath: walURL.path)[.size] as! NSNumber).intValue
                guard after > before else { throw RepositoryError.invalidField("fixtureDidNotSpill") }
                let metrics = try JSONSerialization.data(withJSONObject: ["walBefore": before, "walAfter": after])
                guard FileManager.default.createFile(atPath: directory.appendingPathComponent("uncommitted-wal.json").path,
                                                    contents: metrics, attributes: [.posixPermissions: 0o600]) else {
                    throw RepositoryError.unsafeDatabaseLocation
                }
                // The measured WAL growth proves dirty pages spilled before COMMIT, not only an empty transaction.
                _exit(72)
            } catch {
                try? db.execute(sql: "ROLLBACK")
                throw error
            }
        }
    default: throw RepositoryError.invalidField("fixtureMode")
    }
} catch {
    // Only fixed categories/result codes; never print SQL, parameters, paths, or external descriptions.
    let code: String
    if let repositoryError = error as? RepositoryError {
        switch repositoryError {
        case .unsafeDatabaseLocation: code = "unsafe-location"
        case .databaseBusy: code = "initialization-busy"
        case .unsupportedSchema: code = "unsupported-schema"
        default: code = "repository-error"
        }
    } else if let databaseError = error as? DatabaseError {
        code = "sqlite-\(databaseError.resultCode.rawValue)"
    } else { code = "other-error" }
    FileHandle.standardError.write(Data("database fixture failed: \(code)\n".utf8))
    exit(1)
}
