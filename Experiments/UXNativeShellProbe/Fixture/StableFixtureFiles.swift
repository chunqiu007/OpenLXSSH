import Darwin
import Foundation
import RealIntegrationCore
import RealIntegrationPOSIX

/// Extra stability check around the UNMODIFIED mature reader. All component/noFollow/ACL/owner/
/// mode gates remain ri_open_private's responsibility. This adds held-FD identity and metadata
/// checks, plus a bounded second read comparison, without hashing or emitting secret bytes.
final class StableFixtureFiles {
    private struct Entry {
        let path: String
        let descriptor: Int32
        let before: stat
        let directory: Bool
    }
    private var entries: [Entry] = []
    deinit { entries.forEach { Darwin.close($0.descriptor) } }
    private static func same(_ lhs: stat, _ rhs: stat) -> Bool {
        lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_mode == rhs.st_mode &&
        lhs.st_uid == rhs.st_uid && lhs.st_gid == rhs.st_gid && lhs.st_nlink == rhs.st_nlink &&
        lhs.st_size == rhs.st_size && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec &&
        lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec &&
        lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
    }
    func hold(_ path: String, directory: Bool) throws {
        try PrivateInput.validateSyntax(path)
        let fd = ri_open_private(path, directory ? 1 : 0)
        guard fd >= 0 else { throw SFTPAuthError.unsafeMaterial }
        var info = stat()
        guard fstat(fd, &info) == 0 else { Darwin.close(fd); throw SFTPAuthError.unsafeMaterial }
        entries.append(Entry(path: path, descriptor: fd, before: info, directory: directory))
    }
    func check() throws {
        for entry in entries {
            var current = stat()
            guard fstat(entry.descriptor, &current) == 0, Self.same(entry.before, current) else {
                throw SFTPAuthError.unsafeMaterial
            }
            // Reopening through the mature gate revalidates ACL/mode and every O_NOFOLLOW component.
            let fresh = ri_open_private(entry.path, entry.directory ? 1 : 0)
            guard fresh >= 0 else { throw SFTPAuthError.unsafeMaterial }
            defer { Darwin.close(fresh) }
            var reopened = stat()
            guard fstat(fresh, &reopened) == 0, Self.same(entry.before, reopened) else {
                throw SFTPAuthError.unsafeMaterial
            }
        }
    }
    static func read(_ path: String, limit: Int) throws -> Data {
        let stable = StableFixtureFiles(); try stable.hold(path, directory: false)
        var first = try PrivateInput.read(path, limit: limit)
        do {
            var second = try PrivateInput.read(path, limit: limit)
            defer { second.resetBytes(in: 0..<second.count) }
            try stable.check()
            guard first == second else { throw SFTPAuthError.unsafeMaterial }
            return first
        } catch { first.resetBytes(in: 0..<first.count); throw error }
    }
    static func checkMarker(directory: String, file: String, expected: String) throws {
        try PrivateInput.checkDirectory(directory)
        let bytes = try read(directory + "/" + file, limit: 256)
        guard bytes == Data(expected.utf8) else { throw SFTPAuthError.unsafeMaterial }
    }
    static func holdSelectedInput(_ contract: SFTPAuthContract, path: String, fixtureRoot: String) throws -> StableFixtureFiles {
        let stable = StableFixtureFiles()
        for directory in [URL(fileURLWithPath: path).deletingLastPathComponent().path,
                          fixtureRoot + "/.runtime", fixtureRoot + "/.runtime/" + contract.service.rawValue,
                          contract.credentialDirectory] { try stable.hold(directory, directory: true) }
        var files = [path, fixtureRoot + "/.runtime/state.json", contract.credentialDirectory + "/provenance.json",
                     contract.credentialDirectory + "/known_hosts", contract.credentialDirectory + "/fingerprint.txt"]
        if let key = contract.key.file {
            files += [contract.credentialDirectory + "/" + key, contract.credentialDirectory + "/" + key + ".pub"]
            if contract.key.encrypted { files.append(contract.credentialDirectory + "/key-passphrase.txt") }
        } else { files.append(contract.credentialDirectory + "/password.txt") }
        for file in files { try stable.hold(file, directory: false) }
        return stable
    }
}
