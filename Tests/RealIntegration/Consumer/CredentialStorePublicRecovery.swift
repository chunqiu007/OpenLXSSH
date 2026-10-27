import Darwin
import Foundation
import RealIntegrationCore
import RealIntegrationPOSIX

/// Append-only exact-run receipts with held parent/run descriptors. No recovery
/// enumerator/deletion exists. prepared alone never establishes external ownership.
final class CredentialStorePublicRecovery {
    let directory: String
    private let parentDirectory: String
    private let parentFD: Int32
    private let runFD: Int32
    private let parentIdentity: stat
    private let runIdentity: stat
    private var sequence = 0
    init(directory: String, parentDirectory: String) throws {
        try PrivateInput.validateSyntax(directory); try PrivateInput.validateSyntax(parentDirectory)
        guard URL(fileURLWithPath: directory).deletingLastPathComponent().path == parentDirectory else { throw CredentialStorePublicError.recoveryRecordFailed }
        let parent = ri_open_private(parentDirectory, 1)
        guard parent >= 0 else { throw CredentialStorePublicError.recoveryRecordFailed }
        let run = ri_open_private(directory, 1)
        guard run >= 0 else { Darwin.close(parent); throw CredentialStorePublicError.recoveryRecordFailed }
        var p = stat(), r = stat()
        guard fstat(parent, &p) == 0, fstat(run, &r) == 0 else {
            Darwin.close(parent); Darwin.close(run); throw CredentialStorePublicError.recoveryRecordFailed
        }
        self.directory = directory; self.parentDirectory = parentDirectory
        parentFD = parent; runFD = run; parentIdentity = p; runIdentity = r
        do { try validateIdentity() }
        catch { Darwin.close(parent); Darwin.close(run); throw error }
    }
    deinit { Darwin.close(runFD); Darwin.close(parentFD) }
    private func validateIdentity() throws {
        func same(_ current: stat, _ expected: stat) -> Bool {
            current.st_dev == expected.st_dev && current.st_ino == expected.st_ino && current.st_uid == getuid()
                && current.st_mode & S_IFMT == S_IFDIR && current.st_mode & 0o7777 == 0o700
        }
        var heldParent = stat(), heldRun = stat(), linkedRun = stat()
        let name = URL(fileURLWithPath: directory).lastPathComponent
        guard fstat(parentFD, &heldParent) == 0, fstat(runFD, &heldRun) == 0,
              same(heldParent, parentIdentity), same(heldRun, runIdentity),
              fstatat(parentFD, name, &linkedRun, AT_SYMLINK_NOFOLLOW) == 0, same(linkedRun, runIdentity) else { throw CredentialStorePublicError.recoveryRecordFailed }
        // Re-open full paths through the established no-follow/UID/mode/noACL
        // gate. A replaced parent/path cannot fsync somebody else's directory.
        let parent = ri_open_private(parentDirectory, 1), run = ri_open_private(directory, 1)
        defer { if parent >= 0 { Darwin.close(parent) }; if run >= 0 { Darwin.close(run) } }
        var currentParent = stat(), currentRun = stat()
        guard parent >= 0, run >= 0, fstat(parent, &currentParent) == 0, fstat(run, &currentRun) == 0,
              same(currentParent, parentIdentity), same(currentRun, runIdentity) else { throw CredentialStorePublicError.recoveryRecordFailed }
    }
    func persist(_ event: String, state: CredentialStorePublicState) throws {
        let allowed: Set<String> = ["prepared", "save-attempted", "save-result", "connection-result", "delete-attempted", "delete-result", "missing-result", "store-closed", "failed"]
        guard allowed.contains(event), sequence < 16 else { throw CredentialStorePublicError.recoveryRecordFailed }
        let data = try JSONEncoder().encode(CredentialStorePublicRecoveryRecord(event: event, state: state))
        guard data.count <= 8192 else { throw CredentialStorePublicError.recoveryRecordFailed }
        let name = String(format: "recovery-%02d-", sequence) + event + ".json"
        try CredentialStorePublicDurability.commit(validateIdentity: { try self.validateIdentity() }, writeAndSyncFile: {
            try PrivateInput.writeExclusive(data + Data([10]), to: self.directory + "/" + name)
        }, syncRun: {
            guard fsync(self.runFD) == 0 else { throw CredentialStorePublicError.recoveryRecordFailed }
        }, syncParent: {
            guard fsync(self.parentFD) == 0 else { throw CredentialStorePublicError.recoveryRecordFailed }
        })
        sequence += 1
    }
}
