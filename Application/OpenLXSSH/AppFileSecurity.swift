import Darwin
import Foundation
import OpenLXSSHCore

/// Conservative App-owned storage policy: any extended ACE is rejected, never
/// removed. filesec queries distinguish an absent ACL from a failed ACL read.
enum AppFileSecurity {
    static func requireNoACL(_ descriptor: Int32) throws {
        guard let security = filesec_init() else { throw RepositoryError.unsafeDatabaseLocation }
        defer { filesec_free(security) }
        var info = stat()
        guard fstatx_np(descriptor, &info, security) == 0 else { throw RepositoryError.unsafeDatabaseLocation }
        // Darwin can return success after an internal allocation failure without
        // populating filesec. Require a normal stat property before trusting ACL absence.
        var populated: Int32 = 0, hasACL: Int32 = 0
        guard filesec_query_property(security, FILESEC_MODE, &populated) == 0, populated != 0,
              filesec_query_property(security, FILESEC_ACL, &hasACL) == 0, hasACL == 0 else {
            throw RepositoryError.unsafeDatabaseLocation
        }
    }
    static func directory(_ descriptor: Int32, mode: mode_t? = 0o700) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == geteuid(),
              mode == nil || info.st_mode & 0o7777 == mode else { throw RepositoryError.unsafeDatabaseLocation }
        try requireNoACL(descriptor)
    }
    static func regularFile(_ descriptor: Int32) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(),
              info.st_mode & 0o7777 == 0o600, info.st_nlink == 1 else { throw RepositoryError.unsafeDatabaseLocation }
        try requireNoACL(descriptor)
    }
}
