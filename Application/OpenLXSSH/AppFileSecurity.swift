import Darwin
import Foundation
import OpenLXSSHCore

/// Conservative App-owned storage policy: any extended ACE is rejected, never
/// removed. filesec queries distinguish an absent ACL from a failed ACL read.
enum AppFileSecurity {
    /// The user container is not App-owned storage. macOS normally protects it
    /// with one non-inheriting everyone deny-delete ACE. That restriction adds
    /// no access and is safe to leave intact while creating a private child.
    /// Every other ACL shape still fails closed; App-owned paths use directory().
    static func applicationSupportParent(_ descriptor: Int32) throws {
        guard let security = filesec_init() else { throw RepositoryError.unsafeDatabaseLocation }
        defer { filesec_free(security) }
        var info = stat(), populated: Int32 = 0, hasACL: Int32 = 0
        guard fstatx_np(descriptor, &info, security) == 0,
              filesec_query_property(security, FILESEC_MODE, &populated) == 0, populated != 0,
              filesec_query_property(security, FILESEC_ACL, &hasACL) == 0,
              info.st_mode & S_IFMT == S_IFDIR, info.st_uid == geteuid(),
              info.st_mode & 0o7022 == 0 else { throw RepositoryError.unsafeDatabaseLocation }
        if hasACL == 0 { return }
        var copied: acl_t?
        guard filesec_get_property(security, FILESEC_ACL, &copied) == 0, let copied else {
            throw RepositoryError.unsafeDatabaseLocation
        }
        // FILESEC_ACL returns a separately allocated ACL (Darwin acl_get_fd_np
        // uses the same getter and frees filesec before returning that ACL).
        defer { acl_free(UnsafeMutableRawPointer(copied)) }
        guard try externalACL(copied) == protectedSystemParentACL() else { throw RepositoryError.unsafeDatabaseLocation }
    }

    private static func protectedSystemParentACL() throws -> Data {
        var reference = acl_init(1)
        guard reference != nil else { throw RepositoryError.unsafeDatabaseLocation }
        defer { if let reference { acl_free(UnsafeMutableRawPointer(reference)) } }
        var entry: acl_entry_t?, permissions: acl_permset_t?
        // Darwin's well-known everyone group UUID, independent of the user's
        // account, local group membership or localized ACL text formatting.
        guard let everyone = UUID(uuidString: "ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C"),
              acl_create_entry(&reference, &entry) == 0, let entry,
              acl_set_tag_type(entry, ACL_EXTENDED_DENY) == 0 else { throw RepositoryError.unsafeDatabaseLocation }
        var qualifier = everyone.uuid
        guard withUnsafePointer(to: &qualifier, { acl_set_qualifier(entry, $0) }) == 0,
              acl_get_permset(entry, &permissions) == 0, let permissions,
              acl_clear_perms(permissions) == 0, acl_add_perm(permissions, ACL_DELETE) == 0,
              acl_set_permset(entry, permissions) == 0, let reference else { throw RepositoryError.unsafeDatabaseLocation }
        return try externalACL(reference)
    }

    private static func externalACL(_ acl: acl_t) throws -> Data {
        let size = acl_size(acl)
        guard size > 0, size <= 16 * 1024 else { throw RepositoryError.unsafeDatabaseLocation }
        var bytes = Data(count: size)
        guard bytes.withUnsafeMutableBytes({ acl_copy_ext($0.baseAddress, acl, size) }) == size else {
            throw RepositoryError.unsafeDatabaseLocation
        }
        // Compare the complete public representation, without interpreting a
        // private struct or dropping unknown ACL/entry flags or permission bits.
        return bytes
    }

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
