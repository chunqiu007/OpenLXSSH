import Darwin
import OpenLXSSHTrust

/// Metadata-only checks on the opened object, never on secret contents. Reject
/// every extended ACL, including deny/read-only/empty ACLs, rather than trying
/// to reproduce the kernel's ACE ordering and inheritance policy.
enum TransportFileSecurity {
    static func metadataWithoutACL(_ descriptor: Int32) throws -> stat {
        guard let security = filesec_init() else { throw TransportError.invalidConfiguration }
        defer { filesec_free(security) }
        var metadata = stat()
        guard fstatx_np(descriptor, &metadata, security) == 0 else { throw TransportError.invalidConfiguration }
        try requireNoACL(in: security)
        return metadata
    }

    static func requireNoACL(in security: filesec_t,
        query: (filesec_t, filesec_property_t, UnsafeMutablePointer<Int32>) -> Int32 = { filesec_query_property($0, $1, $2) }) throws {
        // acl_get_fd_np returns NULL/ENOENT for no ACL on Darwin, as well as
        // NULL for errors. filesec_query_property distinguishes successful
        // absence from failure without interpreting errno after a success.
        // Require MODE to be populated too: a fresh/unpopulated filesec would
        // otherwise report ACL absent, including statx's allocation edge case.
        var modePresent: Int32 = 0, aclPresent: Int32 = 0
        guard query(security, FILESEC_MODE, &modePresent) == 0, modePresent != 0,
              query(security, FILESEC_ACL, &aclPresent) == 0, aclPresent == 0 else { throw TransportError.invalidConfiguration }
    }

    @discardableResult
    static func directory(_ descriptor: Int32) throws -> stat {
        let metadata = try metadataWithoutACL(descriptor)
        guard metadata.st_mode & S_IFMT == S_IFDIR, metadata.st_uid == getuid(),
              metadata.st_mode & 0o7777 == 0o700 else { throw TransportError.invalidConfiguration }
        return metadata
    }

    @discardableResult
    static func regularFile(_ descriptor: Int32) throws -> stat {
        let metadata = try metadataWithoutACL(descriptor)
        guard metadata.st_mode & S_IFMT == S_IFREG, metadata.st_uid == getuid(),
              metadata.st_mode & 0o7777 == 0o600, metadata.st_nlink == 1 else { throw TransportError.invalidConfiguration }
        return metadata
    }

    static func validateAuthentication(_ authentication: SSHAuthentication) throws {
        guard case .privateKey(let path, _) = authentication.method else { return }
        // O_EVTONLY obtains metadata without opening a key for content reads;
        // NONBLOCK prevents a malicious FIFO from blocking before type checks.
        // O_NOFOLLOW and descriptor validation reject symlink/special objects.
        let descriptor = open(path.value, O_EVTONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw TransportError.invalidConfiguration }
        defer { Darwin.close(descriptor) }
        try regularFile(descriptor)
    }

    static func sameObject(_ first: stat, _ second: stat) -> Bool {
        first.st_dev == second.st_dev && first.st_ino == second.st_ino
    }
}
