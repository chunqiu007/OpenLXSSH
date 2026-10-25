import Darwin

/// Read-only Darwin ACL checks. In particular, never open/close an existing SQLite inode:
/// closing even an unrelated descriptor can release this process's POSIX SQLite locks.
/// Reject any extended ACL presence (including deny-only entries or an explicit empty ACL);
/// do not rewrite the caller's ACL.
enum DatabaseFileACL {
    static func requireNoExtendedACL(fd: Int32, matching info: stat) throws {
        try query(matching: info) { attributes, buffer in
            fgetattrlist(fd, &attributes, buffer.baseAddress, buffer.count, numericCast(FSOPT_REPORT_FULLSIZE))
        }
    }

    static func requireNoExtendedACL(at name: String, in directoryFD: Int32, matching info: stat) throws {
        try query(matching: info) { attributes, buffer in
            getattrlistat(directoryFD, name, &attributes, buffer.baseAddress, buffer.count,
                          numericCast(FSOPT_NOFOLLOW | FSOPT_REPORT_FULLSIZE))
        }
    }

    private static func query(matching info: stat, _ operation: (inout attrlist, UnsafeMutableRawBufferPointer) -> Int32) throws {
        var attributes = attrlist()
        attributes.bitmapcount = UInt16(ATTR_BIT_MAP_COUNT)
        // Do not request RETURNED_ATTRS/PACK_INVAL_ATTRS: unsupported attributes must fail,
        // not silently become absent ACLs. A successful strict query returns a zero-length
        // security attribute for no ACL on Darwin (independently probed on APFS).
        attributes.commonattr = UInt32(ATTR_CMN_DEVID | ATTR_CMN_EXTENDED_SECURITY | ATTR_CMN_FILEID)
        var buffer = [UInt8](repeating: 0, count: Int(ATTR_MAX_BUFFER))
        let result = buffer.withUnsafeMutableBytes { operation(&attributes, $0) }
        // Successful Darwin calls can leave a stale errno. Every nonzero result, including
        // ENOENT, is a failure here; it is never interpreted as an empty ACL.
        guard result == 0 else { throw RepositoryError.unsafeDatabaseLocation }
        try buffer.withUnsafeBytes { try validate($0, matching: info) }
    }

    // getattrlist packs fields at four-byte boundaries, even for 64-bit types. Use unaligned
    // loads, check the reported full size and every variable-length reference before loading.
    static func validate(_ buffer: UnsafeRawBufferPointer, matching info: stat) throws {
        let deviceOffset = MemoryLayout<UInt32>.size
        let referenceOffset = deviceOffset + MemoryLayout<dev_t>.size
        let inodeOffset = referenceOffset + MemoryLayout<attrreference_t>.size
        let fixedSize = inodeOffset + MemoryLayout<UInt64>.size
        guard buffer.count >= fixedSize else { throw RepositoryError.unsafeDatabaseLocation }
        let returnedSize = Int(buffer.loadUnaligned(as: UInt32.self))
        guard returnedSize >= fixedSize, returnedSize <= buffer.count,
              buffer.loadUnaligned(fromByteOffset: deviceOffset, as: dev_t.self) == info.st_dev,
              buffer.loadUnaligned(fromByteOffset: inodeOffset, as: UInt64.self) == info.st_ino else {
            throw RepositoryError.unsafeDatabaseLocation
        }
        let reference = buffer.loadUnaligned(fromByteOffset: referenceOffset, as: attrreference_t.self)
        let securityOffset = referenceOffset + Int(reference.attr_dataoffset)
        let securitySize = Int(reference.attr_length)
        guard securityOffset >= fixedSize, securityOffset.isMultiple(of: MemoryLayout<UInt32>.size),
              securityOffset <= returnedSize, securitySize == returnedSize - securityOffset else {
            throw RepositoryError.unsafeDatabaseLocation
        }
        // Only absence is accepted. An explicitly empty ACL is still caller-owned ACL
        // metadata and is rejected conservatively, just like allow/deny entries.
        guard securitySize == 0, returnedSize == fixedSize else { throw RepositoryError.unsafeDatabaseLocation }
    }
}
