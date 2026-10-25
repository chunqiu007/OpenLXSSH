import Darwin
import XCTest
@testable import OpenLXSSHCore

final class DatabaseACLBufferTests: XCTestCase {
    private var identity: stat {
        var info = stat()
        info.st_dev = 123
        info.st_ino = 456
        return info
    }
    private let referenceOffset = MemoryLayout<UInt32>.size + MemoryLayout<dev_t>.size
    private var inodeOffset: Int { referenceOffset + MemoryLayout<attrreference_t>.size }
    private var fixedSize: Int { inodeOffset + MemoryLayout<UInt64>.size }
    private var aclOffset: Int { MemoryLayout<kauth_filesec>.offset(of: \kauth_filesec.fsec_acl)! }
    private var countOffset: Int { aclOffset + MemoryLayout<kauth_acl>.offset(of: \kauth_acl.acl_entrycount)! }
    private var headerSize: Int { aclOffset + MemoryLayout<kauth_acl>.offset(of: \kauth_acl.acl_ace)! }

    func testOnlyAbsentExtendedACLIsAccepted() throws {
        XCTAssertNoThrow(try makeBuffer().withUnsafeBytes { try DatabaseFileACL.validate($0, matching: identity) })
        assertUnsafe(makeBuffer(securitySize: headerSize))
        assertUnsafe(makeBuffer(securitySize: headerSize, count: UInt32.max))
    }

    func testAnyACEAndInconsistentACECountAreRejected() {
        for buffer in [
            makeBuffer(securitySize: headerSize + MemoryLayout<kauth_ace>.size, count: 1),
            makeBuffer(securitySize: headerSize, count: 1),
            makeBuffer(securitySize: headerSize, count: UInt32.max - 1),
            makeBuffer(securitySize: headerSize + MemoryLayout<kauth_ace>.size)
        ] { assertUnsafe(buffer) }
    }

    func testTruncatedUnpopulatedOrMalformedAttributeBuffersAreRejected() {
        let valid = makeBuffer(securitySize: headerSize)
        for size in 0..<valid.count { assertUnsafe(Array(valid.prefix(size))) }
        assertUnsafe([UInt8](repeating: 0, count: Int(ATTR_MAX_BUFFER)))
        var buffer = valid
        store(UInt32(valid.count + 1), in: &buffer, at: 0)
        assertUnsafe(buffer)
        buffer = valid
        store(UInt32(0), in: &buffer, at: fixedSize)
        assertUnsafe(buffer)
        for offset: Int32 in [Int32.min, -1, 0, 1, Int32.max] {
            buffer = valid
            store(offset, in: &buffer, at: referenceOffset)
            assertUnsafe(buffer)
        }
        buffer = valid
        store(UInt32.max, in: &buffer, at: referenceOffset + MemoryLayout<Int32>.size)
        assertUnsafe(buffer)
        buffer = makeBuffer()
        store(Int32(0), in: &buffer, at: referenceOffset)
        assertUnsafe(buffer)
    }

    func testReturnedDeviceAndInodeMustMatchTheStatIdentity() {
        var buffer = makeBuffer()
        store(dev_t(124), in: &buffer, at: MemoryLayout<UInt32>.size)
        assertUnsafe(buffer)
        buffer = makeBuffer()
        store(UInt64(457), in: &buffer, at: inodeOffset)
        assertUnsafe(buffer)
    }

    private func makeBuffer(securitySize: Int = 0, count: UInt32 = 0) -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: fixedSize + securitySize)
        store(UInt32(buffer.count), in: &buffer, at: 0)
        store(identity.st_dev, in: &buffer, at: MemoryLayout<UInt32>.size)
        store(attrreference_t(attr_dataoffset: Int32(fixedSize - referenceOffset), attr_length: UInt32(securitySize)), in: &buffer, at: referenceOffset)
        store(UInt64(identity.st_ino), in: &buffer, at: inodeOffset)
        if securitySize >= headerSize {
            store(UInt32(KAUTH_FILESEC_MAGIC), in: &buffer, at: fixedSize)
            store(count, in: &buffer, at: fixedSize + countOffset)
        }
        return buffer
    }

    private func store<T>(_ value: T, in buffer: inout [UInt8], at offset: Int) {
        buffer.withUnsafeMutableBytes { $0.storeBytes(of: value, toByteOffset: offset, as: T.self) }
    }

    private func assertUnsafe(_ buffer: [UInt8], file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try buffer.withUnsafeBytes { try DatabaseFileACL.validate($0, matching: identity) }, file: file, line: line) {
            XCTAssertEqual($0 as? RepositoryError, .unsafeDatabaseLocation, file: file, line: line)
        }
    }
}
