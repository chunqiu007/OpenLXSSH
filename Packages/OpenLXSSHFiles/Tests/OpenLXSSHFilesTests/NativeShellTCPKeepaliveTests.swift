import COpenLXSSHFiles
import Darwin
import Foundation
import XCTest
@testable import OpenLXSSHFiles

/// Real kernel socket options only: no endpoint, SSH handshake, authentication or fixture access.
final class NativeShellTCPKeepaliveTests: XCTestCase {
    private func value(_ fd: Int32, level: Int32, option: Int32) throws -> Int32 {
        var result: Int32 = -1, length = socklen_t(MemoryLayout<Int32>.size)
        XCTAssertEqual(getsockopt(fd, level, option, &result, &length), 0)
        XCTAssertEqual(length, socklen_t(MemoryLayout<Int32>.size))
        return result
    }
    func testKernelTCPKeepaliveReadbackMatchesExactHostBoundsAndDisabledChoice() throws {
        for family in [AF_INET, AF_INET6] {
            let fd = socket(family, SOCK_STREAM, IPPROTO_TCP)
            XCTAssertGreaterThanOrEqual(fd, 0); defer { if fd >= 0 { XCTAssertEqual(Darwin.close(fd), 0) } }
            XCTAssertEqual(try value(fd, level: SOL_SOCKET, option: SO_KEEPALIVE), 0)
            let cases: [(Int32, Int32)] = [(1, 1), (30, 3), (3600, 10)]
            for (interval, count) in cases {
                var actual = rf_tcp_keepalive(), systemError: Int32 = 123
                XCTAssertEqual(rf_tcp_keepalive_configure(fd, interval, count, &actual, &systemError), 0)
                XCTAssertEqual(systemError, 0); XCTAssertEqual(actual.enabled, 1)
                XCTAssertEqual(actual.idle_seconds, interval); XCTAssertEqual(actual.retry_seconds, interval)
                XCTAssertEqual(actual.failed_probes, count)
                XCTAssertNotEqual(try value(fd, level: SOL_SOCKET, option: SO_KEEPALIVE), 0)
                XCTAssertEqual(try value(fd, level: IPPROTO_TCP, option: TCP_KEEPALIVE), interval)
                XCTAssertEqual(try value(fd, level: IPPROTO_TCP, option: TCP_KEEPINTVL), interval)
                XCTAssertEqual(try value(fd, level: IPPROTO_TCP, option: TCP_KEEPCNT), count)
                let receipt = NativeTCPKeepaliveSnapshot(actual)
                XCTAssertTrue(receipt.enabled); XCTAssertEqual(receipt.idleSeconds, Int(interval))
                XCTAssertEqual(receipt.retrySeconds, Int(interval)); XCTAssertEqual(receipt.failedProbes, Int(count))
            }
            var disabled = rf_tcp_keepalive(), systemError: Int32 = 123
            XCTAssertEqual(rf_tcp_keepalive_configure(fd, 0, 10, &disabled, &systemError), 0)
            XCTAssertEqual(systemError, 0); XCTAssertEqual(disabled.enabled, 0)
            XCTAssertEqual(disabled.idle_seconds, 0); XCTAssertEqual(disabled.retry_seconds, 0)
            XCTAssertEqual(disabled.failed_probes, 0)
            XCTAssertEqual(try value(fd, level: SOL_SOCKET, option: SO_KEEPALIVE), 0)
        }
    }
    func testInvalidPolicyAndUnsupportedSocketDoNotCreateSilentFallback() throws {
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { if fd >= 0 { XCTAssertEqual(Darwin.close(fd), 0) } }
        let cases: [(Int32, Int32)] = [(-1, 3), (3601, 3), (30, 0), (30, 11)]
        for (interval, count) in cases {
            var actual = rf_tcp_keepalive(), systemError: Int32 = 123
            XCTAssertEqual(rf_tcp_keepalive_configure(fd, interval, count, &actual, &systemError), Int32(RF_INVALID))
            XCTAssertEqual(systemError, 0); XCTAssertEqual(actual.enabled, 0)
            XCTAssertEqual(try value(fd, level: SOL_SOCKET, option: SO_KEEPALIVE), 0)
        }
        let udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        XCTAssertGreaterThanOrEqual(udp, 0); defer { if udp >= 0 { XCTAssertEqual(Darwin.close(udp), 0) } }
        var actual = rf_tcp_keepalive(), systemError: Int32 = 123
        XCTAssertEqual(rf_tcp_keepalive_configure(udp, 30, 3, &actual, &systemError), Int32(RF_SOCKET_OPTION))
        XCTAssertEqual(systemError, EPROTOTYPE); XCTAssertEqual(actual.enabled, 0)
        XCTAssertEqual(rf_tcp_keepalive_configure(-1, 30, 3, &actual, &systemError), Int32(RF_INVALID))
        XCTAssertEqual(systemError, 0)
    }
}
