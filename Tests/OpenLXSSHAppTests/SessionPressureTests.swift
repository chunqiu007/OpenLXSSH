#if HOST_PROBE
import AppKit
import Foundation
import XCTest
import OpenLXSSHCore
import OpenLXSSHTransport

/// Parser/render input fixture only: never starts SSH or PTY, never reads Keychain.
@MainActor final class SessionPressureTests: XCTestCase {
    func testDeterministicLoadIsUTF8BoundedAndEveryViewGetsUniqueFinalMarker() throws {
        var totals: [Int] = []
        for view in 0..<ProbeOutputLoad.viewCount {
            var count = 0
            for batch in 0..<ProbeOutputLoad.batches {
                let bytes = ProbeOutputLoad.batch(view: view, index: batch)
                XCTAssertNotNil(String(data: bytes, encoding: .utf8))
                XCTAssertLessThanOrEqual(bytes.count, ProbeOutputLoad.maximumBatchBytes)
                XCTAssertEqual(bytes, ProbeOutputLoad.batch(view: view, index: batch))
                let marker = ProbeOutputLoad.marker(view: view)
                XCTAssertEqual(String(decoding: bytes, as: UTF8.self).contains(marker), batch == ProbeOutputLoad.batches - 1)
                count += bytes.count
            }
            totals.append(count)
        }
        XCTAssertEqual(Set(totals).count, 1)
        XCTAssertLessThanOrEqual(ProbeOutputLoad.historyLines, TerminalSettings.maximumHistory)
        XCTAssertLessThan(ProbeOutputLoad.maximumBatchBytes, TerminalSettings.maximumInputBytes)
    }
    func testFiveRealViewsConsumeHiddenBatchesAndDisposeWithoutBuilderRetention() async throws {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = AppRepository(location: .isolated(root))
        let host = HostConfiguration(name: "render fixture only", address: "never-connected.invalid", username: "fixture")
        try await repository.apply([.insertHost(host)])
        let builder = ProbeSessionBuilder(repository: repository)
        var sessions: [ReadySession] = []
        for _ in 0..<5 { sessions.append(try await builder.prepare(hostID: host.id, sessionID: UUID())) }
        var metrics: [ProbeTerminalMetrics] = []
        for (index, ready) in sessions.enumerated() {
            let driver = try XCTUnwrap(ready.driver as? ProbeSessionDriver)
            _ = try driver.connect(ready.configuration, savedPassword: nil)
            driver.terminal.resize(cols: 80, rows: 24); driver.terminal.setHistoryLimit(100)
            driver.terminal.setVisible(index == 0)
            try driver.feedPressure(ProbeOutputLoad.batch(view: index, index: ProbeOutputLoad.batches - 1))
            XCTAssertEqual(driver.terminalMetrics.fedBatches, 1)
            XCTAssertEqual(driver.terminalMetrics.hiddenBatches, index == 0 ? 0 : 1)
            XCTAssertTrue(driver.terminal.text.contains(ProbeOutputLoad.marker(view: index)))
            XCTAssertTrue(driver.terminal.search(ProbeOutputLoad.marker(view: index)))
            driver.terminal.pasteFromApplication("INPUT-\(index)")
            let inputDeadline = ContinuousClock.now + .seconds(2)
            while driver.terminalMetrics.input.isEmpty && ContinuousClock.now < inputDeadline { await Task.yield() }
            XCTAssertEqual(driver.terminalMetrics.input, Data("INPUT-\(index)".utf8))
            metrics.append(driver.terminalMetrics)
            driver.closeTab()
        }
        for ready in sessions {
            let driver = try XCTUnwrap(ready.driver as? ProbeSessionDriver)
            while driver.state != .closed { await Task.yield() }
            XCTAssertEqual(driver.terminalMetrics.closeCount, 1)
            XCTAssertEqual(driver.terminalMetrics.disposedCount, 1)
            XCTAssertThrowsError(try driver.feedPressure(Data([65])))
        }
        sessions.removeAll()
        for _ in 0..<5 { await Task.yield() }
        XCTAssertTrue(builder.drivers.allSatisfy { $0.value == nil })
        XCTAssertEqual(metrics.reduce(0) { $0 + $1.closeCount }, 5)
        XCTAssertEqual(metrics.reduce(0) { $0 + $1.disposedCount }, 5)
        try await repository.close()
    }
}
#endif
