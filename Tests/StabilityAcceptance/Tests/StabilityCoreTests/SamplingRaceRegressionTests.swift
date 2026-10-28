import Darwin
import Foundation
import XCTest
import StabilityPOSIX
@testable import StabilityCore

private final class SamplingKernel {
    struct List {
        var fds: [proc_fdinfo]
        var required: Int32?
        var bytes: Int32?
        var error: Int32?
        init(_ fds: [proc_fdinfo], required: Int32? = nil, bytes: Int32? = nil, error: Int32? = nil) {
            self.fds = fds; self.required = required; self.bytes = bytes; self.error = error
        }
    }
    enum Vnode {
        case path(String, Int32? = nil)
        case failed(Int32 = 0, Int32? = EBADF)
    }
    static func fd(_ number: Int32, vnode: Bool = true) -> proc_fdinfo {
        var value = proc_fdinfo(); value.proc_fd = number
        value.proc_fdtype = vnode ? UInt32(PROX_FDTYPE_VNODE) : UInt32(PROX_FDTYPE_PIPE)
        return value
    }
    var lists = [List([fd(4), fd(6, vnode: false)]), List([fd(6, vnode: false), fd(7)])]
    var vnodes: [Vnode] = [.failed(), .path("/dev/ttys004")]
    var listReads = 0, vnodeReads = 0, identityReads = 0
    var identityError: Int32?, identityBytes: Int32?, changedFrom: Int?
    var identityMutation = 0 // birth, effective UID, or parent; each must remain stable.
    var taskBytes: Int32?
    var metricReturn: Int32 = -1, metricParent: Int32 = 73000, metricComplete: Int32 = 1
    var vnodeIncomingErrno: [Int32] = []
    var context: UnsafeMutableRawPointer { Unmanaged.passUnretained(self).toOpaque() }
    func sample() -> (Int32, stability_process) {
        var value = stability_process()
        let result = stability_process_read_using(73001, &value, samplingIdentity, samplingProcess, samplingVnode, context)
        return (result, value)
    }
}
private func kernel(_ context: UnsafeMutableRawPointer?) -> SamplingKernel {
    Unmanaged<SamplingKernel>.fromOpaque(context!).takeUnretainedValue()
}
private func samplingIdentity(_ pid: pid_t, _ out: UnsafeMutablePointer<proc_bsdinfo>?, _ context: UnsafeMutableRawPointer?) -> Int32 {
    let k = kernel(context); k.identityReads += 1
    if let error = k.identityError { errno = error; return k.identityBytes ?? 0 }
    var value = proc_bsdinfo(); value.pbi_pid = UInt32(pid); value.pbi_ppid = 73000
    value.pbi_uid = getuid(); value.pbi_ruid = getuid(); value.pbi_start_tvsec = 100; value.pbi_start_tvusec = 3
    if let first = k.changedFrom, k.identityReads >= first {
        switch k.identityMutation {
        case 1: value.pbi_uid += 1
        case 2: value.pbi_ppid += 1
        default: value.pbi_start_tvsec = 101
        }
    }
    out?.pointee = value
    return k.identityBytes ?? Int32(MemoryLayout<proc_bsdinfo>.size)
}
private func samplingProcess(_ pid: pid_t, _ flavor: Int32, _ arg: UInt64, _ out: UnsafeMutableRawPointer?, _ size: Int32, _ context: UnsafeMutableRawPointer?) -> Int32 {
    let k = kernel(context)
    if flavor == PROC_PIDTASKINFO {
        var value = proc_taskinfo(); value.pti_resident_size = 4096; value.pti_threadnum = 1
        if let out { withUnsafeBytes(of: &value) { out.copyMemory(from: $0.baseAddress!, byteCount: $0.count) } }
        return k.taskBytes ?? Int32(MemoryLayout<proc_taskinfo>.size)
    }
    guard flavor == PROC_PIDLISTFDS, k.listReads < k.lists.count else { errno = EIO; return 0 }
    let list = k.lists[k.listReads]
    if out == nil { return list.required ?? Int32((list.fds.count + 8) * MemoryLayout<proc_fdinfo>.size) }
    k.listReads += 1
    if let error = list.error { errno = error; return list.bytes ?? 0 }
    if let out, !list.fds.isEmpty {
        list.fds.withUnsafeBytes { out.copyMemory(from: $0.baseAddress!, byteCount: min($0.count, Int(size))) }
    }
    return list.bytes ?? Int32(list.fds.count * MemoryLayout<proc_fdinfo>.size)
}
private func samplingVnode(_ pid: pid_t, _ fd: Int32, _ out: UnsafeMutablePointer<vnode_fdinfowithpath>?, _ context: UnsafeMutableRawPointer?) -> Int32 {
    let k = kernel(context); k.vnodeIncomingErrno.append(errno)
    guard k.vnodeReads < k.vnodes.count else { errno = EIO; return 0 }
    let reply = k.vnodes[k.vnodeReads]; k.vnodeReads += 1
    switch reply {
    case .failed(let bytes, let error): if let error { errno = error }; return bytes
    case .path(let text, let error):
        if let out {
            withUnsafeMutableBytes(of: &out.pointee.pvip.vip_path) { raw in
                let bytes = Array(text.utf8) + [0]
                bytes.withUnsafeBytes { raw.copyMemory(from: $0) }
            }
        }
        if let error { errno = error }
        return Int32(MemoryLayout<vnode_fdinfowithpath>.size)
    }
}
private func samplingMetric(_ pid: pid_t, _ out: UnsafeMutablePointer<stability_process>?, _ context: UnsafeMutableRawPointer?) -> Int32 {
    let k = kernel(context)
    var value = stability_process(); value.pid = pid; value.ppid = k.metricParent; value.uid = getuid()
    value.start_seconds = 100; value.start_microseconds = 3; value.metrics_complete = k.metricComplete
    out?.pointee = value
    return k.metricReturn
}

final class SamplingRaceRegressionTests: XCTestCase {
    private func requireIncomplete(_ k: SamplingKernel, file: StaticString = #filePath, line: UInt = #line) {
        let (result, value) = k.sample()
        XCTAssertTrue(result != 0 || value.metrics_complete == 0, file: file, line: line)
        if result == 0 { XCTAssertEqual(value.pty_fd_count, -1, file: file, line: line) }
    }
    func testConfirmedClosedDescriptorResamplesEntireFreshListOnce() {
        let k = SamplingKernel(); let (result, value) = k.sample()
        XCTAssertEqual(result, 0); XCTAssertEqual(value.metrics_complete, 1)
        XCTAssertEqual(value.fd_list_resamples, 1); XCTAssertEqual(k.listReads, 2)
        XCTAssertEqual(value.fd_count, 2); XCTAssertEqual(value.pty_fd_count, 1)
        XCTAssertEqual(k.vnodeReads, 2, "Fresh vnode must really be read, not assumed to have zero PTYs")
        XCTAssertEqual(k.identityReads, 8, "Initial, before/after fresh list and final identities each have two complete reads")
    }
    func testUnknownErrorsShortReadsAndNegativeEBADFDoNotResample() {
        for reply in [SamplingKernel.Vnode.failed(0, EACCES), .failed(0, EPERM), .failed(0, ENOENT), .failed(0, EIO), .failed(0, nil), .failed(-1, EBADF), .failed(Int32(MemoryLayout<vnode_fdinfowithpath>.size - 1), EBADF)] {
            let k = SamplingKernel(); k.vnodes = [reply]
            requireIncomplete(k); XCTAssertEqual(k.listReads, 1)
        }
    }
    func testPriorErrnoCannotConvertAnUnspecifiedFailureIntoEBADF() {
        let k = SamplingKernel(); k.lists = [.init([SamplingKernel.fd(4), SamplingKernel.fd(5)])]
        k.vnodes = [.path("/dev/null", EBADF), .failed(0, nil)]
        errno = EBADF; requireIncomplete(k)
        XCTAssertEqual(k.vnodeIncomingErrno, [0, 0]); XCTAssertEqual(k.listReads, 1)
    }
    func testEBADFWithDescriptorStillPresentRemainsUnknown() {
        let k = SamplingKernel(); k.lists[1] = k.lists[0]
        requireIncomplete(k); XCTAssertEqual(k.vnodeReads, 1)
    }
    func testFreshListDuplicateShortZeroOversizedAndPermissionFailureRefuse() {
        let fd = SamplingKernel.fd(6, vnode: false)
        for fresh in [SamplingKernel.List([fd, fd]), .init([fd], bytes: 1), .init([fd], bytes: 0), .init([fd], required: 32769), .init([fd], bytes: 32768), .init([fd], error: EACCES), .init([fd], error: EPERM)] {
            let k = SamplingKernel(); k.lists[1] = fresh
            requireIncomplete(k); XCTAssertEqual(k.vnodeReads, 1)
        }
    }
    func testIdentityChangesBeforeAfterFreshListOrAtFinalSnapshotRefuse() {
        for mutation in 0...2 {
            for at in [3, 5, 7] {
                let k = SamplingKernel(); k.changedFrom = at; k.identityMutation = mutation
                requireIncomplete(k)
            }
        }
        for error in [EACCES, EPERM, ESRCH] {
            let k = SamplingKernel(); k.identityError = error
            let (status, _) = k.sample(); XCTAssertNotEqual(status, 0)
        }
    }
    func testSecondDisappearingDescriptorDoesNotAllowRepeatedRetries() {
        let k = SamplingKernel(); k.vnodes = [.failed(), .failed()]
        requireIncomplete(k); XCTAssertEqual(k.listReads, 2); XCTAssertEqual(k.vnodeReads, 2)
    }
    func testFreshUnknownFailureAndTaskShortReadCannotBeRepairedToComplete() {
        let k = SamplingKernel(); k.vnodes = [.failed(), .failed(0, EACCES)]; requireIncomplete(k)
        let task = SamplingKernel(); task.taskBytes = 1
        let (status, value) = task.sample(); XCTAssertEqual(status, 0); XCTAssertEqual(value.metrics_complete, 0)
        XCTAssertEqual(value.fd_list_resamples, 1)
    }
    func testOrdinarySuccessfulVnodeDoesNotConsumeLeftoverErrno() {
        let k = SamplingKernel(); k.vnodes = [.path("/dev/null", EBADF)]
        let (status, value) = k.sample(); XCTAssertEqual(status, 0); XCTAssertEqual(value.metrics_complete, 1)
        XCTAssertEqual(value.pty_fd_count, 0); XCTAssertEqual(value.fd_list_resamples, 0)
    }
    func testOptionalSampleFieldKeepsLegacySchemaRowsDecodable() throws {
        let raw = Data("{\"role\":\"helper\",\"identity\":{\"pid\":1,\"parentPID\":2,\"uid\":501,\"startSeconds\":3,\"startMicroseconds\":4},\"rssBytes\":4096,\"fdDescriptors\":2,\"ptyVnodeDescriptors\":0,\"kernelThreads\":1,\"complete\":true}".utf8)
        let old = try JSONDecoder().decode(ProcessSample.self, from: raw)
        XCTAssertNil(old.fdListResamples)
        let extra = Data(String(decoding: raw, as: UTF8.self).dropLast().appending(",\"fdListResamples\":1}").utf8)
        XCTAssertEqual(try JSONDecoder().decode(ProcessSample.self, from: extra).fdListResamples, 1)
        let row = EvidenceRow(event: .sample, confirmedGoneHelpers: 1)
        XCTAssertEqual(try JSONSerialization.jsonObject(with: JSONEncoder().encode(row)) as? [String: Any] != nil, true)
    }
}

final class HelperDisappearanceRegressionTests: XCTestCase {
    private func helper(_ k: SamplingKernel) -> (Int32, stability_process) {
        var value = stability_process()
        return (stability_helper_read_using(73001, 73000, &value, samplingMetric, samplingIdentity, k.context), value)
    }
    func testOnlyIndependentStrictGoneMaySkipFailedHelperMetricRead() {
        let gone = SamplingKernel(); gone.identityError = ESRCH
        XCTAssertEqual(helper(gone).0, Int32(STABILITY_IDENTITY_GONE)); XCTAssertEqual(gone.identityReads, 1)
        for error in [EACCES, EPERM, 0] {
            let k = SamplingKernel(); k.identityError = error
            XCTAssertEqual(helper(k).0, Int32(STABILITY_IDENTITY_UNKNOWN))
        }
    }
    func testStillPresentAndPartialIdentityDoNotHidePriorMetricFailure() {
        let present = SamplingKernel(); XCTAssertEqual(helper(present).0, Int32(STABILITY_IDENTITY_UNKNOWN))
        let partial = SamplingKernel(); partial.identityBytes = 1
        XCTAssertEqual(helper(partial).0, Int32(STABILITY_IDENTITY_UNKNOWN))
    }
    func testPresentWrongParentRefusesAndIncompleteMetricsStillSurface() {
        let wrong = SamplingKernel(); wrong.metricReturn = 0; wrong.metricParent = 1
        XCTAssertEqual(helper(wrong).0, Int32(STABILITY_IDENTITY_UNKNOWN))
        let unknown = SamplingKernel(); unknown.metricReturn = 0; unknown.metricComplete = 0
        let (status, value) = helper(unknown)
        XCTAssertEqual(status, Int32(STABILITY_IDENTITY_PRESENT)); XCTAssertEqual(value.metrics_complete, 0)
    }
}
