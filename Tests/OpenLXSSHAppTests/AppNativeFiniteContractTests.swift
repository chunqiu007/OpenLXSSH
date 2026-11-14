import Darwin
import Foundation
import XCTest
#if HOST_PROBE
import OpenLXSSHFiles
#endif

/// Pure syntax/state tests: no files, AppKit, fixture, credential, process or network I/O.
final class AppNativeFiniteContractTests: XCTestCase {
    private let id = "12345678-1234-1234-1234-123456789abc"
    private var path: String { AppNativeFiniteContract.inputRoot + "/run-" + id + "/native-app-fixture.json" }
    private var material: String { AppRealIntegrationContract.inputRoot + "/run-" + id + "/app-real-integration.json" }
    private func json() -> String {
        "{\"schema\":1,\"runID\":\"" + id + "\",\"scenario\":\"keyonly-controller-shell\",\"materialContractPath\":\"" + material + "\"}"
    }
    private func decode(_ value: String) throws -> AppNativeFiniteContract { try AppNativeFiniteContract.decodeStrict(Data(value.utf8)) }
    private var live: [String] { ["--native-app-fixture-test", "--native-app-fixture-contract", path, "--authorized-local-fixture", "--primary-released"] }

    func testOrdinaryAndOldArgumentsAreNotAdoptedByNewEntry() throws {
        for arguments in [[], ["--real-fixture-help"], ["--self-test-data-dir", "/not/opened"]] {
            XCTAssertEqual(try AppNativeFiniteArguments.parse(arguments, hostProbe: false).action, .none)
        }
    }
    func testShippingRejectsEveryNewEntryBeforeAnyRuntime() {
        for arguments in [live, ["--native-app-fixture-help"], ["--native-app-fixture-validate", "--native-app-fixture-contract", path], ["--native-app-fixture-unknown"]] {
            XCTAssertThrowsError(try AppNativeFiniteArguments.parse(arguments, hostProbe: false))
        }
    }
    func testHelpAndValidateOnlyParseSyntax() throws {
        XCTAssertEqual(try AppNativeFiniteArguments.parse(["--native-app-fixture-help"], hostProbe: true).action, .help)
        let parsed = try AppNativeFiniteArguments.parse(["--native-app-fixture-validate", "--native-app-fixture-contract", path], hostProbe: true)
        XCTAssertEqual(parsed.action, .validate); XCTAssertEqual(parsed.contractPath, path)
        XCTAssertThrowsError(try AppNativeFiniteArguments.parse(["--native-app-fixture-help", "extra"], hostProbe: true))
        XCTAssertThrowsError(try AppNativeFiniteArguments.parse(["--native-app-fixture-validate", "--native-app-fixture-contract", path, "--authorized-local-fixture"], hostProbe: true))
    }
    func testLiveRequiresBothSingleReleaseGatesAndRejectsMixedOrExtraFlags() throws {
        XCTAssertEqual(try AppNativeFiniteArguments.parse(live, hostProbe: true).action, .live)
        var invalidArguments: [[String]] = []
        invalidArguments.append(Array(live.dropLast()))
        invalidArguments.append(Array(live.dropLast(2)))
        invalidArguments.append(live + ["--primary-released"])
        invalidArguments.append(live + ["--authorized-local-fixture"])
        invalidArguments.append(live + ["--native-app-fixture-contract", path])
        invalidArguments.append(live + ["--real-fixture-test"])
        invalidArguments.append(live + ["--self-test-phase", "sessions"])
        invalidArguments.append(live + ["--real-fixture-scan-seconds", "15"])
        invalidArguments.append(live + ["extra"])
        invalidArguments.append(["--native-app-fixture-test", "--native-app-fixture-contract"])
        for invalid in invalidArguments {
            XCTAssertThrowsError(try AppNativeFiniteArguments.parse(invalid, hostProbe: true))
        }
    }
    func testContractPathsRequireExactCanonicalUUIDAndFixedRoots() throws {
        XCTAssertEqual(try AppNativeFiniteContract.runID(at: path), id)
        for invalid in [path.replacingOccurrences(of: id, with: id.uppercased()), path.replacingOccurrences(of: id, with: "latest"),
                        path.replacingOccurrences(of: "/run-", with: "/../run-"), path + "/extra", path.replacingOccurrences(of: "/Inputs/", with: "/Inputs//"),
                        "/tmp/run-" + id + "/native-app-fixture.json", path + "\n"] {
            XCTAssertThrowsError(try AppNativeFiniteContract.runID(at: invalid))
        }
    }
    func testFourFieldWrapperKeepsOriginalMaterialContractAndRunID() throws {
        let value = try decode(json()); try value.validate(path: path)
        XCTAssertEqual(value.materialContractPath, material)
        let other = material.replacingOccurrences(of: id, with: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        XCTAssertThrowsError(try decode(json().replacingOccurrences(of: material, with: other)).validate(path: path))
        XCTAssertThrowsError(try decode(json().replacingOccurrences(of: "keyonly-controller-shell", with: "password-transient")).validate(path: path))
    }
    func testClosedJSONRejectsDuplicateUnknownExtraAndTrailingFields() {
        let prefix = String(json().dropLast())
        for value in [prefix + ",\"schema\":1}", prefix + ",\"backend\":\"native\"}", json() + "{}", json() + "garbage",
                      json().replacingOccurrences(of: "\"runID\"", with: "\"unknown\""), "{}"] {
            XCTAssertThrowsError(try decode(value))
        }
    }
    func testClosedJSONRejectsCoercedNumbersBooleanOversizeAndNonASCIISpellings() throws {
        for replacement in ["true", "10", "1.0", "1e0", "null", "\"1\""] {
            XCTAssertThrowsError(try decode(json().replacingOccurrences(of: "\"schema\":1", with: "\"schema\":" + replacement)))
        }
        for replacement in ["clé", "line\ncontrol", "escaped\\\"quote", "unicode\\u0061", "escaped\\\\backslash"] {
            XCTAssertThrowsError(try decode(json().replacingOccurrences(of: "keyonly-controller-shell", with: replacement)))
        }
        XCTAssertThrowsError(try decode(String(repeating: " ", count: AppNativeFiniteContract.maximumBytes + 1)))
        XCTAssertEqual(try decode(json().replacingOccurrences(of: "/", with: "\\/")).materialContractPath, material)
    }
    func testOriginalReadOnlyPhaseAndFixedPinGateAreNotWidened() throws {
        let original = AppRealIntegrationContract(schema: 1, phase: nil, runID: id, host: "127.0.0.1", port: 22221, user: "fixture", service: "keyonly",
            generation: AppRealIntegrationContract.fixtureRoot + "/.runtime/keyonly/credentials-012345abcdef", expectedBase: AppNativeFiniteIdentity.base,
            expectedImage: AppNativeFiniteIdentity.image, expectedProject: AppNativeFiniteIdentity.project, expectedContainer: AppNativeFiniteIdentity.container,
            expectedFingerprint: AppNativeFiniteIdentity.fingerprint, collectedAt: 1000, preparedAt: 1010,
            provenanceSHA256: String(repeating: "a", count: 64), knownHostsSHA256: String(repeating: "b", count: 64), generationPublicKeySHA256: String(repeating: "c", count: 64))
        let wrapper = try decode(json()); try wrapper.requireMaterial(original)
        try AppNativeFiniteIdentity.validate(original, path: material, now: 1100, buildEpoch: 900)
        // New binding is not a silent update of the old case or an assertion its validator passed.
        XCTAssertThrowsError(try original.validate(path: material, now: 1100, buildEpoch: 900))
        XCTAssertThrowsError(try AppNativeFiniteIdentity.validate(original, path: material, now: 1121, buildEpoch: 900))
        XCTAssertThrowsError(try AppNativeFiniteIdentity.validate(original, path: material, now: 1100, buildEpoch: 1001))
        let encoded = try JSONEncoder().encode(original)
        let unchanged = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        let invalid: [(String, Any)] = [("expectedContainer", AppRealIntegrationContract.container), ("expectedFingerprint", AppRealIntegrationContract.fingerprint),
            ("expectedContainer", String(repeating: "a", count: 64)), ("expectedFingerprint", "SHA256:unapproved"), ("phase", "terminal-search-paste"),
            ("port", 22222), ("host", "localhost"), ("user", "other"), ("service", "passwordonly"),
            ("generation", AppRealIntegrationContract.fixtureRoot + "/.runtime/keyonly/credentials-../escape"),
            ("runID", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), ("preparedAt", 999.0), ("collectedAt", 1200.0)]
        for (name, replacement) in invalid {
            var fields = unchanged; fields[name] = replacement
            let candidate = try AppRealIntegrationContract.decodeStrict(JSONSerialization.data(withJSONObject: fields))
            XCTAssertThrowsError(try AppNativeFiniteIdentity.validate(candidate, path: material, now: 1100, buildEpoch: 900), name)
        }
    }
    func testSingleMonotonicBudgetsNeverExtendFullOrCleanupDeadline() {
        let start = ContinuousClock.now, budget = AppNativeFiniteBudget(started: .now)
        XCTAssertEqual(budget.preparationDeadline, budget.started + .seconds(30))
        XCTAssertEqual(budget.activeDeadline(start: budget.started + .seconds(60)), budget.fullDeadline - .seconds(12))
        XCTAssertEqual(budget.cleanupDeadline(start: budget.started + .seconds(85)), budget.fullDeadline)
        XCTAssertGreaterThanOrEqual(budget.elapsed(at: start + .seconds(1)), 0)
    }
    func testTerminalEvidenceNeedsExactRemoteLinesNotEchoOrResizeAdmission() throws {
        let plan = try AppNativeFiniteTerminalPlan(nonce: String(repeating: "a", count: 32))
        XCTAssertFalse(try plan.inspect(plan.command).complete)
        let lines = "APP_ACK_" + plan.nonce + "\r\nAPP_PTY_" + plan.nonce + "\r\nAPP_SIZE_" + plan.nonce + " 37 113\r\nAPP_DONE_" + plan.nonce + "\r\n"
        let expected = try plan.inspect(lines)
        XCTAssertTrue(expected.complete)
        XCTAssertEqual(expected.observedRows, 37); XCTAssertEqual(expected.observedColumns, 113)
        let wrongSize = try plan.inspect(lines.replacingOccurrences(of: "37 113", with: "24 80"))
        XCTAssertFalse(wrongSize.complete)
        XCTAssertTrue(wrongSize.ack && wrongSize.pty && wrongSize.completed)
        XCTAssertEqual(wrongSize.observedRows, 24); XCTAssertEqual(wrongSize.observedColumns, 80)
        let badSize = try plan.inspect(lines.replacingOccurrences(of: "37 113", with: "untrusted 80"))
        XCTAssertFalse(badSize.complete); XCTAssertNil(badSize.observedRows); XCTAssertNil(badSize.observedColumns)
        XCTAssertThrowsError(try plan.inspect(lines + lines))
        XCTAssertThrowsError(try plan.inspect(String(repeating: "x", count: AppNativeFiniteTerminalPlan.maximumOutputBytes + 1)))
        XCTAssertThrowsError(try AppNativeFiniteTerminalPlan(nonce: "'; arbitrary"))
    }
    private func fdRow(_ fd: Int32, ino: UInt64 = 10, mode: UInt32 = UInt32(S_IFREG | 0o444), uid: UInt32 = 0,
                       access: Int32 = O_RDONLY, path: String? = nil) -> AppNativeFiniteDescriptorEntry {
        let value = AppNativeFiniteDescriptorValue(mode: mode, uid: uid, dev: 1, ino: ino, access: access)
        return .observed(fd: fd, first: value, second: value, path: path)
    }
    private func fdSnapshot(_ count: Int, elapsed: Double, rows: [AppNativeFiniteDescriptorEntry]? = nil) -> AppNativeFiniteDescriptorSnapshot {
        .init(elapsedSeconds: elapsed, scanUpperExclusive: 1_048_576, count: count,
              entries: rows ?? (0..<min(count, 32)).map { fdRow(Int32($0)) })
    }
    func testDescriptorPhaseValuesPreserveExactCountsElapsedAndOptionalAbsence() throws {
        var values = AppNativeFiniteDescriptorSnapshots()
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(values)) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["schema", "maximumEntries", "atomic", "continuousOpenProven"])
        values.baseline = fdSnapshot(20, elapsed: 0.12)
        XCTAssertNil(values.cleanupFirst); XCTAssertNil(values.cleanupLatest)
        values.cleanupFirst = fdSnapshot(23, elapsed: 8.1)
        values.cleanupLatest = fdSnapshot(23, elapsed: 19.9)
        try values.validate()
        let bytes = try JSONEncoder().encode(values)
        XCTAssertEqual(try AppNativeFiniteDescriptorSnapshots.decodeStrict(bytes), values)
        XCTAssertEqual(values.baseline?.entries.count, 20); XCTAssertEqual(values.cleanupLatest?.entries.count, 23)
        XCTAssertEqual(values.baseline?.elapsedSeconds, 0.12); XCTAssertEqual(values.cleanupFirst?.elapsedSeconds, 8.1)
        XCTAssertFalse(values.atomic); XCTAssertFalse(values.continuousOpenProven)
        object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        let phase = try XCTUnwrap(object["baseline"] as? [String: Any])
        XCTAssertEqual(Set(phase.keys), ["elapsedSeconds", "scanUpperExclusive", "count", "truncated", "complete", "entries"])
        let rows = try XCTUnwrap(phase["entries"] as? [[String: Any]])
        XCTAssertEqual(Set(try XCTUnwrap(rows.first).keys), ["fd", "type", "dev", "ino", "access", "probeStatus", "role"])
    }
    func testDescriptorDiagnosticCapDoesNotCapCountOrClaimCompleteness() throws {
        var values = AppNativeFiniteDescriptorSnapshots()
        values.baseline = fdSnapshot(20, elapsed: 0.1)
        values.cleanupFirst = fdSnapshot(33, elapsed: 8)
        values.cleanupLatest = fdSnapshot(1_048_576, elapsed: 19)
        try values.validate()
        XCTAssertEqual(values.cleanupFirst?.entries.count, 32); XCTAssertEqual(values.cleanupFirst?.count, 33)
        XCTAssertEqual(values.cleanupLatest?.entries.count, 32); XCTAssertEqual(values.cleanupLatest?.count, 1_048_576)
        XCTAssertEqual(values.cleanupLatest?.truncated, true); XCTAssertEqual(values.cleanupLatest?.complete, false)
        XCTAssertNotEqual(values.baseline?.count, values.cleanupLatest?.count)
        let exact = fdSnapshot(32, elapsed: 1)
        XCTAssertFalse(exact.truncated); XCTAssertTrue(exact.complete)
        XCTAssertEqual(try AppNativeFiniteDescriptorSnapshots.decodeStrict(JSONEncoder().encode(values)), values)
    }
    func testDescriptorUnknownAndChangingSlotsStayCountedWithoutIdentityClaims() throws {
        let first = AppNativeFiniteDescriptorValue(mode: UInt32(S_IFREG | 0o444), uid: 0, dev: 1, ino: 5, access: O_RDONLY)
        let unavailable = AppNativeFiniteDescriptorEntry.observed(fd: 1, first: first, second: nil, path: "/usr/share/icu/icudt78l.dat")
        let changed = AppNativeFiniteDescriptorEntry.observed(fd: 2, first: first,
            second: .init(mode: first.mode, uid: 0, dev: 1, ino: 6, access: O_RDONLY), path: "/usr/share/icu/icudt78l.dat")
        XCTAssertEqual(unavailable.probeStatus, .unavailable); XCTAssertEqual(changed.probeStatus, .changed)
        for row in [unavailable, changed] { XCTAssertNil(row.ino); XCTAssertNil(row.access); XCTAssertEqual(row.role, .unknown) }
        let sameInodeDifferentAccess = AppNativeFiniteDescriptorEntry.observed(fd: 3, first: first,
            second: .init(mode: first.mode, uid: 0, dev: 1, ino: 5, access: O_RDWR), path: nil)
        XCTAssertEqual(sameInodeDifferentAccess.probeStatus, .changed)
        var values = AppNativeFiniteDescriptorSnapshots()
        values.baseline = fdSnapshot(3, elapsed: 1, rows: [fdRow(0), unavailable, changed])
        try values.validate()
        XCTAssertEqual(values.baseline?.count, 3); XCTAssertEqual(values.baseline?.entries.count, 3)
        XCTAssertEqual(values.baseline?.complete, false); XCTAssertFalse(values.continuousOpenProven)
        XCTAssertEqual(try AppNativeFiniteDescriptorSnapshots.decodeStrict(JSONEncoder().encode(values)), values)
    }
    func testDescriptorRolesAreAnchoredRootReadOnlyShapesAndNeverPaths() throws {
        let examples: [(String, AppNativeFiniteDescriptorRole)] = [("/usr/share/zoneinfo/Asia/Shanghai", .systemTZShape),
            ("/usr/share/icu/icudt78l.dat", .systemICUShape), ("/usr/share/locale/en_US.UTF-8/LC_CTYPE", .systemLocaleShape),
            ("/System/Library/Fonts/SFNS.ttf", .systemFontShape), ("/usr/share/fonts/system.ttc", .systemFontShape),
            ("/usr/share/system/fonts/system.otf", .systemFontShape)]
        for (path, role) in examples {
            let row = fdRow(21, path: path)
            XCTAssertEqual(row.role, role)
            let text = String(decoding: try JSONEncoder().encode(row), as: UTF8.self)
            XCTAssertFalse(text.contains(path)); XCTAssertFalse(text.contains("path")); XCTAssertFalse(text.contains("uid"))
            XCTAssertEqual(fdRow(21, uid: 501, path: path).role, .unknown)
            XCTAssertEqual(fdRow(21, access: O_RDWR, path: path).role, .unknown)
            XCTAssertEqual(fdRow(21, mode: UInt32(S_IFDIR | 0o555), path: path).role, .unknown)
        }
        for path in ["/Users/private/Library/Keychains/login.keychain-db", "/System/Library/Security/cache",
                     "/usr/share/zoneinfo/../private", "/usr/share/zoneinfo//UTC", "/usr/share/zoneinfo/Security/item",
                     "/usr/share/zoneinfo/keychain-db", "/usr/share/icu/icudt78l.dat/other", "/usr/share/locale/C/unknown",
                     "/System/Library/Fonts-other/SFNS.ttf", "/System/Library/Fonts/private\n.ttf", "/private/var/folders/cache"] {
            let row = fdRow(24, path: path)
            XCTAssertEqual(row.role, .unknown)
            XCTAssertFalse(String(decoding: try JSONEncoder().encode(row), as: UTF8.self).contains(path))
        }
    }
    func testDescriptorStrictSchemaRejectsExtraKeysBadCountsAndFalseContinuity() throws {
        var values = AppNativeFiniteDescriptorSnapshots(); values.baseline = fdSnapshot(1, elapsed: 1)
        let bytes = try JSONEncoder().encode(values)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        for (key, replacement) in [("atomic", true as Any), ("continuousOpenProven", true as Any), ("maximumEntries", 128 as Any), ("rawPath", "/not-emitted" as Any)] {
            var bad = object; bad[key] = replacement
            XCTAssertThrowsError(try AppNativeFiniteDescriptorSnapshots.decodeStrict(JSONSerialization.data(withJSONObject: bad)))
        }
        let baseline = try XCTUnwrap(object["baseline"] as? [String: Any])
        for (key, replacement) in [("count", 2 as Any), ("truncated", true as Any), ("complete", false as Any), ("scanUpperExclusive", 0 as Any)] {
            var bad = object, phase = baseline; phase[key] = replacement; bad["baseline"] = phase
            XCTAssertThrowsError(try AppNativeFiniteDescriptorSnapshots.decodeStrict(JSONSerialization.data(withJSONObject: bad)))
        }
        let rows = try XCTUnwrap(baseline["entries"] as? [[String: Any]])
        for (key, replacement) in [("role", "guessedCache" as Any), ("probeStatus", "closed" as Any), ("pathHash", "forbidden" as Any), ("fd", -1 as Any)] {
            var bad = object, phase = baseline, row = try XCTUnwrap(rows.first)
            row[key] = replacement; phase["entries"] = [row]; bad["baseline"] = phase
            XCTAssertThrowsError(try AppNativeFiniteDescriptorSnapshots.decodeStrict(JSONSerialization.data(withJSONObject: bad)))
        }
        var missingFirst = values; missingFirst.cleanupLatest = fdSnapshot(1, elapsed: 2)
        XCTAssertThrowsError(try missingFirst.validate())
        var backwards = values; backwards.cleanupFirst = fdSnapshot(1, elapsed: 0.5); backwards.cleanupLatest = backwards.cleanupFirst
        XCTAssertThrowsError(try backwards.validate())
    }
    func testDescriptorThreeMaximalSnapshotsFitUnchangedReceiptBudget() throws {
        let rows = (0..<32).map { index in
            AppNativeFiniteDescriptorEntry(fd: Int32(1_048_544 + index), type: UInt32(S_IFREG), dev: Int32.min, ino: UInt64.max,
                access: O_RDONLY, probeStatus: .stable, role: .systemLocaleShape)
        }
        var values = AppNativeFiniteDescriptorSnapshots()
        values.baseline = fdSnapshot(32, elapsed: 29.999999999999996, rows: rows)
        values.cleanupFirst = fdSnapshot(32, elapsed: 79.99999999999999, rows: rows)
        values.cleanupLatest = fdSnapshot(32, elapsed: 89.99999999999999, rows: rows)
        let bytes = try JSONEncoder().encode(values)
        try values.validate()
        XCTAssertEqual(try AppNativeFiniteDescriptorSnapshots.decodeStrict(bytes), values)
        XCTAssertLessThanOrEqual(bytes.count, 14 * 1024, "Leaves >=2KiB for the existing full receipt, whose actual envelope is tested in Python")
    }
    func testQuitAuditRequiresTrueOrderedStorePointsAndTypedPrimaryIsExact() throws {
        var audit = AppNativeFiniteQuitAudit()
        XCTAssertFalse(audit.complete); XCTAssertThrowsError(try audit.after()); XCTAssertThrowsError(try audit.terminating())
        try audit.schedule(); XCTAssertThrowsError(try audit.schedule()); try audit.dispatch()
        try audit.before(); XCTAssertThrowsError(try audit.before()); try audit.after(); try audit.terminating()
        XCTAssertTrue(audit.complete); XCTAssertThrowsError(try audit.terminating())
        // Pure report vocabulary/round-trip only, not proof of actual task or UI disposal.
        let stagesInReport = AppNativeFiniteCleanupStage.allCases.map(\.rawValue)
        XCTAssertEqual(stagesInReport, ["exerciseRunning", "exerciseReturned", "closingTabs", "weakWait", "descriptorWait", "sourceCheck", "metadataDelete", "ready", "quit"])
        let active = AppNativeFiniteActiveSnapshot(activeStage: .awaitingTerminalEvidence, terminalEvidence: nil,
            requestedRows: 37, requestedColumns: 113, driverHasLatestResize: false, driverResizeInFlight: false,
            terminalRows: 24, terminalColumns: 80,
            inputBeforeAdmission: .init(pendingBytes: 0, pendingItems: 0), inputAfterAdmission: .init(pendingBytes: 128, pendingItems: 1))
        XCTAssertEqual(AppNativeFiniteActiveStage.allCases.map(\.rawValue), ["preparingHost", "awaitingDriver", "awaitingTrust", "awaitingConnected", "awaitingResize", "awaitingTerminalEvidence", "awaitingExit", "closingTab"])
        let cleanup = AppNativeFiniteCleanupSnapshot(cleanupStage: .weakWait,
            weakTabAlive: true, weakDriverAlive: true, weakViewAlive: true,
            terminalHasSuperview: false, terminalHasWindow: false, currentSessionTabCount: 0, workspaceIsVault: true,
            descriptorObserved: false, knownHostsCheckPerformed: false, active: active)
        let encodedCleanup = try JSONEncoder().encode(cleanup)
        XCTAssertEqual(try JSONDecoder().decode(AppNativeFiniteCleanupSnapshot.self, from: encodedCleanup), cleanup)
        let cleanupObject = try XCTUnwrap(JSONSerialization.jsonObject(with: encodedCleanup) as? [String: Any])
        XCTAssertEqual(Set(cleanupObject.keys), ["cleanupStage", "weakTabAlive", "weakDriverAlive", "weakViewAlive", "terminalHasSuperview", "terminalHasWindow", "currentSessionTabCount", "workspaceIsVault", "descriptorObserved", "knownHostsCheckPerformed", "active"])
        XCTAssertThrowsError(try JSONDecoder().decode(AppNativeFiniteCleanupStage.self, from: Data("\"untrusted-phase\"".utf8)))
        // Pure closed point schema only: synthetic addresses are never dereferenced or traced.
        let point = try AppNativeFiniteWeakPoint(runID: id, pid: 123, tabAddress: 0x1234, driverAddress: 0x2345, viewAddress: 0x3456,
            elapsedSeconds: 8, weakWaitRemainingSeconds: 11.5)
        let pointBytes = try JSONEncoder().encode(point)
        XCTAssertLessThanOrEqual(pointBytes.count, AppNativeFiniteWeakPoint.maximumBytes)
        XCTAssertEqual(try AppNativeFiniteWeakPoint.decodeStrict(pointBytes), point)
        XCTAssertEqual(point.tabAddress, "0x1234"); XCTAssertEqual(AppNativeFiniteWeakPoint.address(0xABCD), "0xabcd")
        let pointObject = try XCTUnwrap(JSONSerialization.jsonObject(with: pointBytes) as? [String: Any])
        XCTAssertEqual(Set(pointObject.keys), ["schema", "runID", "pid", "cleanupStage", "tabAddress", "driverAddress", "viewAddress", "elapsedSeconds", "weakWaitRemainingSeconds"])
        let badPointValues: [(String, Any)] = [("tabAddress", "0x0"), ("tabAddress", "0x01234"), ("tabAddress", "0xABCD"),
            ("driverAddress", 1234), ("viewAddress", "not-an-address"), ("cleanupStage", "quit"), ("pid", 0),
            ("weakWaitRemainingSeconds", 12.1), ("weakWaitRemainingSeconds", 0.0)]
        for (key, value) in badPointValues {
            var invalidPoint = pointObject; invalidPoint[key] = value
            XCTAssertThrowsError(try AppNativeFiniteWeakPoint.decodeStrict(JSONSerialization.data(withJSONObject: invalidPoint)))
        }
        var extraPoint = pointObject; extraPoint["objectDescription"] = "not-allowed"
        XCTAssertThrowsError(try AppNativeFiniteWeakPoint.decodeStrict(JSONSerialization.data(withJSONObject: extraPoint)))
        XCTAssertThrowsError(try AppNativeFiniteWeakPoint.decodeStrict(Data(repeating: 32, count: 2049)))
        #if HOST_PROBE
        let stages: [NativeShellAuthenticationStage] = [.advertised(password: false, publicKey: true, keyboardInteractive: false),
            .primaryStarted(.publicKey), .primaryResult(.publicKey, code: 0, authenticated: true), .authenticated, .shellReady]
        XCTAssertEqual(try AppNativeFiniteAuthentication(stages).primaryStarted, 1)
        XCTAssertThrowsError(try AppNativeFiniteAuthentication(Array(stages.dropFirst())))
        XCTAssertThrowsError(try AppNativeFiniteAuthentication(stages + [.shellReady]))
        var wrong = stages; wrong[2] = .primaryResult(.publicKey, code: -18, authenticated: false)
        XCTAssertThrowsError(try AppNativeFiniteAuthentication(wrong))
        #endif
    }
}

/// Password M1 additions only. Original 18 methods above are untouched.
/// All bytes below are synthetic public contracts/inputs; no fixture I/O or runtime entry.
final class AppNativePasswordContractTests: XCTestCase {
    private let id = "12345678-1234-1234-1234-123456789abc"
    private var path: String { AppNativePasswordContract.inputRoot + "/run-" + id + "/native-password-fixture.json" }
    private var materialPath: String { AppNativePasswordContract.inputRoot + "/run-" + id + "/native-password-material.json" }
    private var wrapperJSON: String {
        "{\"schema\":1,\"runID\":\"" + id + "\",\"scenario\":\"passwordonly-transient-controller-shell\",\"materialContractPath\":\"" + materialPath + "\"}"
    }
    private func materialObject() -> [String: Any] {
        ["schema": 1, "runID": id, "host": "127.0.0.1", "port": 22222, "user": "fixture", "service": "passwordonly",
         "generation": AppRealIntegrationContract.fixtureRoot + "/.runtime/passwordonly/credentials-012345abcdef",
         "expectedBase": AppNativePasswordIdentity.base, "expectedImage": AppNativePasswordIdentity.image,
         "expectedProject": AppNativePasswordIdentity.project, "expectedContainer": AppNativePasswordIdentity.container,
         "expectedFingerprint": AppNativePasswordIdentity.fingerprint, "networkID": AppNativePasswordIdentity.network,
         "context": AppNativePasswordIdentity.context, "endpoint": AppNativePasswordIdentity.endpoint,
         "collectedAt": 1000, "preparedAt": 1010, "provenanceSHA256": String(repeating: "a", count: 64), "knownHostsSHA256": String(repeating: "b", count: 64)]
    }
    private func decodeMaterial(_ object: [String: Any]) throws -> AppNativePasswordMaterialContract {
        try AppNativePasswordMaterialContract.decodeStrict(JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
    }
    private var live: [String] { ["--native-password-fixture-test", "--native-password-fixture-contract", path, "--authorized-local-fixture", "--primary-released"] }

    func testPasswordEntryIsIndependentInertAndShippingRejected() throws {
        XCTAssertEqual(try AppNativePasswordArguments.parse([], hostProbe: false).action, .none)
        XCTAssertEqual(try AppNativePasswordArguments.parse(["--native-app-fixture-help"], hostProbe: true).action, .none)
        XCTAssertEqual(try AppNativeFiniteArguments.parse(["--native-password-fixture-help"], hostProbe: true).action, .none)
        XCTAssertEqual(try AppNativePasswordArguments.parse(["--native-password-fixture-help"], hostProbe: true).action, .help)
        let validate = ["--native-password-fixture-validate", "--native-password-fixture-contract", path]
        XCTAssertEqual(try AppNativePasswordArguments.parse(validate, hostProbe: true).action, .validate)
        for args in [live, validate, ["--native-password-fixture-help"], ["--native-password-fixture-unknown"]] {
            XCTAssertThrowsError(try AppNativePasswordArguments.parse(args, hostProbe: false))
        }
    }
    func testPasswordEntryRejectsMissingDuplicateMixedAndExtraArguments() throws {
        XCTAssertEqual(try AppNativePasswordArguments.parse(live, hostProbe: true).action, .live)
        var invalid: [[String]] = []
        invalid.append(Array(live.dropLast())); invalid.append(Array(live.dropLast(2)))
        invalid.append(live + ["--primary-released"]); invalid.append(live + ["--authorized-local-fixture"])
        invalid.append(live + ["--native-password-fixture-contract", path])
        invalid.append(live + ["--native-app-fixture-test"]); invalid.append(live + ["--real-fixture-test"])
        invalid.append(live + ["--self-test-phase", "sessions"]); invalid.append(live + ["--backend", "direct"])
        invalid.append(["--native-password-fixture-help", "extra"])
        invalid.append(["--native-password-fixture-validate", "--native-password-fixture-contract", path, "--primary-released"])
        for args in invalid { XCTAssertThrowsError(try AppNativePasswordArguments.parse(args, hostProbe: true)) }
    }
    func testPasswordPathsAndFourFieldWrapperNeverUseOldMaterialPath() throws {
        let value = try AppNativePasswordContract.decodeStrict(Data(wrapperJSON.utf8))
        try value.validate(path: path)
        XCTAssertEqual(try AppNativePasswordContract.runID(at: path), id)
        XCTAssertEqual(value.materialContractPath, materialPath)
        XCTAssertThrowsError(try AppNativeFiniteContract.runID(at: path))
        XCTAssertThrowsError(try AppRealIntegrationContract.validateContractPath(materialPath))
        let oldPath = AppRealIntegrationContract.inputRoot + "/run-" + id + "/app-real-integration.json"
        XCTAssertThrowsError(try AppNativePasswordContract.decodeStrict(Data(wrapperJSON.replacingOccurrences(of: materialPath, with: oldPath).utf8)).validate(path: path))
        for bad in [path.replacingOccurrences(of: id, with: id.uppercased()), path.replacingOccurrences(of: "/run-", with: "/../run-"),
                    path + "/extra", path + "\n", path.replacingOccurrences(of: "/Inputs/", with: "/Inputs//"),
                    "/tmp/run-" + id + "/native-password-fixture.json"] {
            XCTAssertThrowsError(try AppNativePasswordContract.runID(at: bad))
        }
        let other = materialPath.replacingOccurrences(of: id, with: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        XCTAssertThrowsError(try AppNativePasswordContract.decodeStrict(Data(wrapperJSON.replacingOccurrences(of: materialPath, with: other).utf8)).validate(path: path))
        XCTAssertThrowsError(try AppNativePasswordContract.decodeStrict(Data(wrapperJSON.replacingOccurrences(of: "passwordonly-transient-controller-shell", with: "passwordKI").utf8)).validate(path: path))
    }
    func testPasswordWrapperRejectsDuplicatesUnknownCoercionAndNonClosedJSON() throws {
        for suffix in [",\"schema\":1}", ",\"pin\":\"arbitrary\"}", ",\"password\":\"not-accepted\"}"] {
            XCTAssertThrowsError(try AppNativePasswordContract.decodeStrict(Data((String(wrapperJSON.dropLast()) + suffix).utf8)))
        }
        for number in ["true", "1.0", "1e0", "\"1\"", "null", "01", "2"] {
            let text = wrapperJSON.replacingOccurrences(of: "\"schema\":1", with: "\"schema\":" + number)
            XCTAssertThrowsError(try AppNativePasswordContract.decodeStrict(Data(text.utf8)))
        }
        for text in [wrapperJSON + "{}", "{}", wrapperJSON.replacingOccurrences(of: "passwordonly", with: "pass\\u0077ordonly"),
                     wrapperJSON.replacingOccurrences(of: "passwordonly", with: "中文"), String(repeating: " ", count: 4097)] {
            XCTAssertThrowsError(try AppNativePasswordContract.decodeStrict(Data(text.utf8)))
        }
        XCTAssertEqual(try AppNativePasswordContract.decodeStrict(Data(wrapperJSON.replacingOccurrences(of: "/", with: "\\/").utf8)).materialContractPath, materialPath)
    }
    func testPasswordMaterialExactPublicIdentityHasNoKeyOrSecretFields() throws {
        let object = materialObject(), value = try decodeMaterial(object)
        XCTAssertEqual(Set(object.keys), AppNativePasswordMaterialContract.keys)
        try value.validate(path: materialPath, now: 1100, buildEpoch: 900)
        try AppNativePasswordContract.decodeStrict(Data(wrapperJSON.utf8)).requireMaterial(value)
        XCTAssertEqual(value.expectedContainer, "ca01afad3e3b02e90369f29d153aceecd07ba6fced28befdf8b4163f7c27172c")
        XCTAssertEqual(value.expectedFingerprint, "SHA256:YAP/B5jFVHLnyPzRrU3/CJune9REpBSMnm87wcirrJ8")
        XCTAssertEqual(value.networkID, "b949645e158058f7484e21b758459f8d0e6a284f0d2bb641879faf67f2b50ed1")
        XCTAssertEqual(value.context, "desktop-linux"); XCTAssertEqual(value.endpoint, "unix:///Users/liuwenshuo/.docker/run/docker.sock")
        XCTAssertFalse(Set(object.keys).contains("generationPublicKeySHA256")); XCTAssertFalse(Set(object.keys).contains("password"))
        XCTAssertThrowsError(try AppRealIntegrationContract.decodeStrict(JSONSerialization.data(withJSONObject: object)))
    }
    func testPasswordMaterialRejectsAnyOtherPinEndpointServiceOrGeneration() throws {
        let original = materialObject()
        let invalid: [(String, Any)] = [
            ("expectedContainer", AppNativeFiniteIdentity.container), ("expectedContainer", String(repeating: "c", count: 64)),
            ("expectedFingerprint", AppNativeFiniteIdentity.fingerprint), ("expectedFingerprint", "SHA256:unapproved"),
            ("expectedBase", "unapproved"), ("expectedImage", "sha256:" + String(repeating: "d", count: 64)),
            ("expectedProject", "openlxssh-fixture-aaaaaaaaaaaa"), ("networkID", String(repeating: "e", count: 64)),
            ("context", "default"), ("endpoint", "unix:///var/run/docker.sock"), ("host", "localhost"), ("port", 22221),
            ("user", "other"), ("service", "password-kbd"), ("schema", 2),
            ("generation", AppRealIntegrationContract.fixtureRoot + "/.runtime/keyonly/credentials-012345abcdef"),
            ("generation", AppRealIntegrationContract.fixtureRoot + "/.runtime/passwordonly/credentials-../escape"),
            ("runID", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), ("knownHostsSHA256", "bad")]
        for (key, replacement) in invalid {
            var object = original; object[key] = replacement
            XCTAssertThrowsError(try decodeMaterial(object).validate(path: materialPath, now: 1100, buildEpoch: 900), key)
        }
    }
    func testPasswordMaterialRejectsDuplicateMissingUnknownAndCoercedTypes() throws {
        let original = materialObject()
        let text = String(decoding: try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys]), as: UTF8.self)
        for suffix in [",\"schema\":1}", ",\"port\":22222}", ",\"password\":\"not-accepted\"}", ",\"phase\":\"read-only\"}", ",\"generationPublicKeySHA256\":\"not-accepted\"}"] {
            XCTAssertThrowsError(try AppNativePasswordMaterialContract.decodeStrict(Data((String(text.dropLast()) + suffix).utf8)))
        }
        for key in AppNativePasswordMaterialContract.keys {
            var missing = original; missing[key] = nil
            XCTAssertThrowsError(try decodeMaterial(missing), key)
        }
        let wrong: [(String, Any)] = [("schema", true), ("port", "22222"), ("collectedAt", "1000"), ("preparedAt", false), ("host", 127), ("service", NSNull())]
        for (key, value) in wrong { var bad = original; bad[key] = value; XCTAssertThrowsError(try decodeMaterial(bad), key) }
        for number in ["22222.0", "22222e0", "022222", "true"] {
            XCTAssertThrowsError(try AppNativePasswordMaterialContract.decodeStrict(Data(text.replacingOccurrences(of: "\"port\":22222", with: "\"port\":" + number).utf8)))
        }
        XCTAssertThrowsError(try AppNativePasswordMaterialContract.decodeStrict(Data(text.replacingOccurrences(of: "\"collectedAt\":1000", with: "\"collectedAt\":1e999").utf8)))
        XCTAssertThrowsError(try AppNativePasswordMaterialContract.decodeStrict(Data(repeating: 32, count: 8193)))
    }
    func testPasswordFreshnessBuildEpochAndTrustMatchingStayExact() throws {
        let value = try decodeMaterial(materialObject())
        try value.validate(path: materialPath, now: 1120, buildEpoch: 1000)
        for (now, epoch) in [(1120.001, 900.0), (1009.0, 900.0), (1100.0, 1000.001), (1100.0, 0.0), (Double.infinity, 900.0), (1100.0, Double.nan)] {
            XCTAssertThrowsError(try value.validate(path: materialPath, now: now, buildEpoch: epoch))
        }
        var backwards = materialObject(); backwards["preparedAt"] = 999
        XCTAssertThrowsError(try decodeMaterial(backwards).validate(path: materialPath, now: 1100, buildEpoch: 900))
        XCTAssertTrue(value.matchesTrust(host: "127.0.0.1", port: 22222, algorithm: "ssh-ed25519", fingerprint: value.expectedFingerprint))
        XCTAssertFalse(value.matchesTrust(host: "127.0.0.1", port: 22221, algorithm: "ssh-ed25519", fingerprint: value.expectedFingerprint))
        XCTAssertFalse(value.matchesTrust(host: "127.0.0.1", port: 22222, algorithm: "ssh-rsa", fingerprint: value.expectedFingerprint))
        XCTAssertFalse(value.matchesTrust(host: "127.0.0.1", port: 22222, algorithm: "ssh-ed25519", fingerprint: AppNativeFiniteIdentity.fingerprint))
    }
    func testPasswordPublicStateAndProvenanceRejectDuplicateAndWrongIdentity() throws {
        let value = try decodeMaterial(materialObject())
        let state = "{\"version\":1,\"project\":\"" + value.expectedProject + "\",\"image\":\"" + value.expectedBase + "\"}"
        let provenance = "{\"base_image\":\"" + value.expectedBase + "\",\"built_image_id\":\"" + value.expectedImage + "\",\"service\":\"passwordonly\",\"collected_at\":1000}"
        try value.validateState(Data(state.utf8)); try value.validateProvenance(Data(provenance.utf8))
        XCTAssertThrowsError(try value.validateState(Data(state.replacingOccurrences(of: "\"version\":1", with: "\"version\":true").utf8)))
        XCTAssertThrowsError(try value.validateState(Data((String(state.dropLast()) + ",\"version\":1}").utf8)))
        XCTAssertThrowsError(try value.validateProvenance(Data(provenance.replacingOccurrences(of: "passwordonly", with: "keyonly").utf8)))
        XCTAssertThrowsError(try value.validateProvenance(Data(provenance.replacingOccurrences(of: "1000", with: "1001").utf8)))
        XCTAssertThrowsError(try value.validateProvenance(Data((String(provenance.dropLast()) + ",\"service\":\"passwordonly\"}").utf8)))
    }
    func testPasswordSelectedSecretPayloadOnlyStripsOneLFAndRejectsNULCRLF() throws {
        // Synthetic bytes, not fixture material; no secret description/hash is inspected.
        XCTAssertEqual(try AppNativePasswordSecret.payload(Data([65, 66, 10])), Data([65, 66]))
        for bytes in [Data(), Data([10]), Data([65]), Data([65, 0, 10]), Data([65, 13, 10]), Data([65, 10, 10]), Data(repeating: 65, count: 1025)] {
            XCTAssertThrowsError(try AppNativePasswordSecret.payload(bytes))
        }
    }
    func testPasswordTransientFactsRequirePrepareZeroCommitOnceAndSingleConsumption() throws {
        func facts(_ tabs: Int = 0, _ attempts: Int = 0, _ early: Bool = false, _ commits: Int = 1,
                   _ committedTabs: Int = 1, _ consumed: Bool = true, _ primary: Int = 1) throws -> AppNativePasswordTransientFacts {
            try .init(preparedTabCount: tabs, preparedConnectionAttempts: attempts, preparedIntentConsumed: early,
                      commitCount: commits, committedTabCount: committedTabs, intentConsumed: consumed, primaryProviderCalls: primary)
        }
        let value = try facts()
        XCTAssertEqual(value, try JSONDecoder().decode(AppNativePasswordTransientFacts.self, from: JSONEncoder().encode(value)))
        XCTAssertThrowsError(try facts(1)); XCTAssertThrowsError(try facts(0, 1)); XCTAssertThrowsError(try facts(0, 0, true))
        XCTAssertThrowsError(try facts(0, 0, false, 2)); XCTAssertThrowsError(try facts(0, 0, false, 1, 2))
        XCTAssertThrowsError(try facts(0, 0, false, 1, 1, false)); XCTAssertThrowsError(try facts(0, 0, false, 1, 1, true, 2))
        XCTAssertEqual(AppNativeFiniteScenario.password.rawValue, "passwordonly-transient-controller-shell")
        XCTAssertEqual(AppNativeFiniteSourceKeyScope.notApplicablePassword.rawValue, "notApplicablePassword")
    }
    #if HOST_PROBE
    func testPasswordTypedFiveStagesAndAuthenticationOnlyReceiptAreClosed() throws {
        let stages: [NativeShellAuthenticationStage] = [.advertised(password: true, publicKey: false, keyboardInteractive: false),
            .primaryStarted(.password), .primaryResult(.password, code: 0, authenticated: true), .authenticated, .shellReady]
        let auth = try AppNativeFiniteAuthFacts(passwordStages: stages)
        XCTAssertEqual(auth.primaryMethod, "password")
        XCTAssertThrowsError(try AppNativeFiniteAuthentication(stages))
        XCTAssertThrowsError(try AppNativeFiniteAuthFacts(passwordStages: Array(stages.dropFirst())))
        XCTAssertThrowsError(try AppNativeFiniteAuthFacts(passwordStages: stages + [.keyboardStarted]))
        var bad = stages; bad[1] = .primaryStarted(.publicKey)
        XCTAssertThrowsError(try AppNativeFiniteAuthFacts(passwordStages: bad))
        bad = stages; bad[2] = .primaryResult(.password, code: -18, authenticated: false)
        XCTAssertThrowsError(try AppNativeFiniteAuthFacts(passwordStages: bad))
        let transient = try AppNativePasswordTransientFacts(preparedTabCount: 0, preparedConnectionAttempts: 0, preparedIntentConsumed: false,
            commitCount: 1, committedTabCount: 1, intentConsumed: true, primaryProviderCalls: 1)
        let receipt = AppNativePasswordAuthenticationReceipt(runID: id, pid: 123, authentication: auth, transient: transient, credentialCalls: 0)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(receipt)) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["schema", "kind", "scenario", "sourceKeyScope", "acceptanceScope", "guiVerified", "productRuntimeVerified", "runID", "pid", "authentication", "transient", "credentialCalls"])
        XCTAssertEqual(object["acceptanceScope"] as? String, "authentication-only-resources-unverified")
        XCTAssertEqual(object["sourceKeyScope"] as? String, "notApplicablePassword")
        XCTAssertNil(object["sourceKeyUnchanged"]); XCTAssertNil(object["passed"]); XCTAssertNil(object["resourcesReturnedToBaseline"])
        let keyStages: [NativeShellAuthenticationStage] = [.advertised(password: false, publicKey: true, keyboardInteractive: false),
            .primaryStarted(.publicKey), .primaryResult(.publicKey, code: 0, authenticated: true), .authenticated, .shellReady]
        let old = try AppNativeFiniteAuthentication(keyStages)
        let projected = AppNativeFiniteAuthFacts(keyonly: old)
        XCTAssertEqual(try JSONSerialization.jsonObject(with: JSONEncoder().encode(old)) as? NSDictionary,
                       try JSONSerialization.jsonObject(with: JSONEncoder().encode(projected)) as? NSDictionary)
    }
    #endif
}

/// Pure synthetic MFA contracts. No management process, fixture input, socket, AppKit or secret lookup.
final class AppMFAContractTests: XCTestCase {
    private let run = "12345678-1234-1234-1234-123456789abc", session = "0123456789abcdef01234567"
    private var path: String { AppNativeFiniteContract.inputRoot + "/run-" + run + "/native-mfa-fixture.json" }
    private var materialPath: String { AppNativeFiniteContract.inputRoot + "/run-" + run + "/native-mfa-material.json" }
    private func wrapper(_ fixture: AppMFAFixture) -> Data {
        Data(("{\"schema\":1,\"runID\":\"" + run + "\",\"scenario\":\"" + fixture.rawValue + "\",\"materialContractPath\":\"" + materialPath + "\"}").utf8)
    }
    private func fields(_ fixture: AppMFAFixture) -> [String: Any] {
        var result: [String: Any] = ["schema": 1, "runID": run, "host": "127.0.0.1", "port": fixture.port, "user": "fixture", "service": fixture.service, "key": fixture.key,
            "generation": AppRealIntegrationContract.fixtureRoot + "/.runtime/" + fixture.service + "/credentials-012345abcdef",
            "expectedBase": AppNativePasswordIdentity.base, "expectedImage": AppNativePasswordIdentity.image, "expectedProject": AppNativePasswordIdentity.project,
            "expectedContainer": fixture.container, "expectedFingerprint": fixture.fingerprint, "networkID": AppNativePasswordIdentity.network,
            "context": AppNativePasswordIdentity.context, "endpoint": AppNativePasswordIdentity.endpoint, "collectedAt": 1000, "preparedAt": 1010,
            "provenanceSHA256": String(repeating: "a", count: 64), "knownHostsSHA256": String(repeating: "b", count: 64), "policyProofSHA256": String(repeating: "c", count: 64)]
        if fixture.usesKey { result["generationPublicKeySHA256"] = String(repeating: "d", count: 64) }
        return result
    }
    private func material(_ fixture: AppMFAFixture, fields: [String: Any]? = nil) throws -> AppMFAMaterialContract {
        try AppMFAMaterialContract.decodeStrict(JSONSerialization.data(withJSONObject: fields ?? self.fields(fixture), options: [.sortedKeys]), fixture: fixture)
    }
    private func proof(_ value: AppMFAMaterialContract) -> [String: Any] {
        ["schema": 1, "runID": run, "service": value.service, "containerID": value.expectedContainer, "imageID": value.expectedImage,
         "baseImage": value.expectedBase, "project": value.expectedProject, "networkID": value.networkID, "context": value.context, "endpoint": value.endpoint,
         "port": value.port, "verifiedAt": 1005, "runningHealthy": 1, "readonlyRoot": 1, "notPrivileged": 1, "logNone": 1, "loopbackPortExact": 1,
         "internalBridge": 1, "noBindMounts": 1, "rootPolicyMulti": 1]
    }
    private func oneRound(_ value: inout AppMFAKIBudget, index: Int) throws {
        let phase: AppMFAKIBudget.Phase
        if index < 3 {
            phase = try value.claim(name: "", instruction: "", fields: [try AppMFAKIBudget.prompt(session: session, index: index)], echo: [false], now: 10 + Double(index))
            try value.claimManagementRead(phase)
        } else { phase = try value.claim(name: "", instruction: "", fields: [], echo: [], now: 13) }
        try value.consume(phase, now: 14 + Double(index)); try value.resolved(true)
    }
    @MainActor func testMFACleanupCancelledObservationYieldsWithoutChangingPendingOwnerOrExtendingDeadline() async {
        final class State { var pending = 1; var probes = 0; var first = true }
        let state = State(), deadline = ContinuousClock.now + .milliseconds(120)
        let started = ContinuousClock.now
        let observer = Task { @MainActor in
            withUnsafeCurrentTask { $0?.cancel() }
            return await AppMFACleanupWait.observe(deadline: deadline, pending: { state.probes += 1; return state.pending })
        }
        let result = await observer.value
        XCTAssertFalse(result); XCTAssertEqual(state.pending, 1)
        XCTAssertLessThan(state.probes, 20, "Cancellation must not synchronously poll to the original deadline")
        XCTAssertLessThan(started.duration(to: .now), .milliseconds(80))
        let drained = await AppMFACleanupWait.observe(deadline: .now + .seconds(1), pending: {
            if state.first { state.first = false; state.pending = 0; return 1 }
            return state.pending
        })
        XCTAssertTrue(drained); XCTAssertEqual(state.pending, 0)
        let expiredAt = ContinuousClock.now
        let expired = await AppMFACleanupWait.observe(deadline: expiredAt, pending: { 1 })
        XCTAssertFalse(expired)
    }
    func testMFAEntryAndPathsAreIndependentInertAndShippingRejected() throws {
        let args = ["--native-mfa-fixture-test", "--native-mfa-fixture-contract", path, "--authorized-local-fixture", "--primary-released"]
        XCTAssertEqual(try AppMFAArguments.parse(args, hostProbe: true).action, .live)
        XCTAssertEqual(try AppMFAArguments.parse(["--native-mfa-fixture-help"], hostProbe: true).action, .help)
        XCTAssertEqual(try AppMFAArguments.parse(["--native-mfa-fixture-validate", "--native-mfa-fixture-contract", path], hostProbe: true).action, .validate)
        for value in [args, ["--native-mfa-fixture-help"], args + ["--native-password-fixture-test"], args + ["--primary-released"], Array(args.dropLast())] {
            XCTAssertThrowsError(try AppMFAArguments.parse(value, hostProbe: false))
        }
        for value in [args + ["--native-password-fixture-test"], args + ["--primary-released"], Array(args.dropLast()), args + ["--native-app-fixture-test"]] {
            XCTAssertThrowsError(try AppMFAArguments.parse(value, hostProbe: true))
        }
        XCTAssertThrowsError(try AppNativePasswordContract.runID(at: path)); XCTAssertThrowsError(try AppNativeFiniteContract.runID(at: path))
        for fixture in AppMFAFixture.allCases { try AppMFAContract.decodeStrict(wrapper(fixture)).validate(path: path) }
        for bad in [path + "/extra", path.replacingOccurrences(of: run, with: run.uppercased()), path.replacingOccurrences(of: "/run-", with: "/../run-")] {
            XCTAssertThrowsError(try AppMFAContract.runID(at: bad))
        }
    }
    func testMFAWrapperRejectsDuplicateUnknownCoercionAndUnapprovedScenario() throws {
        let valid = String(decoding: wrapper(.keyKI), as: UTF8.self)
        for replacement in ["true", "1.0", "1e0", "\"1\"", "null"] {
            XCTAssertThrowsError(try AppMFAContract.decodeStrict(Data(valid.replacingOccurrences(of: "\"schema\":1", with: "\"schema\":" + replacement).utf8)))
        }
        for bad in [valid + "{}", String(valid.dropLast()) + ",\"schema\":1}", valid.replacingOccurrences(of: AppMFAFixture.keyKI.rawValue, with: "any-mfa"),
                    valid.replacingOccurrences(of: "native-mfa-material", with: "app-real-integration")] {
            XCTAssertThrowsError(try AppMFAContract.decodeStrict(Data(bad.utf8)).validate(path: path))
        }
    }
    func testMFAExactTwoIdentitiesRequireOnlySelectedKeyPublicDigest() throws {
        for fixture in AppMFAFixture.allCases {
            let value = try material(fixture); try value.validate(path: materialPath, now: 1100, buildEpoch: 900)
            XCTAssertEqual(value.expectedContainer, fixture.container); XCTAssertEqual(value.expectedFingerprint, fixture.fingerprint)
            XCTAssertEqual(value.key, fixture.key); XCTAssertEqual(value.generationPublicKeySHA256 != nil, fixture.usesKey)
            var wrong = fields(fixture)
            if fixture.usesKey { wrong["generationPublicKeySHA256"] = nil } else { wrong["generationPublicKeySHA256"] = String(repeating: "d", count: 64) }
            XCTAssertThrowsError(try material(fixture, fields: wrong))
            XCTAssertThrowsError(try AppNativePasswordMaterialContract.decodeStrict(JSONSerialization.data(withJSONObject: fields(fixture))))
        }
        XCTAssertEqual(AppMFAFixture.keyKI.container, "8fe5caf91cd453465d0c90c9c3c6607d7d37252b0a12756048296d26f076dee6")
        XCTAssertEqual(AppMFAFixture.passwordKI.fingerprint, "SHA256:M89ZPAwqBO3k4+50seWt4j0oCpqAamqWCicE+q1hibc")
    }
    func testMFAMaterialRejectsAnyPinServiceGenerationAndWrongTypes() throws {
        for fixture in AppMFAFixture.allCases {
            let badValues: [(String, Any)] = [("expectedContainer", AppNativePasswordIdentity.container), ("expectedFingerprint", AppNativeFiniteIdentity.fingerprint),
                ("port", 22222), ("host", "localhost"), ("service", "keyonly"), ("key", "rsaPlain"), ("context", "default"),
                ("networkID", String(repeating: "0", count: 64)), ("endpoint", "unix:///var/run/docker.sock"), ("policyProofSHA256", "invalid"),
                ("generation", AppRealIntegrationContract.fixtureRoot + "/.runtime/" + fixture.service + "/credentials-../escape"), ("schema", true)]
            for (key, replacement) in badValues {
                var bad = fields(fixture); bad[key] = replacement
                XCTAssertThrowsError(try material(fixture, fields: bad).validate(path: materialPath, now: 1100, buildEpoch: 900), key)
            }
            let text = String(decoding: try JSONSerialization.data(withJSONObject: fields(fixture)), as: UTF8.self)
            XCTAssertThrowsError(try AppMFAMaterialContract.decodeStrict(Data((String(text.dropLast()) + ",\"policyProofSHA256\":\"duplicate\"}").utf8), fixture: fixture))
        }
    }
    func testMFAExternalPolicyProofRequiresSameRunExactIdentityAllFlagsAndFreshBuildEpoch() throws {
        for fixture in AppMFAFixture.allCases {
            let value = try material(fixture), valid = proof(value)
            try value.validatePolicyProof(JSONSerialization.data(withJSONObject: valid), now: 1100, buildEpoch: 900)
            for (key, replacement) in [("runID", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" as Any), ("containerID", AppNativePasswordIdentity.container as Any),
                                       ("rootPolicyMulti", 0 as Any), ("runningHealthy", true as Any), ("verifiedAt", 1011 as Any)] {
                var bad = valid; bad[key] = replacement
                XCTAssertThrowsError(try value.validatePolicyProof(JSONSerialization.data(withJSONObject: bad), now: 1100, buildEpoch: 900), key)
            }
            XCTAssertThrowsError(try value.validatePolicyProof(JSONSerialization.data(withJSONObject: valid), now: 1126, buildEpoch: 900))
            XCTAssertThrowsError(try value.validate(path: materialPath, now: 1121, buildEpoch: 900))
            XCTAssertThrowsError(try value.validate(path: materialPath, now: 1100, buildEpoch: 1001))
        }
    }
    func testMFAFourRoundsRequireThreeReadRepliesAndExplicitZeroTail() throws {
        var value = try AppMFAKIBudget(deadline: 45)
        for index in 0..<4 { try oneRound(&value, index: index) }
        try value.requireComplete()
        XCTAssertEqual(value.fieldCounts, [1, 1, 1, 0]); XCTAssertEqual(value.echoFlags, [[false], [false], [false], []])
        XCTAssertEqual(value.managementReads, 3); XCTAssertEqual(value.secretReplies, 3); XCTAssertEqual(value.zeroReplies, 1)
        XCTAssertEqual(value.replies, 4); XCTAssertEqual(value.rounds, 4); XCTAssertEqual(value.lateReplies, 0)
        XCTAssertThrowsError(try value.claim(name: "", instruction: "", fields: [], echo: [], now: 20))
    }
    func testMFAUnknownEchoWrongOrderSessionAndEarlyZeroAreRejectedWithoutReading() throws {
        let cases: [(String, String, [String], [Bool])] = [("untrusted", "", [try AppMFAKIBudget.prompt(session: session, index: 0)], [false]),
            ("", "", [try AppMFAKIBudget.prompt(session: session, index: 0)], [true]),
            ("", "", [try AppMFAKIBudget.prompt(session: session, index: 1)], [false]), ("", "", [], []), ("", "", ["Password: "], [false])]
        for (name, instruction, fields, echo) in cases {
            var value = try AppMFAKIBudget(deadline: 45)
            XCTAssertThrowsError(try value.claim(name: name, instruction: instruction, fields: fields, echo: echo, now: 1))
            XCTAssertEqual(value.managementReads, 0); XCTAssertEqual(value.replies, 0)
        }
        var value = try AppMFAKIBudget(deadline: 45); try oneRound(&value, index: 0)
        XCTAssertThrowsError(try value.claim(name: "", instruction: "", fields: [try AppMFAKIBudget.prompt(session: "ffffffffffffffffffffffff", index: 1)], echo: [false], now: 20))
    }
    func testMFAReadClaimConsumeAndResolutionAreSingleUseAndCancellationIsNotZero() throws {
        var value = try AppMFAKIBudget(deadline: 45)
        let phase = try value.claim(name: "", instruction: "", fields: [try AppMFAKIBudget.prompt(session: session, index: 0)], echo: [false], now: 1)
        try value.claimManagementRead(phase); XCTAssertThrowsError(try value.claimManagementRead(phase))
        try value.consume(phase, now: 2); try value.resolved(true)
        XCTAssertThrowsError(try value.consume(phase, now: 3)); XCTAssertEqual(value.lateReplies, 1)
        var cancelled = try AppMFAKIBudget(deadline: 45); cancelled.close()
        XCTAssertThrowsError(try cancelled.claim(name: "", instruction: "", fields: [], echo: [], now: 2))
        XCTAssertEqual(cancelled.zeroReplies, 0); XCTAssertEqual(cancelled.managementReads, 0)
        var expired = try AppMFAKIBudget(deadline: 10)
        XCTAssertThrowsError(try expired.claim(name: "", instruction: "", fields: [], echo: [], now: 10))
    }
    func testMFAReplyOwnerRejectsCrossTabHostRequestTokenAndGeneration() throws {
        let tab = UUID(), sessionID = UUID(), request = UUID(), host = UUID()
        let owner = AppMFAReplyOwner(tabID: tab, sessionID: sessionID, requestID: request, hostID: host, generation: 1, port: 22223)
        try owner.validate(current: owner)
        let wrong = [AppMFAReplyOwner(tabID: UUID(), sessionID: sessionID, requestID: request, hostID: host, generation: 1, port: 22223),
            .init(tabID: tab, sessionID: UUID(), requestID: request, hostID: host, generation: 1, port: 22223),
            .init(tabID: tab, sessionID: sessionID, requestID: UUID(), hostID: host, generation: 1, port: 22223),
            .init(tabID: tab, sessionID: sessionID, requestID: request, hostID: UUID(), generation: 1, port: 22223),
            .init(tabID: tab, sessionID: sessionID, requestID: request, hostID: host, generation: 2, port: 22223),
            .init(tabID: tab, sessionID: sessionID, requestID: request, hostID: host, generation: 1, port: 22224)]
        for candidate in wrong { XCTAssertThrowsError(try owner.validate(current: candidate)) }
    }
    func testMFAOTPDecodeEnforcesExactSessionIndexExpiryAndDigits() throws {
        let valid = "{\"session\":\"" + session + "\",\"index\":0,\"expires_at\":1050,\"response\":\"12345678\"}"
        XCTAssertEqual(try AppMFAOTP.decode(Data(valid.utf8), session: session, index: 0, now: 1000), Data([49, 50, 51, 52, 53, 54, 55, 56]))
        for bad in [valid.replacingOccurrences(of: "1050", with: "999"), valid.replacingOccurrences(of: "1050", with: "1076"),
                    valid.replacingOccurrences(of: "12345678", with: "1234567x"), String(valid.dropLast()) + ",\"response\":\"duplicate\"}"] {
            XCTAssertThrowsError(try AppMFAOTP.decode(Data(bad.utf8), session: session, index: 0, now: 1000))
        }
        XCTAssertThrowsError(try AppMFAOTP.decode(Data(valid.utf8), session: "ffffffffffffffffffffffff", index: 0, now: 1000))
        XCTAssertThrowsError(try AppMFAOTP.decode(Data(valid.utf8), session: session, index: 1, now: 1000))
    }
    #if HOST_PROBE
    func testMFACleanupUnknownAndPendingEvidenceStaySeparateFromAuthentication() throws {
        let facts = AppMFAManagementFacts(calls: 3, returnedCalls: 2, successfulReapedCalls: 2, pendingCalls: 1,
            cancellationRequested: true, reapEvidenceComplete: false)
        let receipt = AppMFACleanupReceipt(runID: run, pid: 123, scenario: .keyKI, statusReads: 0, serverSessionStatus: .unknown, management: facts)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(receipt)) as? [String: Any])
        XCTAssertEqual(object["serverSessionStatus"] as? String, "unknown"); XCTAssertEqual(object["statusReads"] as? Int, 0)
        XCTAssertEqual(object["acceptanceScope"] as? String, "authentication-cleanup-only-resources-unverified")
        XCTAssertNil(object["passed"]); XCTAssertNil(object["authentication"]); XCTAssertNil(object["sessionID"])
        let value = try XCTUnwrap(object["management"] as? [String: Any])
        XCTAssertEqual(value["pendingCalls"] as? Int, 1); XCTAssertEqual(value["reapEvidenceComplete"] as? Bool, false)
    }
    func testMFATypedSevenStagesAndReceiptScopeNeverClaimResourcesPassed() throws {
        for fixture in AppMFAFixture.allCases {
            let method: NativeShellPrimaryMethod = fixture.usesKey ? .publicKey : .password
            let code: Int32 = fixture.usesKey ? -19 : -18
            let stages: [NativeShellAuthenticationStage] = [.advertised(password: !fixture.usesKey, publicKey: fixture.usesKey, keyboardInteractive: false),
                .primaryStarted(method), .primaryResult(method, code: code, authenticated: false), .keyboardStarted,
                .keyboardResult(code: 0, authenticated: true), .authenticated, .shellReady]
            let auth = try AppMFAAuthentication(stages, fixture: fixture)
            XCTAssertEqual(auth.primaryCode, code); XCTAssertFalse(auth.primaryAuthenticated); XCTAssertTrue(auth.keyboardAuthenticated)
            XCTAssertThrowsError(try AppMFAAuthentication(Array(stages.dropLast()), fixture: fixture))
            XCTAssertThrowsError(try AppMFAAuthentication(stages + [.shellReady], fixture: fixture))
            var wrong = stages; wrong[2] = .primaryResult(method, code: 0, authenticated: true)
            XCTAssertThrowsError(try AppMFAAuthentication(wrong, fixture: fixture))
            var budget = try AppMFAKIBudget(deadline: 45); for index in 0..<4 { try oneRound(&budget, index: index) }
            let transient: AppNativePasswordTransientFacts?
            if fixture.usesKey { transient = nil }
            else { transient = try AppNativePasswordTransientFacts(preparedTabCount: 0,
                preparedConnectionAttempts: 0, preparedIntentConsumed: false, commitCount: 1, committedTabCount: 1, intentConsumed: true, primaryProviderCalls: 1) }
            let receipt = AppMFAAuthenticationReceipt(runID: run, pid: 123, scenario: fixture, authentication: auth, keyboard: AppMFAKIFacts(budget),
                primaryProviderCalls: 1, credentialCalls: 0, transient: transient, externalPolicyProofValidated: true)
            let object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(receipt)) as? [String: Any])
            XCTAssertEqual(object["acceptanceScope"] as? String, "authentication-only-resources-unverified")
            XCTAssertNil(object["passed"]); XCTAssertNil(object["sessionID"]); XCTAssertNil(object["resourcesReturnedToBaseline"])
            XCTAssertEqual(object["externalPolicyProofValidated"] as? Bool, true)
            XCTAssertEqual(object["transient"] != nil, !fixture.usesKey)
        }
    }
    #endif
}


/// Files R2 additions only. All pre-existing 43 methods and their source prefix stay intact.
final class AppFilesManifestContractTests: XCTestCase {
    private let run = "12345678-1234-1234-1234-123456789abc"
    private var path: String { AppNativeFiniteContract.inputRoot + "/run-" + run + "/" + AppFilesManifestContract.leaf }
    private var materialPath: String { AppNativeFiniteContract.inputRoot + "/run-" + run + "/" + AppFilesManifestContract.materialLeaf }
    private var wrapper: String { "{\"schema\":1,\"runID\":\"" + run + "\",\"scenario\":\"" + AppFilesManifestContract.scenarioName + "\",\"materialContractPath\":\"" + materialPath + "\"}" }
    private func fields() -> [String: Any] {
        ["schema": 1, "runID": run, "host": "127.0.0.1", "port": 22221, "user": "fixture", "service": "keyonly",
         "generation": AppRealIntegrationContract.fixtureRoot + "/.runtime/keyonly/credentials-012345abcdef",
         "expectedBase": AppNativeFiniteIdentity.base, "expectedImage": AppNativeFiniteIdentity.image, "expectedProject": AppNativeFiniteIdentity.project,
         "expectedContainer": AppNativeFiniteIdentity.container, "expectedFingerprint": AppNativeFiniteIdentity.fingerprint,
         "collectedAt": 1000, "preparedAt": 1010, "provenanceSHA256": String(repeating: "a", count: 64),
         "knownHostsSHA256": String(repeating: "b", count: 64), "generationPublicKeySHA256": String(repeating: "c", count: 64)]
    }
    private func material(_ fields: [String: Any]) throws -> AppFilesManifestMaterial {
        try AppFilesManifestMaterial.decodeStrict(JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys]))
    }
    func testFilesClosedEntryRequiresReleaseAndShippingRejectsBeforeRuntime() throws {
        let live = ["--native-files-fixture-test", "--native-files-fixture-contract", path, "--authorized-local-fixture", "--primary-released"]
        XCTAssertEqual(try AppFilesManifestArguments.parse(live, hostProbe: true).action, .live)
        XCTAssertThrowsError(try AppFilesManifestArguments.parse(live, hostProbe: false))
        XCTAssertThrowsError(try AppFilesManifestArguments.parse(["--native-files-fixture-help"], hostProbe: false))
        let invalid: [[String]] = [Array(live.dropLast()), live + ["--primary-released"], live + ["--native-app-fixture-test"],
            live + ["--native-mfa-fixture-test"], live + ["--host", "localhost"], live + ["--nonce", String(repeating: "a", count: 32)],
            live + ["--native-files-fixture-contract", path], ["--native-files-fixture-test", "--native-files-fixture-contract"]]
        for arguments in invalid { XCTAssertThrowsError(try AppFilesManifestArguments.parse(arguments, hostProbe: true)) }
        XCTAssertEqual(try AppFilesManifestArguments.parse(["--native-files-fixture-validate", "--native-files-fixture-contract", path], hostProbe: true).action, .validate)
        XCTAssertThrowsError(try AppFilesManifestArguments.parse(["--native-files-fixture-validate", "--native-files-fixture-contract", path, "--authorized-local-fixture"], hostProbe: true))
        XCTAssertEqual(try AppFilesManifestArguments.parse(["--native-app-fixture-help"], hostProbe: true).action, .none)
    }
    func testFilesWrapperRejectsOldMaterialPathsUnknownNonceAndDuplicateFields() throws {
        let value = try AppFilesManifestContract.decodeStrict(Data(wrapper.utf8)); try value.validate(path: path)
        XCTAssertEqual(value.runID, run)
        let invalid = [wrapper.replacingOccurrences(of: materialPath, with: AppRealIntegrationContract.inputRoot + "/run-" + run + "/app-real-integration.json"),
            wrapper.replacingOccurrences(of: AppFilesManifestContract.scenarioName, with: "keyonly-controller-shell"),
            String(wrapper.dropLast()) + ",\"nonce\":\"fixed\"}", String(wrapper.dropLast()) + ",\"schema\":1}",
            wrapper.replacingOccurrences(of: "\"schema\":1", with: "\"schema\":true"), wrapper + "{}"]
        for bytes in invalid { XCTAssertThrowsError(try AppFilesManifestContract.decodeStrict(Data(bytes.utf8)).validate(path: path)) }
        for bad in [path.replacingOccurrences(of: run, with: run.uppercased()), path.replacingOccurrences(of: "/run-", with: "/../run-"), path + "/extra"] {
            XCTAssertThrowsError(try AppFilesManifestContract.runID(at: bad))
        }
    }
    func testFilesMaterialUsesApprovedIndependentKeyonlyPinAndFreshnessOnly() throws {
        let value = try material(fields()); try value.validate(path: materialPath, now: 1100, buildEpoch: 900)
        XCTAssertTrue(value.matchesTrust(host: "127.0.0.1", port: 22221, algorithm: "ssh-ed25519", fingerprint: AppNativeFiniteIdentity.fingerprint))
        XCTAssertFalse(value.matchesTrust(host: "localhost", port: 22221, algorithm: "ssh-ed25519", fingerprint: AppNativeFiniteIdentity.fingerprint))
        let wrong: [(String, Any)] = [("expectedContainer", AppRealIntegrationContract.container), ("expectedFingerprint", AppRealIntegrationContract.fingerprint),
            ("host", "localhost"), ("port", 22222), ("service", "passwordonly"), ("user", "other"),
            ("generation", AppRealIntegrationContract.fixtureRoot + "/.runtime/keyonly/credentials-../escape"), ("generationPublicKeySHA256", "unknown")]
        for (key, replacement) in wrong { var candidate = fields(); candidate[key] = replacement; XCTAssertThrowsError(try material(candidate).validate(path: materialPath, now: 1100, buildEpoch: 900)) }
        XCTAssertThrowsError(try value.validate(path: materialPath, now: 1121, buildEpoch: 900))
        XCTAssertThrowsError(try value.validate(path: materialPath, now: 1100, buildEpoch: 1001))
        var extra = fields(); extra["phase"] = "read-only"; XCTAssertThrowsError(try material(extra))
        extra = fields(); extra["privateKey"] = "not-an-input"; XCTAssertThrowsError(try material(extra))
        extra = fields(); extra["port"] = true; XCTAssertThrowsError(try material(extra))
    }
    func testFilesPublicStateAndProvenanceAreClosedAndExact() throws {
        let value = try material(fields())
        let state = try JSONSerialization.data(withJSONObject: ["version": 1, "project": value.expectedProject, "image": value.expectedBase])
        try value.validateState(state)
        XCTAssertThrowsError(try value.validateState(Data("{\"version\":1,\"project\":\"wrong\",\"image\":\"wrong\"}".utf8)))
        let origin: [String: Any] = ["base_image": value.expectedBase, "built_image_id": value.expectedImage, "service": "keyonly", "collected_at": 1000]
        try value.validateProvenance(JSONSerialization.data(withJSONObject: origin))
        var bad = origin; bad["service"] = "passwordonly"; XCTAssertThrowsError(try value.validateProvenance(JSONSerialization.data(withJSONObject: bad)))
        bad = origin; bad["collected_at"] = 999; XCTAssertThrowsError(try value.validateProvenance(JSONSerialization.data(withJSONObject: bad)))
    }
    func testFilesNonceBoundaryRejectsSiblingDotComponentsAndRootEscape() throws {
        let scope = try AppFilesManifestScope(nonce: String(repeating: "a", count: 32))
        XCTAssertTrue(scope.contains(Data(scope.root.utf8))); XCTAssertTrue(scope.contains(Data((scope.root + "/tree/a").utf8)))
        for invalid in [scope.root + "-other/a", scope.home, scope.root + "/../outside", scope.root + "//a", scope.root + "/.", scope.root + "/"] { XCTAssertFalse(scope.contains(Data(invalid.utf8))) }
        XCTAssertEqual(scope.payloads.count, 2); XCTAssertEqual(scope.payloads.map { $0.bytes }.reduce(0, +), 12288)
        XCTAssertEqual(scope.relativeDirectories.count, 2); XCTAssertEqual(scope.relativeEntries.count, 4)
        XCTAssertTrue(scope.payloads[0].relative.hasPrefix(".")); XCTAssertTrue(scope.child.contains("e\u{301}"))
        XCTAssertTrue(scope.exactTransferRisk(Data((scope.root + "/" + scope.tree).utf8)))
        XCTAssertFalse(scope.exactTransferRisk(Data((scope.root + "/" + scope.tree + "/unknown").utf8)))
        XCTAssertThrowsError(try AppFilesManifestScope(nonce: "caller-supplied"))
    }
    func testFilesPrepareDeltasKeepCumulativeProbeIOAndRejectCounterRegression() throws {
        let probe = AppFilesManifestIO(readOpen: 4, read: 8, writeOpen: 2, write: 2, mutations: 7, readBytes: 128, writeBytes: 64)
        XCTAssertEqual(try probe.delta(from: probe), .zero)
        let streamed = AppFilesManifestIO(readOpen: 4, read: 8, writeOpen: 4, write: 4, mutations: 11, readBytes: 128, writeBytes: 12352)
        let delta = try streamed.delta(from: probe)
        XCTAssertEqual(delta.writeBytes, 12288); XCTAssertEqual(delta.writeOpen, 2); XCTAssertEqual(delta.readOpen, 0)
        XCTAssertThrowsError(try probe.delta(from: streamed))
    }
}


final class AppFilesManifestScopeGuardTests: XCTestCase {
    func testCapabilityAncestorGuardRejectsDeepUnapprovedApprovedAndUnknownLeaves() throws {
        let scope = try AppFilesManifestScope(nonce: String(repeating: "a", count: 32))
        let approved = Data((scope.root + "/.openlxssh-capability.APPROVED").utf8)
        let rejected = [scope.root + "/.openlxssh-capability.UNAPPROVED/nested/victim",
            scope.root + "/.openlxssh-capability.APPROVED/nested/victim",
            scope.root + "/.openlxssh-capability.APPROVED/source/victim",
            scope.root + "/.openlxssh-capability.APPROVED/not-whitelisted",
            scope.root + "/tree/.openlxssh-capability.APPROVED/source",
            scope.root + "/.openlxssh-capability.UNAPPROVED/source"]
        for path in rejected { XCTAssertFalse(scope.allowsRemoteMutation(Data(path.utf8), approvedProbe: approved), path) }
        XCTAssertFalse(scope.allowsRemoteMutation(approved, approvedProbe: nil))
        XCTAssertFalse(scope.allowsRemoteMutation(approved, approvedProbe: Data((scope.root + "/nested/.openlxssh-capability.APPROVED").utf8)))
        XCTAssertTrue(scope.allowsRemoteMutation(approved, approvedProbe: approved))
        for leaf in ["source", "destination", "absent-target"] {
            XCTAssertTrue(scope.allowsRemoteMutation(approved + Data(("/" + leaf).utf8), approvedProbe: approved))
        }
        XCTAssertTrue(scope.allowsRemoteMutation(Data((scope.root + "/树 folder/.hidden [#; $].bin").utf8), approvedProbe: approved))
    }
    func testDescriptorPairClosesFirstWhenSecondAcquisitionThrowsAndBothWhenBodyThrows() throws {
        enum Failure: Error { case injected }
        var first: Int32 = -1
        XCTAssertThrowsError(try AppFilesManifestDescriptors.withPair(source: {
            first = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(first, 0); return first
        }, download: { throw Failure.injected }) { _, _ in XCTFail("Body cannot run after failed download acquisition") })
        errno = 0; XCTAssertEqual(fcntl(first, F_GETFD), -1); XCTAssertEqual(errno, EBADF)
        var second: Int32 = -1
        XCTAssertThrowsError(try AppFilesManifestDescriptors.withPair(source: {
            first = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(first, 0); return first
        }, download: {
            second = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            XCTAssertGreaterThanOrEqual(second, 0); return second
        }) { _, _ in throw Failure.injected })
        for fd in [first, second] { errno = 0; XCTAssertEqual(fcntl(fd, F_GETFD), -1); XCTAssertEqual(errno, EBADF) }
    }
}


#if HOST_PROBE
final class AppFilesManifestReceiptTests: XCTestCase {
    func testCompactFDWireVersionZeroAndUnknownNullColumnsAreLossless() throws {
        var snapshots = AppNativeFiniteDescriptorSnapshots()
        let entries = [AppNativeFiniteDescriptorEntry(fd: 0, type: 0, dev: 0, ino: 0, access: 0, probeStatus: .stable, role: .unknown),
            AppNativeFiniteDescriptorEntry(fd: 1, type: nil, dev: nil, ino: nil, access: nil, probeStatus: .unavailable, role: .unknown)]
        snapshots.baseline = .init(elapsedSeconds: 0, scanUpperExclusive: 8, count: 2, entries: entries)
        let bytes = try JSONEncoder().encode(AppFilesManifestDescriptorEvidence(snapshots))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        XCTAssertEqual(object["wireVersion"] as? Int, 1)
        XCTAssertEqual(object["atomic"] as? Bool, false); XCTAssertEqual(object["continuousOpenProven"] as? Bool, false)
        let row = try XCTUnwrap(object["baseline"] as? [Any]); XCTAssertEqual(row.count, 6)
        XCTAssertEqual(row[2] as? Int, 2); XCTAssertEqual(row[3] as? Bool, false); XCTAssertEqual(row[4] as? Bool, false)
        let values = try XCTUnwrap(row[5] as? [[Any]]); XCTAssertEqual(values.count, 2)
        XCTAssertEqual(values[0].count, 7); XCTAssertEqual(values[1].count, 7)
        for index in 0..<7 { XCTAssertEqual(values[0][index] as? Int, 0) }
        XCTAssertEqual(values[1][0] as? Int, 1)
        for index in 1...4 { XCTAssertTrue(values[1][index] is NSNull, "Unknown columns cannot become zero") }
        XCTAssertEqual(values[1][5] as? Int, 1); XCTAssertEqual(values[1][6] as? Int, 0)
    }

    func testExactRuntimeReceiptFitsOriginal16KiBBoundWithFullStreamsAndThreeWideFDSnapshots() throws {
        let run = "12345678-1234-1234-1234-123456789abc", id = UUID(uuidString: "12345678-1234-1234-1234-123456789ABC")!
        let scope = try AppFilesManifestScope(nonce: String(repeating: "a", count: 32))
        let remoteRoot = scope.root + "/" + scope.tree, localRoot = "/" + scope.tree
        func b64(_ path: String) -> String { Data(path.utf8).base64EncodedString() }
        var plans: [AppFilesManifestPlanEvidence] = [], jobs: [AppFilesManifestJobEvidence] = []
        for upload in [true, false] {
            let source = upload ? localRoot : remoteRoot, destination = upload ? remoteRoot : localRoot
            let names = scope.relativeEntries.map { b64(source + ($0.isEmpty ? "" : "/" + $0)) }
            plans.append(.init(planID: id, reviewID: id, serviceID: id, hostID: id, lifetime: id, revision: id,
                direction: upload ? "upload" : "download", sourceBase64: b64(source), destinationBase64: b64(destination),
                itemCount: 4, fileCount: 2, directoryCount: 2, totalBytes: 12288, namesBase64: names, remoteDelta: .zero, localDelta: .zero,
                jobsBefore: 0, jobsAfter: 0, confirmCalls: 1))
            let items = scope.relativeEntries.map { relative -> AppFilesManifestItemEvidence in
                let suffix = relative.isEmpty ? "" : "/" + relative
                let bytes = scope.payloads.first(where: { $0.relative == relative })?.bytes ?? 0
                return .init(sourceBase64: b64(source + suffix), destinationBase64: b64(destination + suffix), bytes: UInt64(bytes), acknowledgedRiskCount: 3)
            }
            var streams: [AppFilesManifestStream] = []
            for (relative, bytes) in scope.payloads {
                for _ in 0..<2 { // Include the bounded remote-source digest recheck as separate actual streams.
                    streams.append(.init(side: upload ? "source" : "remote", pathBase64: b64(source + "/" + relative), writing: false, bytes: bytes, sha256: String(repeating: "f", count: 64)))
                    streams.append(.init(side: upload ? "remote" : "download", pathBase64: b64(destination + "/" + relative), writing: true, bytes: bytes, sha256: String(repeating: "f", count: 64)))
                }
            }
            jobs.append(.init(id: id, generation: id, planID: id, batchID: id, transferredBytes: 12288, succeededFiles: 2, succeededDirectories: 2,
                items: items, remoteDelta: .zero, localDelta: .zero, streams: streams))
        }
        var descriptors = AppNativeFiniteDescriptorSnapshots()
        let entries = (0..<32).map { index in AppNativeFiniteDescriptorEntry(fd: Int32(index), type: 0o100000, dev: Int32.max,
            ino: UInt64.max, access: 0, probeStatus: .stable, role: .systemLocaleShape) }
        descriptors.baseline = .init(elapsedSeconds: 1, scanUpperExclusive: 10240, count: 32, entries: entries)
        descriptors.cleanupFirst = .init(elapsedSeconds: 2, scanUpperExclusive: 10240, count: 32, entries: entries)
        descriptors.cleanupLatest = .init(elapsedSeconds: 3, scanUpperExclusive: 10240, count: 32, entries: entries)
        let digests = scope.payloads.map { AppFilesManifestDigest(relativePathBase64: b64($0.relative), bytes: $0.bytes, sha256: String(repeating: "f", count: 64)) }
        let facts = AppFilesManifestServiceFacts(remote: .zero, local: .zero, attempts: 1, remoteServices: 1, localServices: 2, closedRemote: 1, closedLocal: 2,
            liveHandles: 0, rescuedHandles: 0, handleCloseFailures: 0, observationFailed: false, bindings: [id])
        let capability = AppFilesManifestCapability(planID: id, serverBinding: id, parentBase64: b64(scope.root),
            directoryBase64: b64(scope.root + "/.openlxssh-capability." + id.uuidString), acknowledgedRiskCount: 1, passed: true, retainedPathCount: 0, remoteDelta: .zero)
        let report = AppFilesManifestReport(runID: run, pid: 12345, checkpoint: "failure", elapsedSeconds: 90,
            passed: false, failureCode: .resources, transferOnly: true, closedAndClean: false, localStoreRemoved: false,
            nonce: scope.nonce, sourceKeyUnchanged: true, fixtureKnownHostsUnchanged: true, trustMatchedOutOfBand: true, credentialCalls: 0, capabilityPassed: true,
            serverBinding: id, capability: capability, plans: plans, jobs: jobs, source: digests, remote: digests, download: digests, services: facts,
            managerClosed: true, managerDrained: true, managerJobs: 1, managerOperations: 0, managerPreparing: 0, managerReady: 0, managerConfirming: 0,
            managerReservedEntries: 4, managerReservedMetadataBytes: 8192, remoteRootRemoved: true, localPayloadRemoved: true,
            deletePlanIDs: [id, id], descriptors: .init(descriptors), descriptorIdentityMatched: false, quit: .init())
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(report)
        XCTAssertLessThanOrEqual(bytes.count, 16 * 1024, "Actual runtime Encodable schema, including a wide failure, must fit its unchanged writer bound")
        print("Files runtime receipt encoded bytes: \(bytes.count)")
    }
}
#endif


#if HOST_PROBE
/// Real local trust owners only. No connector.connect(), network, credential or fixture inputs.
@MainActor final class AppFilesEnvironmentOwnerTests: XCTestCase {
    private func trustDescriptors(_ identity: stat) throws -> Set<Int32> {
        let limit = getdtablesize()
        guard limit > 0, limit <= 1_048_576 else { throw AppNativeFiniteFailure.resources }
        var values: Set<Int32> = []
        for fd in 0..<limit {
            var current = stat()
            if fstat(fd, &current) == 0, current.st_mode & S_IFMT == S_IFDIR,
               current.st_dev == identity.st_dev, current.st_ino == identity.st_ino { values.insert(fd) }
        }
        return values
    }
    private func identity(_ directory: URL) throws -> stat {
        var info = stat()
        guard lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR else { throw AppNativeFiniteFailure.unsafeInput }
        return info
    }
    func testDistinctEnvironmentsRetainTwoDescriptorsForSameOwnedTrustDirectory() async throws {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-env-two-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let modelEnvironment = SessionEnvironment(location: .isolated(root))
        let actualEnvironment = SessionEnvironment(location: .isolated(root))
        XCTAssertFalse(modelEnvironment === actualEnvironment)
        let modelStore = try await modelEnvironment.sharedTrustStore()
        let modelStoreRecords = try await modelStore.records(); XCTAssertTrue(modelStoreRecords.isEmpty)
        let trustIdentity = try identity(root.appendingPathComponent("Trust", isDirectory: true))
        let beforeActual = try trustDescriptors(trustIdentity)
        XCTAssertEqual(beforeActual.count, 1)
        let actualStore = try await actualEnvironment.sharedTrustStore()
        let actualStoreRecords = try await actualStore.records(); XCTAssertTrue(actualStoreRecords.isEmpty)
        XCTAssertFalse(modelStore === actualStore)
        let afterActual = try trustDescriptors(trustIdentity)
        XCTAssertEqual(afterActual.count, 2); XCTAssertTrue(beforeActual.isSubset(of: afterActual))
        XCTAssertEqual(afterActual.subtracting(beforeActual).count, 1)
        withExtendedLifetime((modelEnvironment, actualEnvironment, modelStore, actualStore)) {}
    }
    func testPrewarmingActualConnectorEnvironmentReusesExactStoreAndTrustDescriptorSet() async throws {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-env-actual-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let location = AppDataLocation.isolated(root), repository = AppRepository(location: location)
        let security = SecurityCoordinator(repository: repository, location: location)
        let actualEnvironment = SessionEnvironment(location: location)
        let connector = LibSSH2FilesConnector(repository: repository, security: security, environment: actualEnvironment)
        let connectorEnvironment = connector.environment
        XCTAssertTrue(connectorEnvironment === actualEnvironment)
        let baselineStore = try await actualEnvironment.sharedTrustStore()
        let baselineStoreRecords = try await baselineStore.records(); XCTAssertTrue(baselineStoreRecords.isEmpty)
        let trustIdentity = try identity(root.appendingPathComponent("Trust", isDirectory: true))
        let baseline = try trustDescriptors(trustIdentity)
        XCTAssertEqual(baseline.count, 1)
        let laterStore = try await connectorEnvironment.sharedTrustStore()
        let laterStoreRecords = try await laterStore.records(); XCTAssertTrue(laterStoreRecords.isEmpty)
        XCTAssertTrue(baselineStore === laterStore)
        XCTAssertEqual(try trustDescriptors(trustIdentity), baseline)
        try await security.close(); try await repository.close()
        withExtendedLifetime((actualEnvironment, connector, baselineStore, laterStore)) {}
    }
}
#endif


final class AppFilesConflictContractTests: XCTestCase {
    private let run = "12345678-1234-1234-1234-123456789abc"
    private var path: String { AppNativeFiniteContract.inputRoot + "/run-" + run + "/" + AppFilesConflictContract.leaf }
    func testConflictClosedEntryRejectsShippingMixedFlagsAndOtherScenarios() throws {
        let args = ["--native-files-conflict-test", "--native-files-conflict-contract", path, "--authorized-local-fixture", "--primary-released"]
        XCTAssertEqual(try AppFilesConflictArguments.parse(args, hostProbe: true).action, .live)
        XCTAssertThrowsError(try AppFilesConflictArguments.parse(args, hostProbe: false))
        for bad in [Array(args.dropLast()), args + ["--native-files-fixture-test"], args + ["--primary-released"], args + ["--strategy", "overwrite"]] {
            XCTAssertThrowsError(try AppFilesConflictArguments.parse(bad, hostProbe: true))
        }
        XCTAssertEqual(try AppFilesConflictArguments.parse(["--native-files-fixture-help"], hostProbe: true).action, .none)
    }
    func testConflictWrapperPreservesSameApprovedMaterialAndRejectsEndpointOrNonceOverrides() throws {
        let material = AppNativeFiniteContract.inputRoot + "/run-" + run + "/" + AppFilesManifestContract.materialLeaf
        let json = "{\"schema\":1,\"runID\":\"" + run + "\",\"scenario\":\"" + AppFilesConflictContract.scenario + "\",\"materialContractPath\":\"" + material + "\"}"
        try AppFilesConflictContract.decodeStrict(Data(json.utf8)).validate(path: path)
        for bad in [json.replacingOccurrences(of: AppFilesConflictContract.scenario, with: AppFilesManifestContract.scenarioName),
                    String(json.dropLast()) + ",\"nonce\":\"fixed\"}", String(json.dropLast()) + ",\"host\":\"localhost\"}",
                    json.replacingOccurrences(of: material, with: "/tmp/material.json")] {
            XCTAssertThrowsError(try AppFilesConflictContract.decodeStrict(Data(bad.utf8)).validate(path: path))
        }
    }
    func testConflictFinalScopeHasOnlyThreePayloadsAndExactAlternateRisk() throws {
        let scope = try AppFilesManifestScope(nonce: String(repeating: "a", count: 32))
        let payloads = scope.conflictFinalPayloads()
        XCTAssertEqual(payloads.count, 3); XCTAssertEqual(payloads.map { $0.bytes }.reduce(0, +), 16384)
        XCTAssertEqual(payloads.filter { $0.fresh }.map { $0.relative }, [scope.conflictAlternate])
        XCTAssertTrue(scope.allowsConflictRisk(Data((scope.root + "/" + scope.tree + "/" + scope.conflictAlternate).utf8)))
        XCTAssertFalse(scope.allowsConflictRisk(Data((scope.root + "/" + scope.tree + "/neighbor").utf8)))
        XCTAssertFalse(scope.allowsRemoteMutation(Data((scope.root + "-other/" + scope.conflictAlternate).utf8), approvedProbe: nil))
    }
    #if HOST_PROBE
    func testPhaseBindingIsOneShotAndSamePathFreshObservationsCannotUseSeedOwner() throws {
        var ledger = AppFilesConflictPhaseLedger()
        XCTAssertThrowsError(try ledger.begin("seed", liveHandles: 1))
        let seed = try ledger.begin("seed", liveHandles: 0), seedJob = UUID(), seedGeneration = UUID()
        XCTAssertThrowsError(try ledger.begin("fresh", liveHandles: 0))
        try ledger.bind(seed, jobID: seedJob, generation: seedGeneration)
        XCTAssertThrowsError(try ledger.bind(seed, jobID: seedJob, generation: seedGeneration))
        XCTAssertThrowsError(try ledger.finish(seed, liveHandles: 1)); try ledger.finish(seed, liveHandles: 0)
        let fresh = try ledger.begin("fresh", liveHandles: 0)
        XCTAssertNotEqual(seed, fresh); XCTAssertThrowsError(try ledger.bind(fresh, jobID: seedJob, generation: UUID()))
        let freshJob = UUID(); try ledger.bind(fresh, jobID: freshJob, generation: UUID()); try ledger.finish(fresh, liveHandles: 0)
        XCTAssertEqual(ledger.owners.first?.phaseID, seed); XCTAssertEqual(ledger.owners.last?.jobID, freshJob)
        let verify = try ledger.begin("verify", liveHandles: 0); try ledger.finish(verify, liveHandles: 0)
        XCTAssertEqual(ledger.owners.count, 3)
    }
    func testMixedOutcomeCannotBeReportedAsFullSuccessOrTwelveKiB() throws {
        try AppFilesConflictOutcome.validate(state: .succeeded, bytes: 12288, files: 2, directories: 2, skipped: 0, fresh: false)
        try AppFilesConflictOutcome.validate(state: .completedWithSkips, bytes: 4096, files: 1, directories: 2, skipped: 1, fresh: true)
        XCTAssertThrowsError(try AppFilesConflictOutcome.validate(state: .succeeded, bytes: 4096, files: 1, directories: 2, skipped: 1, fresh: true))
        XCTAssertThrowsError(try AppFilesConflictOutcome.validate(state: .completedWithSkips, bytes: 12288, files: 1, directories: 2, skipped: 1, fresh: true))
        let scope = try AppFilesManifestScope(nonce: String(repeating: "a", count: 32))
        XCTAssertEqual(AppFilesConflictPayload.data(relative: scope.payloads[0].relative, size: 4096).count, 4096)
        XCTAssertNotEqual(AppFilesConflictPayload.data(relative: scope.payloads[0].relative, size: 4096), AppFilesConflictPayload.data(relative: scope.payloads[1].relative, size: 4096))
    }
    #endif
}


#if HOST_PROBE
final class AppFilesConflictReceiptTests: XCTestCase {
    func testConflictActualWideReceiptRetainsTwoPlansMixedItemsAllPhasesAndFits16KiB() throws {
        let id = UUID(), scope = try AppFilesManifestScope(nonce: String(repeating: "a", count: 32))
        let remote = scope.root + "/" + scope.tree, source = "/" + scope.tree
        func b64(_ path: String) -> String { Data(path.utf8).base64EncodedString() }
        var plans: [AppFilesManifestPlanEvidence] = [], jobs: [AppFilesConflictJob] = []
        let phases = [UUID(), UUID()]
        for index in 0..<2 {
            plans.append(.init(planID: id, reviewID: id, serviceID: id, hostID: id, lifetime: id, revision: id, direction: "upload",
                sourceBase64: b64(source), destinationBase64: b64(remote), itemCount: 4, fileCount: 2, directoryCount: 2, totalBytes: 12288,
                namesBase64: scope.relativeEntries.map { b64(source + ($0.isEmpty ? "" : "/" + $0)) }, remoteDelta: .zero, localDelta: .zero,
                jobsBefore: 0, jobsAfter: 0, confirmCalls: 1))
            let items = scope.relativeEntries.map { relative -> AppFilesConflictItem in
                let skipped = index == 1 && relative == scope.payloads[1].relative
                let dest = index == 1 && relative == scope.payloads[0].relative ? scope.conflictAlternate : relative
                return .init(source: b64(source + (relative.isEmpty ? "" : "/" + relative)), destination: b64(remote + (dest.isEmpty ? "" : "/" + dest)),
                    state: skipped ? "skipped" : "succeeded", bytes: skipped ? 0 : UInt64(scope.payloads.first(where: { $0.relative == relative })?.bytes ?? 0), risks: 3)
            }
            var streams: [AppFilesConflictStream] = []
            for payload in index == 0 ? scope.payloads : [scope.payloads[0]] {
                for _ in 0..<2 {
                    streams.append(.init(phaseID: phases[index], value: .init(side: index == 0 ? "source" : "fresh", pathBase64: b64(source + "/" + payload.relative), writing: false, bytes: payload.bytes, sha256: String(repeating: "f", count: 64))))
                    streams.append(.init(phaseID: phases[index], value: .init(side: "remote", pathBase64: b64(remote + "/" + (index == 0 ? payload.relative : scope.conflictAlternate)), writing: true, bytes: payload.bytes, sha256: String(repeating: "f", count: 64))))
                }
            }
            jobs.append(.init(phaseID: phases[index], id: id, generation: id, planID: id, batchID: id, state: index == 0 ? "succeeded" : "completedWithSkips", transferredBytes: index == 0 ? 12288 : 4096, items: items, remoteDelta: .zero, localDelta: .zero, streams: streams))
        }
        let decisions = scope.payloads.enumerated().map { index, payload in AppFilesConflictDecision(id: id, jobID: id, generation: id, batchID: id, phaseID: phases[1],
            source: b64(source + "/" + payload.relative), destination: b64(remote + "/" + payload.relative), strategy: index == 0 ? "rename" : "skip", applyToBatch: index == 1) }
        let digests = scope.payloads.map { AppFilesManifestDigest(relativePathBase64: b64($0.relative), bytes: $0.bytes, sha256: String(repeating: "f", count: 64)) }
        let final = scope.conflictFinalPayloads().map { AppFilesManifestDigest(relativePathBase64: b64($0.relative), bytes: $0.bytes, sha256: String(repeating: "f", count: 64)) }
        let verify = UUID(), verification = scope.conflictFinalPayloads().map { AppFilesConflictStream(phaseID: verify, value: .init(side: "remote", pathBase64: b64(remote + "/" + $0.relative), writing: false, bytes: $0.bytes, sha256: String(repeating: "f", count: 64))) }
        let entries = (0..<32).map { AppNativeFiniteDescriptorEntry(fd: Int32($0), type: 0o100000, dev: Int32.max, ino: UInt64.max, access: 0, probeStatus: .stable, role: .systemLocaleShape) }
        var fd = AppNativeFiniteDescriptorSnapshots()
        fd.baseline = .init(elapsedSeconds: 1, scanUpperExclusive: 10240, count: 32, entries: entries)
        fd.cleanupFirst = .init(elapsedSeconds: 2, scanUpperExclusive: 10240, count: 32, entries: entries)
        fd.cleanupLatest = .init(elapsedSeconds: 3, scanUpperExclusive: 10240, count: 32, entries: entries)
        let services = AppFilesManifestServiceFacts(remote: .zero, local: .zero, attempts: 1, remoteServices: 1, localServices: 2, closedRemote: 1, closedLocal: 2, liveHandles: 0, rescuedHandles: 0, handleCloseFailures: 0, observationFailed: false, bindings: [id])
        let report = AppFilesConflictReport(runID: "12345678-1234-1234-1234-123456789abc", pid: 12345, checkpoint: "failure", elapsedSeconds: 90,
            passed: false, failureCode: .resources, transferOnly: true, closedAndClean: false, localStoreRemoved: false, nonce: scope.nonce,
            sourceKeyUnchanged: true, fixtureKnownHostsUnchanged: true, trustMatchedOutOfBand: true, credentialCalls: 0,
            capability: .init(planID: id, serverBinding: id, parentBase64: b64(scope.root), directoryBase64: b64(scope.root + "/.openlxssh-capability." + id.uuidString), acknowledgedRiskCount: 1, passed: true, retainedPathCount: 0, remoteDelta: .zero),
            plans: plans.map(AppFilesConflictPlan.init), jobs: jobs, decisions: decisions, seed: digests, fresh: digests, remoteVerified: final, verificationPhaseID: verify, verificationStreams: verification,
            services: services, managerClosed: true, managerDrained: true, managerJobs: 1, managerOperations: 0, remoteRootRemoved: true, localPayloadRemoved: true, deletePlanIDs: [id, id],
            descriptors: .init(fd), descriptorIdentityMatched: false, quit: .init())
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let bytes = try encoder.encode(report)
        XCTAssertLessThanOrEqual(bytes.count, 16 * 1024)
        print("Files conflict runtime wide receipt bytes: \(bytes.count)")
    }
}
#endif


final class AppFilesCancelContractTests: XCTestCase {
    private let run = "12345678-1234-1234-1234-123456789abc"
    func testCancelClosedEntryAndWrapperRejectUnreleasedMixedOverrideInputs() throws {
        let path = AppNativeFiniteContract.inputRoot + "/run-" + run + "/" + AppFilesCancelContract.leaf
        let args = ["--native-files-cancel-test", "--native-files-cancel-contract", path, "--authorized-local-fixture", "--primary-released"]
        XCTAssertEqual(try AppFilesCancelArguments.parse(args, hostProbe: true).action, .live)
        XCTAssertThrowsError(try AppFilesCancelArguments.parse(args, hostProbe: false))
        for bad in [Array(args.dropLast()), args + ["--native-files-conflict-test"], args + ["--bytes", "1073741824"]] { XCTAssertThrowsError(try AppFilesCancelArguments.parse(bad, hostProbe: true)) }
        let material = AppNativeFiniteContract.inputRoot + "/run-" + run + "/" + AppFilesManifestContract.materialLeaf
        let json = "{\"schema\":1,\"runID\":\"" + run + "\",\"scenario\":\"" + AppFilesCancelContract.scenario + "\",\"materialContractPath\":\"" + material + "\"}"
        try AppFilesCancelContract.decodeStrict(Data(json.utf8)).validate(path: path)
        XCTAssertThrowsError(try AppFilesCancelContract.decodeStrict(Data((String(json.dropLast()) + ",\"gate\":\"override\"}").utf8)))
    }
    func testCancelExactPayloadAndPhaseOwnersAreBoundedFreshAndNonResumable() throws {
        let scope = try AppFilesManifestScope(nonce: String(repeating: "a", count: 32))
        XCTAssertEqual(scope.payloads(for: .cancelRetry).map { $0.bytes }, [4096, 262144]); XCTAssertEqual(scope.payloads(for: .roundtrip).map { $0.bytes }, [4096,8192])
        #if HOST_PROBE
        var ledger = AppFilesCancelPhaseLedger()
        let a = try ledger.begin("attempt", liveHandles: 0), job = UUID(), gen = UUID()
        try ledger.bind(a, jobID: job, generation: gen); XCTAssertThrowsError(try ledger.finish(a, liveHandles: 1)); try ledger.finish(a, liveHandles: 0)
        let b = try ledger.begin("retry", liveHandles: 0); XCTAssertNotEqual(a,b)
        XCTAssertThrowsError(try ledger.bind(b, jobID: job, generation: UUID())); XCTAssertThrowsError(try ledger.bind(b, jobID: UUID(), generation: gen))
        try ledger.bind(b, jobID: UUID(), generation: UUID()); try ledger.finish(b, liveHandles: 0)
        let v = try ledger.begin("verify", liveHandles: 0); try ledger.finish(v, liveHandles: 0)
        #endif
    }
    #if HOST_PROBE
    func testGateSecondReadCancellationThrowsLocallyWithoutForwardingOrTokenReplacement() async throws {
        let gate = AppFilesCancelReadGate(), token = CancellationToken(), phase = UUID(), path = Data("/tree/second".utf8)
        try gate.arm(phaseID: phase, path: path, deadline: .now + .seconds(2))
        try await gate.beforeRead(path: path, phaseID: phase, token: token)
        let worker = Task { try await gate.beforeRead(path: path, phaseID: phase, token: token) }
        while !gate.snapshot().waiting { try await Task.sleep(for: .milliseconds(1)) }
        token.cancel()
        do { try await worker.value; XCTFail("Gate cannot forward cancelled second read") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        let facts = gate.snapshot(); XCTAssertEqual(facts.readCalls,2); XCTAssertEqual(facts.forwardedReads,1)
        XCTAssertTrue(facts.localCancellationObserved); XCTAssertFalse(facts.waiting); XCTAssertFalse(facts.aborted)
    }
    func testGateAbortDeadlineAndOtherPhaseNeverCreateFalseCancellationEvidence() async throws {
        let gate = AppFilesCancelReadGate(), token = CancellationToken(), phase = UUID(), path = Data("/tree/second".utf8)
        try gate.arm(phaseID: phase, path: path, deadline: .now + .seconds(2))
        try await gate.beforeRead(path: path, phaseID: UUID(), token: token); XCTAssertEqual(gate.snapshot().readCalls,0)
        try await gate.beforeRead(path: path, phaseID: phase, token: token)
        let worker = Task { try await gate.beforeRead(path: path, phaseID: phase, token: token) }
        while !gate.snapshot().waiting { try await Task.sleep(for: .milliseconds(1)) }; gate.abortIfWaiting()
        do { try await worker.value; XCTFail("Aborted gate cannot forward") } catch { }
        XCTAssertFalse(gate.snapshot().localCancellationObserved); XCTAssertTrue(gate.snapshot().aborted); XCTAssertFalse(gate.snapshot().waiting)
        let expired = AppFilesCancelReadGate(); try expired.arm(phaseID: phase, path: path, deadline: .now)
        try await expired.beforeRead(path: path, phaseID: phase, token: token)
        do { try await expired.beforeRead(path: path, phaseID: phase, token: token); XCTFail("Expired gate") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind,.timeout) }
        XCTAssertFalse(expired.snapshot().localCancellationObserved)
    }
    #endif
}


#if HOST_PROBE
final class AppFilesCancelReceiptTests: XCTestCase {
    func testActualCancelRetryWideReportPreservesPartialNullableErrorsAndFits16KiB() throws {
        let id=UUID(), scope=try AppFilesManifestScope(nonce:String(repeating:"a",count:32)), root=scope.root+"/"+scope.tree, local="/"+scope.tree
        func b64(_ x:String)->String { Data(x.utf8).base64EncodedString() }
        var plans:[AppFilesConflictPlan]=[], jobs:[AppFilesCancelJob]=[]
        let phases=[UUID(),UUID()]
        for index in 0..<2 {
            let plan=AppFilesManifestPlanEvidence(planID:id,reviewID:id,serviceID:id,hostID:id,lifetime:id,revision:id,direction:"upload",sourceBase64:b64(local),destinationBase64:b64(root),itemCount:4,fileCount:2,directoryCount:2,totalBytes:266240,namesBase64:scope.relativeEntries.map { b64(local+($0.isEmpty ? "" : "/"+$0)) },remoteDelta:.zero,localDelta:.zero,jobsBefore:index,jobsAfter:index,confirmCalls:1)
            plans.append(.init(plan))
            let items=scope.relativeEntries.map { relative -> AppFilesCancelItem in
                let failed=index==0 && relative==scope.payloads[1].relative, skipped=index==1 && relative==scope.payloads[0].relative
                return .init(source:b64(local+(relative.isEmpty ? "" : "/"+relative)),destination:b64(root+(relative.isEmpty ? "" : "/"+relative)),state:failed ? "failed" : (skipped ? "skipped" : "succeeded"),bytes:failed || skipped ? 0 : UInt64(scope.payloads(for:.cancelRetry).first(where:{$0.relative==relative})?.bytes ?? 0),error:failed ? "cancelled" : nil,risks:3,retained:nil)
            }
            var streams:[AppFilesConflictStream]=[]
            for payload in index==0 ? scope.payloads(for:.cancelRetry) : [scope.payloads(for:.cancelRetry)[1]] {
                let size=index==0 && payload.bytes>4096 ? 65536 : payload.bytes
                streams.append(.init(phaseID:phases[index],value:.init(side:"source",pathBase64:b64(local+"/"+payload.relative),writing:false,bytes:size,sha256:String(repeating:"f",count:64))))
                let remotePath=index==0 && payload.bytes>4096 ? root+"/"+scope.child+"/.openlxssh-transfer."+id.uuidString+".part" : root+"/"+payload.relative
                streams.append(.init(phaseID:phases[index],value:.init(side:"remote",pathBase64:b64(remotePath),writing:true,bytes:size,sha256:String(repeating:"f",count:64))))
            }
            jobs.append(.init(phaseID:phases[index],id:id,generation:id,planID:id,batchID:id,retryOf:index==0 ? nil : id,state:index==0 ? "cancelled" : "completedWithSkips",bytes:index==0 ? 69632 : 262144,error:index==0 ? "cancelled" : nil,items:items,retained:[],remoteDelta:.zero,localDelta:.zero,streams:streams))
        }
        let payloads=scope.payloads(for:.cancelRetry), source=payloads.map { AppFilesManifestDigest(relativePathBase64:b64($0.relative),bytes:$0.bytes,sha256:String(repeating:"f",count:64)) }
        let verify=UUID(), streams=payloads.map { AppFilesConflictStream(phaseID:verify,value:.init(side:"remote",pathBase64:b64(root+"/"+$0.relative),writing:false,bytes:$0.bytes,sha256:String(repeating:"f",count:64))) }
        let entries=(0..<32).map { AppNativeFiniteDescriptorEntry(fd:Int32($0),type:0o100000,dev:Int32.max,ino:UInt64.max,access:0,probeStatus:.stable,role:.systemLocaleShape) }
        var fd=AppNativeFiniteDescriptorSnapshots();fd.baseline = .init(elapsedSeconds:1,scanUpperExclusive:10240,count:32,entries:entries);fd.cleanupFirst = .init(elapsedSeconds:2,scanUpperExclusive:10240,count:32,entries:entries);fd.cleanupLatest = .init(elapsedSeconds:3,scanUpperExclusive:10240,count:32,entries:entries)
        let report=AppFilesCancelReport(runID:"12345678-1234-1234-1234-123456789abc",pid:12345,checkpoint:"failure",elapsedSeconds:90,passed:false,failureCode:.resources,transferOnly:true,closedAndClean:false,localStoreRemoved:false,nonce:scope.nonce,sourceKeyUnchanged:true,fixtureKnownHostsUnchanged:true,trustMatchedOutOfBand:true,credentialCalls:0,
            capability:.init(planID:id,serverBinding:id,parentBase64:b64(scope.root),directoryBase64:b64(scope.root+"/.openlxssh-capability."+id.uuidString),acknowledgedRiskCount:1,passed:true,retainedPathCount:0,remoteDelta:.zero),plans:plans,jobs:jobs,
            gate:.init(phaseID:phases[0],readCalls:2,forwardedReads:1,arrived:true,waiting:false,localCancellationObserved:true,aborted:false),cancelPoint:.init(phaseID:phases[0],jobID:id,generation:id,transferredBytes:69632,remoteWrittenBytes:65536,firstCommitted:true),partialVerified:source[0],secondAbsentAfterCancel:true,source:source,remoteVerified:source,verificationPhaseID:verify,verificationStreams:streams,
            services:.init(remote:.zero,local:.zero,attempts:1,remoteServices:1,localServices:1,closedRemote:1,closedLocal:1,liveHandles:0,rescuedHandles:0,handleCloseFailures:0,observationFailed:false,bindings:[id]),managerClosed:true,managerDrained:true,managerJobs:2,managerOperations:0,remoteRootRemoved:true,localPayloadRemoved:true,deletePlanIDs:[id,id],descriptors:.init(fd),descriptorIdentityMatched:false,quit:.init())
        let encoder=JSONEncoder();encoder.outputFormatting=[.sortedKeys];let bytes=try encoder.encode(report)
        XCTAssertLessThanOrEqual(bytes.count,16384);print("Files cancel retry actual wide receipt bytes: \(bytes.count)")
        let json=try XCTUnwrap(JSONSerialization.jsonObject(with:bytes) as? [String:Any]), rows=try XCTUnwrap(json["jobs"] as? [[Any]])
        XCTAssertTrue(rows[0][5] is NSNull);XCTAssertEqual(rows[0][8] as? String,"cancelled");XCTAssertTrue(rows[1][8] is NSNull)
    }
}
#endif


#if HOST_PROBE
final class AppFilesCurrentDecisionTests: XCTestCase {
    func testRetryRiskUsesExactJobMailboxWhenCancelledHistoryIsFirstAndRejectsForeignOwners() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("OpenLXSSH-AppTests-exact-risk-" + UUID().uuidString)
        let a = root.appendingPathComponent("a"), b = root.appendingPathComponent("b")
        try FileManager.default.createDirectory(at: a, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: b, withIntermediateDirectories: true)
        try Data([1, 2, 3]).write(to: a.appendingPathComponent("file"))
        let manager = TransferManager(idleTimeout: nil)
        addTeardownBlock { await manager.cancelAllAndWait(); try FileManager.default.removeItem(at: root) }
        let source = try ExactRiskLocalService(root: a), target = try ExactRiskLocalService(root: b)
        let sourceID = try await manager.registerService(source, hostID: "fixture"), targetID = try await manager.registerService(target, hostID: "fixture")
        let request = TransferRequest(hostID: "fixture", source: .init(serviceID: sourceID, path: try RemotePath("/file")), destination: .init(serviceID: targetID, path: try RemotePath("/copy")))
        let original = try await manager.enqueue(request)
        func waiting(_ id: UUID) async throws -> TransferJobSnapshot {
            for await snapshot in try await manager.updates() {
                if let job = snapshot.jobs.first(where: { $0.id == id && $0.pendingDecision != nil }) { return job }
            }
            throw AppNativeFiniteFailure.operation
        }
        let first = try await waiting(original), oldDecision = try XCTUnwrap(first.pendingDecision)
        _ = await manager.cancel(original)
        for await snapshot in try await manager.updates() {
            if snapshot.jobs.first(where: { $0.id == original })?.state == .cancelled { break }
        }
        let retryID = try await manager.retry(original), retry = try await waiting(retryID), decision = try XCTUnwrap(retry.pendingDecision)
        let jobs = await manager.snapshot().jobs
        XCTAssertEqual(jobs.count, 2); XCTAssertEqual(jobs[0].id, original); XCTAssertEqual(jobs[0].state, .cancelled)
        XCTAssertEqual(jobs[1].id, retryID); XCTAssertNotEqual(first.generation, retry.generation)
        XCTAssertTrue(AppFilesCurrentDecision.matches(jobs, jobID: retryID, generation: retry.generation, decision: decision))
        XCTAssertTrue(AppFilesCurrentDecision.matches(Array(jobs.reversed()), jobID: retryID, generation: retry.generation, decision: decision))
        XCTAssertFalse(AppFilesCurrentDecision.matches(jobs, jobID: original, generation: first.generation, decision: oldDecision))
        XCTAssertFalse(AppFilesCurrentDecision.matches(jobs, jobID: retryID, generation: first.generation, decision: decision))
        XCTAssertFalse(AppFilesCurrentDecision.matches(jobs, jobID: retryID, generation: retry.generation, decision: oldDecision))
        guard case .risk = decision.question else { XCTFail("Actual manager must be awaiting a risk"); return }
        let accepted = await manager.resolve(decision, answer: .risk(accepted: true)); XCTAssertTrue(accepted)
        var next: TransferJobSnapshot?
        for await snapshot in try await manager.updates() {
            if let job = snapshot.jobs.first(where: { $0.id == retryID }), let pending = job.pendingDecision, pending.id != decision.id { next = job; break }
        }
        let nextJob = try XCTUnwrap(next), nextDecision = try XCTUnwrap(nextJob.pendingDecision), afterReply = await manager.snapshot().jobs
        XCTAssertEqual(nextJob.generation, retry.generation); XCTAssertEqual(nextDecision.jobID, retryID)
        XCTAssertFalse(AppFilesCurrentDecision.matches(afterReply, jobID: retryID, generation: retry.generation, decision: decision), "Same job/generation but stale request must be rejected")
        XCTAssertTrue(AppFilesCurrentDecision.matches(afterReply, jobID: retryID, generation: retry.generation, decision: nextDecision))
        _ = await manager.resolve(nextDecision, answer: .risk(accepted: false))
    }
}
/// Real LocalFileService bytes; only traversal capability asks the real manager for a risk.
private actor ExactRiskLocalService: RemoteFileService {
    nonisolated let capabilities = FileServiceCapabilities(traversal: .remoteComponentLstat, exclusiveCreate: true, noReplace: .atomicLocal, canAttemptAtomicReplace: true)
    let base: LocalFileService
    init(root: URL) throws { base = try LocalFileService(root: root) }
    func initialDirectory(token: CancellationToken) async throws -> RemotePath { try await base.initialDirectory(token: token) }
    func list(_ p: RemotePath, token: CancellationToken) async throws -> [DirectoryEntry] { try await base.list(p, token: token) }
    func lstat(_ p: RemotePath, token: CancellationToken) async throws -> FileAttributes { try await base.lstat(p, token: token) }
    func fstat(_ h: FileHandleID, token: CancellationToken) async throws -> FileAttributes? { try await base.fstat(h, token: token) }
    func open(_ p: RemotePath, mode: OpenMode, token: CancellationToken) async throws -> FileHandleID { try await base.open(p, mode: mode, token: token) }
    func read(_ h: FileHandleID, maxBytes: Int, token: CancellationToken) async throws -> Data { try await base.read(h, maxBytes: maxBytes, token: token) }
    func write(_ h: FileHandleID, data: Data, token: CancellationToken) async throws -> Int { try await base.write(h, data: data, token: token) }
    func finish(_ h: FileHandleID, token: CancellationToken) async throws { try await base.finish(h, token: token) }
    func closeHandle(_ h: FileHandleID) async throws { try await base.closeHandle(h) }
    func mkdir(_ p: RemotePath, token: CancellationToken) async throws { try await base.mkdir(p, token: token) }
    func rename(_ p: RemotePath, to q: RemotePath, mode: RenameMode, token: CancellationToken) async throws { try await base.rename(p, to: q, mode: mode, token: token) }
    func commit(_ p: RemotePath, to q: RemotePath, request: CommitRequest, token: CancellationToken) async throws { try await base.commit(p, to: q, request: request, token: token) }
    func remove(_ p: RemotePath, directory: Bool, token: CancellationToken) async throws { try await base.remove(p, directory: directory, token: token) }
    nonisolated func cancel() { base.cancel() }
    func close() async { await base.close() }
}
#endif

#if HOST_PROBE
/// Trust-only pure models. No AppKit, files, key parser/tool, credentials or connections.
final class AppTrustContractTests: XCTestCase {
    private let id = "12345678-1234-1234-1234-123456789abc"
    private var root: String { AppNativeFiniteContract.inputRoot + "/run-" + id }
    private var path: String { root + "/" + AppTrustContract.leaf }
    private var materialPath: String { root + "/" + AppTrustContract.materialLeaf }
    private func wrapper(_ scenario: AppTrustScenario = .once) -> String {
        "{\"schema\":1,\"runID\":\"" + id + "\",\"scenario\":\"" + scenario.rawValue + "\",\"materialContractPath\":\"" + materialPath + "\"}"
    }
    private func bytes(_ digit: String) -> AppTrustPublicBytes { .init(presence: "present", bytes: 54, sha256: String(repeating: digit, count: 64)) }
    private func owner() -> AppTrustOwner { .init(tabID: UUID(), sessionID: UUID(), generation: 1) }
    private func fact(_ ordinal: Int, pending: Bool = true) throws -> AppTrustAttemptFacts {
        var value = AppTrustAttemptFacts(attemptID: UUID(), ordinal: ordinal)
        value.connectionCalls = 1
        value.pendingCalls = pending ? 1 : 0; value.pendingRequestID = pending ? UUID() : nil
        if pending {
            value.request(stage: "pending", id: value.pendingRequestID)
            try value.capturePreAcceptance(promptID: try XCTUnwrap(value.pendingRequestID))
        }
        value.primary(sessionID: UUID(), requestID: UUID()); value.shellSessions = 1
        value.authentication = AppNativeFiniteAuthFacts(keyonly: try AppNativeFiniteAuthentication([
            .advertised(password: false, publicKey: true, keyboardInteractive: false), .primaryStarted(.publicKey),
            .primaryResult(.publicKey, code: 0, authenticated: true), .authenticated, .shellReady]))
        value.stages = ["advertised", "primaryStarted.publicKey", "primaryResult.publicKey", "authenticated", "shellReady"]
        return value
    }
    private func points(_ scenario: AppTrustScenario, count: Int = 2) -> [AppTrustStorePoint] {
        var result = [AppTrustStorePoint(label: "initialized", records: 0, publicBytes: bytes("a"))]
        if scenario == .changed { result.append(.init(label: "seeded-wrong-public-pin", records: 1, publicBytes: bytes("b"))) }
        for ordinal in 1...count { result.append(.init(label: "attempt-\(ordinal)", records: scenario == .once ? 0 : 1, publicBytes: bytes(scenario == .once ? "a" : "b"))) }
        return result
    }
    func testTrustFlagsAreIndependentClosedAndShippingRejected() throws {
        let live = ["--native-trust-fixture-test", "--native-trust-fixture-contract", path, "--authorized-local-fixture", "--primary-released"]
        XCTAssertEqual(try AppTrustArguments.parse(live, hostProbe: true).action, .live)
        XCTAssertEqual(try AppTrustArguments.parse(["--native-trust-fixture-help"], hostProbe: true).action, .help)
        XCTAssertEqual(try AppTrustArguments.parse(["--native-trust-fixture-validate", "--native-trust-fixture-contract", path], hostProbe: true).action, .validate)
        XCTAssertEqual(try AppTrustArguments.parse(["--native-app-fixture-help"], hostProbe: true).action, .none)
        for value in [live, ["--native-trust-fixture-help"], ["--native-trust-fixture-unknown"]] { XCTAssertThrowsError(try AppTrustArguments.parse(value, hostProbe: false)) }
        for value in [Array(live.dropLast()), live + ["--primary-released"], live + ["--native-app-fixture-test"], live + ["--native-trust-fixture-contract", path],
                      ["--native-trust-fixture-validate", "--native-trust-fixture-contract", path, "--primary-released"]] {
            XCTAssertThrowsError(try AppTrustArguments.parse(value, hostProbe: true))
        }
    }
    func testTrustWrapperHasExactlyFourKeysThreeScenariosAndItsOwnFixedLeaves() throws {
        for scenario in AppTrustScenario.allCases { let value = try AppTrustContract.decodeStrict(Data(wrapper(scenario).utf8)); try value.validate(path: path); XCTAssertEqual(value.scenario, scenario) }
        for text in [wrapper().replacingOccurrences(of: "\"schema\":1", with: "\"schema\":true"), wrapper().replacingOccurrences(of: "\"schema\":1", with: "\"schema\":1.0"),
                     String(wrapper().dropLast()) + ",\"schema\":1}", String(wrapper().dropLast()) + ",\"endpoint\":\"override\"}", wrapper() + "{}",
                     wrapper().replacingOccurrences(of: AppTrustScenario.once.rawValue, with: "keyonly-controller-shell")] {
            XCTAssertThrowsError(try AppTrustContract.decodeStrict(Data(text.utf8)))
        }
        for other in [path.replacingOccurrences(of: id, with: id.uppercased()), path.replacingOccurrences(of: AppTrustContract.leaf, with: "native-app-fixture.json"), path + "/extra", "/tmp/run-" + id + "/" + AppTrustContract.leaf] { XCTAssertThrowsError(try AppTrustContract.runID(at: other)) }
        XCTAssertThrowsError(try AppTrustContract.decodeStrict(Data(wrapper().replacingOccurrences(of: AppTrustContract.materialLeaf, with: "native-files-material.json").utf8)).validate(path: path))
    }
    func testTrustMaterialUsesApprovedPublicSchemaButOnlyTrustMaterialPath() throws {
        let binding = AppFilesManifestMaterial(schema: 1, runID: id, host: "127.0.0.1", port: 22221, user: "fixture", service: "keyonly",
            generation: AppRealIntegrationContract.fixtureRoot + "/.runtime/keyonly/credentials-012345abcdef", expectedBase: AppNativeFiniteIdentity.base,
            expectedImage: AppNativeFiniteIdentity.image, expectedProject: AppNativeFiniteIdentity.project, expectedContainer: AppNativeFiniteIdentity.container,
            expectedFingerprint: AppNativeFiniteIdentity.fingerprint, collectedAt: 1000, preparedAt: 1010,
            provenanceSHA256: String(repeating: "a", count: 64), knownHostsSHA256: String(repeating: "b", count: 64), generationPublicKeySHA256: String(repeating: "c", count: 64))
        let value = AppTrustMaterial(binding: binding)
        try value.validate(path: materialPath, now: 1100, buildEpoch: 900)
        XCTAssertThrowsError(try value.validate(path: materialPath.replacingOccurrences(of: AppTrustContract.materialLeaf, with: "native-files-material.json"), now: 1100, buildEpoch: 900))
        XCTAssertThrowsError(try value.validate(path: materialPath, now: 1121, buildEpoch: 900))
        XCTAssertThrowsError(try value.validate(path: materialPath, now: 1100, buildEpoch: 1001))
        XCTAssertThrowsError(try value.validate(path: materialPath.replacingOccurrences(of: id, with: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), now: 1100, buildEpoch: 900))
        let fields: [String: Any] = ["schema": 1, "runID": id, "host": binding.host, "port": binding.port, "user": binding.user, "service": binding.service,
            "generation": binding.generation, "expectedBase": binding.expectedBase, "expectedImage": binding.expectedImage, "expectedProject": binding.expectedProject,
            "expectedContainer": binding.expectedContainer, "expectedFingerprint": binding.expectedFingerprint, "collectedAt": binding.collectedAt, "preparedAt": binding.preparedAt,
            "provenanceSHA256": binding.provenanceSHA256, "knownHostsSHA256": binding.knownHostsSHA256, "generationPublicKeySHA256": binding.generationPublicKeySHA256]
        let decoded = try AppTrustMaterial.decodeStrict(JSONSerialization.data(withJSONObject: fields)); try decoded.validate(path: materialPath, now: 1100, buildEpoch: 900)
        for (key, replacement) in [("host", "localhost"), ("expectedFingerprint", "SHA256:unapproved"), ("expectedContainer", String(repeating: "a", count: 64)),
                                   ("service", "passwordonly"), ("generation", binding.generation + "/../escape")] {
            var changed = fields; changed[key] = replacement
            XCTAssertThrowsError(try AppTrustMaterial.decodeStrict(JSONSerialization.data(withJSONObject: changed)).validate(path: materialPath, now: 1100, buildEpoch: 900))
        }
        var coerced = fields; coerced["port"] = "22221"
        XCTAssertThrowsError(try AppTrustMaterial.decodeStrict(JSONSerialization.data(withJSONObject: coerced)))
        var extra = fields; extra["phase"] = "read-only"
        XCTAssertThrowsError(try AppTrustMaterial.decodeStrict(JSONSerialization.data(withJSONObject: extra)))
    }
    func testOnceRequiresTwoRealFreshOwnersTwoPromptsAndUnchangedPublicStoreBytes() throws {
        let facts = try [fact(1), fact(2)], owners = [owner(), owner()]
        try AppTrustAcceptance.validate(.once, facts: facts, owners: owners, beforeInitialization: .missing, points: points(.once))
        var bad = points(.once); bad[2] = .init(label: "attempt-2", records: 0, publicBytes: bytes("c"))
        XCTAssertThrowsError(try AppTrustAcceptance.validate(.once, facts: facts, owners: owners, beforeInitialization: .missing, points: bad))
        XCTAssertThrowsError(try AppTrustAcceptance.validate(.once, facts: facts, owners: owners, beforeInitialization: bytes("a"), points: points(.once)))
        XCTAssertThrowsError(try AppTrustPublicBytes(presence: "missing", bytes: 0, sha256: String(repeating: "a", count: 64)).validate())
    }
    func testPersistentRequiresOnePromptOneRecordAndOnlyFirstStoreMutation() throws {
        let facts = try [fact(1), fact(2, pending: false)], owners = [owner(), owner()]
        try AppTrustAcceptance.validate(.persistent, facts: facts, owners: owners, beforeInitialization: .missing, points: points(.persistent))
        XCTAssertThrowsError(try AppTrustAcceptance.validate(.persistent, facts: [facts[0], try fact(2)], owners: owners, beforeInitialization: .missing, points: points(.persistent)))
        var bad = points(.persistent); bad[2] = .init(label: "attempt-2", records: 1, publicBytes: bytes("c"))
        XCTAssertThrowsError(try AppTrustAcceptance.validate(.persistent, facts: facts, owners: owners, beforeInitialization: .missing, points: bad))
    }
    func testChangedRequiresExactPublicPinFactAndZeroPrimaryKeyboardAndShell() throws {
        var value = AppTrustAttemptFacts(attemptID: UUID(), ordinal: 1); value.connectionCalls = 1
        value.changed = .init(expectedFingerprint: AppTrustPublicPin.fingerprint, presentedFingerprint: AppNativeFiniteIdentity.fingerprint, exactEndpoint: true, exactAlgorithm: true)
        value.errorKind = "untrusted"; value.errorOperation = "host-key"
        let owners = [owner()], store = points(.changed, count: 1)
        try AppTrustAcceptance.validate(.changed, facts: [value], owners: owners, beforeInitialization: .missing, points: store)
        for branch in 0..<6 {
            var bad = value
            if branch == 0 { bad.primary(sessionID: UUID(), requestID: UUID()) }
            if branch == 1 { bad.keyboardCalls = 1 }
            if branch == 2 { bad.pendingCalls = 1; bad.pendingRequestID = UUID() }
            if branch == 3 { bad.changed = .init(expectedFingerprint: "SHA256:other", presentedFingerprint: AppNativeFiniteIdentity.fingerprint, exactEndpoint: true, exactAlgorithm: true) }
            if branch == 4 { bad.changed = .init(expectedFingerprint: AppTrustPublicPin.fingerprint, presentedFingerprint: AppNativeFiniteIdentity.fingerprint, exactEndpoint: false, exactAlgorithm: true) }
            if branch == 5 { bad.errorOperation = "host-key-changed" }
            XCTAssertThrowsError(try AppTrustAcceptance.validate(.changed, facts: [bad], owners: owners, beforeInitialization: .missing, points: store))
        }
        var callback = value; callback.changedCallbacks = 1; callback.request(stage: "changed", id: nil)
        callback.recordCallbackChange(try XCTUnwrap(value.changed))
        try AppTrustAcceptance.validate(.changed, facts: [callback], owners: owners, beforeInitialization: .missing, points: store)
        var mutated = store; mutated[2] = .init(label: "attempt-1", records: 1, publicBytes: bytes("c"))
        XCTAssertThrowsError(try AppTrustAcceptance.validate(.changed, facts: [value], owners: owners, beforeInitialization: .missing, points: mutated))
    }
    func testAttemptObserverCountsAndOwnerReplayCannotBeSubstitutedForActualCalls() throws {
        var first = try fact(1); first.primary(sessionID: UUID(), requestID: UUID())
        XCTAssertEqual(first.primaryCalls, 2); XCTAssertTrue(first.observationFailed)
        let second = try fact(2), owners = [owner(), owner()]
        XCTAssertThrowsError(try AppTrustAcceptance.validate(.once, facts: [first, second], owners: owners, beforeInitialization: .missing, points: points(.once)))
        let valid = try [fact(1), fact(2)]
        XCTAssertThrowsError(try AppTrustAcceptance.validate(.once, facts: valid, owners: [owners[0], owners[0]], beforeInitialization: .missing, points: points(.once)))
        var replay = valid[1]; replay.primaryRequestID = valid[0].primaryRequestID
        XCTAssertThrowsError(try AppTrustAcceptance.validate(.once, facts: [valid[0], replay], owners: owners, beforeInitialization: .missing, points: points(.once)))
        var reordered = valid[1]; reordered.requests.reverse()
        XCTAssertThrowsError(try AppTrustAcceptance.validate(.once, facts: [valid[0], reordered], owners: owners, beforeInitialization: .missing, points: points(.once)))
        var overflow = valid[0]; for _ in 0..<9 { overflow.request(stage: "keyboard", id: nil) }
        XCTAssertTrue(overflow.observationFailed); XCTAssertEqual(overflow.requests.count, 8)
    }
    func testEarlyReceiptRemainsResourceUnverifiedAndCloseNeverRenewsSharedDeadline() throws {
        let start = ContinuousClock.now, active = start + .seconds(45)
        XCTAssertEqual(AppTrustAcceptance.closeDeadline(now: start, active: active), start + .seconds(2))
        XCTAssertEqual(AppTrustAcceptance.closeDeadline(now: start + .seconds(44), active: active), active)
        let facts = try [fact(1)], owners = [owner()], store = points(.once, count: 1)
        try AppTrustAcceptance.validate(.once, facts: facts, owners: owners, beforeInitialization: .missing, points: store)
        let receipt = AppTrustAuthenticationReceipt(runID: id, pid: 12345, scenario: .once, ordinal: 1, beforeInitialization: .missing, points: store, facts: facts, owners: owners, credentialCalls: 0)
        let data = try JSONEncoder().encode(receipt), json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(json["acceptanceScope"] as? String, "trust-authentication-only-resources-unverified"); XCTAssertNil(json["passed"])
        XCTAssertEqual(AppTrustScenario.allCases.map(\.attempts), [2, 2, 1]); XCTAssertLessThan(data.count, 16384)
    }
    func testPreAcceptanceSamplesRejectEveryProviderPrecallAndRequireExactSinglePrompt() throws {
        let promptID = UUID()
        func pending() -> AppTrustAttemptFacts {
            var value = AppTrustAttemptFacts(attemptID: UUID(), ordinal: 1)
            value.connectionCalls = 1; value.pendingCalls = 1; value.pendingRequestID = promptID
            value.request(stage: "pending", id: promptID); return value
        }
        var positive = pending(); try positive.capturePreAcceptance(promptID: promptID)
        let sample = try XCTUnwrap(positive.preAcceptanceProviderZero)
        XCTAssertEqual(sample.primaryCalls, 0); XCTAssertEqual(sample.keyboardCalls, 0); XCTAssertEqual(sample.shellSessions, 0)
        XCTAssertEqual(sample.pendingCalls, 1); XCTAssertEqual(sample.pendingRequestID, promptID)
        XCTAssertThrowsError(try positive.capturePreAcceptance(promptID: promptID), "A later sample cannot overwrite the pre-acceptance point")
        for branch in 0..<6 {
            var bad = pending()
            if branch == 0 { bad.primary(sessionID: UUID(), requestID: UUID()) }
            if branch == 1 { bad.keyboardCalls = 1 }
            if branch == 2 { bad.shellSessions = 1 }
            if branch == 3 { bad.pendingCalls = 0 }
            if branch == 4 { bad.pendingCalls = 2 }
            if branch == 5 { bad.pendingRequestID = UUID() }
            XCTAssertThrowsError(try bad.capturePreAcceptance(promptID: promptID), "branch \(branch)")
            XCTAssertNotNil(bad.preAcceptanceProviderZero, "The actual failing counts remain evidence")
        }
        var missing = try fact(1); missing.preAcceptanceProviderZero = nil
        XCTAssertThrowsError(try AppTrustAcceptance.validate(.once, facts: [missing], owners: [owner()], beforeInitialization: .missing, points: points(.once, count: 1)))
        var forged = try fact(1)
        forged.preAcceptanceProviderZero = .init(primaryCalls: -1, keyboardCalls: 0, shellSessions: 0, pendingCalls: 1, pendingRequestID: forged.pendingRequestID)
        XCTAssertThrowsError(try AppTrustAcceptance.validate(.once, facts: [forged], owners: [owner()], beforeInitialization: .missing, points: points(.once, count: 1)))
        let entries = (0..<32).map { AppNativeFiniteDescriptorEntry(fd: Int32($0), type: 0o100000, dev: Int32.max, ino: UInt64.max, access: 0, probeStatus: .stable, role: .unknown) }
        var descriptors = AppNativeFiniteDescriptorSnapshots()
        descriptors.baseline = .init(elapsedSeconds: 1, scanUpperExclusive: 10240, count: 32, entries: entries)
        descriptors.cleanupFirst = .init(elapsedSeconds: 2, scanUpperExclusive: 10240, count: 32, entries: entries)
        descriptors.cleanupLatest = .init(elapsedSeconds: 3, scanUpperExclusive: 10240, count: 32, entries: entries)
        let weak = AppTrustWeakFacts(tabAlive: false, driverAlive: false, viewAlive: false)
        let terminal = AppNativeFiniteTerminalPlan.Evidence(ack: true, pty: true, resized113x37: true, completed: true, observedRows: 37, observedColumns: 113)
        let attempts = try (1...2).map { ordinal in AppTrustAttemptReport(facts: try fact(ordinal), owner: owner(), terminal: terminal,
            closeDisposition: "closed", canonicalDrained: true, queueEmpty: true, weakAfterClose: weak, weakNow: weak) }
        let report = AppTrustReport(runID: id, pid: Int32.max, scenario: .once, checkpoint: "ready-for-native-quit", elapsedSeconds: 90,
            passed: false, failureCode: .resources, closedAndClean: false, localStoreRemoved: false, authenticationComplete: true,
            beforeInitialization: .missing, points: points(.once), attempts: attempts, sourceKeyScope: "fixture-client-key-memory-comparison-only",
            sourceKeyUnchanged: true, fixtureKnownHostsUnchanged: true, credentialCalls: 0, descriptorBaseline: 32, descriptorAfter: 32,
            descriptorIdentityMatched: false, descriptors: .init(descriptors), registryBaselineActive: 0, registryBaselineRetired: 0,
            registryAfterActive: 0, registryAfterRetired: 0, quit: .init())
        let data = try JSONEncoder().encode(report)
        XCTAssertLessThanOrEqual(data.count, 16 * 1024)
        let encoded = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual((encoded["attempts"] as? [Any])?.count, 2); XCTAssertEqual(encoded["passed"] as? Bool, false)
        print("Trust actual wide receipt bytes: \(data.count)")
    }
    func testChangedCallbackCannotReplaceTypedErrorAndMismatchedSourcesAreRejected() throws {
        let exact = AppTrustChangedFact(expectedFingerprint: AppTrustPublicPin.fingerprint, presentedFingerprint: AppNativeFiniteIdentity.fingerprint, exactEndpoint: true, exactAlgorithm: true)
        let wrong = AppTrustChangedFact(expectedFingerprint: "SHA256:foreign", presentedFingerprint: AppNativeFiniteIdentity.fingerprint, exactEndpoint: true, exactAlgorithm: true)
        var ordinary = AppTrustAttemptFacts(attemptID: UUID(), ordinal: 1)
        ordinary.connectionCalls = 1; ordinary.errorKind = "untrusted"; ordinary.errorOperation = "host-key"
        let owners = [owner()], store = points(.changed, count: 1)
        XCTAssertThrowsError(try AppTrustAcceptance.validate(.changed, facts: [ordinary], owners: owners, beforeInitialization: .missing, points: store))
        for count in [-1, Int.max] {
            var invalidCount = ordinary; invalidCount.recordTypedChange(exact); invalidCount.changedCallbacks = count
            XCTAssertThrowsError(try AppTrustAcceptance.validate(.changed, facts: [invalidCount], owners: owners, beforeInitialization: .missing, points: store))
        }
        var callbackOnly = ordinary; callbackOnly.changedCallbacks = 1; callbackOnly.request(stage: "changed", id: nil); callbackOnly.recordCallbackChange(exact)
        XCTAssertNil(callbackOnly.changed)
        XCTAssertThrowsError(try AppTrustAcceptance.validate(.changed, facts: [callbackOnly], owners: owners, beforeInitialization: .missing, points: store))
        var typedOnly = ordinary; typedOnly.recordTypedChange(exact)
        try AppTrustAcceptance.validate(.changed, facts: [typedOnly], owners: owners, beforeInitialization: .missing, points: store)
        var both = callbackOnly; both.recordTypedChange(exact)
        try AppTrustAcceptance.validate(.changed, facts: [both], owners: owners, beforeInitialization: .missing, points: store)
        var callbackFirst = callbackOnly; callbackFirst.recordTypedChange(wrong)
        XCTAssertTrue(callbackFirst.observationFailed)
        XCTAssertThrowsError(try AppTrustAcceptance.validate(.changed, facts: [callbackFirst], owners: owners, beforeInitialization: .missing, points: store))
        var typedFirst = typedOnly; typedFirst.changedCallbacks = 1; typedFirst.request(stage: "changed", id: nil); typedFirst.recordCallbackChange(wrong)
        XCTAssertTrue(typedFirst.observationFailed)
        XCTAssertThrowsError(try AppTrustAcceptance.validate(.changed, facts: [typedFirst], owners: owners, beforeInitialization: .missing, points: store))
    }
}
#endif

final class AppConcurrentContractTests: XCTestCase {
    private let run = "12345678-1234-1234-1234-123456789abc"
    private var path: String { AppNativeFiniteContract.inputRoot + "/run-" + run + "/" + AppConcurrentContract.leaf }
    private var materialPath: String { AppNativeFiniteContract.inputRoot + "/run-" + run + "/" + AppConcurrentContract.materialLeaf }
    func testConcurrentClosedFlagsAndFourKeysNeverAdoptSingleCaseInputs() throws {
        let live = ["--native-concurrent-fixture-test", "--native-concurrent-fixture-contract", path, "--authorized-local-fixture", "--primary-released"]
        XCTAssertEqual(try AppConcurrentArguments.parse(live, hostProbe: true).action, .live)
        XCTAssertEqual(try AppConcurrentArguments.parse(["--native-concurrent-fixture-help"], hostProbe: true).action, .help)
        XCTAssertEqual(try AppConcurrentArguments.parse(["--native-mfa-fixture-help"], hostProbe: true).action, .none)
        XCTAssertThrowsError(try AppConcurrentArguments.parse(live, hostProbe: false))
        for value in [Array(live.dropLast()), live + ["--native-mfa-fixture-test"], live + ["--primary-released"], live + ["--port", "22224"]] {
            XCTAssertThrowsError(try AppConcurrentArguments.parse(value, hostProbe: true))
        }
        let json = "{\"schema\":1,\"runID\":\"" + run + "\",\"scenario\":\"keyki-concurrent-cancel-a\",\"materialContractPath\":\"" + materialPath + "\"}"
        try AppConcurrentContract.decodeStrict(Data(json.utf8)).validate(path: path)
        XCTAssertThrowsError(try AppMFAContract.decodeStrict(Data(json.utf8)))
        XCTAssertThrowsError(try AppTrustContract.decodeStrict(Data(json.utf8)))
        for changed in [json.replacingOccurrences(of: "keyki-concurrent-cancel-a", with: "passwordki-concurrent-cancel-a"),
                        json.replacingOccurrences(of: "\"schema\":1", with: "\"schema\":true"), String(json.dropLast()) + ",\"scenario\":\"keyki-concurrent-cancel-a\"}"] {
            XCTAssertThrowsError(try AppConcurrentContract.decodeStrict(Data(changed.utf8)))
        }
        XCTAssertThrowsError(try AppConcurrentContract.decodeStrict(Data(json.replacingOccurrences(of: AppConcurrentContract.materialLeaf, with: AppMFAContract.materialLeaf).utf8)).validate(path: path))
        XCTAssertThrowsError(try AppConcurrentContract.runID(at: path.replacingOccurrences(of: run, with: run.uppercased())))
        XCTAssertThrowsError(try AppConcurrentContract.runID(at: path.replacingOccurrences(of: AppConcurrentContract.leaf, with: AppMFAContract.leaf)))
    }
    func testConcurrentMaterialHasNewLeafButRetainsExactKeyKIPolicyBinding() throws {
        let value = AppMFAMaterialContract(fixture: .keyKI, schema: 1, runID: run, host: "127.0.0.1", port: 22223, user: "fixture", service: "key-kbd", key: "edplain",
            generation: AppRealIntegrationContract.fixtureRoot + "/.runtime/key-kbd/credentials-012345abcdef", expectedBase: AppNativePasswordIdentity.base,
            expectedImage: AppNativePasswordIdentity.image, expectedProject: AppNativePasswordIdentity.project, expectedContainer: AppMFAFixture.keyKI.container,
            expectedFingerprint: AppMFAFixture.keyKI.fingerprint, networkID: AppNativePasswordIdentity.network, context: AppNativePasswordIdentity.context,
            endpoint: AppNativePasswordIdentity.endpoint, provenanceSHA256: String(repeating: "a", count: 64), knownHostsSHA256: String(repeating: "b", count: 64),
            policyProofSHA256: String(repeating: "c", count: 64), collectedAt: 1000, preparedAt: 1010, generationPublicKeySHA256: String(repeating: "d", count: 64))
        let material = AppConcurrentMaterial(binding: value)
        try material.validate(path: materialPath, now: 1100, buildEpoch: 900)
        XCTAssertThrowsError(try value.validate(path: materialPath, now: 1100, buildEpoch: 900), "Old single-MFA path validator stays closed")
        XCTAssertThrowsError(try material.validate(path: materialPath.replacingOccurrences(of: AppConcurrentContract.materialLeaf, with: AppMFAContract.materialLeaf), now: 1100, buildEpoch: 900))
        XCTAssertThrowsError(try material.validate(path: materialPath, now: 1121, buildEpoch: 900))
        XCTAssertThrowsError(try material.validate(path: materialPath, now: 1100, buildEpoch: 1001))
    }
    func testTicketLedgerBConnectsBeforeAWithoutArrivalOrderAndRejectsThirdDuplicateForeign() throws {
        var ledger = AppConcurrentTicketLedger(); let host = UUID(), appA = UUID(), appB = UUID()
        let a = try ledger.prepare(hostID: host, appSessionID: appA), b = try ledger.prepare(hostID: host, appSessionID: appB)
        XCTAssertEqual(a.appSessionID, appA); XCTAssertEqual(b.appSessionID, appB); XCTAssertNotEqual(a.id, b.id)
        try ledger.connect(b); try ledger.primary(b); try ledger.connect(a); try ledger.primary(a); try ledger.requireTwo()
        XCTAssertThrowsError(try ledger.connect(a)); XCTAssertThrowsError(try ledger.primary(b))
        XCTAssertThrowsError(try ledger.prepare(hostID: host, appSessionID: UUID()))
        XCTAssertThrowsError(try ledger.connect(.init(id: UUID(), hostID: host, appSessionID: appA)))
        var other = AppConcurrentTicketLedger(); _ = try other.prepare(hostID: host, appSessionID: appA)
        XCTAssertThrowsError(try other.prepare(hostID: host, appSessionID: appA))
        XCTAssertThrowsError(try other.prepare(hostID: UUID(), appSessionID: appB))
    }
    func testPairAndReplyLeaseRequireExactAppOwnerFixtureAndRequestAfterAwait() throws {
        let host = UUID(), appA = UUID(), appB = UUID()
        let a = AppConcurrentOwner(role: .a, ticketID: UUID(), hostID: host, tabID: appA, appSessionID: appA, requestID: UUID(), generation: 1)
        let b = AppConcurrentOwner(role: .b, ticketID: UUID(), hostID: host, tabID: appB, appSessionID: appB, requestID: UUID(), generation: 1)
        let fixtureA = String(repeating: "a", count: 24), fixtureB = String(repeating: "b", count: 24)
        var pair = try AppConcurrentFirstPair(a: a, b: b, fixtureA: fixtureA, fixtureB: fixtureB)
        XCTAssertThrowsError(try AppConcurrentFirstPair(a: a, b: b, fixtureA: fixtureA, fixtureB: fixtureA))
        XCTAssertThrowsError(try pair.beginB(a, fixture: fixtureA))
        XCTAssertThrowsError(try pair.beginB(b, fixture: fixtureA))
        try pair.beginB(b, fixture: fixtureB)
        let newer = AppConcurrentOwner(role: .b, ticketID: b.ticketID, hostID: host, tabID: appB, appSessionID: appB, requestID: UUID(), generation: 1)
        XCTAssertThrowsError(try pair.finishB(newer, fixture: fixtureB))
        try pair.finishB(b, fixture: fixtureB)
        XCTAssertThrowsError(try pair.finishB(b, fixture: fixtureB), "No late duplicate after a consumed reply lease")
    }
    func testCancelAClaimsOneRoundWithoutReadsAndCannotCancelBManagementPlan() throws {
        let fixtureA = String(repeating: "a", count: 24), fixtureB = String(repeating: "b", count: 24)
        var a = try AppMFAKIBudget(deadline: 45), b = try AppMFAKIBudget(deadline: 45)
        _ = try a.claim(name: "", instruction: "", fields: [try AppMFAKIBudget.prompt(session: fixtureA, index: 0)], echo: [false], now: 1)
        var managerA = AppConcurrentManagementPlan(role: .a), managerB = AppConcurrentManagementPlan(role: .b)
        a.close(); managerA.cancel()
        XCTAssertEqual(a.rounds, 1); XCTAssertEqual(a.replies, 0); XCTAssertEqual(a.managementReads, 0); XCTAssertTrue(a.closed)
        XCTAssertThrowsError(try managerA.response(index: 0)); XCTAssertFalse(managerB.cancelled)
        for index in 0..<3 {
            let phase = try b.claim(name: "", instruction: "", fields: [try AppMFAKIBudget.prompt(session: fixtureB, index: index)], echo: [false], now: 2 + Double(index))
            try managerB.response(index: index); try b.claimManagementRead(phase); try b.consume(phase, now: 3 + Double(index)); try b.resolved(true)
        }
        let zero = try b.claim(name: "", instruction: "", fields: [], echo: [], now: 8)
        try b.consume(zero, now: 9); try b.resolved(true); try b.requireComplete()
        XCTAssertEqual(b.lateReplies, 0); XCTAssertEqual(managerB.responseReads, 3)
        XCTAssertThrowsError(try managerB.status()); managerB.cancel(); try managerB.status(); XCTAssertThrowsError(try managerB.status())
        try managerA.status(); XCTAssertEqual(managerA.statusReads, 1)
        var wrongIndex = AppConcurrentManagementPlan(role: .b); XCTAssertThrowsError(try wrongIndex.response(index: 1))
        var wrongFixture = try AppMFAKIBudget(deadline: 45)
        let first = try wrongFixture.claim(name: "", instruction: "", fields: [try AppMFAKIBudget.prompt(session: fixtureB, index: 0)], echo: [false], now: 1)
        try wrongFixture.claimManagementRead(first); try wrongFixture.consume(first, now: 2); try wrongFixture.resolved(true)
        XCTAssertThrowsError(try wrongFixture.claim(name: "", instruction: "", fields: [try AppMFAKIBudget.prompt(session: fixtureA, index: 1)], echo: [false], now: 3))
    }
    func testPerOwnerCleanupCannotHidePresentUnknownOrUnreapedAInCombinedTotals() throws {
        for role in AppConcurrentRole.allCases {
            let count = role == .a ? 1 : 4
            let complete = AppMFAManagementFacts(calls: count, returnedCalls: count, successfulReapedCalls: count, pendingCalls: 0, cancellationRequested: true, reapEvidenceComplete: true)
            try AppConcurrentStatusFacts(role: role, statusReads: 1, serverSessionStatus: .removed, management: complete).requireComplete()
            for status in [AppMFAStatus.present, .unknown] {
                XCTAssertThrowsError(try AppConcurrentStatusFacts(role: role, statusReads: 1, serverSessionStatus: status, management: complete).requireComplete())
            }
            let unreaped = AppMFAManagementFacts(calls: count, returnedCalls: count, successfulReapedCalls: count - 1, pendingCalls: 0, cancellationRequested: true, reapEvidenceComplete: false)
            XCTAssertThrowsError(try AppConcurrentStatusFacts(role: role, statusReads: 1, serverSessionStatus: .removed, management: unreaped).requireComplete())
            XCTAssertThrowsError(try AppConcurrentStatusFacts(role: role, statusReads: 0, serverSessionStatus: .removed, management: complete).requireComplete())
        }
    }
}

#if HOST_PROBE
final class AppConcurrentReceiptTests: XCTestCase {
    func testThreeFullAndFailureReceiptsEncodeBothOwnersAllFDEntriesUnder16KiBWithoutFixtureIDs() throws {
        let run = "12345678-1234-1234-1234-123456789abc", host = UUID(), appA = UUID(), appB = UUID()
        let ticketA = AppConcurrentTicket(id: UUID(), hostID: host, appSessionID: appA), ticketB = AppConcurrentTicket(id: UUID(), hostID: host, appSessionID: appB)
        let ownerA = AppConcurrentOwner(role: .a, ticketID: ticketA.id, hostID: host, tabID: appA, appSessionID: appA, requestID: UUID(), generation: 1)
        let ownerB = AppConcurrentOwner(role: .b, ticketID: ticketB.id, hostID: host, tabID: appB, appSessionID: appB, requestID: UUID(), generation: 1)
        var factsA = AppConcurrentNativeFacts(ticket: ticketA), factsB = AppConcurrentNativeFacts(ticket: ticketB)
        factsA.connectCalls = 1; factsA.primaryCalls = 1; factsA.keyboardCalls = 1; factsA.packageSessionID = UUID(); factsA.primaryRequestID = UUID()
        factsA.errorKind = "cancelled"; factsA.errorOperation = "other"
        let stagesA: [NativeShellAuthenticationStage] = [.advertised(password: false, publicKey: true, keyboardInteractive: true),
            .primaryStarted(.publicKey), .primaryResult(.publicKey, code: -19, authenticated: false), .keyboardStarted, .keyboardResult(code: -1, authenticated: false)]
        factsA.aCancellation = try AppConcurrentCancelledAuthentication(stagesA, errorKind: "cancelled")
        XCTAssertThrowsError(try AppConcurrentCancelledAuthentication(stagesA, errorKind: "unknown"))
        factsA.stages = ["advertised", "primaryStarted.publicKey", "primaryResult.publicKey", "keyboardStarted", "keyboardResult"]
        factsB.connectCalls = 1; factsB.primaryCalls = 1; factsB.keyboardCalls = 4; factsB.shellSessions = 1; factsB.packageSessionID = UUID(); factsB.primaryRequestID = UUID()
        let stagesB: [NativeShellAuthenticationStage] = [.advertised(password: false, publicKey: true, keyboardInteractive: true),
            .primaryStarted(.publicKey), .primaryResult(.publicKey, code: -19, authenticated: false), .keyboardStarted, .keyboardResult(code: 0, authenticated: true), .authenticated, .shellReady]
        factsB.bAuthentication = try AppMFAAuthentication(stagesB, fixture: .keyKI)
        factsB.stages = factsA.stages + ["authenticated", "shellReady"]
        let fixtureA = String(repeating: "a", count: 24), fixtureB = String(repeating: "b", count: 24)
        var a = try AppMFAKIBudget(deadline: 45), b = try AppMFAKIBudget(deadline: 45)
        _ = try a.claim(name: "", instruction: "", fields: [try AppMFAKIBudget.prompt(session: fixtureA, index: 0)], echo: [false], now: 1); a.close()
        for index in 0..<3 {
            let phase = try b.claim(name: "", instruction: "", fields: [try AppMFAKIBudget.prompt(session: fixtureB, index: index)], echo: [false], now: 2)
            try b.claimManagementRead(phase); try b.consume(phase, now: 3); try b.resolved(true)
        }
        let zero = try b.claim(name: "", instruction: "", fields: [], echo: [], now: 4); try b.consume(zero, now: 5); try b.resolved(true)
        let isolation = AppConcurrentIsolationFacts(a: ownerA, b: ownerB, twoFirstPending: true, distinctDrivers: true, distinctPackageSessions: true,
            distinctFixtureSessions: true, tokensUncancelledAtFirstPair: true, aManagementReadsBeforeCancel: 0, bManagementReadsBeforeCancel: 0,
            crossReplyRejected: true, bPromptUnchangedAfterCross: true, lateReplyRejected: true, bOwnerUnchangedAfterACancel: true)
        try isolation.requireComplete()
        let aliased = AppConcurrentIsolationFacts(a: ownerA, b: ownerA, twoFirstPending: true, distinctDrivers: true, distinctPackageSessions: true,
            distinctFixtureSessions: true, tokensUncancelledAtFirstPair: true, aManagementReadsBeforeCancel: 0, bManagementReadsBeforeCancel: 0,
            crossReplyRejected: true, bPromptUnchangedAfterCross: true, lateReplyRejected: true, bOwnerUnchangedAfterACancel: true)
        XCTAssertThrowsError(try aliased.requireComplete())
        let statusA = AppConcurrentStatusFacts(role: .a, statusReads: 1, serverSessionStatus: .removed,
            management: .init(calls: 1, returnedCalls: 1, successfulReapedCalls: 1, pendingCalls: 0, cancellationRequested: true, reapEvidenceComplete: true))
        let statusB = AppConcurrentStatusFacts(role: .b, statusReads: 1, serverSessionStatus: .removed,
            management: .init(calls: 4, returnedCalls: 4, successfulReapedCalls: 4, pendingCalls: 0, cancellationRequested: true, reapEvidenceComplete: true))
        let entries = (0..<32).map { AppNativeFiniteDescriptorEntry(fd: Int32($0), type: 0o100000, dev: Int32.max, ino: UInt64.max, access: 0, probeStatus: .stable, role: .unknown) }
        var fd = AppNativeFiniteDescriptorSnapshots()
        fd.baseline = .init(elapsedSeconds: 1, scanUpperExclusive: 10240, count: 32, entries: entries)
        fd.cleanupFirst = .init(elapsedSeconds: 2, scanUpperExclusive: 10240, count: 32, entries: entries)
        fd.cleanupLatest = .init(elapsedSeconds: 3, scanUpperExclusive: 10240, count: 32, entries: entries)
        let weak = AppTrustWeakFacts(tabAlive: false, driverAlive: false, viewAlive: false)
        let auth = AppConcurrentAuthenticationReceipt(runID: run, pid: Int32.max, isolation: isolation, a: factsA, b: factsB,
            aKeyboard: AppMFAKIFacts(a), bKeyboard: AppMFAKIFacts(b), aBudgetClosed: true, credentialCalls: 0)
        let cleanup = AppConcurrentCleanupReceipt(runID: run, pid: Int32.max, a: statusA, b: statusB, passed: true)
        func report(failed: Bool) -> AppConcurrentReport {
            var lifecycleA = factsA, lifecycleB = factsB
            if failed {
                lifecycleA.errorKind = "cancelled"; lifecycleA.errorOperation = "keyboard-authentication"
                lifecycleB.errorKind = "cancelled"; lifecycleB.errorOperation = "keyboard-authentication"
                // Bound the widest failure wire, including every optional native diagnostic value.
                lifecycleA.bAuthentication = factsB.bAuthentication; lifecycleB.aCancellation = factsA.aCancellation
            }
            return .init(runID: run, pid: Int32.max, checkpoint: failed ? "failure" : "ready-for-native-quit", elapsedSeconds: 90,
                passed: !failed, failureCode: failed ? .resources : nil, authenticationComplete: true, cleanupComplete: true, closedAndClean: !failed,
                localStoreRemoved: false, a: .init(role: .a, owner: ownerA, native: lifecycleA, closeDisposition: "closed", canonicalDrained: true, queueEmpty: true, nativeClosed: true, weak: weak),
                b: .init(role: .b, owner: ownerB, native: lifecycleB, closeDisposition: "closed", canonicalDrained: true, queueEmpty: true, nativeClosed: true, weak: weak), isolation: isolation,
                aKeyboard: AppMFAKIFacts(a), bKeyboard: AppMFAKIFacts(b), managementA: statusA, managementB: statusB,
                sourceKeyUnchanged: true, fixtureKnownHostsUnchanged: true, approvedPinUnchanged: true, credentialCalls: 0,
                descriptors: .init(fd), descriptorIdentityMatched: !failed, registryBaselineActive: 0, registryBaselineRetired: 0,
                registryAfterActive: 0, registryAfterRetired: 0, quit: .init())
        }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let encoded = try [("authentication", encoder.encode(auth)), ("cleanup", encoder.encode(cleanup)),
            ("overall", encoder.encode(report(failed: false))), ("failure-all-optionals", encoder.encode(report(failed: true)))]
        for (label, data) in encoded {
            print("Concurrent actual \(label) receipt bytes: \(data.count)")
            XCTAssertLessThanOrEqual(data.count, 16384)
            let text = String(decoding: data, as: UTF8.self)
            XCTAssertFalse(text.contains(fixtureA)); XCTAssertFalse(text.contains(fixtureB)); XCTAssertFalse(text.contains("One-time response"))
        }
    }
}
#endif
