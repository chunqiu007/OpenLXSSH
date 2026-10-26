import Foundation
import XCTest
import OpenLXSSHCore
import OpenLXSSHFiles
import OpenLXSSHSecurity

@MainActor final class FilesAuthenticationTests: XCTestCase {
    private func fixture() throws -> (URL, AppRepository) {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        addTeardownBlock { try FileManager.default.removeItem(at: root) }
        return (root, AppRepository(location: .isolated(root)))
    }
    private func host() -> HostConfiguration { HostConfiguration(name: "auth preparation only", address: "never-connected.invalid", username: "fixture") }
    private func request(_ host: HostConfiguration) -> FilesRequest { FilesRequest(id: UUID(), generation: 1, host: host) }
    private func plan(_ connector: LibSSH2FilesConnector, host: HostConfiguration, input: FilesConnectInput, token: CancellationToken = .init(), current: FilesAuthCurrent = .init()) async throws -> FilesAuthenticationPlan {
        try await connector.prepareAuthentication(request: request(host), input: input, token: token, keyboard: { _, reply in reply.resolve([]) }, isCurrent: { await current.value })
    }
    func testProductionManualAndKeyboardOnlyPlansNeverReadSavedSecret() async throws {
        let (root, repo) = try fixture(), credentials = FilesAuthCredentials()
        let security = SecurityCoordinator(repository: repo, location: .isolated(root), credentials: credentials)
        let connector = LibSSH2FilesConnector(repository: repo, security: security, environment: SessionEnvironment(location: .isolated(root)))
        var host = host(); host.authentication = .passwordWithMFA
        try await repo.apply([.insertHost(host)])
        let manual = try await plan(connector, host: host, input: .init(primary: .manual(.init(utf8: UUID().uuidString))))
        XCTAssertEqual(manual.methods.count, 2)
        if case .password = manual.methods[0] {} else { XCTFail("Expected typed initial password") }
        if case .keyboardInteractive = manual.methods[1] {} else { XCTFail("Expected separate manual challenge") }
        let keyboard = try await plan(connector, host: host, input: .init(primary: .saved, keyboardOnly: true))
        XCTAssertEqual(keyboard.methods.count, 1)
        let reads = await credentials.readCount
        XCTAssertEqual(reads, 0)
        try await security.close(); try await repo.close()
    }
    func testProductionFirstMetadataCancellationOrRequestChangePreventsCredentialRead() async throws {
        for invalidation in 0...1 {
            let (root, repo) = try fixture(), credentials = FilesAuthCredentials(), current = FilesAuthCurrent(), token = CancellationToken()
            var host = host(); let ref = UUID(); host.credentialRef = ref; host.savePasswordAuthorized = true
            try await repo.apply([.registerCredential(.init(id: ref, purpose: .password, isSavingAuthorized: true)), .insertHost(host)])
            let wrapped = FilesAuthRepository(base: repo)
            let security = SecurityCoordinator(repository: wrapped, location: .isolated(root), credentials: credentials)
            let connector = LibSSH2FilesConnector(repository: wrapped, security: security, environment: SessionEnvironment(location: .isolated(root)))
            await wrapped.pause.arm()
            let task = Task { try await self.plan(connector, host: host, input: .init(primary: .saved), token: token, current: current) }
            await wrapped.pause.arrived()
            if invalidation == 0 { token.cancel() } else { await current.invalidate() }
            await wrapped.pause.release()
            do { _ = try await task.value; XCTFail("Expected stale plan rejection") } catch {}
            let reads = await credentials.readCount
            XCTAssertEqual(reads, 0)
            try await security.close(); try await repo.close()
        }
    }
    func testSavedPasswordPlanRejectsReferenceChangeBeforeTCP() async throws {
        let (root, repo) = try fixture(), credentials = FilesAuthCredentials()
        var host = host(); let ref = UUID(); host.credentialRef = ref; host.savePasswordAuthorized = true
        try await repo.apply([.registerCredential(.init(id: ref, purpose: .password, isSavingAuthorized: true)), .insertHost(host)])
        let security = SecurityCoordinator(repository: repo, location: .isolated(root), credentials: credentials)
        let connector = LibSSH2FilesConnector(repository: repo, security: security, environment: SessionEnvironment(location: .isolated(root)))
        let request = request(host), current = FilesAuthCurrent()
        let value = try await connector.prepareAuthentication(request: request, input: .init(primary: .saved), token: .init(),
            keyboard: { _, reply in reply.resolve([]) }, isCurrent: { await current.value })
        if case .password(let bytes) = value.methods[0] { XCTAssertFalse(bytes.isEmpty) } else { XCTFail("Expected typed saved password") }
        try await connector.validatePreparedPlan(value, request: request, token: .init(), isCurrent: { await current.value })
        var revoked = host; revoked.savePasswordAuthorized = false; revoked.credentialRef = nil
        try await repo.apply([.updateHost(revoked)])
        do { try await connector.validatePreparedPlan(value, request: request, token: .init(), isCurrent: { await current.value }); XCTFail("Revoked prepared password passed validation") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        do { _ = try await plan(connector, host: host, input: .init(primary: .saved)); XCTFail("Revoked row returned plan") } catch {}
        let reads = await credentials.readCount
        XCTAssertEqual(reads, 1)
        try await security.close(); try await repo.close()
    }
    func testProductionCredentialAwaitRevokedHostReferenceNeverReturnsPlan() async throws {
        let (root, repo) = try fixture(), credentials = FilesAuthCredentials()
        var host = host(); let ref = UUID(); host.credentialRef = ref; host.savePasswordAuthorized = true
        try await repo.apply([.registerCredential(.init(id: ref, purpose: .password, isSavingAuthorized: true)), .insertHost(host)])
        let security = SecurityCoordinator(repository: repo, location: .isolated(root), credentials: credentials)
        let connector = LibSSH2FilesConnector(repository: repo, security: security, environment: SessionEnvironment(location: .isolated(root)))
        await credentials.pause.arm()
        let task = Task { try await self.plan(connector, host: host, input: .init(primary: .saved)) }
        await credentials.pause.arrived()
        var revoked = host; revoked.credentialRef = nil; revoked.savePasswordAuthorized = false
        try await repo.apply([.updateHost(revoked)])
        await credentials.pause.release()
        do { _ = try await task.value; XCTFail("Revoked host returned a plan") } catch {}
        let reads = await credentials.readCount
        XCTAssertEqual(reads, 1)
        try await security.close(); try await repo.close()
    }
    func testProductionCredentialAwaitCancellationAndKeyphraseReferenceChangeRejectPlan() async throws {
        let (root, repo) = try fixture(), credentials = FilesAuthCredentials()
        let security = SecurityCoordinator(repository: repo, location: .isolated(root), credentials: credentials)
        let phrase = OpenLXSSHSecurity.SecretBytes(utf8: UUID().uuidString)
        let key = try await security.createKey(.generate, protection: .passphrase(phrase), rememberPassphrase: phrase).id
        var host = host(); host.authentication = .privateKey; host.keyRef = key
        try await repo.apply([.insertHost(host)])
        let connector = LibSSH2FilesConnector(repository: repo, security: security, environment: SessionEnvironment(location: .isolated(root)))
        await credentials.pause.arm()
        let token = CancellationToken()
        let first = Task { try await self.plan(connector, host: host, input: .init(primary: .saved), token: token) }
        await credentials.pause.arrived(); token.cancel(); await credentials.pause.release()
        do { _ = try await first.value; XCTFail("Cancelled key plan returned") } catch {}
        await credentials.pause.arm()
        let second = Task { try await self.plan(connector, host: host, input: .init(primary: .saved)) }
        await credentials.pause.arrived()
        let newRef = UUID()
        try await repo.apply([.registerCredential(.init(id: newRef, purpose: .privateKeyPassphrase, isSavingAuthorized: true)), .updateKeyPassphrase(keyID: key, credentialRef: newRef)])
        await credentials.pause.release()
        do { _ = try await second.value; XCTFail("Changed keyphrase ref returned") } catch {}
        // Manual explicit material preparation uses the real validated UUID API,
        // preserves key bytes on disk and exposes no file-export path.
        let manual = try await plan(connector, host: host, input: .init(primary: .manual(phrase)))
        if case .publicKey(_, let bytes, _) = manual.methods[0] { XCTAssertFalse(bytes.isEmpty) } else { XCTFail("Expected memory private key") }
        let denied = Task { try await security.privateKeyForFileAuthentication(host: host, authorized: false) }
        do { _ = try await denied.value; XCTFail("Unapproved material accepted") } catch {}
        try await security.close(); try await repo.close()
    }
    func testSavedKeyphraseRevokedAfterPostReadCheckBeforeFinalMetadataRejectsPlan() async throws {
        for replacement in [false, true] {
            let (root, repo) = try fixture(), credentials = FilesAuthCredentials()
            let wrapped = FilesAuthRepository(base: repo)
            let security = SecurityCoordinator(repository: wrapped, location: .isolated(root), credentials: credentials)
            let phrase = OpenLXSSHSecurity.SecretBytes(utf8: UUID().uuidString)
            let keyID = try await security.createKey(.generate, protection: .passphrase(phrase), rememberPassphrase: phrase).id
            var host = host(); host.authentication = .privateKey; host.keyRef = keyID
            try await repo.apply([.insertHost(host)])
            let connector = LibSSH2FilesConnector(repository: wrapped, security: security, environment: SessionEnvironment(location: .isolated(root)))
            // First metadata after the saved read is initialSecret's post-read check.
            // Pause before obtaining the next snapshot, after that check has returned.
            await wrapped.pauseBeforeFinalMetadataAfterSavedRead(credentials)
            let task = Task { try await self.plan(connector, host: host, input: .init(primary: .saved)) }
            await wrapped.beforeRead.arrived()
            let checks = await wrapped.metadataReadsAfterSavedRead
            XCTAssertEqual(checks, 2)
            if replacement {
                let newRef = UUID()
                try await repo.apply([.registerCredential(.init(id: newRef, purpose: .privateKeyPassphrase, isSavingAuthorized: true)), .updateKeyPassphrase(keyID: keyID, credentialRef: newRef)])
            } else {
                _ = try await security.forgetKeyPassphrase(keyID)
            }
            let current = try await repo.securityMetadata()
            XCTAssertTrue(current.hosts.contains(host)) // Only the key/credential authorization changed.
            await wrapped.beforeRead.release()
            do { _ = try await task.value; XCTFail("Revoked keyphrase returned a plan after the final metadata read") }
            catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
            let reads = await credentials.readCount
            XCTAssertEqual(reads, 1)
            try await security.close(); try await repo.close()
        }
    }
    func testPreparedPlanPreTCPValidationRejectsKeyphraseRevocationDuringMetadataAwait() async throws {
        for replacement in [false, true] {
            let (root, repo) = try fixture(), credentials = FilesAuthCredentials()
            let wrapped = FilesAuthRepository(base: repo)
            let security = SecurityCoordinator(repository: wrapped, location: .isolated(root), credentials: credentials)
            let phrase = OpenLXSSHSecurity.SecretBytes(utf8: UUID().uuidString)
            let keyID = try await security.createKey(.generate, protection: .passphrase(phrase), rememberPassphrase: phrase).id
            var host = host(); host.authentication = .privateKey; host.keyRef = keyID
            try await repo.apply([.insertHost(host)])
            let connector = LibSSH2FilesConnector(repository: wrapped, security: security, environment: SessionEnvironment(location: .isolated(root)))
            let request = request(host), token = CancellationToken(), current = FilesAuthCurrent()
            let prepared = try await connector.prepareAuthentication(request: request, input: .init(primary: .saved), token: token,
                keyboard: { _, reply in reply.resolve([]) }, isCurrent: { await current.value })
            try await connector.validatePreparedPlan(prepared, request: request, token: token, isCurrent: { await current.value })
            // This is the same production seam called after sharedTrustStore and before TCP.
            // No service, socket or network factory is substituted by the test.
            await wrapped.pauseBeforeNextMetadataRead()
            let task = Task { try await connector.validatePreparedPlan(prepared, request: request, token: token, isCurrent: { await current.value }) }
            await wrapped.beforeRead.arrived()
            if replacement {
                let newRef = UUID()
                try await repo.apply([.registerCredential(.init(id: newRef, purpose: .privateKeyPassphrase, isSavingAuthorized: true)), .updateKeyPassphrase(keyID: keyID, credentialRef: newRef)])
            } else {
                _ = try await security.forgetKeyPassphrase(keyID)
            }
            let metadata = try await repo.securityMetadata()
            XCTAssertTrue(metadata.hosts.contains(host))
            await wrapped.beforeRead.release()
            do { try await task.value; XCTFail("Prepared plan passed pre-TCP validation after keyphrase revocation") }
            catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
            let reads = await credentials.readCount
            XCTAssertEqual(reads, 1)
            try await security.close(); try await repo.close()
        }
    }
    func testManualPrivateKeyPlanRemainsValidAfterForgetAndUnencryptedKeyNeedsNoSavedSecret() async throws {
        let (root, repo) = try fixture(), credentials = FilesAuthCredentials()
        let security = SecurityCoordinator(repository: repo, location: .isolated(root), credentials: credentials)
        let connector = LibSSH2FilesConnector(repository: repo, security: security, environment: SessionEnvironment(location: .isolated(root)))
        let phrase = OpenLXSSHSecurity.SecretBytes(utf8: UUID().uuidString)
        let encryptedID = try await security.createKey(.generate, protection: .passphrase(phrase), rememberPassphrase: phrase).id
        let plainID = try await security.createKey(.generate, protection: .unencrypted, rememberPassphrase: nil).id
        for keyID in [encryptedID, plainID] {
            var host = host(); host.authentication = .privateKey; host.keyRef = keyID
            try await repo.apply([.insertHost(host)])
            let request = request(host), current = FilesAuthCurrent()
            let prepared = try await connector.prepareAuthentication(request: request,
                input: .init(primary: .manual(keyID == encryptedID ? phrase : .init(utf8: ""))), token: .init(),
                keyboard: { _, reply in reply.resolve([]) }, isCurrent: { await current.value })
            try await connector.validatePreparedPlan(prepared, request: request, token: .init(), isCurrent: { await current.value })
            if keyID == encryptedID {
                _ = try await security.forgetKeyPassphrase(keyID)
                // Forgetting saved authorization does not revoke manually supplied material.
                try await connector.validatePreparedPlan(prepared, request: request, token: .init(), isCurrent: { await current.value })
            }
            if case .publicKey(_, let bytes, _) = prepared.methods[0] { XCTAssertFalse(bytes.isEmpty) }
            else { XCTFail("Expected a typed private key plan") }
        }
        let reads = await credentials.readCount
        XCTAssertEqual(reads, 0)
        try await security.close(); try await repo.close()
    }
    func testPreparedPlanRejectsWrongRequestAndCancellationOrStaleGenerationDuringFinalAwait() async throws {
        let (root, repo) = try fixture(), credentials = FilesAuthCredentials()
        let wrapped = FilesAuthRepository(base: repo)
        let security = SecurityCoordinator(repository: wrapped, location: .isolated(root), credentials: credentials)
        let connector = LibSSH2FilesConnector(repository: wrapped, security: security, environment: SessionEnvironment(location: .isolated(root)))
        let host = host(); try await repo.apply([.insertHost(host)])
        let request = request(host), current = FilesAuthCurrent()
        let prepared = try await connector.prepareAuthentication(request: request, input: .init(primary: .manual(.init(utf8: UUID().uuidString))),
            token: .init(), keyboard: { _, reply in reply.resolve([]) }, isCurrent: { await current.value })
        do { try await connector.validatePreparedPlan(prepared, request: self.request(host), token: .init(), isCurrent: { await current.value }); XCTFail("Another request reused a prepared plan") }
        catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        for cancelToken in [false, true] {
            let token = CancellationToken(), suppliedCurrent = FilesAuthCurrent()
            await wrapped.pauseBeforeNextMetadataRead()
            let task = Task { try await connector.validatePreparedPlan(prepared, request: request, token: token, isCurrent: { await suppliedCurrent.value }) }
            await wrapped.beforeRead.arrived()
            if cancelToken { token.cancel() } else { await suppliedCurrent.invalidate() }
            await wrapped.beforeRead.release()
            do { try await task.value; XCTFail("Cancelled or stale final validation succeeded") }
            catch let error as FileServiceError { XCTAssertEqual(error.kind, .cancelled) }
        }
        let reads = await credentials.readCount
        XCTAssertEqual(reads, 0)
        try await security.close(); try await repo.close()
    }
}

private actor FilesAuthCurrent {
    private(set) var value = true
    func invalidate() { value = false }
}
private actor FilesAuthPause {
    private var armed = false, reached = false
    private var waiting: CheckedContinuation<Void, Never>?
    private var observer: CheckedContinuation<Void, Never>?
    func arm() { armed = true; reached = false }
    func wait() async { guard armed else { return }; reached = true; observer?.resume(); observer = nil; await withCheckedContinuation { waiting = $0 } }
    func arrived() async { if !reached { await withCheckedContinuation { observer = $0 } } }
    func release() { armed = false; waiting?.resume(); waiting = nil }
}
private actor FilesAuthCredentials: CredentialAccess {
    let pause = FilesAuthPause()
    private(set) var readCount = 0
    func save(_ secret: OpenLXSSHSecurity.SecretBytes, as reference: OpenLXSSHSecurity.CredentialReference, authorization: RememberAuthorization) -> CredentialSaveResult { .saved(reference) }
    func read(_ reference: OpenLXSSHSecurity.CredentialReference) async -> CredentialReadResult { readCount += 1; await pause.wait(); return .available(.init(utf8: UUID().uuidString)) }
    func deleteExact(_ reference: OpenLXSSHSecurity.CredentialReference) -> CredentialDeleteResult { .deleted }
    func close() {}
}
private actor FilesAuthRepository: AppRepositoryProtocol {
    let base: AppRepository
    let pause = FilesAuthPause()
    let beforeRead = FilesAuthPause()
    private var savedReadCredentials: FilesAuthCredentials?
    private var pauseNextMetadataRead = false
    private(set) var metadataReadsAfterSavedRead = 0
    init(base: AppRepository) { self.base = base }
    func pauseBeforeFinalMetadataAfterSavedRead(_ credentials: FilesAuthCredentials) async {
        savedReadCredentials = credentials; metadataReadsAfterSavedRead = 0
        await beforeRead.arm()
    }
    func pauseBeforeNextMetadataRead() async {
        pauseNextMetadataRead = true; await beforeRead.arm()
    }
    func securityMetadata() async throws -> SecurityMetadata {
        var shouldPause = pauseNextMetadataRead
        pauseNextMetadataRead = false
        if let credentials = savedReadCredentials, await credentials.readCount > 0 {
            metadataReadsAfterSavedRead += 1
            if metadataReadsAfterSavedRead == 2 {
                savedReadCredentials = nil; shouldPause = true
            }
        }
        if shouldPause { await beforeRead.wait() }
        let value = try await base.securityMetadata(); await pause.wait(); return value
    }
    func snapshot(query: HostQuery) async throws -> AppSnapshot { try await base.snapshot(query: query) }
    func apply(_ changes: [RepositoryChange]) async throws { try await base.apply(changes) }
    func copyHost(id: UUID) async throws -> HostConfiguration { try await base.copyHost(id: id) }
    func copyFolder(id: UUID) async throws -> HostFolder { try await base.copyFolder(id: id) }
    func close() async throws { try await base.close() }
}
