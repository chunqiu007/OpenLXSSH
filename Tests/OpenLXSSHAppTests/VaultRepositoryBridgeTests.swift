import Foundation
import XCTest
import OpenLXSSHCore

@MainActor final class VaultRepositoryBridgeTests: XCTestCase {
    private func fixture() throws -> (URL, AppRepository) {
        let root = try AppDataLocation.canonical(FileManager.default.temporaryDirectory).appendingPathComponent("OpenLXSSH-AppTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let repository = AppRepository(location: .isolated(root))
        addTeardownBlock {
            try await repository.close()
            try FileManager.default.removeItem(at: root)
        }
        return (root, repository)
    }
    private func host(_ name: String, folderID: UUID? = nil) -> HostConfiguration {
        HostConfiguration(name: name, address: "never-connected.invalid", username: "fixture", folderID: folderID)
    }

    func testLegacySnapshotInitializerAndUnsupportedProtocolDefaultsRemainExplicit() async throws {
        let snapshot = AppSnapshot(hosts: [], folders: [], keys: [], settings: AppSettings())
        XCTAssertNil(snapshot.allHosts)
        XCTAssertTrue(snapshot.folderPaths.isEmpty)
        XCTAssertTrue(snapshot.tags.isEmpty)
        XCTAssertTrue(snapshot.hostMetadata.isEmpty)
        XCTAssertNil(snapshot.allHostMetadata)
        XCTAssertTrue(snapshot.hostTagIDs.isEmpty)
        let legacy: any AppRepositoryProtocol = LegacyVaultBridgeRepository()
        do { _ = try await legacy.vaultMetadata(query: HostQuery()); XCTFail("Unsupported metadata query succeeded") }
        catch let error as RepositoryError { XCTAssertEqual(error, .notFound) }
        do { _ = try await legacy.folderDeletionImpact(id: UUID()); XCTFail("Unsupported folder impact was fabricated") }
        catch let error as RepositoryError { XCTAssertEqual(error, .notFound) }
        do { _ = try await legacy.tagDeletionImpact(id: UUID()); XCTFail("Unsupported tag impact was fabricated") }
        catch let error as RepositoryError { XCTAssertEqual(error, .notFound) }
        do { try await legacy.updateKeyLabel(keyID: UUID(), label: "not supported"); XCTFail("Unsupported label update succeeded") }
        catch let error as RepositoryError { XCTAssertEqual(error, .notFound) }
    }

    func testFilteredSnapshotKeepsCompleteCatalogPathsTagsAndReferenceCounts() async throws {
        let (_, repository) = try fixture()
        let root = HostFolder(name: "Café中文"), outside = HostFolder(name: "outside")
        let nested = HostFolder(name: "nested", parentID: root.id)
        let tag = HostTag(name: "team"), secondTag = HostTag(name: "chosen"), unusedTag = HostTag(name: "unused")
        let credential = CredentialReference(purpose: .password, isSavingAuthorized: true)
        let phrase = CredentialReference(purpose: .privateKeyPassphrase, isSavingAuthorized: true)
        let key = ManagedKeyReference(algorithm: .rsa, passphraseCredentialRef: phrase.id, label: "public label")
        let a = HostConfiguration(name: "A", address: "a.invalid", username: "fixture", credentialRef: credential.id, savePasswordAuthorized: true, folderID: root.id)
        let b = HostConfiguration(name: "B", address: "b.invalid", username: "fixture", authentication: .privateKey, keyRef: key.id, folderID: nested.id)
        let c = HostConfiguration(name: "C", address: "c.invalid", username: "fixture", authentication: .privateKeyWithMFA, keyRef: key.id, folderID: outside.id)
        let d = HostConfiguration(name: "D", address: "d.invalid", username: "fixture", credentialRef: credential.id, savePasswordAuthorized: true)
        try await repository.apply([.saveFolder(root), .saveFolder(nested), .saveFolder(outside), .addTag(tag), .addTag(secondTag), .addTag(unusedTag),
            .registerCredential(credential), .registerCredential(phrase), .registerKey(key), .insertHost(a), .insertHost(b), .insertHost(c), .insertHost(d),
            .setHostTags(hostID: a.id, tagIDs: [tag.id]), .setHostTags(hostID: b.id, tagIDs: [tag.id, secondTag.id]), .setHostTags(hostID: c.id, tagIDs: [secondTag.id])])
        let query = HostQuery(search: "CAFE中", folder: .folderAndDescendants(root.id), sort: .name, sortDirection: .descending, tagIDs: [tag.id, secondTag.id])
        let snapshot = try await repository.snapshot(query: query)
        XCTAssertEqual(snapshot.hosts, [b])
        XCTAssertEqual(snapshot.hostMetadata.map(\.host), [b])
        XCTAssertEqual(snapshot.hostMetadata.first?.folderPath?.folderIDs, [root.id, nested.id])
        XCTAssertEqual(Set(snapshot.allHosts?.map(\.id) ?? []), [a.id, b.id, c.id, d.id])
        XCTAssertEqual(snapshot.catalog.count, 4)
        XCTAssertEqual(Set(snapshot.folderPaths.map(\.id)), [root.id, nested.id, outside.id])
        XCTAssertEqual(Set(snapshot.folders.map(\.id)), [root.id, nested.id, outside.id])
        XCTAssertEqual(Set(snapshot.tags.map(\.id)), [tag.id, secondTag.id, unusedTag.id])
        XCTAssertEqual(snapshot.hostTagIDs[a.id], [tag.id])
        XCTAssertEqual(snapshot.hostTagIDs[b.id], [tag.id, secondTag.id])
        XCTAssertEqual(snapshot.hostTagIDs[d.id], [])
        XCTAssertEqual(snapshot.keyHostReferenceCounts[key.id], 2)
        XCTAssertEqual(snapshot.credentialHostReferenceCounts[credential.id], 2)
        XCTAssertEqual(snapshot.credentialKeyReferenceCounts[phrase.id], 1)
        XCTAssertEqual(snapshot.tagHostReferenceCounts[tag.id], 2)
        XCTAssertEqual(snapshot.tagHostReferenceCounts[secondTag.id], 2)
        let protocolRepository: any AppRepositoryProtocol = repository
        let metadata = try await protocolRepository.vaultMetadata(query: query)
        XCTAssertEqual(metadata.hosts, snapshot.hostMetadata)
        let descending = try await repository.snapshot(query: HostQuery(folder: .folderAndDescendants(root.id), sortDirection: .descending))
        XCTAssertEqual(descending.hosts.map(\.id), [b.id, a.id])
        let empty = try await repository.snapshot(query: HostQuery(search: "no-such-host"))
        XCTAssertTrue(empty.hosts.isEmpty)
        XCTAssertEqual(empty.catalog.count, 4)
        XCTAssertEqual(empty.keyHostReferenceCounts[key.id], 2)
    }

    func testImpactQueriesAndMetadataUpdatesUseCheckedCoreOperations() async throws {
        let (_, repository) = try fixture()
        let root = HostFolder(name: "root"), tag = HostTag(name: "tag")
        let child = HostFolder(name: "child", parentID: root.id)
        let a = host("A", folderID: root.id), b = host("B", folderID: child.id)
        let phrase = CredentialReference(purpose: .privateKeyPassphrase, isSavingAuthorized: true)
        let key = ManagedKeyReference(algorithm: .ed25519, passphraseCredentialRef: phrase.id)
        try await repository.apply([.saveFolder(root), .saveFolder(child), .insertHost(a), .insertHost(b), .addTag(tag),
            .assignTag(hostID: a.id, tagID: tag.id), .assignTag(hostID: b.id, tagID: tag.id), .registerCredential(phrase), .registerKey(key)])
        let protocolRepository: any AppRepositoryProtocol = repository
        let folderImpact = try await protocolRepository.folderDeletionImpact(id: root.id)
        XCTAssertEqual(folderImpact.folder, root)
        XCTAssertEqual(folderImpact.directHostCount, 1)
        XCTAssertEqual(folderImpact.directChildFolderCount, 1)
        let tagImpact = try await protocolRepository.tagDeletionImpact(id: tag.id)
        XCTAssertEqual(tagImpact.hostCount, 2)
        try await protocolRepository.updateKeyLabel(keyID: key.id, label: "renamed")
        let security = try await repository.securityMetadata()
        let renamed = try XCTUnwrap(security.keys.first)
        XCTAssertEqual(renamed.label, "renamed")
        XCTAssertEqual(renamed.authenticationIdentity, key.authenticationIdentity)
        XCTAssertEqual(security.credentials, [phrase])
        XCTAssertTrue(security.tickets.isEmpty)
        do { _ = try await repository.folderDeletionImpact(id: UUID()); XCTFail("Unknown group succeeded") }
        catch let error as RepositoryError { XCTAssertEqual(error, .notFound) }
        do { _ = try await repository.tagDeletionImpact(id: UUID()); XCTFail("Unknown tag succeeded") }
        catch let error as RepositoryError { XCTAssertEqual(error, .notFound) }
        do { try await repository.updateKeyLabel(keyID: UUID(), label: "missing"); XCTFail("Unknown key succeeded") }
        catch let error as RepositoryError { XCTAssertEqual(error, .notFound) }
        do { try await repository.updateKeyLabel(keyID: key.id, label: "\n"); XCTFail("Invalid label succeeded") }
        catch let error as RepositoryError { XCTAssertEqual(error, .invalidField("keyLabel")) }
        try await repository.apply([.moveHost(a.id, folderID: child.id), .setHostTags(hostID: a.id, tagIDs: []), .deleteFolders([root.id])])
        let changed = try await repository.snapshot(query: HostQuery())
        XCTAssertEqual(changed.hosts.count, 2)
        XCTAssertEqual(changed.folders.first?.id, child.id)
        XCTAssertNil(changed.folders.first?.parentID)
        XCTAssertEqual(changed.hostTagIDs[a.id], [])
        XCTAssertEqual(changed.hostTagIDs[b.id], [tag.id])
    }

    func testRecursiveCopyPreservesOriginalsHierarchyTagsAndSharedAuthorization() async throws {
        let (_, repository) = try fixture()
        let parent = HostFolder(name: "parent")
        let root = HostFolder(name: String(repeating: "中", count: 85), sortOrder: 7, parentID: parent.id)
        let child = HostFolder(name: "child", sortOrder: 2, parentID: root.id)
        let leaf = HostFolder(name: "leaf", parentID: child.id)
        let tag = HostTag(name: "tag")
        let credential = CredentialReference(purpose: .password, isSavingAuthorized: true)
        let phrase = CredentialReference(purpose: .privateKeyPassphrase, isSavingAuthorized: true)
        let key = ManagedKeyReference(algorithm: .rsa, passphraseCredentialRef: phrase.id)
        let a = HostConfiguration(name: "A", address: "a.invalid", username: "fixture", credentialRef: credential.id, savePasswordAuthorized: true,
            folderID: root.id, isFavorite: true, favoriteOrder: 9, lastConnectedAt: Date(timeIntervalSince1970: 100))
        let b = HostConfiguration(name: "B", address: "b.invalid", username: "fixture", authentication: .privateKeyWithMFA, keyRef: key.id,
            folderID: leaf.id, lastConnectedAt: Date(timeIntervalSince1970: 200))
        let c = host("C", folderID: child.id), outside = host("outside", folderID: parent.id)
        try await repository.apply([.saveFolder(parent), .saveFolder(root), .saveFolder(child), .saveFolder(leaf), .addTag(tag),
            .registerCredential(credential), .registerCredential(phrase), .registerKey(key), .insertHost(a), .insertHost(b), .insertHost(c), .insertHost(outside),
            .assignTag(hostID: a.id, tagID: tag.id), .assignTag(hostID: b.id, tagID: tag.id)])
        let before = try await repository.snapshot(query: HostQuery())
        let copy = try await repository.copyFolder(id: root.id)
        XCTAssertNotEqual(copy.id, root.id)
        XCTAssertEqual(copy.parentID, parent.id)
        XCTAssertEqual(copy.sortOrder, root.sortOrder)
        XCTAssertLessThanOrEqual(copy.name.utf8.count, 256)
        XCTAssertTrue(copy.name.hasSuffix(" 副本"))
        let after = try await repository.snapshot(query: HostQuery())
        for original in before.catalog { XCTAssertEqual(after.catalog.first { $0.id == original.id }, original) }
        for original in before.folderPaths { XCTAssertEqual(after.folderPaths.first { $0.id == original.id }, original) }
        let copiedPaths = after.folderPaths.filter { $0.folderIDs.contains(copy.id) }
        XCTAssertEqual(copiedPaths.count, 3)
        let copiedChild = try XCTUnwrap(copiedPaths.first { $0.components.last?.name == "child" })
        let copiedLeaf = try XCTUnwrap(copiedPaths.first { $0.components.last?.name == "leaf" })
        XCTAssertEqual(copiedLeaf.components.last?.parentID, copiedChild.id)
        let copies = after.catalog.filter { $0.folderPath?.folderIDs.contains(copy.id) == true }
        XCTAssertEqual(copies.count, 3)
        for original in before.catalog.filter({ $0.folderPath?.folderIDs.contains(root.id) == true }) {
            let copied = try XCTUnwrap(copies.first { $0.host.name == original.host.name })
            var expected = original.host
            expected.id = copied.id; expected.folderID = copied.host.folderID; expected.lastConnectedAt = nil
            XCTAssertNotEqual(copied.id, original.id)
            XCTAssertEqual(copied.host, expected)
            XCTAssertEqual(copied.tagIDs, original.tagIDs)
        }
        XCTAssertEqual(after.keys, before.keys)
        let metadata = try await repository.securityMetadata()
        XCTAssertEqual(Set(metadata.credentials.map(\.id)), [credential.id, phrase.id])
        XCTAssertTrue(metadata.tickets.isEmpty)
        do { _ = try await repository.copyFolder(id: UUID()); XCTFail("Missing group copy succeeded") }
        catch let error as RepositoryError { XCTAssertEqual(error, .notFound) }
        let unchanged = try await repository.snapshot(query: HostQuery())
        XCTAssertEqual(unchanged.catalog, after.catalog)
        XCTAssertEqual(unchanged.folderPaths, after.folderPaths)
    }

    func testCopyHostRetainsTagsThroughAppBridge() async throws {
        let (_, repository) = try fixture()
        let tag = HostTag(name: "tag"), group = HostFolder(name: "group")
        let original = host("original", folderID: group.id)
        try await repository.apply([.saveFolder(group), .addTag(tag), .insertHost(original), .assignTag(hostID: original.id, tagID: tag.id)])
        let copied = try await repository.copyHost(id: original.id)
        let snapshot = try await repository.snapshot(query: HostQuery(tagIDs: [tag.id]))
        XCTAssertEqual(Set(snapshot.hosts.map(\.id)), [original.id, copied.id])
        XCTAssertEqual(snapshot.hostTagIDs[copied.id], [tag.id])
        XCTAssertEqual(copied.folderID, group.id)
        XCTAssertFalse(copied.savePasswordAuthorized)
        XCTAssertNil(copied.lastConnectedAt)
    }
}

/// Deliberately implements only the pre-U2 protocol requirements.
private actor LegacyVaultBridgeRepository: AppRepositoryProtocol {
    func snapshot(query: HostQuery) -> AppSnapshot { AppSnapshot(hosts: [], folders: [], keys: [], settings: AppSettings()) }
    func apply(_ changes: [RepositoryChange]) throws { throw RepositoryError.notFound }
    func copyHost(id: UUID) throws -> HostConfiguration { throw RepositoryError.notFound }
    func copyFolder(id: UUID) throws -> HostFolder { throw RepositoryError.notFound }
    func close() {}
}
