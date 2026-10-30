import Foundation
import GRDB

public enum RepositoryError: Error, Equatable, Sendable {
    case invalidField(String)
    case notFound
    case conflictingID
    case staleRecord
    case resourceInUse
    case savingNotAuthorized
    case cleanupAlreadyScheduled
    case resourceStillRegistered
    case unsupportedSchema
    case databaseBusy
    case unsafeDatabaseLocation
}

public enum AuthenticationKind: String, Codable, Sendable, DatabaseValueConvertible {
    case password, passwordWithMFA, privateKey, privateKeyWithMFA
    var usesKey: Bool { self == .privateKey || self == .privateKeyWithMFA }
}

/// Metadata only. No API in this package accepts a password or a key's contents.
public struct HostConfiguration: Codable, Equatable, Sendable, Identifiable, FetchableRecord, PersistableRecord {
    public static let databaseTableName = "hosts"
    public var id: UUID
    public var name: String
    public var address: String
    public var port: Int
    public var username: String
    public var authentication: AuthenticationKind
    public var credentialRef: UUID?
    public var keyRef: UUID?
    public var savePasswordAuthorized: Bool
    public var folderID: UUID?
    public var isFavorite: Bool
    public var favoriteOrder: Int
    public var lastConnectedAt: Date?
    /// Zero disables keepalive. These are OpenSSH-style interval/count values, not reconnect policy.
    public var keepaliveInterval: Int
    public var keepaliveCountMax: Int

    public init(id: UUID = UUID(), name: String, address: String, port: Int = 22,
                username: String, authentication: AuthenticationKind = .password,
                credentialRef: UUID? = nil, keyRef: UUID? = nil,
                savePasswordAuthorized: Bool = false, folderID: UUID? = nil,
                isFavorite: Bool = false, favoriteOrder: Int = 0,
                lastConnectedAt: Date? = nil, keepaliveInterval: Int = 30, keepaliveCountMax: Int = 3) {
        self.id = id; self.name = name; self.address = address; self.port = port
        self.username = username; self.authentication = authentication
        self.credentialRef = credentialRef; self.keyRef = keyRef
        self.savePasswordAuthorized = savePasswordAuthorized; self.folderID = folderID
        self.isFavorite = isFavorite; self.favoriteOrder = favoriteOrder
        self.lastConnectedAt = lastConnectedAt
        self.keepaliveInterval = keepaliveInterval; self.keepaliveCountMax = keepaliveCountMax
    }

    /// Older exported metadata may predate the v2 authorization/order fields. Absence never
    /// grants permission to read a saved password, even when a credential reference is present.
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(UUID.self, forKey: .id)
        name = try values.decode(String.self, forKey: .name)
        address = try values.decode(String.self, forKey: .address)
        port = try values.decodeIfPresent(Int.self, forKey: .port) ?? 22
        username = try values.decode(String.self, forKey: .username)
        authentication = try values.decodeIfPresent(AuthenticationKind.self, forKey: .authentication) ?? .password
        credentialRef = try values.decodeIfPresent(UUID.self, forKey: .credentialRef)
        keyRef = try values.decodeIfPresent(UUID.self, forKey: .keyRef)
        savePasswordAuthorized = try values.decodeIfPresent(Bool.self, forKey: .savePasswordAuthorized) ?? false
        folderID = try values.decodeIfPresent(UUID.self, forKey: .folderID)
        isFavorite = try values.decodeIfPresent(Bool.self, forKey: .isFavorite) ?? false
        favoriteOrder = try values.decodeIfPresent(Int.self, forKey: .favoriteOrder) ?? 0
        lastConnectedAt = try values.decodeIfPresent(Date.self, forKey: .lastConnectedAt)
        keepaliveInterval = try values.decodeIfPresent(Int.self, forKey: .keepaliveInterval) ?? 30
        keepaliveCountMax = try values.decodeIfPresent(Int.self, forKey: .keepaliveCountMax) ?? 3
    }

    public static func databaseDateEncodingStrategy(for column: String) -> DatabaseDateEncodingStrategy { .timeIntervalSince1970 }
    public static func databaseDateDecodingStrategy(for column: String) -> DatabaseDateDecodingStrategy { .timeIntervalSince1970 }

    func validate() throws {
        try validateText(name, field: "name", limit: 256)
        try validateText(address, field: "address", limit: 1024, noWhitespace: true)
        try validateText(username, field: "username", limit: 256, noWhitespace: true)
        guard (1...65535).contains(port) else { throw RepositoryError.invalidField("port") }
        try validateKeepalive(interval: keepaliveInterval, count: keepaliveCountMax)
        guard (-1_000_000_000...1_000_000_000).contains(favoriteOrder) else { throw RepositoryError.invalidField("favoriteOrder") }
        if let date = lastConnectedAt, !date.timeIntervalSince1970.isFinite { throw RepositoryError.invalidField("lastConnectedAt") }
        guard !authentication.usesKey || (credentialRef == nil && !savePasswordAuthorized),
              authentication.usesKey || keyRef == nil else { throw RepositoryError.invalidField("authenticationReferences") }
        if credentialRef != nil && !savePasswordAuthorized { throw RepositoryError.savingNotAuthorized }
    }
}

/// Local organization only. A parent does not confer credentials or connection settings.
public struct HostFolder: Codable, Equatable, Sendable, Identifiable, FetchableRecord, PersistableRecord {
    public static let databaseTableName = "folders"
    public var id: UUID
    public var name: String
    public var sortOrder: Int
    public var parentID: UUID?
    public init(id: UUID = UUID(), name: String, sortOrder: Int = 0, parentID: UUID? = nil) {
        self.id = id; self.name = name; self.sortOrder = sortOrder; self.parentID = parentID
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(UUID.self, forKey: .id)
        name = try values.decode(String.self, forKey: .name)
        sortOrder = try values.decodeIfPresent(Int.self, forKey: .sortOrder) ?? 0
        parentID = try values.decodeIfPresent(UUID.self, forKey: .parentID)
    }
}

public struct HostTag: Codable, Equatable, Sendable, Identifiable, FetchableRecord, PersistableRecord {
    public static let databaseTableName = "tags"
    public var id: UUID
    public var name: String
    public init(id: UUID = UUID(), name: String) { self.id = id; self.name = name }
}

/// Root-to-leaf components retain exact identities even for identically named siblings or names
/// containing path separators. displayName is presentation/search text, never an identifier.
public struct HostFolderPath: Equatable, Sendable, Identifiable {
    public let components: [HostFolder]
    public var id: UUID { components[components.count - 1].id }
    public var folderIDs: [UUID] { components.map(\.id) }
    public var displayName: String { components.map(\.name).joined(separator: " / ") }
    public var identityPath: String { folderIDs.map(\.uuidString).joined(separator: "/") }

    init(components: [HostFolder]) { self.components = components }
}

public struct HostMetadata: Equatable, Sendable, Identifiable {
    public var host: HostConfiguration
    public var folderPath: HostFolderPath?
    public var tags: [HostTag]
    public var id: UUID { host.id }
    public var tagIDs: Set<UUID> { Set(tags.map(\.id)) }
}

/// One consistent SQLite read for the Vault's filtered hosts and complete organization catalog.
public struct VaultMetadataSnapshot: Equatable, Sendable {
    public var hosts: [HostMetadata]
    public var folders: [HostFolderPath]
    public var tags: [HostTag]
}

public struct FolderDeletionImpact: Equatable, Sendable {
    public var folder: HostFolder
    public var directHostCount: Int
    public var directChildFolderCount: Int
}

public struct TagDeletionImpact: Equatable, Sendable {
    public var tag: HostTag
    public var hostCount: Int
}

public enum CredentialPurpose: String, Codable, Sendable, DatabaseValueConvertible { case password, privateKeyPassphrase }
public struct CredentialReference: Codable, Equatable, Sendable, Identifiable, FetchableRecord, PersistableRecord {
    public static let databaseTableName = "credentials"
    public var id: UUID
    public var purpose: CredentialPurpose
    /// Must be explicitly true to register metadata for an externally saved credential.
    public var isSavingAuthorized: Bool
    public init(id: UUID = UUID(), purpose: CredentialPurpose, isSavingAuthorized: Bool) {
        self.id = id; self.purpose = purpose; self.isSavingAuthorized = isSavingAuthorized
    }
}

public enum ManagedKeyAlgorithm: String, Codable, Sendable, DatabaseValueConvertible { case ed25519, rsa }

/// The saved-secret authorization identity excludes editable presentation metadata such as label.
public struct ManagedKeyAuthenticationIdentity: Equatable, Hashable, Sendable {
    public let id: UUID
    public let algorithm: ManagedKeyAlgorithm
    public let passphraseCredentialRef: UUID?
}

public struct ManagedKeyReference: Codable, Equatable, Sendable, Identifiable, FetchableRecord, PersistableRecord {
    public static let databaseTableName = "managedKeys"
    public var id: UUID
    public var algorithm: ManagedKeyAlgorithm
    public var passphraseCredentialRef: UUID?
    public var label: String
    public var authenticationIdentity: ManagedKeyAuthenticationIdentity {
        ManagedKeyAuthenticationIdentity(id: id, algorithm: algorithm, passphraseCredentialRef: passphraseCredentialRef)
    }
    public init(id: UUID = UUID(), algorithm: ManagedKeyAlgorithm, passphraseCredentialRef: UUID? = nil, label: String = "") {
        self.id = id; self.algorithm = algorithm; self.passphraseCredentialRef = passphraseCredentialRef; self.label = label
    }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(UUID.self, forKey: .id)
        algorithm = try values.decode(ManagedKeyAlgorithm.self, forKey: .algorithm)
        passphraseCredentialRef = try values.decodeIfPresent(UUID.self, forKey: .passphraseCredentialRef)
        label = try values.decodeIfPresent(String.self, forKey: .label) ?? ""
    }
}

public enum TerminalTheme: String, Codable, Sendable, DatabaseValueConvertible { case system, light, dark }
public enum TerminalCursorShape: String, Codable, Sendable, DatabaseValueConvertible { case block, underline, bar }
/// Management navigation only. No option may restore an SSH session or answer authentication.
public enum StartupManagementPage: String, Codable, Sendable, DatabaseValueConvertible { case vault, sftp, lastManagement }
public struct AppSettings: Codable, Equatable, Sendable, FetchableRecord, PersistableRecord {
    public static let databaseTableName = "settings"
    public static let maximumHistoryLines = 100_000
    public private(set) var id: Int = 1
    public var historyLines: Int = 10_000
    public var fontName: String = "SFMono-Regular"
    public var fontSize: Double = 13
    public var theme: TerminalTheme = .system
    public var foregroundColor: String = "#D8DEE9"
    public var backgroundColor: String = "#20242C"
    public var cursorColor: String = "#D8DEE9"
    public var keepaliveInterval: Int = 30
    public var keepaliveCountMax: Int = 3
    public var cursorShape: TerminalCursorShape = .block
    public var cursorBlink: Bool = true
    public var startupPage: StartupManagementPage = .vault
    public init() {}

    /// Old metadata omits new preferences. Missing values use safe defaults; present,
    /// malformed values are rejected instead of silently accepting a corrupt setting.
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decodeIfPresent(Int.self, forKey: .id) ?? 1
        historyLines = try values.decodeIfPresent(Int.self, forKey: .historyLines) ?? 10_000
        fontName = try values.decodeIfPresent(String.self, forKey: .fontName) ?? "SFMono-Regular"
        fontSize = try values.decodeIfPresent(Double.self, forKey: .fontSize) ?? 13
        theme = try values.decodeIfPresent(TerminalTheme.self, forKey: .theme) ?? .system
        foregroundColor = try values.decodeIfPresent(String.self, forKey: .foregroundColor) ?? "#D8DEE9"
        backgroundColor = try values.decodeIfPresent(String.self, forKey: .backgroundColor) ?? "#20242C"
        cursorColor = try values.decodeIfPresent(String.self, forKey: .cursorColor) ?? "#D8DEE9"
        keepaliveInterval = try values.decodeIfPresent(Int.self, forKey: .keepaliveInterval) ?? 30
        keepaliveCountMax = try values.decodeIfPresent(Int.self, forKey: .keepaliveCountMax) ?? 3
        cursorShape = try values.decodeIfPresent(TerminalCursorShape.self, forKey: .cursorShape) ?? .block
        cursorBlink = try values.decodeIfPresent(Bool.self, forKey: .cursorBlink) ?? true
        startupPage = try values.decodeIfPresent(StartupManagementPage.self, forKey: .startupPage) ?? .vault
        try validate()
    }

    func validate() throws {
        guard id == 1 else { throw RepositoryError.invalidField("settingsID") }
        guard (0...Self.maximumHistoryLines).contains(historyLines) else { throw RepositoryError.invalidField("historyLines") }
        try validateText(fontName, field: "fontName", limit: 256)
        guard fontSize.isFinite, (6...72).contains(fontSize) else { throw RepositoryError.invalidField("fontSize") }
        for color in [foregroundColor, backgroundColor, cursorColor] {
            guard color.utf8.count == 7, color.first == "#", color.dropFirst().allSatisfy({ $0.isASCII && $0.isHexDigit }) else {
                throw RepositoryError.invalidField("color")
            }
        }
        try validateKeepalive(interval: keepaliveInterval, count: keepaliveCountMax)
    }
}

public enum ExternalResourceKind: String, Codable, Sendable, DatabaseValueConvertible { case credential, privateKey }
public struct ExternalResource: Equatable, Sendable {
    public var kind: ExternalResourceKind
    public var id: UUID
    public init(kind: ExternalResourceKind, id: UUID) { self.kind = kind; self.id = id }
}
public enum CleanupReason: String, Codable, Sendable, DatabaseValueConvertible { case removedReference, orphanedExternalResource }
public enum CleanupState: String, Codable, Sendable, DatabaseValueConvertible { case pending, completed }
/// Only structured failure codes may be persisted; arbitrary external error descriptions may contain secrets.
public enum CleanupFailure: String, Codable, Sendable, DatabaseValueConvertible { case unavailable, permissionDenied, transient }
public struct CleanupTicket: Codable, Equatable, Sendable, Identifiable, FetchableRecord, PersistableRecord {
    public static let databaseTableName = "cleanupTickets"
    public let id: UUID
    public let resourceKind: ExternalResourceKind
    public let resourceID: UUID
    public let reason: CleanupReason
    public var state: CleanupState
    public let createdAt: Date
    public var attemptCount: Int
    public var lastFailure: CleanupFailure?
    public static func databaseDateEncodingStrategy(for column: String) -> DatabaseDateEncodingStrategy { .timeIntervalSince1970 }
    public static func databaseDateDecodingStrategy(for column: String) -> DatabaseDateDecodingStrategy { .timeIntervalSince1970 }
}

public enum FolderFilter: Equatable, Sendable {
    case all, ungrouped
    /// Direct members only, preserving the original single-level API's semantics.
    case folder(UUID)
    case folderAndDescendants(UUID)
}
public enum HostSort: Equatable, Sendable { case name, recentlyConnected, favorites }
public enum HostSortDirection: Equatable, Sendable { case ascending, descending }
public struct HostQuery: Equatable, Sendable {
    public var search: String
    public var favoritesOnly: Bool
    public var folder: FolderFilter
    public var sort: HostSort
    public var sortDirection: HostSortDirection
    /// All selected tag IDs must be assigned to a host (AND, not OR). Unknown IDs match nothing.
    public var tagIDs: Set<UUID>
    public init(search: String = "", favoritesOnly: Bool = false, folder: FolderFilter = .all, sort: HostSort = .name,
                sortDirection: HostSortDirection? = nil, tagIDs: Set<UUID> = []) {
        self.search = search; self.favoritesOnly = favoritesOnly; self.folder = folder; self.sort = sort
        self.sortDirection = sortDirection ?? (sort == .recentlyConnected ? .descending : .ascending)
        self.tagIDs = tagIDs
    }
}

/// Optimistic editor precondition checked under the same immediate write transaction as the update.
/// Connection activity is deliberately not editable; it is ignored here and preserved by the update.
public struct HostEditPrecondition: Equatable, Sendable {
    public let host: HostConfiguration
    public let tagIDs: Set<UUID>?
    public init(host: HostConfiguration, tagIDs: Set<UUID>? = nil) { self.host = host; self.tagIDs = tagIDs }
}

/// Every batch is one real SQLite transaction. A failing command rolls back the entire batch.
public enum RepositoryChange: Sendable {
    case insertHost(HostConfiguration), updateHost(HostConfiguration), deleteHost(UUID)
    case updateHostIfUnchanged(HostConfiguration, expected: HostEditPrecondition)
    case saveFolder(HostFolder), moveFolder(UUID, parentID: UUID?), deleteFolder(UUID)
    /// A set is dissolved to its nearest surviving ancestors, independent of input order.
    case deleteFolders(Set<UUID>)
    case moveHost(UUID, folderID: UUID?)
    /// Tag metadata changes do not implicitly assign or unassign any host.
    case addTag(HostTag), saveTag(HostTag), renameTag(UUID, name: String), deleteTag(UUID)
    case assignTag(hostID: UUID, tagID: UUID), unassignTag(hostID: UUID, tagID: UUID)
    case setHostTags(hostID: UUID, tagIDs: Set<UUID>)
    case registerCredential(CredentialReference), registerKey(ManagedKeyReference)
    case updateKeyPassphrase(keyID: UUID, credentialRef: UUID?)
    case updateKeyLabel(keyID: UUID, label: String)
    case deleteCredential(UUID), deleteKey(UUID)
    case saveSettings(AppSettings)
    case setFavorite(UUID, Bool, order: Int = 0)
    case markConnected(UUID, Date)
    case scheduleOrphanCleanup(ExternalResource)
}

func validateText(_ value: String, field: String, limit: Int, noWhitespace: Bool = false) throws {
    guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, value.utf8.count <= limit,
          !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
          !noWhitespace || !value.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.contains($0) }) else {
        throw RepositoryError.invalidField(field)
    }
}
func validateKeepalive(interval: Int, count: Int) throws {
    guard (0...3600).contains(interval), (1...10).contains(count) else { throw RepositoryError.invalidField("keepalive") }
}
