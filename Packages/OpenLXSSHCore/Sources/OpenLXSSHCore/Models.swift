import Foundation
import GRDB

public enum RepositoryError: Error, Equatable, Sendable {
    case invalidField(String)
    case notFound
    case conflictingID
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

/// There is deliberately no parent-folder relationship.
public struct HostFolder: Codable, Equatable, Sendable, Identifiable, FetchableRecord, PersistableRecord {
    public static let databaseTableName = "folders"
    public var id: UUID
    public var name: String
    public var sortOrder: Int
    public init(id: UUID = UUID(), name: String, sortOrder: Int = 0) { self.id = id; self.name = name; self.sortOrder = sortOrder }
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
public struct ManagedKeyReference: Codable, Equatable, Sendable, Identifiable, FetchableRecord, PersistableRecord {
    public static let databaseTableName = "managedKeys"
    public var id: UUID
    public var algorithm: ManagedKeyAlgorithm
    public var passphraseCredentialRef: UUID?
    public init(id: UUID = UUID(), algorithm: ManagedKeyAlgorithm, passphraseCredentialRef: UUID? = nil) {
        self.id = id; self.algorithm = algorithm; self.passphraseCredentialRef = passphraseCredentialRef
    }
}

public enum TerminalTheme: String, Codable, Sendable, DatabaseValueConvertible { case system, light, dark }
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
    public init() {}

    func validate() throws {
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

public enum FolderFilter: Equatable, Sendable { case all, ungrouped, folder(UUID) }
public enum HostSort: Sendable { case name, recentlyConnected, favorites }
public struct HostQuery: Sendable {
    public var search: String
    public var favoritesOnly: Bool
    public var folder: FolderFilter
    public var sort: HostSort
    public init(search: String = "", favoritesOnly: Bool = false, folder: FolderFilter = .all, sort: HostSort = .name) {
        self.search = search; self.favoritesOnly = favoritesOnly; self.folder = folder; self.sort = sort
    }
}

/// Every batch is one real SQLite transaction. A failing command rolls back the entire batch.
public enum RepositoryChange: Sendable {
    case insertHost(HostConfiguration), updateHost(HostConfiguration), deleteHost(UUID)
    case saveFolder(HostFolder), deleteFolder(UUID)
    case registerCredential(CredentialReference), registerKey(ManagedKeyReference)
    case updateKeyPassphrase(keyID: UUID, credentialRef: UUID?)
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
