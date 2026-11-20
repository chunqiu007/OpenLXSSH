import Foundation

/// Bounds manager-owned metadata, not file contents. Each preparation reserves its entire
/// allowance before I/O. Accounting includes conservative container/entry overhead as well as
/// raw path/name/identity bytes; backend list() responses retain their existing backend bounds.
/// Ready/history reservations shrink to conservatively measured metadata; removal of the last
/// associated job releases that shared reservation. Observers may retain immutable snapshots,
/// whose external lifetime is not controlled by this manager's admission budget.
public struct TransferPlanLimits: Sendable {
    public let maxEntries: Int
    public let maxDepth: Int
    public let maxMetadataBytes: Int
    public let maxTotalEntries: Int
    public let maxTotalMetadataBytes: Int
    public let maxConcurrentPreparations: Int
    public let maxPendingPlans: Int
    public let lifetime: Duration
    public init(maxEntries: Int = 10_000, maxDepth: Int = 32, maxMetadataBytes: Int = 8 * 1024 * 1024,
                maxTotalEntries: Int = 20_000, maxTotalMetadataBytes: Int = 16 * 1024 * 1024,
                maxConcurrentPreparations: Int = 2, maxPendingPlans: Int = 8, lifetime: Duration = .seconds(300)) {
        precondition((1...10_000).contains(maxEntries) && (0...32).contains(maxDepth))
        precondition((1...8 * 1024 * 1024).contains(maxMetadataBytes))
        precondition(maxTotalEntries >= maxEntries && maxTotalEntries <= 20_000)
        precondition(maxTotalMetadataBytes >= maxMetadataBytes && maxTotalMetadataBytes <= 16 * 1024 * 1024)
        precondition((1...2).contains(maxConcurrentPreparations) && (1...16).contains(maxPendingPlans))
        precondition(lifetime > .zero && lifetime <= .seconds(300))
        self.maxEntries = maxEntries; self.maxDepth = maxDepth; self.maxMetadataBytes = maxMetadataBytes
        self.maxTotalEntries = maxTotalEntries; self.maxTotalMetadataBytes = maxTotalMetadataBytes
        self.maxConcurrentPreparations = maxConcurrentPreparations; self.maxPendingPlans = maxPendingPlans; self.lifetime = lifetime
    }
}
public struct TransferPlanResources: Sendable, Equatable {
    public let preparing: Int
    public let ready: Int
    public let confirming: Int
    public let reservedEntries: Int
    public let reservedMetadataBytes: Int
    public static let empty = Self(preparing: 0, ready: 0, confirming: 0, reservedEntries: 0, reservedMetadataBytes: 0)
    public var hasPendingPlans: Bool { preparing + ready + confirming > 0 }
}
public struct TransferPlanIssue: Sendable, Equatable {
    public let requestIndex: Int
    public let error: FileServiceError
}
public struct TransferBatchPlan: Sendable {
    public let id: UUID
    public let createdAt: Date
    public let expiresAt: Date
    public let requests: [TransferRequest]
    public let issues: [TransferPlanIssue]
    public var enumerationComplete: Bool { requests.allSatisfy { $0.sourceManifest?.enumerationComplete == true } }
    public var canExecute: Bool { !requests.isEmpty && enumerationComplete && issues.isEmpty }
    public var itemCount: Int { requests.reduce(0) { $0 + ($1.sourceManifest?.entries.count ?? 0) } }
    public var fileCount: Int { requests.reduce(0) { $0 + ($1.sourceManifest?.fileCount ?? 0) } }
    public var directoryCount: Int { requests.reduce(0) { $0 + ($1.sourceManifest?.directoryCount ?? 0) } }
    public var rejectedCount: Int { requests.reduce(0) { $0 + ($1.sourceManifest?.rejectedCount ?? 0) } }
    /// nil means unknown/incomplete/overflow, never an invented zero-byte total.
    public var totalBytes: UInt64? {
        guard enumerationComplete else { return nil }
        var result: UInt64 = 0
        for request in requests {
            guard let size = request.sourceManifest?.totalBytes else { return nil }
            let sum = result.addingReportingOverflow(size); guard !sum.overflow else { return nil }; result = sum.partialValue
        }
        return result
    }
}

/// Internally constructed, immutable metadata shared by plans, requests and snapshots. It owns
/// no service, credential, view or file contents. Equality is identity, not a 10,000-item copy/walk.
/// Attribute/child-set checks are NOT CAS: same-attribute ABA and the final check/use race remain.
public final class TransferSourceManifest: Sendable, Equatable {
    public struct Entry: Sendable, Equatable {
        public let path: RemotePath
        public let attributes: FileAttributes
        /// Exact raw names, sorted by bytes. nil for non-directories, [] for a known empty directory.
        public let children: [FileName]?
        /// Exact readlink bytes, never a path resolved through the local filesystem.
        public let linkTarget: Data?
    }
    struct Anchor: Sendable { let path: RemotePath; let attributes: FileAttributes }
    public let planID: UUID
    public let hostID: String
    public let source: TransferLocation
    public let destination: TransferLocation
    public let entries: [Entry]
    public let enumerationComplete: Bool
    public let issues: [FileServiceError]
    public let metadataBytes: Int
    let managerIdentity: UUID
    let sourceIdentity: ObjectIdentifier
    let destinationIdentity: ObjectIdentifier
    let sourceAnchors: [Anchor]
    let destinationAnchors: [Anchor]
    private let indices: [RemotePath: Int]
    public var fileCount: Int { entries.filter { $0.attributes.kind == .regular }.count }
    public var directoryCount: Int { entries.filter { $0.attributes.kind == .directory }.count }
    public var rejectedCount: Int {
        let rejectedLinks = Set(issues.filter { $0.kind == .symbolicLink }.compactMap(\.path))
        return entries.filter {
            switch $0.attributes.kind {
            case .regular, .directory: false
            case .symbolicLink: $0.linkTarget == nil || rejectedLinks.contains($0.path)
            default: true
            }
        }.count
    }
    public var totalBytes: UInt64? {
        guard enumerationComplete else { return nil }
        var total: UInt64 = 0
        for entry in entries where entry.attributes.kind == .regular {
            guard let size = entry.attributes.size else { return nil }
            let sum = total.addingReportingOverflow(size); guard !sum.overflow else { return nil }; total = sum.partialValue
        }
        return total
    }
    public static func == (lhs: TransferSourceManifest, rhs: TransferSourceManifest) -> Bool { lhs === rhs }
    init(planID: UUID, managerIdentity: UUID, request: TransferRequest,
         sourceIdentity: ObjectIdentifier, destinationIdentity: ObjectIdentifier, scan: TransferManifestScan,
         destinationAnchors: [Anchor], destinationIssue: FileServiceError?, metadataBytes: Int) {
        self.planID = planID; self.managerIdentity = managerIdentity; hostID = request.hostID
        source = request.source; destination = request.destination
        self.sourceIdentity = sourceIdentity; self.destinationIdentity = destinationIdentity
        entries = scan.entries; sourceAnchors = scan.anchors; self.destinationAnchors = destinationAnchors
        issues = scan.issues + (destinationIssue.map { [$0] } ?? [])
        enumerationComplete = scan.complete && destinationIssue == nil
        self.metadataBytes = metadataBytes
        indices = Dictionary(uniqueKeysWithValues: scan.entries.enumerated().map { ($0.element.path, $0.offset) })
    }
    func matches(_ request: TransferRequest, manager: UUID) -> Bool {
        managerIdentity == manager && hostID == request.hostID && source == request.source && destination == request.destination
    }
    func checkBinding(hostID: String, source: any RemoteFileService, sourcePath: RemotePath,
                      destination: any RemoteFileService, destinationPath: RemotePath) throws {
        guard enumerationComplete, issues.isEmpty, self.hostID == hostID, self.source.path == sourcePath,
              self.destination.path == destinationPath, sourceIdentity == ObjectIdentifier(source),
              destinationIdentity == ObjectIdentifier(destination) else {
            throw FileServiceError(.conflict, operation: "manifest-binding", path: sourcePath)
        }
    }
    func entry(_ path: RemotePath) throws -> Entry {
        guard let index = indices[path] else { throw FileServiceError(.raceDetected, operation: "source-not-in-manifest", path: path) }
        return entries[index]
    }
    /// Includes directories later removed by "..". They must also refer to real directories
    /// at the destination for the original, unmodified target string to resolve safely.
    func linkTargetEntries(for entry: Entry) throws -> [Entry] {
        try Self.resolveLink(entry, root: source.path) { path in
            indices[path].map { entries[$0] }
        }.traversal
    }
    fileprivate static func resolveLink(_ entry: Entry, root: RemotePath,
                                        lookup: (RemotePath) -> Entry?) throws -> (traversal: [Entry], target: Entry) {
        var currentLink = entry
        var visitedLinks = Set([entry.path])
        var result: [Entry] = [], seen: Set<RemotePath> = []
        while true {
            let unsafe = FileServiceError(.symbolicLink, operation: "manifest-link-unsafe-target", path: currentLink.path)
            let outside = FileServiceError(.symbolicLink, operation: "manifest-link-outside-tree", path: currentLink.path)
            guard let target = currentLink.linkTarget, !target.isEmpty, target.count <= 32_768,
                  !target.contains(0), var current = lookup(currentLink.path.parent) else { throw unsafe }
            guard target.first != 47 else { throw outside }
            if seen.insert(current.path).inserted { result.append(current) }
            // Empty interior components are repeated separators. A trailing separator, dot,
            // or dot-dot still requires the preceding component to be a real directory.
            for part in target.split(separator: 47, omittingEmptySubsequences: false) {
                guard current.attributes.kind == .directory else { throw unsafe }
                if part.isEmpty || part.elementsEqual([46]) { continue }
                if part.elementsEqual([46, 46]) {
                    guard current.path != root else { throw outside }
                    guard let parent = lookup(current.path.parent) else { throw unsafe }
                    current = parent
                } else {
                    guard let name = try? FileName(bytes: Data(part)),
                          let path = try? current.path.appending(name), let next = lookup(path),
                          next.attributes.kind == .regular || next.attributes.kind == .directory
                              || (next.attributes.kind == .symbolicLink && next.linkTarget != nil) else { throw unsafe }
                    current = next
                }
                if seen.insert(current.path).inserted { result.append(current) }
            }
            if current.attributes.kind == .symbolicLink {
                guard visitedLinks.insert(current.path).inserted, visitedLinks.count <= 16 else {
                    throw FileServiceError(.symbolicLink, operation: "manifest-link-unsafe-target", path: entry.path)
                }
                currentLink = current
                continue
            }
            if current.attributes.kind == .directory,
               visitedLinks.contains(where: { $0.parent.components.starts(with: current.path.components) }) {
                throw FileServiceError(.symbolicLink, operation: "manifest-link-unsafe-target", path: entry.path)
            }
            return (result, current)
        }
    }
    private func unchanged(_ service: any RemoteFileService, path: RemotePath, attributes: FileAttributes,
                           token: CancellationToken) async throws {
        do {
            guard try await service.lstat(path, token: token) == attributes else {
                throw FileServiceError(.raceDetected, operation: "manifest-source-attributes-changed", path: path)
            }
        } catch let error as FileServiceError where error.kind == .notFound || error.kind == .symbolicLink {
            throw FileServiceError(.raceDetected, operation: "manifest-source-replaced", path: path)
        }
        try token.check()
    }
    private func validateEntry(_ service: any RemoteFileService, _ entry: Entry, token: CancellationToken) async throws {
        try await unchanged(service, path: entry.path, attributes: entry.attributes, token: token)
        if let target = entry.linkTarget {
            guard try await service.readSymbolicLink(entry.path, token: token) == target else {
                throw FileServiceError(.raceDetected, operation: "manifest-link-target-changed", path: entry.path)
            }
            try token.check()
        }
        if let expected = entry.children {
            let rows = try await service.list(entry.path, token: token); try token.check()
            guard rows.count == expected.count, Set(rows.map(\.name)).count == rows.count,
                  rows.map(\.name).sorted(by: { $0.bytes.lexicographicallyPrecedes($1.bytes) }) == expected else {
                throw FileServiceError(.raceDetected, operation: "manifest-directory-children-changed", path: entry.path)
            }
            try await unchanged(service, path: entry.path, attributes: entry.attributes, token: token)
        }
    }
    /// Checks only approved paths, never turns a fresh listing into new expected metadata.
    func revalidate(_ service: any RemoteFileService, token: CancellationToken) async throws {
        for anchor in sourceAnchors { try await unchanged(service, path: anchor.path, attributes: anchor.attributes, token: token) }
        for entry in entries { try await validateEntry(service, entry, token: token) }
    }
    /// Re-run after decision/risk awaits and immediately before reading/creating/committing.
    /// Parent child sets also catch changes when a backend has coarse/missing directory timestamps.
    /// Re-listing ancestors is deliberately conservative: a flat n-file directory can return
    /// O(n²) metadata rows during execution. Memory bounds are not a total-time guarantee.
    func validateSource(_ service: any RemoteFileService, path: RemotePath, token: CancellationToken) async throws {
        try token.check()
        for anchor in sourceAnchors { try await unchanged(service, path: anchor.path, attributes: anchor.attributes, token: token) }
        var chain = [try entry(path)], current = path
        while current != source.path {
            guard current != .root else { throw FileServiceError(.invalidPath, operation: "manifest-source-boundary", path: path) }
            current = current.parent; chain.append(try entry(current))
        }
        for item in chain.reversed() { try await validateEntry(service, item, token: token) }
    }
    func validateDestination(_ service: any RemoteFileService, token: CancellationToken) async throws {
        for anchor in destinationAnchors { try await unchanged(service, path: anchor.path, attributes: anchor.attributes, token: token) }
    }
    static func anchors(_ service: any RemoteFileService, parent: RemotePath, token: CancellationToken,
                        maxBytes: Int = 8 * 1024 * 1024) async throws -> [Anchor] {
        var current = RemotePath.root, result: [Anchor] = [], bytes = 0
        let components = parent.components
        guard components.count <= 32 else { throw FileServiceError(.resourceLimit, operation: "manifest-parent-depth-limit", path: parent) }
        for index in 0...components.count {
            if index > 0 { current = try current.appending(components[index - 1]) }
            try token.check()
            guard 256 + current.bytes.count <= maxBytes - bytes else { throw FileServiceError(.resourceLimit, operation: "manifest-ancestor-limit", path: current) }
            let attr = try await service.lstat(current, token: token)
            guard attr.kind == .directory else {
                throw FileServiceError(attr.kind == .symbolicLink ? .symbolicLink : .invalidPath, operation: "manifest-parent-kind", path: current)
            }
            let charge = 256 + current.bytes.count + (attr.identity?.utf8.count ?? 0)
            guard charge <= maxBytes - bytes else { throw FileServiceError(.resourceLimit, operation: "manifest-ancestor-limit", path: current) }
            bytes += charge; result.append(Anchor(path: current, attributes: attr))
        }
        return result
    }
    static func anchorBytes(_ anchors: [Anchor]) -> Int {
        anchors.reduce(0) { $0 + 256 + $1.path.bytes.count + ($1.attributes.identity?.utf8.count ?? 0) }
    }
}

/// One bounded metadata scan using lstat/list and, for preserved links, readlink. On a problem the prefix is explicitly incomplete and
/// unconfirmable; the error is retained instead of silently skipping the rejected subtree.
struct TransferManifestScan: Sendable {
    var entries: [TransferSourceManifest.Entry] = []
    var anchors: [TransferSourceManifest.Anchor] = []
    var issues: [FileServiceError] = []
    var complete = false
    var metadataBytes = 0
    var preserveRelativeLinks = false
    let maxEntries: Int
    let maxDepth: Int
    let maxBytes: Int
    mutating func run(_ service: any RemoteFileService, request: TransferRequest, token: CancellationToken) async throws {
        do {
            try charge(512 + request.hostID.utf8.count + request.source.path.bytes.count + request.destination.path.bytes.count)
            guard request.destination.path.name != nil else { throw FileServiceError(.invalidPath, operation: "manifest-destination-root") }
            guard request.source.serviceID != request.destination.serviceID else {
                throw FileServiceError(.invalidPath, operation: "manifest-same-namespace-copy-not-supported", path: request.source.path)
            }
            anchors = try await TransferSourceManifest.anchors(service, parent: request.source.path.parent, token: token, maxBytes: maxBytes - metadataBytes)
            try charge(TransferSourceManifest.anchorBytes(anchors))
            try await walk(service, path: request.source.path, depth: 0, token: token)
            if let root = entries.first {
                guard (request.kind == .file && root.attributes.kind == .regular) ||
                      (request.kind == .tree && root.attributes.kind == .directory) else {
                    throw FileServiceError(.raceDetected, operation: "manifest-request-kind-changed", path: root.path)
                }
            }
            try validateLinks(root: request.source.path, token: token)
            complete = true
        } catch {
            try token.check()
            issues = [error as? FileServiceError ?? FileServiceError(.io, operation: "manifest-enumeration", path: request.source.path)]
        }
    }
    mutating func charge(_ bytes: Int) throws {
        guard bytes <= maxBytes - metadataBytes else { throw FileServiceError(.resourceLimit, operation: "manifest-metadata-limit") }
        metadataBytes += bytes
    }
    private func validateLinks(root: RemotePath, token: CancellationToken) throws {
        guard entries.contains(where: { $0.linkTarget != nil }) else { return }
        let indices = Dictionary(uniqueKeysWithValues: entries.enumerated().map { ($0.element.path, $0.offset) })
        struct DirectoryEdge { let directory: RemotePath; let link: RemotePath? }
        var edges: [RemotePath: [DirectoryEdge]] = [:]
        for entry in entries where entry.linkTarget != nil {
            try token.check()
            let result = try TransferSourceManifest.resolveLink(entry, root: root) { path in
                indices[path].map { entries[$0] }
            }
            if result.target.attributes.kind == .directory {
                edges[entry.path.parent, default: []].append(.init(directory: result.target.path, link: entry.path))
            }
        }
        guard !edges.isEmpty else { return }
        for entry in entries where entry.attributes.kind == .directory && entry.path != root {
            edges[entry.path.parent, default: []].append(.init(directory: entry.path, link: nil))
        }
        // A pair of individually in-tree directory links can still form a cycle. Visit
        // the directory graph once, without recursion or any filesystem traversal.
        enum Visit { case enter(DirectoryEdge), leave(DirectoryEdge) }
        var active: Set<RemotePath> = [], finished: Set<RemotePath> = [], activeLinks: [RemotePath] = []
        var stack: [Visit] = [.enter(.init(directory: root, link: nil))]
        while let visit = stack.popLast() {
            try token.check()
            switch visit {
            case .enter(let edge):
                if finished.contains(edge.directory) { continue }
                guard active.insert(edge.directory).inserted else {
                    throw FileServiceError(.symbolicLink, operation: "manifest-link-unsafe-target", path: edge.link ?? activeLinks.last)
                }
                if let link = edge.link { activeLinks.append(link) }
                stack.append(.leave(edge))
                for child in edges[edge.directory, default: []].reversed() { stack.append(.enter(child)) }
            case .leave(let edge):
                active.remove(edge.directory)
                finished.insert(edge.directory)
                if edge.link != nil { activeLinks.removeLast() }
            }
        }
    }
    private mutating func walk(_ service: any RemoteFileService, path: RemotePath, depth: Int, token: CancellationToken) async throws {
        try token.check()
        guard depth <= maxDepth, entries.count < maxEntries else { throw FileServiceError(.resourceLimit, operation: "manifest-recursive-bound", path: path) }
        let attr = try await service.lstat(path, token: token)
        try charge(512 + 2 * path.bytes.count + (attr.identity?.utf8.count ?? 0))
        let index = entries.count
        entries.append(.init(path: path, attributes: attr, children: attr.kind == .directory ? [] : nil, linkTarget: nil))
        if attr.kind == .symbolicLink, preserveRelativeLinks, depth > 0 {
            let target = try await service.readSymbolicLink(path, token: token)
            try token.check()
            try charge(target.count)
            guard try await service.lstat(path, token: token) == attr else {
                throw FileServiceError(.raceDetected, operation: "manifest-link-changed-during-scan", path: path)
            }
            entries[index] = .init(path: path, attributes: attr, children: nil, linkTarget: target)
            return
        }
        guard attr.kind == .regular || attr.kind == .directory else {
            throw FileServiceError(attr.kind == .symbolicLink ? .symbolicLink : .unsupported, operation: "manifest-rejected-kind", path: path)
        }
        if attr.kind == .directory {
            let rows = try await service.list(path, token: token); try token.check()
            guard rows.count <= maxEntries - entries.count else { throw FileServiceError(.resourceLimit, operation: "manifest-item-limit", path: path) }
            guard Set(rows.map(\.name)).count == rows.count else { throw FileServiceError(.protocolFailure, operation: "manifest-duplicate-name", path: path) }
            try charge(rows.reduce(0) { $0 + 64 + $1.name.bytes.count })
            let names = rows.map(\.name).sorted { $0.bytes.lexicographicallyPrecedes($1.bytes) }
            entries[index] = .init(path: path, attributes: attr, children: names, linkTarget: nil)
            for name in names { try await walk(service, path: path.appending(name), depth: depth + 1, token: token) }
            guard try await service.lstat(path, token: token) == attr else {
                throw FileServiceError(.raceDetected, operation: "manifest-directory-changed-during-scan", path: path)
            }
        }
    }
}
