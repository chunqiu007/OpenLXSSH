import AppKit
import Combine
import CoreFoundation
import Darwin
import Foundation
import SwiftUI
import OpenLXSSHFiles
import OpenLXSSHCore

/// Immutable, presentation-scoped operation input. Display strings are never parsed back into paths.
struct FilesOperationTarget: Identifiable, Sendable {
    enum Owner: Sendable {
        case local(revision: UUID)
        case remote(lifetime: UUID, generation: UInt64, serviceID: UUID, host: HostConfiguration, revision: UUID)
    }
    let id = UUID()
    let owner: Owner
    let endpoint: String
    let parent: RemotePath
    let parentAttributes: FileAttributes
    let entries: [DirectoryEntry]
    func path(for entry: DirectoryEntry) -> RemotePath? {
        guard entries.contains(entry) else { return nil }
        return try? parent.appending(entry.name)
    }
}

struct DualFilesDialog: Identifiable {
    enum Content {
        case host, name(FilesOperationTarget, Bool), details(FilesOperationTarget, Bool), deleteOptions(FilesOperationTarget, Bool)
        case localDelete(BrowserDeleteReview), remoteDelete(FilesDeleteBatchReview)
    }
    let id = UUID()
    let content: Content
}

enum FilesBrowserContentState: Equatable {
    case loading, notLoaded, failed(hasSnapshot: Bool), empty, filteredEmpty, populated
    static func resolve(loading: Bool, hasSnapshot: Bool, readFailed: Bool, total: Int, visible: Int) -> Self {
        if loading { return .loading }
        if readFailed { return .failed(hasSnapshot: hasSnapshot) }
        if !hasSnapshot { return .notLoaded }
        if total == 0 { return .empty }
        return visible == 0 ? .filteredEmpty : .populated
    }
}

/// This is the owner used by FilesTasksView, not a parallel test-only presentation helper.
@MainActor final class FilesHistoryRemovalOwner: ObservableObject {
    @Published private(set) var review: FilesHistoryRemovalReview?
    @Published private(set) var inFlightIDs: Set<UUID> = []
    var isInFlight: Bool { review.map { inFlightIDs.contains($0.id) } ?? false }
    func prepare(using model: FilesController) {
        cancel(using: model)
        review = model.prepareHistoryRemoval()
    }
    func cancel(using model: FilesController) {
        if let review { model.discardHistoryRemoval(review) }
        review = nil // A submitted metadata mutation is not rolled back or silently cancelled.
    }
    @discardableResult func confirm(using model: FilesController) -> Task<Bool, Never>? {
        guard let review, !inFlightIDs.contains(review.id) else { return nil }
        inFlightIDs.insert(review.id)
        let removal = model.removeFinishedTransfers(review)
        return Task { @MainActor [weak self] in
            let result = await removal.value
            self?.inFlightIDs.remove(review.id)
            if self?.review?.id == review.id { self?.review = nil }
            return result
        }
    }
}

struct FilesDirectorySnapshot: Sendable {
    let attributes: FileAttributes
    let entries: [DirectoryEntry]
}

struct BrowserDeleteItem: Sendable {
    let operations: SafeFileOperations
    let plan: DeletePlan
}
struct BrowserDeleteOutcome: Sendable {
    let reports: [DeleteReport]
    let failure: FileServiceError?
}
struct BrowserDeleteReview: Identifiable, Sendable {
    let id = UUID()
    let revision: UUID
    let parent: RemotePath
    let items: [BrowserDeleteItem]
    var localRoot: RemotePath? = nil
    let target: FilesOperationTarget
    var canExecute: Bool { !items.isEmpty && items.allSatisfy { $0.plan.canExecute } }
    var itemCount: Int { items.reduce(0) { $0 + $1.plan.items.count } }
    func pathBytes(_ path: RemotePath) -> Data {
        guard let localRoot, localRoot != .root else { return path.bytes }
        return localRoot.bytes + (path == .root ? Data() : path.bytes)
    }
    func displayedPath(_ path: RemotePath) -> String { FileDisplay.bytes(pathBytes(path)) }
}

/// Metadata and explicit file actions run on this worker, not on the UI actor.
actor LocalBrowserWorker {
    private let boundary: URL?
    private let beforeList: (@Sendable () async throws -> Void)?
    private let validateBoundary: (@Sendable () throws -> Void)?
    private var service: LocalFileService?
    private var root: RemotePath?
    init(boundary: URL?, beforeList: (@Sendable () async throws -> Void)? = nil,
         validateBoundary: (@Sendable () throws -> Void)? = nil) {
        self.boundary = boundary; self.beforeList = beforeList; self.validateBoundary = validateBoundary
    }
    private func opened() throws -> (LocalFileService, RemotePath) {
        try validateBoundary?()
        if let service, let root { return (service, root) }
        let root = try boundary.map { try FilesLocalPaths.rawPath(FilesLocalPaths.components($0)) } ?? .root
        let fd = try FilesLocalPaths.openDirectory(try FilesLocalPaths.components(FilesLocalPaths.url(root)))
        defer { Darwin.close(fd) }
        let service = try LocalFileService(rootDirectoryDescriptor: fd)
        self.service = service; self.root = root
        return (service, root)
    }
    func initialPath() throws -> RemotePath {
        if let boundary { return try FilesLocalPaths.rawPath(FilesLocalPaths.components(boundary)) }
        return try FilesLocalPaths.rawPath(FilesLocalPaths.components(FileManager.default.homeDirectoryForCurrentUser))
    }
    private func relative(_ path: RemotePath, root: RemotePath) throws -> RemotePath {
        guard root != .root else { return path }
        if path == root { return .root }
        guard path.bytes.starts(with: root.bytes + Data([47])) else { throw FileServiceError(.invalidPath, operation: "local-browser-outside-root") }
        return try RemotePath(bytes: Data(path.bytes.dropFirst(root.bytes.count)))
    }
    func list(_ path: RemotePath, token: CancellationToken) async throws -> FilesDirectorySnapshot {
        try await beforeList?(); try token.check()
        let (service, root) = try opened(), relative = try relative(path, root: root)
        let attributes = try await service.lstat(relative, token: token)
        guard attributes.kind == .directory else { throw FileServiceError(attributes.kind == .symbolicLink ? .symbolicLink : .conflict, operation: "local-browser-directory") }
        return FilesDirectorySnapshot(attributes: attributes, entries: try await service.list(relative, token: token))
    }
    func mkdir(_ name: FileName, target: FilesOperationTarget, token: CancellationToken) async throws {
        let (service, root) = try opened(), parent = target.parent
        guard try await service.lstat(relative(parent, root: root), token: token) == target.parentAttributes else {
            throw FileServiceError(.raceDetected, operation: "local-mkdir-parent-changed", path: parent)
        }
        try await service.mkdir(relative(parent.appending(name), root: root), token: token)
    }
    func rename(_ entry: DirectoryEntry, name: FileName, target: FilesOperationTarget, token: CancellationToken) async throws {
        let (service, root) = try opened(), parent = target.parent, source = try relative(parent.appending(entry.name), root: root)
        guard try await service.lstat(relative(parent, root: root), token: token) == target.parentAttributes,
              try await service.lstat(source, token: token) == entry.attributes else { throw FileServiceError(.raceDetected, operation: "local-rename-stale") }
        let result = try await SafeFileOperations(service: service, hostID: "local-browser").rename(source, to: name, token: token)
        if case .failed(let error) = result.state { throw error }
    }
    func prepareDelete(_ selected: [DirectoryEntry], parent: RemotePath, revision: UUID, target: FilesOperationTarget, linkOnly: Bool, token: CancellationToken) async throws -> BrowserDeleteReview {
        let (service, root) = try opened()
        guard try await service.lstat(relative(parent, root: root), token: token) == target.parentAttributes else {
            throw FileServiceError(.raceDetected, operation: "local-delete-parent-changed", path: parent)
        }
        var items: [BrowserDeleteItem] = []
        do {
            for entry in selected {
                let path = try relative(parent.appending(entry.name), root: root)
                guard try await service.lstat(path, token: token) == entry.attributes else { throw FileServiceError(.raceDetected, operation: "local-delete-selection-changed") }
                let operations = SafeFileOperations(service: service, hostID: "local-browser")
                let plan = try await operations.prepareDelete(path, links: linkOnly ? .removeLinkOnly : .reject, token: token)
                items.append(BrowserDeleteItem(operations: operations, plan: plan))
            }
            return BrowserDeleteReview(revision: revision, parent: parent, items: items, localRoot: root, target: target)
        } catch {
            for item in items { await item.operations.discardDeletePlan(item.plan) }
            throw error
        }
    }
    func execute(_ review: BrowserDeleteReview, token: CancellationToken) async -> BrowserDeleteOutcome {
        var reports: [DeleteReport] = []
        do {
            let (service, root) = try opened()
            guard try await service.lstat(relative(review.parent, root: root), token: token) == review.target.parentAttributes else {
                throw FileServiceError(.raceDetected, operation: "local-delete-parent-changed", path: review.parent)
            }
            try await FilesDeletePreflight.validate(review.items, token: token)
            var confirmations: [DeleteConfirmation] = []
            for item in review.items {
                confirmations.append(try await item.operations.confirmDelete(item.plan, displayedRoot: item.plan.root,
                    displayedItemCount: item.plan.items.count, acknowledgedRisks: item.plan.risks))
            }
            for (item, confirmation) in zip(review.items, confirmations) {
                let report = try await item.operations.executeDelete(item.plan, confirmation: confirmation, token: token)
                reports.append(report)
                if !report.allSucceeded { throw FileServiceError(.raceDetected, operation: "local-delete-batch-stopped", path: item.plan.root) }
            }
            return BrowserDeleteOutcome(reports: reports, failure: nil)
        } catch {
            for item in review.items { await item.operations.discardDeletePlan(item.plan) }
            return BrowserDeleteOutcome(reports: reports, failure: error as? FileServiceError ?? FileServiceError(.io, operation: "local-delete-batch"))
        }
    }
    func close() async { await service?.close(); service = nil }
}

enum FilesDeletePreflight {
    static func validate(_ items: [BrowserDeleteItem], token: CancellationToken) async throws {
        guard !items.isEmpty, items.allSatisfy({ $0.plan.canExecute }) else { throw FileServiceError(.riskRejected, operation: "delete-incomplete-batch-plan") }
        for item in items {
            try token.check()
            let fresh = try await item.operations.prepareDelete(item.plan.root, links: item.plan.linkPolicy, token: token)
            await item.operations.discardDeletePlan(fresh)
            guard fresh.items == item.plan.items, fresh.issues == item.plan.issues, fresh.risks == item.plan.risks else {
                throw FileServiceError(.raceDetected, operation: "delete-batch-preflight-changed", path: item.plan.root)
            }
        }
    }
}

@MainActor final class LocalBrowserModel: ObservableObject {
    @Published private(set) var path: RemotePath?
    @Published private(set) var entries: [DirectoryEntry] = []
    @Published private(set) var loading = false
    @Published private(set) var readFailed = false
    @Published var issue: AppIssue?
    @Published var selection: Set<FileName> = []
    @Published var filter = ""
    @Published var showsHidden = false
    @Published var sort = FilesSort()
    @Published private(set) var history = FilesNavigationHistory()
    @Published private(set) var deleteReview: BrowserDeleteReview?
    @Published private(set) var deleteReports: [DeleteReport] = []
    private let worker: LocalBrowserWorker
    private let boundary: RemotePath?
    private var parentAttributes: FileAttributes?
    private var activated = false
    private var revision = UUID()
    private var operation: Task<Void, Never>?
    private var cancellation: CancellationToken?
    private var operationIsMutation = false
    private var pendingTargets: [UUID: FilesOperationTarget] = [:]
    init(root: URL? = nil, beforeList: (@Sendable () async throws -> Void)? = nil,
         validateBoundary: (@Sendable () throws -> Void)? = nil) {
        worker = LocalBrowserWorker(boundary: root, beforeList: beforeList, validateBoundary: validateBoundary)
        boundary = root.flatMap { try? FilesLocalPaths.rawPath(FilesLocalPaths.components($0)) }
    }
    var visibleEntries: [DirectoryEntry] { sort.apply(entries.filter { (showsHidden || $0.name.bytes.first != 46) && (filter.isEmpty || FileDisplay.name($0.name).localizedStandardContains(filter)) }) }
    var selectedEntries: [DirectoryEntry] { visibleEntries.filter { selection.contains($0.name) } }
    var contentState: FilesBrowserContentState {
        .resolve(loading: loading, hasSnapshot: path != nil, readFailed: readFailed, total: entries.count, visible: visibleEntries.count)
    }
    var canGoUp: Bool { path != nil && path != .root && path != boundary && !loading }
    func captureTarget(_ selected: [DirectoryEntry] = []) -> FilesOperationTarget? {
        guard !loading, let parent = path, let parentAttributes, selected.count <= 128, selected.allSatisfy(entries.contains) else { return nil }
        guard pendingTargets.count < 8 else {
            issue = .files(FileServiceError(.resourceLimit, operation: "local-pending-operation-targets")); return nil
        }
        let target = FilesOperationTarget(owner: .local(revision: revision), endpoint: "本地 · 此 Mac", parent: parent, parentAttributes: parentAttributes, entries: selected)
        pendingTargets[target.id] = target
        return target
    }
    func discardTarget(_ target: FilesOperationTarget) { pendingTargets[target.id] = nil }
    private func consumeTarget(_ target: FilesOperationTarget) -> Bool {
        let registered = pendingTargets.removeValue(forKey: target.id)
        guard registered != nil, case .local(let expected) = target.owner, expected == revision,
              !loading, target.parent == path, target.entries.allSatisfy(entries.contains) else {
            issue = .files(FileServiceError(.raceDetected, operation: "local-operation-owner-stale", path: target.parent)); return false
        }
        return true
    }
    func activate() {
        guard !loading, !activated || path == nil else { return }
        activated = true
        begin { [self] token in let initial = try await worker.initialPath(); try await load(initial, token: token) }
    }
    /// Leaving the retained page cancels only local metadata work, never remote I/O/transfers.
    func deactivate() { pendingTargets = [:]; if !operationIsMutation { cancel() } else { discardDelete() } }
    func navigate(_ target: RemotePath, historyIndex: Int? = nil) {
        guard !loading else { return }
        begin { [self] token in try await load(target, token: token, historyIndex: historyIndex) }
    }
    func go(_ text: String) { do { navigate(try RemotePath(text)) } catch { issue = .files(error) } }
    func back() { if let target = history.backward { navigate(target.path, historyIndex: target.index) } }
    func forward() { if let target = history.forward { navigate(target.path, historyIndex: target.index) } }
    func up() { if canGoUp, let path { navigate(path.parent) } }
    func refresh() { if let path { navigate(path) } else { activate() } }
    func refreshPreservingSelection() {
        guard !loading, pendingTargets.isEmpty, let path else { return }
        let selected = selection
        begin { [self] token in
            try await load(path, token: token)
            selection = selected.intersection(Set(entries.map(\.name)))
        }
    }
    func enter(_ entry: DirectoryEntry) {
        guard entries.contains(entry), let path, entry.attributes.kind == .directory else { issue = .files(FileServiceError(.symbolicLink, operation: "local-enter-link-refused")); return }
        do { navigate(try path.appending(entry.name)) } catch { issue = .files(error) }
    }
    private func load(_ target: RemotePath, token: CancellationToken, historyIndex: Int? = nil) async throws {
        do {
            let snapshot = try await worker.list(target, token: token); try token.check()
            path = target; parentAttributes = snapshot.attributes; entries = snapshot.entries; selection = []; history.commit(target, index: historyIndex); readFailed = false
        } catch {
            if !token.isCancelled && !Task.isCancelled { readFailed = true }
            throw error
        }
    }
    private func begin(mutation: Bool = false, _ body: @escaping @MainActor (CancellationToken) async throws -> Void) {
        guard !loading else { return }
        let id = UUID(), token = CancellationToken(); revision = id; pendingTargets = [:]; cancellation = token; loading = true; issue = nil
        operationIsMutation = mutation
        discardDelete()
        operation = Task { [weak self] in
            defer {
                if self?.revision == id {
                    self?.loading = false; self?.operation = nil; self?.cancellation = nil; self?.operationIsMutation = false
                }
            }
            do { try await body(token) }
            catch { if self?.revision == id, !token.isCancelled { self?.issue = .files(error) } }
        }
    }
    func mkdir(_ name: FileName) {
        guard let target = captureTarget() else { return }
        mkdir(name, target: target)
    }
    func mkdir(_ name: FileName, target: FilesOperationTarget) {
        guard consumeTarget(target), target.entries.isEmpty else { return }
        let parent = target.parent
        begin(mutation: true) { [self] token in try await worker.mkdir(name, target: target, token: token); try await load(parent, token: token) }
    }
    func rename(_ entry: DirectoryEntry, to name: FileName) {
        guard let target = captureTarget([entry]) else { return }
        rename(to: name, target: target)
    }
    func rename(to name: FileName, target: FilesOperationTarget) {
        guard consumeTarget(target), target.entries.count == 1, let entry = target.entries.first else { return }
        let parent = target.parent
        begin(mutation: true) { [self] token in try await worker.rename(entry, name: name, target: target, token: token); try await load(parent, token: token) }
    }
    func prepareDelete(_ selected: [DirectoryEntry], linkOnly: Bool) {
        guard let target = captureTarget(selected) else { return }
        prepareDelete(target, linkOnly: linkOnly)
    }
    func prepareDelete(_ target: FilesOperationTarget, linkOnly: Bool) {
        guard consumeTarget(target), !target.entries.isEmpty else { return }
        let worker = worker, parent = target.parent, selected = target.entries
        begin { [weak self] token in
            let expected = self?.revision ?? UUID()
            let review = try await worker.prepareDelete(selected, parent: parent, revision: expected, target: target, linkOnly: linkOnly, token: token)
            guard let self, revision == expected, path == parent, !token.isCancelled else {
                for item in review.items { await item.operations.discardDeletePlan(item.plan) }
                return
            }
            deleteReview = review
        }
    }
    func discardDelete(_ expected: BrowserDeleteReview? = nil) {
        if let expected, deleteReview?.id != expected.id { return }
        if let review = deleteReview { Task { for item in review.items { await item.operations.discardDeletePlan(item.plan) } } }
        deleteReview = nil
    }
    func executeDelete(_ review: BrowserDeleteReview) {
        guard review.id == deleteReview?.id, review.revision == revision, review.parent == path, review.canExecute else { return }
        deleteReview = nil
        begin(mutation: true) { [self] token in
            let outcome = await worker.execute(review, token: token)
            // A cancellation can be partial. Preserve the actual report even if the refresh is cancelled.
            deleteReports = outcome.reports
            if let failure = outcome.failure { issue = .files(failure) }
            try await load(review.parent, token: token)
        }
    }
    func cancel() { pendingTargets = [:]; cancellation?.cancel(); operation?.cancel(); discardDelete() }
    func waitUntilIdle() async { await operation?.value }
    func close() async { cancel(); await operation?.value; await worker.close(); activated = false }
    deinit { cancellation?.cancel(); operation?.cancel(); let worker = worker; Task { await worker.close() } }
}

/// Short-lived, view-owned input. Routing invalidation does not touch the controller/service/jobs.
@MainActor final class FilesInitialInputOwner: ObservableObject {
    struct Context: Equatable {
        let visible: Bool
        let hostID: UUID?
        let identity: HostConnectionIdentity?
        let epoch: UUID
    }
    @Published var secret = ""
    @Published var showSecret = false
    @Published var saved = false
    @Published var keyboardOnly = false
    private var context: Context?
    func update(_ value: Context) {
        if context != value || !value.visible { clear() }
        context = value
    }
    func clear() { secret = ""; showSecret = false; saved = false; keyboardOnly = false }
    func take() -> FilesConnectInput? {
        guard context?.visible == true, context?.hostID != nil else { clear(); return nil }
        let value = FilesConnectInput(primary: saved ? .saved : .manual(.init(utf8: secret)), keyboardOnly: keyboardOnly)
        clear(); return value
    }
}

// Files layout is independent of browsing, operation targets, authentication and transfers.
// These are the same native layout owners used by DualPaneFilesView and unhosted tests.
enum FilesLayoutSide: String { case local, remote }
enum FilesLayoutColumn: String, CaseIterable, Hashable {
    case name, modified, size, kind, permissions
    var title: String {
        switch self { case .name: "名称"; case .modified: "修改时间"; case .size: "大小"; case .kind: "类型"; case .permissions: "权限" }
    }
    var defaultWidth: Double {
        switch self { case .name: 240; case .modified: 135; case .size: 85; case .kind: 80; case .permissions: 65 }
    }
}
struct FilesTableLayout: Equatable {
    struct Column: Equatable { let id: FilesLayoutColumn; let width: Double }
    let columns: [Column]
    static let minimumWidth = 55.0
    static let maximumWidth = 4096.0
    static let standard = Self(columns: FilesLayoutColumn.allCases.map { Column(id: $0, width: $0.defaultWidth) })
    var isValid: Bool {
        columns.count == FilesLayoutColumn.allCases.count && Set(columns.map(\.id)) == Set(FilesLayoutColumn.allCases) &&
            columns.allSatisfy { $0.width.isFinite && (Self.minimumWidth...Self.maximumWidth).contains($0.width) }
    }
    static func maximumWidth(onVisibleWidth width: Double?) -> Double {
        min(maximumWidth, max(minimumWidth, width.flatMap { $0.isFinite && $0 > 0 ? $0 : nil } ?? 1440))
    }
}
enum FilesSplitLayout {
    static let minimumPaneWidth = 300.0
    static func validFraction(_ value: Double) -> Bool { value.isFinite && value > 0 && value < 1 }
    static func leftWidth(fraction: Double, availableWidth: Double) -> Double {
        guard availableWidth.isFinite, availableWidth > 0 else { return 0 }
        let minimum = min(minimumPaneWidth, availableWidth / 2)
        return min(availableWidth - minimum, max(minimum, availableWidth * (validFraction(fraction) ? fraction : 0.5)))
    }
}

/// An explicit whitelist, not AppKit's process-wide autosave archive. Nil disables all I/O.
@MainActor final class FilesLayoutPreferences {
    static let splitKey = "OpenLXSSH.Files.Layout.v1.split"
    static func columnsKey(_ side: FilesLayoutSide) -> String { "OpenLXSSH.Files.Layout.v1.columns." + side.rawValue }
    private let defaults: UserDefaults?
    init(defaults: UserDefaults?) { self.defaults = defaults }
    private static func number(_ value: Any?) -> Double? {
        guard let value = value as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID() else { return nil }
        let result = value.doubleValue
        return result.isFinite ? result : nil
    }
    func columns(_ side: FilesLayoutSide) -> FilesTableLayout {
        let key = Self.columnsKey(side)
        guard let value = defaults?.object(forKey: key) else { return .standard }
        func recover() -> FilesTableLayout { defaults?.removeObject(forKey: key); return .standard }
        guard let dictionary = value as? [String: Any], Set(dictionary.keys) == ["order", "widths"],
              let order = dictionary["order"] as? [String], order.count == FilesLayoutColumn.allCases.count,
              let widths = dictionary["widths"] as? [String: Any], Set(widths.keys) == Set(FilesLayoutColumn.allCases.map(\.rawValue)) else { return recover() }
        var columns: [FilesTableLayout.Column] = []
        for rawID in order {
            guard let id = FilesLayoutColumn(rawValue: rawID), let width = Self.number(widths[rawID]) else { return recover() }
            columns.append(.init(id: id, width: width))
        }
        let result = FilesTableLayout(columns: columns)
        guard result.isValid else { return recover() }
        return result
    }
    @discardableResult func saveColumns(_ layout: FilesTableLayout, side: FilesLayoutSide) -> Bool {
        guard let defaults, layout.isValid else { return false }
        defaults.set(["order": layout.columns.map { $0.id.rawValue },
                      "widths": Dictionary(uniqueKeysWithValues: layout.columns.map { ($0.id.rawValue, $0.width) })],
                     forKey: Self.columnsKey(side))
        return true
    }
    func splitFraction() -> Double {
        guard let value = defaults?.object(forKey: Self.splitKey) else { return 0.5 }
        guard let fraction = Self.number(value), FilesSplitLayout.validFraction(fraction) else {
            defaults?.removeObject(forKey: Self.splitKey); return 0.5
        }
        return fraction
    }
    @discardableResult func saveSplitFraction(_ value: Double) -> Bool {
        guard let defaults, FilesSplitLayout.validFraction(value) else { return false }
        defaults.set(value, forKey: Self.splitKey); return true
    }
}

/// Owns column geometry only. Subclasses keep row identity, selection, sort and actions.
@MainActor class FilesTableLayoutOwner: NSObject, NSTableViewDelegate {
    private weak var layoutTable: NSTableView?
    private let preferences: FilesLayoutPreferences
    private let side: FilesLayoutSide?
    private var applying = false
    init(defaults: UserDefaults?, side: FilesLayoutSide?) {
        preferences = FilesLayoutPreferences(defaults: side == nil ? nil : defaults); self.side = side
        super.init()
    }
    func configureColumns(in table: NSTableView) {
        guard layoutTable == nil, table.tableColumns.isEmpty else { return }
        applying = true; defer { applying = false }
        layoutTable = table
        // Never set autosaveName: even changing it can write to the global AppKit domain.
        table.autosaveTableColumns = false
        table.columnAutoresizingStyle = .noColumnAutoresizing; table.allowsColumnResizing = true; table.allowsColumnReordering = true
        let layout = side.map(preferences.columns) ?? .standard
        let maximum = widthLimit(table)
        for value in layout.columns {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(value.id.rawValue))
            column.title = value.id.title; column.minWidth = FilesTableLayout.minimumWidth; column.maxWidth = maximum
            column.width = min(maximum, value.width); column.resizingMask = .userResizingMask
            column.sortDescriptorPrototype = NSSortDescriptor(key: value.id.rawValue, ascending: true)
            table.addTableColumn(column)
        }
        table.delegate = self
    }
    private func widthLimit(_ table: NSTableView) -> Double {
        FilesTableLayout.maximumWidth(onVisibleWidth: table.window?.screen.map { Double($0.visibleFrame.width) })
    }
    func updateColumnBounds() {
        guard let table = layoutTable, !applying else { return }
        applying = true; defer { applying = false }
        let maximum = widthLimit(table)
        for column in table.tableColumns { column.minWidth = FilesTableLayout.minimumWidth; column.maxWidth = maximum }
    }
    func tableViewColumnDidMove(_ notification: Notification) { recordColumns(notification) }
    func tableViewColumnDidResize(_ notification: Notification) { recordColumns(notification) }
    private func recordColumns(_ notification: Notification) {
        guard !applying, let table = notification.object as? NSTableView, table === layoutTable, let side else { return }
        updateColumnBounds()
        var columns: [FilesTableLayout.Column] = []
        for column in table.tableColumns {
            guard let id = FilesLayoutColumn(rawValue: column.identifier.rawValue) else { return }
            columns.append(.init(id: id, width: Double(column.width)))
        }
        preferences.saveColumns(.init(columns: columns), side: side)
    }
}

/// Two stable hosting instances, owned by this exact split view; no ancestor/window search.
/// SwiftUI's root Files state stays outside this component. Updating values never replaces hosts.
@MainActor final class FilesNativeSplitView<Left: View, Right: View>: NSSplitView, NSSplitViewDelegate {
    let leftHost: NSHostingView<Left>
    let rightHost: NSHostingView<Right>
    private let preferences: FilesLayoutPreferences
    private var fraction: Double
    private var applying = false
    private var appliedPosition: CGFloat?
    private var appliedSize: NSSize?
    init(left: Left, right: Right, defaults: UserDefaults?) {
        leftHost = NSHostingView(rootView: left); rightHost = NSHostingView(rootView: right)
        let preferences = FilesLayoutPreferences(defaults: defaults)
        self.preferences = preferences; fraction = preferences.splitFraction()
        super.init(frame: .zero)
        isVertical = true; dividerStyle = .paneSplitter
        identifier = NSUserInterfaceItemIdentifier("files.panes.split")
        setAccessibilityLabel("本地与远端文件分栏")
        leftHost.sizingOptions = []; rightHost.sizingOptions = []
        addArrangedSubview(leftHost); addArrangedSubview(rightHost)
        delegate = self
    }
    required init?(coder: NSCoder) { nil }
    func update(left: Left, right: Right) { leftHost.rootView = left; rightHost.rootView = right }
    override func layout() {
        super.layout()
        if appliedSize != bounds.size { applyLayout() }
    }
    private var availableWidth: Double { max(0, Double(bounds.width - dividerThickness)) }
    private var minimum: CGFloat { min(CGFloat(FilesSplitLayout.minimumPaneWidth), CGFloat(availableWidth / 2)) }
    private func applyLayout() {
        guard !applying, bounds.width.isFinite, bounds.height.isFinite else { return }
        applying = true; defer { applying = false }
        let width = CGFloat(FilesSplitLayout.leftWidth(fraction: fraction, availableWidth: availableWidth))
        let rightX = width + min(max(0, bounds.width), dividerThickness)
        leftHost.frame = NSRect(x: 0, y: 0, width: width, height: max(0, bounds.height))
        rightHost.frame = NSRect(x: rightX, y: 0, width: max(0, bounds.width - rightX), height: max(0, bounds.height))
        appliedPosition = width; appliedSize = bounds.size
    }
    func splitView(_ splitView: NSSplitView, resizeSubviewsWithOldSize oldSize: NSSize) { applyLayout() }
    func splitView(_ splitView: NSSplitView, canCollapseSubview subview: NSView) -> Bool { false }
    func splitView(_ splitView: NSSplitView, shouldHideDividerAt dividerIndex: Int) -> Bool { false }
    func splitView(_ splitView: NSSplitView, constrainMinCoordinate proposedMinimumPosition: CGFloat, ofSubviewAt dividerIndex: Int) -> CGFloat {
        max(proposedMinimumPosition, minimum)
    }
    func splitView(_ splitView: NSSplitView, constrainMaxCoordinate proposedMaximumPosition: CGFloat, ofSubviewAt dividerIndex: Int) -> CGFloat {
        min(proposedMaximumPosition, CGFloat(availableWidth) - minimum)
    }
    func splitView(_ splitView: NSSplitView, constrainSplitPosition proposedPosition: CGFloat, ofSubviewAt dividerIndex: Int) -> CGFloat {
        min(CGFloat(availableWidth) - minimum, max(minimum, proposedPosition))
    }
    func splitViewDidResizeSubviews(_ notification: Notification) {
        guard let source = notification.object as? NSSplitView, source === self, !applying,
              availableWidth >= 2 * FilesSplitLayout.minimumPaneWidth, let appliedPosition,
              abs(leftHost.frame.width - appliedPosition) > 0.5 else { return }
        let value = Double(leftHost.frame.width) / availableWidth
        guard FilesSplitLayout.validFraction(value) else { applyLayout(); return }
        fraction = value; self.appliedPosition = leftHost.frame.width
        preferences.saveSplitFraction(value)
    }
}

// Non-secret, immutable transfer-review models shared by the actual Files UI and unhosted tests.
// Local browsing, operation targets, layout and authentication input above remain independent.
enum FilesTransferPlanPhase: String { case preparing, ready, confirming }

struct FilesTransferPlanReview: Identifiable, Sendable {
    let id: UUID
    let plan: TransferBatchPlan
    let context: FilesTransferContext
    let direction: String
    let localRoots: [TransferServiceID: RemotePath]
    let registeredLocalIDs: [TransferServiceID]
    var canConfirm: Bool { plan.canExecute }
    func displayedPath(_ path: RemotePath, serviceID: TransferServiceID) -> String {
        guard let root = localRoots[serviceID] else { return FileDisplay.path(path) }
        return FileDisplay.bytes((root == .root ? Data() : root.bytes) + path.bytes)
    }
    var countSummary: String {
        (plan.enumerationComplete ? "已审 " : "枚举未完成 · 已见 ") + "\(plan.itemCount) 项 · \(plan.fileCount) 文件 · \(plan.directoryCount) 文件夹 · \(plan.rejectedCount) 不支持项"
    }
    var bytesSummary: String {
        plan.totalBytes.map { ByteCountFormatter.string(fromByteCount: Int64(clamping: $0), countStyle: .file) } ?? "总大小未知"
    }
    var labels: [FilesTransferLabel] {
        plan.requests.map { request in
            FilesTransferLabel(endpoint: context.endpoint, direction: direction, localRoots: localRoots, totalBytes: request.sourceManifest?.totalBytes)
        }
    }
}

enum FilesTransferPlanDisplay {
    static func countSummary(_ job: TransferJobSnapshot) -> String {
        guard let manifest = job.request.sourceManifest else { return "已报告 \(job.items.count) 子项（枚举总数未知）" }
        return "已审 \(manifest.entries.count) 项 · \(manifest.fileCount) 文件 · \(manifest.directoryCount) 文件夹 · 实际已报告 \(job.items.count) 项"
    }
}

/// The actual inline panel used by DualPaneFilesView. Kept in this registered shared source
/// so unhosted, self-owned-window tests measure the same view rather than a replacement.
struct FilesTransferPlanPanel: View {
    @ObservedObject var model: FilesController
    @State private var expanded: Bool
    private let layoutChanged: (@MainActor ([String: CGRect]) -> Void)?
    init(model: FilesController, initiallyExpanded: Bool = true,
         layoutChanged: (@MainActor ([String: CGRect]) -> Void)? = nil) {
        self.model = model; _expanded = State(initialValue: initiallyExpanded); self.layoutChanged = layoutChanged
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(model.transferPlanPhase == .confirming ? "正在复核来源，尚未加入队列" : model.transferPlanReview == nil ? "正在只读枚举目录，尚未加入队列" : "核对目录传输计划 · 尚未加入队列")
                    .font(.headline).lineLimit(1)
                Spacer(minLength: 8)
                Button("取消本次计划", role: .cancel) { model.cancelTransferPlan() }
                    .accessibilityIdentifier("files.plan.cancel").planPanelFrame("cancel")
            }
            if let review = model.transferPlanReview {
                HStack(spacing: 12) {
                    Text(verbatim: review.direction + " · " + review.context.endpoint)
                        .lineLimit(1).truncationMode(.middle).help(review.context.endpoint)
                    Spacer(minLength: 0)
                    Text(review.countSummary + " · " + review.bytesSummary).fixedSize()
                        .accessibilityIdentifier("files.plan.summary").planPanelFrame("summary")
                }.font(.caption)
                // Keep essential summary/actions outside the scroll viewport. Expanded roots,
                // all issues and the full safety explanation remain scrollable at small heights.
                ScrollView(.vertical) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(review.canConfirm ? "来源变化会停止；同名冲突在传输时另行处理，已完成项目不会撤销。" : "计划不完整或包含不支持项，不能传输。请处理所示问题，取消后重新选择。")
                            .font(.caption).foregroundStyle(.secondary)
                        DisclosureGroup("源与目标（\(review.plan.requests.count) 个根项目）", isExpanded: $expanded) {
                            VStack(alignment: .leading, spacing: 5) {
                                ForEach(review.plan.requests.indices, id: \.self) { index in
                                    let request = review.plan.requests[index]
                                    Text(verbatim: review.displayedPath(request.source.path, serviceID: request.source.serviceID) + " → " + review.displayedPath(request.destination.path, serviceID: request.destination.serviceID))
                                        .font(.caption.monospaced()).textSelection(.enabled)
                                }
                            }.frame(maxWidth: .infinity, alignment: .leading)
                        }.font(.caption)
                        ForEach(review.plan.issues.indices, id: \.self) { index in
                            let issue = review.plan.issues[index]
                            Text(verbatim: AppIssue.files(issue.error).message + (issue.error.path.map { "\n路径：" + FileDisplay.path($0) } ?? ""))
                                .font(.caption).foregroundStyle(.orange)
                        }
                        Text("取消计划不更改文件；计划最多保留 5 分钟。")
                            .font(.caption2).foregroundStyle(.secondary)
                        DisclosureGroup("技术详情") {
                            Text("确认前再次检查全部来源。属性检查不是文件锁；来源变化会停止并保留实际结果。目标冲突在实际传输时另行处理，开始后的已提交子项不会回滚。").font(.caption2)
                            ForEach(review.plan.requests.indices, id: \.self) { index in
                                let request = review.plan.requests[index]
                                Text(verbatim: "源路径字节(base64)：" + pathBytes(request.source.path, serviceID: request.source.serviceID, review: review).base64EncodedString()).font(.caption2.monospaced())
                                Text(verbatim: "目标路径字节(base64)：" + pathBytes(request.destination.path, serviceID: request.destination.serviceID, review: review).base64EncodedString()).font(.caption2.monospaced())
                            }
                            ForEach(review.plan.issues.indices, id: \.self) { index in
                                let error = review.plan.issues[index].error
                                Text(verbatim: error.kind.rawValue + " · " + error.operation).font(.caption2.monospaced())
                            }
                        }.font(.caption).textSelection(.enabled)
                    }.frame(maxWidth: .infinity, alignment: .leading)
                        .planPanelFrame("detailsContent")
                }.frame(height: 72).accessibilityIdentifier("files.plan.details.viewport").planPanelFrame("detailsViewport")
                HStack {
                    Spacer()
                    Button(model.transferPlanPhase == .confirming ? "正在复核…" : "已核对，开始\(review.direction)") {
                        model.confirmTransferPlan(review)
                    }.disabled(!review.canConfirm || model.transferPlanPhase != .ready || model.admissionFrozen)
                        .accessibilityIdentifier("files.plan.confirm").planPanelFrame("confirm")
                }
            } else {
                HStack { ProgressView().controlSize(.small); Text("仅检查名称、类型和大小，不读取文件内容。总量尚未知。取消后等待本次检查释放资源，不影响其他任务。").font(.caption) }
            }
        }.padding(10).background(Color(nsColor: .controlBackgroundColor))
            .coordinateSpace(name: "files.plan.panel")
            .onPreferenceChange(FilesPlanPanelFrames.self) { frames in layoutChanged?(frames) }
        Divider()
    }
    private func pathBytes(_ path: RemotePath, serviceID: TransferServiceID, review: FilesTransferPlanReview) -> Data {
        guard let root = review.localRoots[serviceID] else { return path.bytes }
        return (root == .root ? Data() : root.bytes) + path.bytes
    }
}
private struct FilesPlanPanelFrames: PreferenceKey {
    static let defaultValue: [String: CGRect] = [:]
    static func reduce(value: inout [String: CGRect], nextValue: () -> [String: CGRect]) {
        value.merge(nextValue(), uniquingKeysWith: { _, last in last })
    }
}
private extension View {
    func planPanelFrame(_ name: String) -> some View {
        background(GeometryReader { geometry in
            Color.clear.preference(key: FilesPlanPanelFrames.self, value: [name: geometry.frame(in: .named("files.plan.panel"))])
        })
    }
}

