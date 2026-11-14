import AppKit
import SwiftUI
import OpenLXSSHFiles

enum FilesTaskAction { case details, decision, locate, cancel, cancelBatch, retry, clearFinished }
struct FilesTaskActionAvailability {
    let state: TransferJobState
    let hasDecision: Bool
    let frozen: Bool
    let planInProgress: Bool
    let hasFinishedJobs: Bool
    let batchActiveCount: Int
    var historyReviewOpen = false
    func allows(_ action: FilesTaskAction) -> Bool {
        switch action {
        case .details: true
        case .decision: hasDecision && state.isActive && !frozen
        case .locate: !frozen && (state == .succeeded || state == .completedWithSkips)
        case .cancel: state.isActive && !frozen
        case .cancelBatch: batchActiveCount > 0 && !frozen
        case .retry: !frozen && !planInProgress && (state == .failed || state == .cancelled)
        case .clearFinished: hasFinishedJobs && !frozen && !historyReviewOpen
        }
    }
}
struct FilesTaskBatchGroup: Identifiable {
    let id: TransferBatchID
    let number: Int
    var jobs: [TransferJobSnapshot]
    var activeCount: Int { jobs.filter { $0.state.isActive }.count }
    private var priority: Int { jobs.contains { $0.pendingDecision != nil } ? 2 : activeCount > 0 ? 1 : 0 }
    static func groups(_ jobs: [TransferJobSnapshot]) -> [Self] {
        var values: [Self] = [], indexes: [TransferBatchID: Int] = [:]
        for job in jobs {
            if let index = indexes[job.request.batchID] { values[index].jobs.append(job) }
            else {
                indexes[job.request.batchID] = values.count
                values.append(Self(id: job.request.batchID, number: values.count + 1, jobs: [job]))
            }
        }
        for index in values.indices {
            values[index].jobs = values[index].jobs.enumerated().sorted { left, right in
                let l = left.element.pendingDecision != nil ? 2 : left.element.state.isActive ? 1 : 0
                let r = right.element.pendingDecision != nil ? 2 : right.element.state.isActive ? 1 : 0
                return l == r ? left.offset < right.offset : l > r
            }.map(\.element)
        }
        return values.sorted { $0.priority == $1.priority ? $0.number > $1.number : $0.priority > $1.priority }
    }
}
private struct FilesTaskDetailPresentation: Identifiable {
    let id = UUID()
    let jobID: TransferJobID
    let generation: UUID
}

/// Mounted at the MainView root, not inside FilesPanelView or a terminal tab.
struct FilesApplicationUI: View {
    @ObservedObject var model: FilesController
    var showsTasks = true
    @State private var dialog: FilesDialog?
    @State private var ownerWindow: NSWindow?
    var body: some View {
        VStack(spacing: 0) {
            if model.tasksVisible && showsTasks {
                FilesTasksView(model: model) { decision in dialog = FilesDialog(content: .transferDecision(decision)) }
            }
            HStack {
                if let prompt = model.trustPrompt { NativeButton(title: "核实 SFTP 主机身份…", id: "files.trust.open") { dialog = FilesDialog(content: .trust(prompt)) } }
                if let prompt = model.keyboardPrompt { NativeButton(title: "继续 SFTP 认证…", id: "files.keyboard.open") { dialog = FilesDialog(content: .keyboard(prompt)) } }
                if let risk = model.pendingRisk, let id = model.riskID { NativeButton(title: "核对文件操作风险…", id: "files.risk.open") { dialog = FilesDialog(content: .risk(risk, id)) } }
                Spacer(minLength: 0)
            }.fixedSize(horizontal: false, vertical: true)
        }
        .background(ChallengeWindowObserver { ownerWindow = $0; presentPending() }.frame(width: 0, height: 0))
        .onChange(of: model.visible) { _, _ in presentPending() }
        .onChange(of: model.trustPrompt?.id) { _, id in
            if case .trust(let prompt)? = dialog?.content, prompt.id != id { dialog = nil }
            presentPending()
        }
        .onChange(of: model.keyboardPrompt?.id) { _, id in
            if case .keyboard(let prompt)? = dialog?.content, prompt.id != id { dialog = nil }
            presentPending()
        }
        .onChange(of: model.transferSnapshot) { _, snapshot in
            if case .transferDecision(let request)? = dialog?.content,
               !snapshot.jobs.contains(where: { $0.pendingDecision == request }) { dialog = nil }
            if dialog == nil, let request = snapshot.jobs.compactMap(\.pendingDecision).first,
               case .conflict = request.question {
                dialog = FilesDialog(content: .transferDecision(request))
            }
        }
        .onChange(of: model.riskID) { _, id in if case .risk(_, let p)? = dialog?.content, p != id { dialog = nil } }
        .nativeSheet(item: $dialog, allowsTerminationReview: Self.allowsTerminationReview(for: dialog?.content),
                     onAttemptDismiss: { cancelPresented(); return true }) { item in
            switch item.content {
            case .trust(let p): FilesTrustView(model: model, prompt: p) { dismiss(item.id) }
            case .keyboard(let p): FilesKeyboardView(model: model, prompt: p) { dismiss(item.id) }
            case .risk(let r, let id): FilesRiskView(model: model, risk: r, requestID: id) { dismiss(item.id) }
            case .transferDecision(let request): FilesTransferDecisionView(model: model, request: request) { dismiss(item.id) }
            default: EmptyView()
            }
        }
    }
    static func allowsTerminationReview(for content: FilesDialog.Content?) -> Bool {
        guard let content else { return false }
        switch content {
        case .trust(_), .keyboard(_): return true
        default: return false
        }
    }
    private func dismiss(_ id: UUID) { if dialog?.id == id { dialog = nil } }
    private func presentPending() {
        guard dialog == nil,
              let pending = model.pendingAuthenticationPresentation(modalAvailable: ChallengeWindowObserver.isAvailable(ownerWindow)) else { return }
        switch pending {
        case .trust(let prompt): dialog = FilesDialog(content: .trust(prompt))
        case .keyboard(let prompt): dialog = FilesDialog(content: .keyboard(prompt))
        }
    }
    private func cancelPresented() {
        switch dialog?.content {
        case .trust(let prompt): model.cancelTrust(prompt)
        case .keyboard(let prompt): model.cancelKeyboard(prompt)
        case .transferDecision(let request): Task { _ = await model.cancelTransferDecision(request) }
        default: break
        }
    }
}

struct FilesTasksView: View {
    @ObservedObject var model: FilesController
    var showsSharedIssue = true
    let decision: (TransferDecisionRequest) -> Void
    @StateObject private var historyOwner = FilesHistoryRemovalOwner()
    @State private var detailPresentation: FilesTaskDetailPresentation?
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Divider()
            HStack {
                Text("传输任务 · \(model.transferSnapshot.jobs.filter { $0.state.isActive }.count) 活动").font(.headline)
                Spacer()
                Button("清除记录") { historyOwner.prepare(using: model); _ = historyOwner.confirm(using: model) }
                    .disabled(model.admissionFrozen || !model.transferSnapshot.jobs.contains { !$0.state.isActive })
                NativeButton(title: "收起任务", id: "transfers.hide") { model.tasksVisible = false }.fixedSize()
            }
            if model.transferSnapshot.jobs.isEmpty { Text("暂无任务").font(.caption) }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 10) {
                    ForEach(batchGroups) { batch in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text("批次 \(batch.number) · \(batch.jobs.count) 项 · \(batch.activeCount) 活动").font(.subheadline).bold()
                                Spacer()
                                if batch.activeCount > 0 {
                                    NativeButton(title: "取消本批（\(batch.activeCount) 项活动）", id: "transfer.batch.cancel." + batch.id.uuidString,
                                        enabled: !model.admissionFrozen) { cancelBatch(batch.id) }.fixedSize()
                                }
                            }
                            ForEach(batch.jobs, id: \.id) { job in taskRow(job) }
                        }.padding(10).background(DesktopStyle.panel, in: RoundedRectangle(cornerRadius: 8))
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.frame(minHeight: 70, maxHeight: .infinity)
            if showsSharedIssue { IssueView(issue: model.transferPreparationIssue ?? model.issue) { model.issue = nil; model.dismissTransferPreparationIssue() } }
        }.padding(.horizontal, 14).padding(.bottom, 10)
        .foregroundStyle(DesktopStyle.barForeground).background(DesktopStyle.managementBar)
        .environment(\.colorScheme, .dark)
        .nativeSheet(item: $detailPresentation) { detail in taskDetails(detail) }
        .onChange(of: model.transferSnapshot) { _, snapshot in
            if let detailPresentation, !snapshot.jobs.contains(where: { $0.id == detailPresentation.jobID && $0.generation == detailPresentation.generation }) { self.detailPresentation = nil }
        }
        .onChange(of: model.admissionFrozen) { _, frozen in if frozen { historyOwner.cancel(using: model) } }
        .onDisappear { historyOwner.cancel(using: model) }
    }
    private func taskRow(_ job: TransferJobSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(verbatim: ((job.items.first?.destination ?? job.request.destination.path).name.map(FileDisplay.name) ?? "/") + " · " + (model.transferLabels[job.id]?.direction ?? "传输") + " · " + state(job.state)).font(.headline)
            Text(verbatim: progress(job) + (job.cancellationRequested && job.state.isActive ? " · 正在取消并等待清理" : "")).font(.caption)
            if let total = model.transferLabels[job.id]?.totalBytes, total > 0, job.transferredBytes <= total {
                ProgressView(value: Double(job.transferredBytes), total: Double(total)).frame(maxWidth: 320)
            }
            if let error = job.error { Text(verbatim: AppIssue.files(error).message).font(.caption).foregroundStyle(.red) }
            HStack {
                NativeButton(title: "详情", id: "transfer.details." + job.id.uuidString) { perform(.details, job: job) }.fixedSize()
                if job.state.isActive { NativeButton(title: "取消任务", id: "transfer.cancel." + job.id.uuidString, enabled: availability(for: job).allows(.cancel)) { perform(.cancel, job: job) }.fixedSize() }
                if job.pendingDecision != nil { NativeButton(title: "处理同名…", id: "transfer.decision." + job.id.uuidString, enabled: availability(for: job).allows(.decision)) { perform(.decision, job: job) }.fixedSize() }
                if job.state == .failed || job.state == .cancelled { NativeButton(title: "重试…", id: "transfer.retry." + job.id.uuidString, enabled: availability(for: job).allows(.retry)) { perform(.retry, job: job) }.fixedSize() }
                if job.state == .succeeded || job.state == .completedWithSkips { NativeButton(title: "定位结果", id: "transfer.locate." + job.id.uuidString, enabled: availability(for: job).allows(.locate)) { perform(.locate, job: job) }.fixedSize() }
            }
            DisclosureGroup("结果与路径") {
            ForEach(Array(job.items.enumerated()), id: \.offset) { _, item in
                Text(verbatim: model.displayedTransferPath(item.destination, serviceID: job.request.destination.serviceID, jobID: job.id) + " · " + itemState(item.state)).font(.caption2)
                if let temp = item.retainedTemporary { Text(verbatim: "待核实临时路径（可能未创建或未清理，不自动删除）：" + localPath(temp, serviceID: job.request.destination.serviceID, jobID: job.id)).font(.caption2).foregroundStyle(.orange) }
            }
            }
            DisclosureGroup("技术详情（任务）") {
                Text(verbatim: "任务：" + job.id.uuidString + "\n批次：" + job.request.batchID.uuidString).font(.caption2.monospaced())
                Text(verbatim: "源服务内路径字节(base64)：" + job.request.source.path.bytes.base64EncodedString()).font(.caption2.monospaced())
                Text(verbatim: "目标服务内路径字节(base64)：" + job.request.destination.path.bytes.base64EncodedString()).font(.caption2.monospaced())
                if let error = job.error { Text(verbatim: error.kind.rawValue + " · " + error.operation).font(.caption2.monospaced()) }
            }.font(.caption).textSelection(.enabled)
            Divider()
        }
        .contextMenu { taskMenu(job) }
    }
    private func availability(for job: TransferJobSnapshot) -> FilesTaskActionAvailability {
        FilesTaskActionAvailability(state: job.state, hasDecision: job.pendingDecision != nil, frozen: model.admissionFrozen,
            planInProgress: model.transferPlanPhase != nil, hasFinishedJobs: model.transferSnapshot.jobs.contains { !$0.state.isActive },
            batchActiveCount: model.transferSnapshot.jobs.filter { $0.request.batchID == job.request.batchID && $0.state.isActive }.count,
            historyReviewOpen: historyOwner.review != nil)
    }
    private func perform(_ action: FilesTaskAction, job expected: TransferJobSnapshot) {
        guard let job = model.transferSnapshot.jobs.first(where: { $0.id == expected.id && $0.generation == expected.generation }),
              availability(for: job).allows(action) else { return }
        switch action {
        case .details: detailPresentation = FilesTaskDetailPresentation(jobID: job.id, generation: job.generation)
        case .decision: if let pending = job.pendingDecision { decision(pending) }
        case .locate: model.locateTransfer(job)
        case .cancel: Task { await model.cancelTransfer(job.id) }
        case .cancelBatch: cancelBatch(job.request.batchID)
        case .retry: model.chooseTransferRetry(job.id, window: NSApp.keyWindow ?? NSApp.mainWindow)
        case .clearFinished: historyOwner.prepare(using: model) // The existing immutable review, not a file deletion.
        }
    }
    private func cancelBatch(_ id: TransferBatchID) {
        guard !model.admissionFrozen, model.transferSnapshot.jobs.contains(where: { $0.request.batchID == id && $0.state.isActive }) else { return }
        Task { await model.cancelBatch(id) }
    }
    @ViewBuilder private func taskMenu(_ job: TransferJobSnapshot) -> some View {
        let actions = availability(for: job)
        Button("查看详情…") { perform(.details, job: job) }
        Button("处理冲突或风险…") { perform(.decision, job: job) }.disabled(!actions.allows(.decision))
        Button("定位结果") { perform(.locate, job: job) }.disabled(!actions.allows(.locate))
        Divider()
        Button("取消此任务") { perform(.cancel, job: job) }.disabled(!actions.allows(.cancel))
        Button("取消所属批次（\(actions.batchActiveCount) 项活动）") { perform(.cancelBatch, job: job) }.disabled(!actions.allows(.cancelBatch))
        Button("重试…") { perform(.retry, job: job) }.disabled(!actions.allows(.retry))
        Divider()
        Button("移除已完成记录…") { perform(.clearFinished, job: job) }.disabled(!actions.allows(.clearFinished))
    }
    private func taskDetails(_ detail: FilesTaskDetailPresentation) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("传输详情").font(.title2).bold()
            if let job = model.transferSnapshot.jobs.first(where: { $0.id == detail.jobID && $0.generation == detail.generation }) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        Text(verbatim: model.transferLabels[job.id]?.endpoint ?? job.request.hostID).font(.headline)
                        Text(state(job.state) + " · " + progress(job))
                        Text(verbatim: "源：" + model.displayedTransferPath(job.request.source.path, serviceID: job.request.source.serviceID, jobID: job.id))
                        Text(verbatim: "目标：" + model.displayedTransferPath(job.request.destination.path, serviceID: job.request.destination.serviceID, jobID: job.id))
                        if let error = job.error { Text(AppIssue.files(error).message).foregroundStyle(.red) }
                        ForEach(Array(job.items.enumerated()), id: \.offset) { _, item in
                            Text(verbatim: model.displayedTransferPath(item.destination, serviceID: job.request.destination.serviceID, jobID: job.id) + " · " + itemState(item.state))
                        }
                        Text("关闭详情或移除记录不会删除文件。失败重试从零开始，并重新核对目标。").font(.caption).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                }
                HStack {
                    Button("定位结果") { perform(.locate, job: job) }.disabled(!availability(for: job).allows(.locate))
                    Spacer()
                    Button("关闭") { detailPresentation = nil }.keyboardShortcut(.cancelAction)
                }
            } else { Text("这条任务记录已移除。"); Button("关闭") { detailPresentation = nil } }
        }.padding(22).frame(width: 620, height: 440)
    }
    private func reviewedPath(_ path: RemotePath, serviceID: UUID, job: TransferJobSnapshot, review: FilesHistoryRemovalReview) -> String {
        guard let root = review.labels[job.id]?.localRoots[serviceID] else { return FileDisplay.path(path) }
        return FileDisplay.bytes((root == .root ? Data() : root.bytes) + path.bytes)
    }
    private func progress(_ job: TransferJobSnapshot) -> String {
        let bytes = ByteCountFormatter.string(fromByteCount: Int64(clamping: job.transferredBytes), countStyle: .file)
        let total = model.transferLabels[job.id]?.totalBytes.map { ByteCountFormatter.string(fromByteCount: Int64(clamping: $0), countStyle: .file) } ?? "总量未知"
        let speed = model.transferSpeeds[job.id].map { ByteCountFormatter.string(fromByteCount: Int64(min(Double(Int64.max), max(0, $0))), countStyle: .file) + "/s" } ?? "速度未知"
        return bytes + " / " + total + " · " + speed + (job.request.kind == .tree ? " · " + FilesTransferPlanDisplay.countSummary(job) : "")
    }
    private var batchGroups: [FilesTaskBatchGroup] { FilesTaskBatchGroup.groups(model.transferSnapshot.jobs) }
    private func localPath(_ path: RemotePath, serviceID: UUID, jobID: UUID) -> String {
        model.displayedTransferPath(path, serviceID: serviceID, jobID: jobID)
    }
    private func state(_ state: TransferJobState) -> String {
        switch state {
        case .queued: "排队"
        case .running: "传输／清理中"
        case .waitingConflict: "等待冲突决定"
        case .waitingRisk: "等待独立风险确认"
        case .succeeded: "全部成功"
        case .completedWithSkips: "部分跳过，未全部成功"
        case .skipped: "全部跳过"
        case .failed: "失败／未全部完成"
        case .cancelled: "已取消（已提交项目不会回滚）"
        }
    }
    private func itemState(_ state: TransferItemState) -> String {
        switch state { case .succeeded(let bytes): "成功 \(bytes) 字节"; case .skipped: "跳过"; case .failed(let e): "失败 " + e.kind.rawValue }
    }
}

struct FilesTransferDecisionView: View {
    @ObservedObject var model: FilesController
    let request: TransferDecisionRequest
    let dismiss: () -> Void
    @State private var batch = false
    @State private var submitting = false
    @State private var pathContentHeight: CGFloat = 44
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(isConflict ? "已存在同名项目" : "当前传输的决定").font(.title2)
            switch request.question {
            case .conflict(let conflict):
                Text(verbatim: conflict.destination.name.map(FileDisplay.name) ?? "/").font(.headline)
                if conflict.sourceKind != .regular || conflict.existing.kind != .regular {
                    Text("此类型不能替换。可取消，或都保留并自动使用新名称。")
                        .font(.caption).foregroundStyle(.secondary)
                }
                DisclosureGroup("位置详情") {
                    Text(verbatim: model.transferLabels[request.jobID]?.endpoint ?? "原端点不可用").font(.caption)
                    paths(source: "来源：" + shown(conflict.source, source: true),
                          destination: "已有：" + shown(conflict.destination, source: false))
                }.font(.caption)
                NativeButton(title: batch ? "应用到本批次后续同名项目：已选择" : "应用到本批次后续同名项目",
                    id: "transfer.conflict.batch", enabled: !submitting) { batch.toggle() }.fixedSize()
                HStack {
                    NativeButton(title: "取消", id: "transfer.decision.cancel", enabled: !submitting) { cancelDecision() }.fixedSize()
                    Spacer()
                    NativeButton(title: "替换", id: "transfer.conflict.overwrite",
                        enabled: !submitting && conflict.sourceKind == .regular && conflict.existing.kind == .regular) {
                        answer(.conflict(.overwrite, applyToBatch: batch))
                    }.fixedSize()
                    NativeButton(title: "都保留", id: "transfer.conflict.keepBoth",
                        enabled: !submitting && (conflict.sourceKind == .regular || conflict.sourceKind == .directory)) {
                        answer(.conflict(.autoRename, applyToBatch: batch))
                    }.fixedSize()
                }
            case .risk(let risk):
                FilesRiskDescription(risk: risk)
                if let job = model.transferSnapshot.jobs.first(where: { $0.id == request.jobID && $0.generation == request.generation }) {
                    paths(source: "源：" + shown(job.request.source.path, source: true),
                          destination: "目标：" + shown(job.request.destination.path, source: false))
                }
                Text("此次风险独立确认；覆盖决定和批量策略不代表接受此风险。")
                HStack {
                    NativeButton(title: "拒绝风险", id: "transfer.risk.reject") { answer(.risk(accepted: false)) }.fixedSize()
                    NativeButton(title: "明确接受此次风险", id: "transfer.risk.accept") { answer(.risk(accepted: true)) }.fixedSize()
                }
            }
            if !isConflict {
                DisclosureGroup("技术详情（任务标识）") {
                    Text(verbatim: "任务：" + request.jobID.uuidString).font(.caption2.monospaced()).textSelection(.enabled)
                }.font(.caption)
                HStack {
                    NativeButton(title: "暂不决定", id: "transfer.decision.dismiss", enabled: !submitting) { dismiss() }.fixedSize()
                    NativeButton(title: "取消此任务", id: "transfer.decision.cancel", enabled: !submitting) { cancelDecision() }.fixedSize()
                }
            }
            IssueView(issue: model.issue) { model.issue = nil }
        }.padding(24).frame(width: 650)
    }
    private func paths(source: String, destination: String) -> some View {
        ScrollView(.vertical) {
            VStack(alignment: .leading, spacing: 8) {
                Text(verbatim: source).lineLimit(nil).fixedSize(horizontal: false, vertical: true)
                Text(verbatim: destination).lineLimit(nil).fixedSize(horizontal: false, vertical: true)
            }.frame(maxWidth: .infinity, alignment: .leading)
                .textSelection(.enabled)
                .onGeometryChange(for: CGFloat.self) { min(144, max(44, $0.size.height.rounded(.up))) } action: { height in
                    if pathContentHeight != height { pathContentHeight = height }
                }
        }.frame(height: pathContentHeight)
    }
    private func shown(_ path: RemotePath, source: Bool) -> String {
        guard let job = model.transferSnapshot.jobs.first(where: { $0.id == request.jobID && $0.generation == request.generation }) else { return FileDisplay.path(path) }
        return model.displayedTransferPath(path, serviceID: source ? job.request.source.serviceID : job.request.destination.serviceID, jobID: job.id)
    }
    private var isConflict: Bool { if case .conflict = request.question { return true }; return false }
    private func answer(_ answer: TransferDecisionAnswer) {
        guard !submitting else { return }; submitting = true
        Task { _ = await model.answerTransfer(request, answer: answer); dismiss() }
    }
    private func cancelDecision() {
        guard !submitting else { return }; submitting = true
        Task { _ = await model.cancelTransferDecision(request); dismiss() }
    }
}


/// A compact, application-owned summary. View visibility never owns the jobs.
struct FilesTransferStatus: View {
    @ObservedObject var model: FilesController
    @State private var completionHidden = false
    @State private var dialog: FilesDialog?
    private var active: [TransferJobSnapshot] { model.transferSnapshot.jobs.filter { $0.state.isActive } }
    private var failed: Bool {
        if model.transferPreparationIssue != nil { return true }
        guard let latestBatch = model.transferSnapshot.jobs.last?.request.batchID else { return false }
        return model.transferSnapshot.jobs.contains { $0.request.batchID == latestBatch && $0.state == .failed }
    }
    private var completionTitle: String {
        guard let batch = model.transferSnapshot.jobs.last?.request.batchID else { return "暂无传输" }
        let jobs = model.transferSnapshot.jobs.filter { $0.request.batchID == batch }
        if jobs.allSatisfy({ $0.state == .cancelled }) { return "已取消" }
        if jobs.allSatisfy({ $0.state == .skipped }) { return "已跳过" }
        if jobs.contains(where: { $0.state == .cancelled }) { return "部分取消" }
        if jobs.contains(where: { $0.state == .skipped || $0.state == .completedWithSkips }) { return "完成（含跳过）" }
        return "传输完成"
    }
    private var preparing: Bool { model.transferPlanPhase != nil }
    private var needsAction: Bool { active.contains { $0.pendingDecision != nil } }
    private var signature: String { model.transferSnapshot.jobs.map { $0.id.uuidString + $0.state.rawValue }.joined() + String(preparing) }
    private var shouldShow: Bool { preparing || !active.isEmpty || failed || (!completionHidden && !model.transferSnapshot.jobs.isEmpty) }
    var body: some View {
        VStack(spacing: 0) {
            if model.tasksVisible {
                HStack(spacing: 0) {
                    Spacer(minLength: 0)
                    FilesTasksView(model: model) { request in
                        dialog = FilesDialog(content: .transferDecision(request))
                    }.frame(width: 530, height: 190).padding(.top, 6)
                }.frame(height: 196)
            }
            HStack(spacing: 0) {
                Spacer(minLength: 8)
                if shouldShow || model.tasksVisible {
                    Button { model.tasksVisible.toggle() } label: {
                        TimelineView(.periodic(from: .now, by: 1)) { _ in summary }
                    }.buttonStyle(.plain).accessibilityIdentifier("transfers.status")
                }
            }.padding(.horizontal, 10).frame(height: 38)
        }
        .foregroundStyle(DesktopStyle.barForeground).background(DesktopStyle.managementBar)
        .environment(\.colorScheme, .dark)
        .task(id: signature) {
            completionHidden = false
            guard !preparing && active.isEmpty && !failed && !model.transferSnapshot.jobs.isEmpty else { return }
            do { try await Task.sleep(for: .seconds(4)) } catch { return }
            completionHidden = true
        }
        .nativeSheet(item: $dialog, onAttemptDismiss: {
            if case .transferDecision(let request)? = dialog?.content { Task { _ = await model.cancelTransferDecision(request) } }
            return true
        }) { item in
            if case .transferDecision(let request) = item.content {
                FilesTransferDecisionView(model: model, request: request) { dialog = nil }
            }
        }
    }
    private var summary: some View {
        let totals = active.map { model.transferLabels[$0.id]?.totalBytes }
        let sum = totals.compactMap { $0 }.reduce((value: UInt64(0), overflow: false)) { result, value in
            let added = result.value.addingReportingOverflow(value)
            return (added.partialValue, result.overflow || added.overflow)
        }
        let total = sum.value
        let bytes = active.reduce(UInt64(0)) { result, job in
            let added = result.addingReportingOverflow(job.transferredBytes)
            return added.overflow ? UInt64.max : added.partialValue
        }
        let known = !sum.overflow && !active.isEmpty && totals.allSatisfy { $0 != nil } && total > 0
        let speed = active.compactMap { model.currentTransferSpeed($0.id) }.reduce(0, +)
        let title = needsAction ? "需要处理" : preparing ? "准备中" : !active.isEmpty ? "↑↓ \(active.count) 项" : failed ? "传输失败 · 查看" : completionTitle
        return HStack(spacing: 8) {
            Text(title).font(.caption).lineLimit(1)
            if !active.isEmpty && !needsAction {
                if known {
                    ProgressView(value: min(Double(bytes), Double(total)), total: Double(total)).frame(width: 68)
                    Text("\(Int(min(100, Double(bytes) / Double(total) * 100)))%").font(.caption.monospacedDigit())
                } else { Text("统计中").font(.caption).foregroundStyle(DesktopStyle.barSecondary) }
                if speed > 0 {
                    Text(ByteCountFormatter.string(fromByteCount: Int64(min(speed, Double(Int64.max))), countStyle: .file) + "/s")
                        .font(.caption.monospacedDigit()).lineLimit(1)
                } else if bytes == 0 { Text("准备中").font(.caption).foregroundStyle(DesktopStyle.barSecondary) }
            }
            Image(systemName: "chevron.up").font(.caption2)
        }.frame(width: 300, alignment: .trailing).padding(.vertical, 5)
            .accessibilityElement(children: .combine)
    }
}
