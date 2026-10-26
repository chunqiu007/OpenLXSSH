import AppKit
import SwiftUI
import OpenLXSSHFiles

/// Mounted at the MainView root, not inside FilesPanelView or a terminal tab.
struct FilesApplicationUI: View {
    @ObservedObject var model: FilesController
    @State private var dialog: FilesDialog?
    var body: some View {
        VStack(spacing: 0) {
            if model.tasksVisible {
                FilesTasksView(model: model) { decision in dialog = FilesDialog(content: .transferDecision(decision)) }
            }
            HStack {
                if let prompt = model.trustPrompt { NativeButton(title: "核实 SFTP 主机身份…", id: "files.trust.open") { dialog = FilesDialog(content: .trust(prompt)) } }
                if let prompt = model.keyboardPrompt { NativeButton(title: "继续 SFTP 认证…", id: "files.keyboard.open") { dialog = FilesDialog(content: .keyboard(prompt)) } }
                if let risk = model.pendingRisk, let id = model.riskID { NativeButton(title: "核对文件操作风险…", id: "files.risk.open") { dialog = FilesDialog(content: .risk(risk, id)) } }
                Spacer(minLength: 0)
            }.fixedSize(horizontal: false, vertical: true)
        }
        .onChange(of: model.transferSnapshot) { _, snapshot in
            if case .transferDecision(let request)? = dialog?.content,
               !snapshot.jobs.contains(where: { $0.pendingDecision == request }) { dialog = nil }
        }
        .onChange(of: model.trustPrompt?.id) { _, id in if case .trust(let p)? = dialog?.content, p.id != id { dialog = nil } }
        .onChange(of: model.keyboardPrompt?.id) { _, id in if case .keyboard(let p)? = dialog?.content, p.id != id { dialog = nil } }
        .onChange(of: model.riskID) { _, id in if case .risk(_, let p)? = dialog?.content, p != id { dialog = nil } }
        .nativeSheet(item: $dialog) { item in
            switch item.content {
            case .trust(let p): FilesTrustView(model: model, prompt: p) { dialog = nil }
            case .keyboard(let p): FilesKeyboardView(model: model, prompt: p) { dialog = nil }
            case .risk(let r, let id): FilesRiskView(model: model, risk: r, requestID: id) { dialog = nil }
            case .transferDecision(let request): FilesTransferDecisionView(model: model, request: request) { dialog = nil }
            default: EmptyView()
            }
        }
    }
}

struct FilesTasksView: View {
    @ObservedObject var model: FilesController
    let decision: (TransferDecisionRequest) -> Void
    @State private var removalReview: FilesHistoryRemovalReview?
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Divider()
            HStack {
                Text("传输任务 · \(model.transferSnapshot.jobs.filter { $0.state.isActive }.count) 活动").font(.headline)
                Spacer()
                NativeButton(title: "收起任务", id: "transfers.hide") { model.tasksVisible = false }.fixedSize()
            }
            Text("字节数为已流式读取／写入量，不代表目标已提交。整个文件夹不是事务；成功、跳过和失败逐项报告。重试为新任务从零开始，不续传。").font(.caption2)
            HStack {
                NativeButton(title: removalReview == nil ? "移除已完成记录…" : "取消移除记录", id: "transfers.remove.prepare", enabled: !model.admissionFrozen) {
                    if let review = removalReview { model.discardHistoryRemoval(review); removalReview = nil }
                    else { removalReview = model.prepareHistoryRemoval() }
                }.fixedSize()
                if let review = removalReview {
                    Text("仅移除下列已核对的 \(review.jobs.count) 条记录，不删除文件或自有残留；后续新完成任务不包含在内。").font(.caption2)
                    NativeButton(title: "已核对，移除这 \(review.jobs.count) 条记录", id: "transfers.remove.confirm", enabled: !model.admissionFrozen) {
                        let removal = model.removeFinishedTransfers(review)
                        Task { _ = await removal.value; removalReview = nil }
                    }.fixedSize()
                }
            }
            if let review = removalReview {
                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(review.jobs, id: \.id) { job in
                            Text(verbatim: job.id.uuidString + " · " + (model.transferLabels[job.id]?.endpoint ?? job.request.hostID) + " · " + state(job.state)).font(.caption2)
                            ForEach(job.retainedTemporaryPaths, id: \.self) { path in
                                Text(verbatim: "移除后不会再显示；请先复制保存：" + model.displayedTransferPath(path, serviceID: job.request.destination.serviceID, jobID: job.id)).font(.caption2).textSelection(.enabled)
                            }
                        }
                    }
                }.frame(maxHeight: 100)
            }
            if model.transferSnapshot.jobs.isEmpty { Text("暂无任务").font(.caption) }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 10) {
                    ForEach(orderedJobs, id: \.id) { job in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(verbatim: (model.transferLabels[job.id]?.direction ?? "传输") + " · " + (model.transferLabels[job.id]?.endpoint ?? job.request.hostID)).font(.headline)
                            Text(verbatim: model.displayedTransferPath(job.request.source.path, serviceID: job.request.source.serviceID, jobID: job.id) + " → " + model.displayedTransferPath(job.request.destination.path, serviceID: job.request.destination.serviceID, jobID: job.id)).font(.caption.monospaced()).textSelection(.enabled)
                            Text(verbatim: state(job.state) + (job.cancellationRequested && job.state.isActive ? " · 正在取消并等待清理" : "") + " · 已流式传输 \(job.transferredBytes) 字节").font(.caption)
                            if let error = job.error { Text(verbatim: "失败原因：" + error.kind.rawValue + " · " + error.operation).font(.caption).foregroundStyle(.red) }
                            HStack {
                                if job.state.isActive { NativeButton(title: "取消任务", id: "transfer.cancel." + job.id.uuidString) { Task { await model.cancelTransfer(job.id) } }.fixedSize() }
                                if let pending = job.pendingDecision { NativeButton(title: "处理冲突／风险…", id: "transfer.decision." + job.id.uuidString) { decision(pending) }.fixedSize() }
                                if job.state == .failed || job.state == .cancelled { NativeButton(title: "从零重试", id: "transfer.retry." + job.id.uuidString, enabled: !model.admissionFrozen) { do { _ = try model.retryTransfer(job.id) } catch { model.issue = .files(error) } }.fixedSize() }
                            }
                            ForEach(Array(job.items.enumerated()), id: \.offset) { _, item in
                                Text(verbatim: model.displayedTransferPath(item.destination, serviceID: job.request.destination.serviceID, jobID: job.id) + " · " + itemState(item.state)).font(.caption2)
                                if let temp = item.retainedTemporary { Text(verbatim: "未清理自有临时文件（请人工核对，不自动删除）：" + localPath(temp, serviceID: job.request.destination.serviceID, jobID: job.id)).font(.caption2).foregroundStyle(.orange) }
                            }
                            Divider()
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.frame(minHeight: 110, maxHeight: 230)
            IssueView(issue: model.issue) { model.issue = nil }
        }.padding(.horizontal, 14).padding(.bottom, 10)
        .onChange(of: model.admissionFrozen) { _, frozen in if frozen { removalReview = nil } }
        .onDisappear { if let review = removalReview { model.discardHistoryRemoval(review) }; removalReview = nil }
    }
    private var orderedJobs: [TransferJobSnapshot] {
        model.transferSnapshot.jobs.enumerated().sorted { left, right in
            let l = left.element.pendingDecision != nil ? 2 : left.element.state.isActive ? 1 : 0
            let r = right.element.pendingDecision != nil ? 2 : right.element.state.isActive ? 1 : 0
            return l == r ? left.offset > right.offset : l > r
        }.map(\.element)
    }
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
    @State private var name = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("当前传输的决定").font(.title2)
            Text(verbatim: "任务 " + request.jobID.uuidString).font(.caption.monospaced())
            Text(verbatim: model.transferLabels[request.jobID]?.endpoint ?? "原端点不可用")
            switch request.question {
            case .conflict(let conflict):
                Text(verbatim: "源：" + shown(conflict.source, source: true))
                Text(verbatim: "已存在目标：" + shown(conflict.destination, source: false) + " · " + conflict.existing.kind.rawValue)
                NativeButton(title: batch ? "覆盖／跳过应用同主机本批次：已选择" : "覆盖／跳过应用同主机本批次", id: "transfer.conflict.batch") { batch.toggle() }.fixedSize()
                HStack {
                    NativeButton(title: "跳过", id: "transfer.conflict.skip") { answer(.conflict(.skip, applyToBatch: batch)) }.fixedSize()
                    NativeButton(title: "覆盖（风险另核）", id: "transfer.conflict.overwrite") { answer(.conflict(.overwrite, applyToBatch: batch)) }.fixedSize()
                }
                NativeField(placeholder: "仅此项的新名称", id: "transfer.conflict.name", text: $name).frame(height: 26)
                NativeButton(title: "仅此项重命名", id: "transfer.conflict.rename") {
                    do { answer(.conflict(.renameTo(try FileName(name)), applyToBatch: false)) }
                    catch { model.issue = .files(error) }
                }.fixedSize()
            case .risk(let risk):
                Text(verbatim: FileDisplay.risk(risk))
                if let job = model.transferSnapshot.jobs.first(where: { $0.id == request.jobID && $0.generation == request.generation }) {
                    Text(verbatim: "原始源：" + shown(job.request.source.path, source: true))
                    Text(verbatim: "原始目标：" + shown(job.request.destination.path, source: false))
                }
                Text("此次风险独立确认；覆盖决定和批量策略不代表接受此风险。")
                HStack {
                    NativeButton(title: "拒绝风险", id: "transfer.risk.reject") { answer(.risk(accepted: false)) }.fixedSize()
                    NativeButton(title: "明确接受此次风险", id: "transfer.risk.accept") { answer(.risk(accepted: true)) }.fixedSize()
                }
            }
            HStack {
                NativeButton(title: "暂不决定", id: "transfer.decision.dismiss") { dismiss() }.fixedSize()
                NativeButton(title: "取消此任务", id: "transfer.decision.cancel") { Task { await model.cancelTransfer(request.jobID); dismiss() } }.fixedSize()
            }
            IssueView(issue: model.issue) { model.issue = nil }
        }.padding(24).frame(width: 650)
    }
    private func shown(_ path: RemotePath, source: Bool) -> String {
        guard let job = model.transferSnapshot.jobs.first(where: { $0.id == request.jobID && $0.generation == request.generation }) else { return FileDisplay.path(path) }
        return model.displayedTransferPath(path, serviceID: source ? job.request.source.serviceID : job.request.destination.serviceID, jobID: job.id)
    }
    private func answer(_ answer: TransferDecisionAnswer) { Task { _ = await model.answerTransfer(request, answer: answer); dismiss() } }
}
