import SwiftUI
import OpenLXSSHTrust

struct TrustManagementView: View {
    @StateObject private var model: TrustManagementModel
    @State private var replacement = ""
    @State private var verified = false
    var dismiss: () -> Void
    let embedded: Bool
    let searchFocusRequest: UUID?

    init(environment: SessionEnvironment, embedded: Bool = false, searchFocusRequest: UUID? = nil, dismiss: @escaping () -> Void) {
        _model = StateObject(wrappedValue: TrustManagementModel(environment: environment))
        self.dismiss = dismiss; self.embedded = embedded
        self.searchFocusRequest = searchFocusRequest
    }
    var body: some View {
        VStack(spacing: 0) {
            header
            searchBar
            if let notice = model.notice {
                Text(notice).font(.caption).foregroundStyle(.secondary)
                    .accessibilityIdentifier("trust.manage.notice").padding(.horizontal, 20).padding(.bottom, 8)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    readFailure
                    IssueView(issue: model.issue) { model.issue = nil }
                    if model.loading { ProgressView("正在读取已知主机…").controlSize(.small) }
                    if model.refreshRequired {
                        Label("已提交的信任变更待重新读取；下列内容为上次成功读取的记录。", systemImage: "arrow.clockwise")
                            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                            .accessibilityIdentifier("trust.manage.committedRefresh")
                    }
                    if let record = model.replacementRecord { replacementEditor(record) }
                    recordsContent
                }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(width: embedded ? nil : 720)
        .frame(minHeight: embedded ? 0 : 480, maxHeight: .infinity)
        .background(DesktopStyle.background)
        .task { model.open(); await model.load() }
        .onDisappear { model.close() }
        .onChange(of: replacement) { _, _ in verified = false }
        .nativeSheet(item: Binding(get: { model.removalReview }, set: { if $0 == nil { model.cancelReview() } }),
                     onAttemptDismiss: { !model.busy }) { review in
            TrustRemovalConfirmation(model: model, review: review)
        }
    }
    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("已知主机").font(.system(size: 23, weight: .semibold))
                    Text("\(model.records.count) 条已信任主机指纹 · App 专属信任库")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 8)
                Button { Task { await model.load() } } label: { Image(systemName: "arrow.clockwise") }
                    .help("刷新已知主机").accessibilityLabel("刷新已知主机")
                    .accessibilityIdentifier("trust.manage.refresh").disabled(model.busy || model.loading)
                if !embedded {
                    Button("完成") { model.close(); dismiss() }
                        .accessibilityIdentifier("trust.manage.done").disabled(model.busy)
                }
            }
            Text("来源：OpenLXSSH App 专属信任库。SSH 与 SFTP 共用；不读取或修改系统 ~/.ssh/known_hosts。移除后，下次连接需要重新确认该公钥。")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }.padding(.horizontal, 20).padding(.top, 18).padding(.bottom, 12)
    }
    private var searchBar: some View {
        DesktopSearchField(placeholder: "搜索端点、算法或公钥指纹", id: "trust.manage.search", text: $model.search, focusRequest: searchFocusRequest, clearLabel: "清除已知主机搜索")
            .accessibilityLabel("搜索已知主机端点、算法或指纹")
            .padding(.horizontal, 20).padding(.bottom, 14)
    }
    @ViewBuilder private var readFailure: some View {
        if let issue = model.loadIssue {
            VStack(alignment: .leading, spacing: 8) {
                Label("无法读取已知主机", systemImage: "exclamationmark.triangle").font(.headline)
                Text(issue.message).font(.caption).fixedSize(horizontal: false, vertical: true)
                Button("重试读取") { Task { await model.load() } }
                    .accessibilityIdentifier("trust.manage.retry").disabled(model.busy || model.loading)
            }.padding(14).frame(maxWidth: .infinity, alignment: .leading)
                .background(DesktopStyle.panel, in: RoundedRectangle(cornerRadius: DesktopStyle.cornerRadius))
                .accessibilityIdentifier("trust.manage.readFailure")
        }
    }
    @ViewBuilder private var recordsContent: some View {
        if model.hasLoaded && model.records.isEmpty && model.loadIssue == nil {
            ContentUnavailableView("暂无已知主机", systemImage: "checkmark.shield", description: Text("首次连接时可将核实过的公钥添加到本 App 信任库。"))
                .accessibilityIdentifier("trust.manage.empty")
        } else if !model.records.isEmpty && model.filteredRecords.isEmpty {
            ContentUnavailableView {
                Label("没有匹配的已知主机", systemImage: "magnifyingglass")
            } description: { Text("试试端点、算法或完整指纹。搜索不会连接服务器。") }
            actions: { Button("清除搜索") { model.search = "" } }
                .accessibilityIdentifier("trust.manage.noMatches")
        } else {
            ForEach(model.filteredRecords, id: \.self) { record in recordRow(record) }
        }
    }
    private func recordRow(_ record: TrustedHostKey) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: "checkmark.shield.fill")
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(DesktopStyle.statusGreen)
                    .frame(width: 32, height: 32)
                    .background(DesktopStyle.statusGreen.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 3) {
                    Text(verbatim: TrustManagementModel.endpoint(record)).font(.system(size: 14, weight: .semibold))
                        .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        .accessibilityLabel("端点，" + TrustManagementModel.endpoint(record))
                    HStack(spacing: 6) {
                        DesktopBadge(text: record.key.algorithm, color: .accentColor, fill: DesktopStyle.iconSurface)
                            .accessibilityLabel("算法，" + record.key.algorithm)
                        DesktopBadge(text: "App 专属信任库")
                    }
                }
            }
            Text(verbatim: record.key.fingerprint)
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
                .padding(10)
                .background(DesktopStyle.well, in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(DesktopStyle.border))
                .accessibilityLabel("完整公钥指纹，" + record.key.fingerprint)
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 12) { copyActions(record); managementActions(record) }
                VStack(alignment: .leading, spacing: 10) { copyActions(record); managementActions(record) }
            }
        }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
            .background(DesktopStyle.panel, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(DesktopStyle.border))
    }
    private func copyActions(_ record: TrustedHostKey) -> some View {
        HStack(spacing: 12) {
            Button("复制端点") { model.copyEndpoint(record) }
                .accessibilityLabel("复制完整端点，" + TrustManagementModel.endpoint(record))
            Button("复制指纹") { model.copyFingerprint(record) }
                .accessibilityLabel("复制完整公钥指纹，" + TrustManagementModel.endpoint(record) + "，" + record.key.algorithm)
        }.fixedSize()
    }
    private func managementActions(_ record: TrustedHostKey) -> some View {
        HStack(spacing: 12) {
            Button("人工核实后替换…") {
                if model.beginReplacement(record) { replacement = ""; verified = false }
            }.accessibilityIdentifier("trust.manage.replace." + record.key.fingerprint)
            Button("移除…", role: .destructive) { model.reviewRemoval(record) }
                .accessibilityLabel("移除此端点与算法的信任，" + TrustManagementModel.endpoint(record) + "，" + record.key.algorithm)
                .accessibilityIdentifier("trust.manage.remove." + record.key.fingerprint)
        }.fixedSize().disabled(model.busy || model.loading)
    }
    private func replacementEditor(_ record: TrustedHostKey) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("人工核实后精确替换").font(.headline)
            Text(verbatim: TrustManagementModel.endpoint(record) + " · " + record.key.algorithm)
                .fixedSize(horizontal: false, vertical: true)
            Text("密钥变化仍会阻止连接。仅在独立可信渠道确认新公钥后替换，不会自动信任扫描到的其他算法。")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Text(verbatim: "当前指纹：" + record.key.fingerprint).font(.caption.monospaced())
                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            NativeField(placeholder: "独立可信渠道取得的新公钥：algorithm base64", id: "trust.replacement.public", text: $replacement)
                .frame(height: 28).disabled(model.busy || model.pending != nil)
            Button("核对新指纹") { verified = false; let line = replacement; Task { await model.prepare(record, line: line) } }
                .accessibilityIdentifier("trust.replacement.prepare").disabled(model.busy || model.loading || model.pending != nil)
            if let pending = model.pending {
                Text(verbatim: "新指纹：" + pending.fingerprint).font(.caption.monospaced())
                    .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                Toggle("已通过独立可信渠道核实新指纹", isOn: $verified).toggleStyle(.checkbox).disabled(model.busy)
                    .accessibilityIdentifier("trust.replacement.verified")
                Button("精确替换此主机与算法") { Task { _ = await model.confirm(pending) } }
                    .accessibilityIdentifier("trust.replacement.confirm").disabled(!verified || model.busy || model.loading)
            }
            Button("取消替换") { model.cancelReview(); replacement = ""; verified = false }
                .disabled(model.busy).accessibilityIdentifier("trust.replacement.cancel")
        }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
            .background(DesktopStyle.panel, in: RoundedRectangle(cornerRadius: DesktopStyle.cornerRadius))
    }
}

private struct TrustRemovalConfirmation: View {
    @ObservedObject var model: TrustManagementModel
    let review: TrustRemovalReview
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("移除此条主机信任？").font(.title3).bold()
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    Text(verbatim: TrustManagementModel.endpoint(review.record)).font(.headline)
                    Text(verbatim: review.record.key.algorithm)
                    Text(verbatim: review.record.key.fingerprint).font(.caption.monospaced()).textSelection(.enabled)
                    Text("只移除以上端点、算法及公钥的 App 专属信任记录。下次连接需要重新确认；不删除远端密钥、不影响其他算法，也不修改系统 known_hosts。")
                        .font(.caption).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, alignment: .leading).fixedSize(horizontal: false, vertical: true)
            }.frame(maxHeight: 240)
            if model.busy { ProgressView("正在精确移除…").controlSize(.small) }
            HStack {
                Spacer()
                Button("取消") { model.cancelReview(review) }.keyboardShortcut(.cancelAction).disabled(model.busy)
                    .accessibilityIdentifier("trust.remove.cancel")
                Button("移除此条信任", role: .destructive) { Task { _ = await model.remove(review) } }
                    .disabled(model.busy || model.removalReview != review).accessibilityIdentifier("trust.remove.confirm")
            }
        }.padding(24).frame(width: 500)
    }
}
