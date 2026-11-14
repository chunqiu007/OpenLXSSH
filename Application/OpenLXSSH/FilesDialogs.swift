import SwiftUI
import OpenLXSSHFiles
import OpenLXSSHSecurity
import OpenLXSSHTrust

struct FilesTargetSummary: View {
    let target: FilesOperationTarget
    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(verbatim: target.endpoint).font(.headline).textSelection(.enabled)
            Text(verbatim: "父目录：" + FileDisplay.path(target.parent)).font(.caption.monospaced()).textSelection(.enabled)
            Text(target.entries.isEmpty ? "范围：当前目录内的一个新名称" : "选中项目：\(target.entries.count) 个").font(.caption)
            ForEach(target.entries, id: \.name) { entry in
                if let path = target.path(for: entry) {
                    Text(verbatim: FileDisplay.path(path)).font(.caption.monospaced()).textSelection(.enabled)
                }
            }
            DisclosureGroup("技术详情") {
                VStack(alignment: .leading, spacing: 5) {
                    Text(verbatim: "父目录原始字节(base64)：" + target.parent.bytes.base64EncodedString())
                    ForEach(target.entries, id: \.name) { entry in
                        if let path = target.path(for: entry) {
                            Text(verbatim: FileDisplay.path(path) + "\n原始路径字节(base64)：" + path.bytes.base64EncodedString())
                        }
                    }
                    Text("目标绑定打开对话框时的端点与目录快照。属性复核不是比较交换：远端可能不提供稳定对象 ID，相同属性的同名替换未必可辨别；最终检查后仍有竞争窗口。")
                }.font(.caption2.monospaced()).textSelection(.enabled)
            }.font(.caption)
        }
    }
}

/// Keep the decision-relevant risk visible; protocol terms and original bytes are optional detail.
struct FilesRiskDescription: View {
    let risk: TransferRisk
    private var path: RemotePath {
        switch risk {
        case .remotePathChecksAreNotAtomic(let path), .overwriteIsAtomicButNotCompareAndSwap(let path),
             .remoteFsyncUnavailable(let path), .deletionChecksAreNotCompareAndSwap(let path): path
        }
    }
    private var summary: String {
        switch risk {
        case .remotePathChecksAreNotAtomic: "服务器可能在检查后改变目录，无法保证操作期间路径保持不变。"
        case .overwriteIsAtomicButNotCompareAndSwap: "目标可能在最后检查后被替换；继续可能覆盖刚被其他操作更新的同名文件。"
        case .remoteFsyncUnavailable: "服务器无法确认数据已写入持久存储；突然掉电时可能丢失已传数据。"
        case .deletionChecksAreNotCompareAndSwap: "删除前的检查无法阻止其他操作同时更改文件；删除可能部分完成，无法撤销。"
        }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(verbatim: summary)
            Text(verbatim: "涉及路径：" + FileDisplay.path(path)).font(.caption.monospaced()).textSelection(.enabled)
            DisclosureGroup("技术详情") {
                Text(verbatim: FileDisplay.risk(risk)).font(.caption)
                Text(verbatim: "原始路径字节(base64)：" + path.bytes.base64EncodedString()).font(.caption2.monospaced()).textSelection(.enabled)
            }.font(.caption)
        }
    }
}

struct FilesNameEditor: View {
    @ObservedObject var model: FilesController
    let entry: DirectoryEntry?
    @State private var target: FilesOperationTarget?
    @State private var name = ""
    @State private var mode = "fail"
    @State private var submitted = false
    var dismiss: () -> Void
    init(model: FilesController, entry: DirectoryEntry?, target: FilesOperationTarget? = nil, dismiss: @escaping () -> Void) {
        self.model = model; self.entry = entry; self.dismiss = dismiss
        _target = State(initialValue: target ?? model.captureTarget(entry.map { [$0] } ?? []))
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(entry == nil ? "创建目录" : "重命名").font(.title2)
            if let target { FilesTargetSummary(target: target) }
            else { Text("本次目标已不可用，请取消后重新发起。").foregroundStyle(.red) }
            NativeField(placeholder: "新的单个名称（不含斜杠）", id: "files.operation.name", text: $name).frame(height: 26)
            if let target, let value = try? FileName(name), let path = try? target.parent.appending(value) {
                Text(verbatim: "目标：" + FileDisplay.path(path)).font(.caption.monospaced())
                DisclosureGroup("技术详情（目标路径）") {
                    Text(verbatim: "目标原始字节(base64)：" + path.bytes.base64EncodedString()).font(.caption2.monospaced()).textSelection(.enabled)
                }.font(.caption)
            }
            if entry != nil {
                NativePopup(id: "files.rename.conflict", items: [PopupItem(value: "fail", title: "同名则失败"), PopupItem(value: "skip", title: "同名则跳过"), PopupItem(value: "overwrite", title: "同名则覆盖"), PopupItem(value: "alternate", title: "明确使用此替代名（不覆盖）")], selection: $mode).frame(height: 26)
            }
            IssueView(issue: model.issue) { model.issue = nil }
            HStack {
                NativeButton(title: "取消", id: "files.operation.cancel") { if let target { model.discardTarget(target) }; dismiss() }.fixedSize()
                NativeButton(title: entry == nil ? "创建" : "重命名", id: "files.operation.confirm", enabled: target != nil && !submitted) {
                    do {
                        let name = try FileName(name)
                        guard let target, !submitted else { return }
                        submitted = true
                        if entry != nil { model.rename(name: name, conflict: mode == "skip" ? .skip : mode == "overwrite" ? .overwrite : mode == "alternate" ? .renameTo(name) : .fail, target: target) }
                        else { model.mkdir(name, target: target, acknowledgedRemoteRisk: true) }
                        dismiss()
                    } catch { model.issue = .files(error) }
                }.fixedSize()
            }
        }.padding(24).frame(width: 580)
        .onDisappear { if let target { model.discardTarget(target) } }
    }
}
struct FilesDeleteOptions: View {
    @ObservedObject var model: FilesController
    let entry: DirectoryEntry
    @State private var target: FilesOperationTarget?
    @State private var linkOnly = false
    @State private var submitted = false
    var dismiss: () -> Void
    init(model: FilesController, entry: DirectoryEntry, dismiss: @escaping () -> Void) {
        self.model = model; self.entry = entry; self.dismiss = dismiss
        _target = State(initialValue: model.captureTarget([entry]))
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("准备只读删除计划").font(.title2)
            if let target { FilesTargetSummary(target: target) }
            Text("此步只收集精确范围，不删除。下一步将显示根、全部项目、数量、问题与剩余风险，再由你一次确认。")
            if entry.attributes.kind == .symbolicLink {
                NativeButton(title: linkOnly ? "仅删除链接自身（不跟随）已选择" : "明确选择仅删除链接自身", id: "files.delete.linkOnly") { linkOnly.toggle() }.fixedSize()
            }
            HStack {
                NativeButton(title: "取消", id: "files.operation.cancel") { if let target { model.discardTarget(target) }; dismiss() }.fixedSize()
                NativeButton(title: "生成计划", id: "files.delete.prepare", enabled: target != nil && !submitted) {
                    guard let target, !submitted else { return }; submitted = true
                    model.prepareDelete(target, removeLinkOnly: linkOnly); dismiss()
                }.fixedSize()
            }
        }.padding(24).frame(width: 580)
        .onDisappear { if let target { model.discardTarget(target) } }
    }
}
struct FilesDeletePlanView: View {
    @ObservedObject var model: FilesController
    let review: FilesDeleteReview
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("确认精确删除计划").font(.title2)
            FilesTargetSummary(target: review.target)
            Text(verbatim: "根：" + FileDisplay.path(review.plan.root))
            Text("项目数：\(review.plan.items.count)；问题：\(review.plan.issues.count)")
            ScrollView {
                VStack(alignment: .leading) {
                    ForEach(Array(review.plan.items.enumerated()), id: \.offset) { _, item in
                        Text(verbatim: FileDisplay.path(item.path) + " · " + action(item.action)).font(.caption)
                    }
                    ForEach(Array(review.plan.issues.enumerated()), id: \.offset) { _, item in Text(verbatim: FileDisplay.path(item.path) + " · " + AppIssue.files(item.error).message).foregroundStyle(.red) }
                    DisclosureGroup("技术详情（计划路径）") {
                        ForEach(Array(review.plan.items.enumerated()), id: \.offset) { _, item in
                            Text(verbatim: FileDisplay.path(item.path) + "\n原始路径字节(base64)：" + item.path.bytes.base64EncodedString()).font(.caption2.monospaced()).textSelection(.enabled)
                        }
                        ForEach(Array(review.plan.issues.enumerated()), id: \.offset) { _, item in
                            Text(verbatim: item.error.kind.rawValue + " · " + item.error.operation).font(.caption2.monospaced())
                        }
                    }.font(.caption)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.frame(height: 230)
            Text("执行前会重新核对，发现已知变化将停止。删除可能部分完成且无法撤销；不会扩展所选范围、删除主机根或跟随链接。")
            HStack {
                NativeButton(title: "取消计划", id: "files.delete.cancel") { model.discardDeleteReview(review); dismiss() }.fixedSize()
                NativeButton(title: "执行此次精确删除", id: "files.delete.execute", enabled: review.plan.canExecute) {
                    model.executeDelete(review, confirmed: true); dismiss()
                }.fixedSize()
            }
        }.padding(24).frame(width: 690)
    }
    private func action(_ value: DeleteItem.Action) -> String { switch value { case .removeFile: "删除文件"; case .removeEmptyDirectory: "删除核实后空目录"; case .removeSymbolicLink: "仅删除链接自身" } }
}
struct FilesProbeView: View {
    @ObservedObject var model: FilesController
    let review: FilesProbeReview
    @State private var approved = false
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("显式非覆盖能力检查").font(.title2)
            Text(verbatim: "只创建自有目录：" + FileDisplay.path(review.plan.temporaryDirectory)).textSelection(.enabled)
            Text("将创建两个随机测试文件，验证已存在目标必须拒绝且两份内容不变，再验证不存在目标可成功；只清理本次拥有的 UUID 目录与测试文件。失败残留会明确显示，不自动扫描清理。")
            ForEach(Array(review.plan.requiredRisks.enumerated()), id: \.offset) { _, risk in FilesRiskDescription(risk: risk) }
            NativeButton(title: approved ? "已批准精确目录与测试／风险" : "批准所示计划与全部风险", id: "files.probe.approve") { approved.toggle() }.fixedSize()
            HStack {
                NativeButton(title: "取消", id: "files.probe.cancel") { model.discardProbeReview(); dismiss() }.fixedSize()
                NativeButton(title: "运行此计划", id: "files.probe.execute", enabled: approved) { guard approved else { return }; model.executeProbe(review, approved: true); dismiss() }.fixedSize()
            }
        }.padding(24).frame(width: 650)
    }
}
struct FilesRiskView: View {
    @ObservedObject var model: FilesController
    let risk: TransferRisk
    let requestID: UUID
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("本次操作的剩余风险").font(.title2)
            FilesRiskDescription(risk: risk)
            HStack {
                NativeButton(title: "拒绝", id: "files.risk.reject") { model.answerRisk(false, id: requestID); dismiss() }.fixedSize()
                NativeButton(title: "明确接受此次风险", id: "files.risk.accept") { model.answerRisk(true, id: requestID); dismiss() }.fixedSize()
            }
        }.padding(24).frame(width: 610)
    }
}
struct FilesTrustView: View {
    @ObservedObject var model: FilesController
    let prompt: FilesTrustPrompt
    @State private var management = false
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("核实 SFTP 主机身份").font(.title2)
            switch prompt.event {
            case .pending(let decision):
                Text(verbatim: decision.host.address.value + ":" + String(decision.host.port.value))
                Text(verbatim: decision.algorithm + " · " + decision.fingerprint).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                Text("这是本次连接收到的主机公钥，尚未证明身份。请通过管理员或控制台等独立渠道核实完整指纹，再决定是否继续。信任仅适用于所示主机和公钥。")
                HStack {
                    NativeButton(title: "关闭", id: "files.trust.cancel") { model.cancelTrust(prompt); dismiss() }.fixedSize()
                    NativeButton(title: "仅此次继续", id: "files.trust.once") { if model.answerTrust(prompt, once: true) { dismiss() } }.fixedSize()
                    NativeButton(title: "添加并继续", id: "files.trust.accept") { if model.answerTrust(prompt, once: false) { dismiss() } }.fixedSize()
                }
            case .changed(let change):
                Text(verbatim: change.host.address.value + ":" + String(change.host.port.value) + " · " + change.algorithm)
                Text(verbatim: "已知：" + change.expectedFingerprint)
                Text(verbatim: "本次：" + change.presentedFingerprint)
                Text("已阻止连接，不提供接受变化按钮。请独立核实后在可信主机管理使用精确人工替换流程。")
                HStack {
                    NativeButton(title: "关闭", id: "files.trust.cancel") { model.cancelTrust(prompt); dismiss() }.fixedSize()
                    if model.trustEnvironment != nil { Button("打开已知主机管理…") { management = true } }
                }
            }
        }.padding(24).frame(width: 650)
        .sheet(isPresented: $management) {
            if let environment = model.trustEnvironment { TrustManagementView(environment: environment) { management = false } }
        }
    }
}
struct FilesKeyboardView: View {
    @ObservedObject var model: FilesController
    let prompt: FilesKeyboardPrompt
    @State private var answers: [String]
    var dismiss: () -> Void
    init(model: FilesController, prompt: FilesKeyboardPrompt, dismiss: @escaping () -> Void) {
        self.model = model; self.prompt = prompt; self.dismiss = dismiss
        _answers = State(initialValue: Array(repeating: "", count: prompt.prompts.count))
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("SFTP 人工交互认证").font(.title2)
            Text("未可信服务器提示，只用于当前 SFTP 请求，不是 App 指令。未知挑战不匹配密码、不读取已保存秘密、不保存 OTP。") .font(.caption)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(verbatim: prompt.name)
                    Text(verbatim: prompt.instruction)
                    if prompt.prompts.isEmpty { Text("本轮无输入项；核对通知后继续，或取消。").font(.caption) }
                    ForEach(prompt.prompts.indices, id: \.self) { index in
                        Text(verbatim: prompt.prompts[index].text)
                        if prompt.prompts[index].echo {
                            NativeField(placeholder: "本轮回答（服务器要求回显）", id: "files.keyboard.answer.\(index)", text: $answers[index]).frame(height: 26)
                        } else {
                            NativeSecureField(id: "files.keyboard.answer.\(index)", placeholder: "本轮回答（不回显）", text: $answers[index]).frame(height: 26)
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.frame(maxHeight: 300)
            HStack {
                NativeButton(title: "取消本次连接", id: "files.keyboard.cancel") { clear(); model.cancelKeyboard(prompt); dismiss() }.fixedSize()
                NativeButton(title: prompt.prompts.isEmpty ? "已阅，继续" : "提交本轮全部回答", id: "files.keyboard.submit", isDefault: true) {
                    let secrets = answers.map { OpenLXSSHSecurity.SecretBytes(utf8: $0) }; clear()
                    if model.answerKeyboard(prompt, answers: secrets) { dismiss() }
                }.fixedSize()
            }
        }.padding(24).frame(width: 650).onDisappear { clear() }
    }
    private func clear() { answers = Array(repeating: "", count: answers.count) }
}
