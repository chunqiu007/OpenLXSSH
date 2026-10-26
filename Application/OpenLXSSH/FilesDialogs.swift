import SwiftUI
import OpenLXSSHFiles
import OpenLXSSHSecurity
import OpenLXSSHTrust

struct FilesNameEditor: View {
    @ObservedObject var model: FilesController
    let entry: DirectoryEntry?
    @State private var name = ""
    @State private var mode = "fail"
    @State private var acceptedRisk = false
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(entry == nil ? "创建目录" : "安全重命名").font(.title2)
            if let entry { Text(verbatim: "源：" + FileDisplay.name(entry.name)) }
            Text(verbatim: "父目录：" + FileDisplay.path(model.path))
            NativeField(placeholder: "新的单个名称（不含斜杠）", id: "files.operation.name", text: $name).frame(height: 26)
            if entry != nil {
                NativePopup(id: "files.rename.conflict", items: [PopupItem(value: "fail", title: "同名则失败"), PopupItem(value: "skip", title: "同名则跳过"), PopupItem(value: "overwrite", title: "同名则覆盖（另核非 CAS 风险）"), PopupItem(value: "alternate", title: "明确使用此替代名（不覆盖）")], selection: $mode).frame(height: 26)
            } else {
                Text("远端逐段 lstat 不等同原子 no-follow；检查后服务器仍可能改变树。创建只限所显示父目录与单个名称，不自动提权。")
                NativeButton(title: acceptedRisk ? "已核对远端路径剩余风险" : "明确接受本次远端路径剩余风险", id: "files.mkdir.risk") { acceptedRisk.toggle() }.fixedSize()
            }
            IssueView(issue: model.issue) { model.issue = nil }
            HStack {
                NativeButton(title: "取消", id: "files.operation.cancel") { dismiss() }.fixedSize()
                NativeButton(title: entry == nil ? "创建" : "重命名", id: "files.operation.confirm", enabled: entry != nil || acceptedRisk) {
                    do {
                        let name = try FileName(name)
                        if let entry { model.rename(entry, name: name, conflict: mode == "skip" ? .skip : mode == "overwrite" ? .overwrite : mode == "alternate" ? .renameTo(name) : .fail) }
                        else { guard acceptedRisk else { return }; model.mkdir(name, acknowledgedRemoteRisk: acceptedRisk) }
                        dismiss()
                    } catch { model.issue = .files(error) }
                }.fixedSize()
            }
        }.padding(24).frame(width: 580)
    }
}
struct FilesDeleteOptions: View {
    @ObservedObject var model: FilesController
    let entry: DirectoryEntry
    @State private var linkOnly = false
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("准备只读删除计划").font(.title2)
            Text(verbatim: FileDisplay.name(entry.name) + " · " + entry.attributes.kind.rawValue)
            Text("此步只收集精确范围，不删除。下一步将显示根、全部项目、数量、问题与剩余风险，再由你一次确认。")
            if entry.attributes.kind == .symbolicLink {
                NativeButton(title: linkOnly ? "仅删除链接自身（不跟随）已选择" : "明确选择仅删除链接自身", id: "files.delete.linkOnly") { linkOnly.toggle() }.fixedSize()
            }
            HStack {
                NativeButton(title: "取消", id: "files.operation.cancel") { dismiss() }.fixedSize()
                NativeButton(title: "生成计划", id: "files.delete.prepare") { model.prepareDelete(entry, removeLinkOnly: linkOnly); dismiss() }.fixedSize()
            }
        }.padding(24).frame(width: 580)
    }
}
struct FilesDeletePlanView: View {
    @ObservedObject var model: FilesController
    let review: FilesDeleteReview
    @State private var confirmed = false
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("确认精确删除计划").font(.title2)
            Text(verbatim: "根：" + FileDisplay.path(review.plan.root))
            Text("项目数：\(review.plan.items.count)；问题：\(review.plan.issues.count)")
            ScrollView {
                VStack(alignment: .leading) {
                    ForEach(Array(review.plan.items.enumerated()), id: \.offset) { _, item in Text(verbatim: FileDisplay.path(item.path) + " · " + action(item.action)).font(.caption) }
                    ForEach(Array(review.plan.issues.enumerated()), id: \.offset) { _, item in Text(verbatim: FileDisplay.path(item.path) + " · " + item.error.kind.rawValue).foregroundStyle(.red) }
                    ForEach(Array(review.plan.risks.enumerated()), id: \.offset) { _, risk in Text(verbatim: FileDisplay.risk(risk)).font(.caption) }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.frame(height: 230)
            Text("执行前完整复核；已知变化会停止。最终检查不是比较交换，不保证服务器之后不改树。不会扩展计划、删除主机根或跟随链接。")
            NativeButton(title: confirmed ? "已核对全部范围与风险" : "确认所示根、数量、项目及全部风险", id: "files.delete.acknowledge") { confirmed.toggle() }.fixedSize()
            HStack {
                NativeButton(title: "取消计划", id: "files.delete.cancel") { model.discardDeleteReview(); dismiss() }.fixedSize()
                NativeButton(title: "执行此次精确删除", id: "files.delete.execute", enabled: confirmed && review.plan.canExecute) {
                    guard confirmed else { return }; model.executeDelete(review, confirmed: true); dismiss()
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
            ForEach(Array(review.plan.requiredRisks.enumerated()), id: \.offset) { _, risk in Text(verbatim: FileDisplay.risk(risk)) }
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
            Text(verbatim: FileDisplay.risk(risk))
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
    @State private var verified = false
    var dismiss: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("SFTP 同握手主机身份").font(.title2)
            switch prompt.event {
            case .pending(let decision):
                Text(verbatim: decision.host.address.value + ":" + String(decision.host.port.value))
                Text(verbatim: decision.algorithm + " · " + decision.fingerprint).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                Text("来源：当前 libssh2 握手的真实公钥；尚未证明身份。请通过管理员／控制台等独立渠道核实完整指纹，接受仅绑定本次端点与精确公钥。")
                NativeButton(title: verified ? "已独立核实" : "我已独立核实完整指纹", id: "files.trust.verified") { verified.toggle() }.fixedSize()
                NativeButton(title: "接受此精确指纹", id: "files.trust.accept", enabled: verified) { guard verified else { return }; if model.answerTrust(prompt, verified: true) { dismiss() } }.fixedSize()
            case .changed(let change):
                Text(verbatim: change.host.address.value + ":" + String(change.host.port.value) + " · " + change.algorithm)
                Text(verbatim: "已知：" + change.expectedFingerprint)
                Text(verbatim: "本次：" + change.presentedFingerprint)
                Text("已阻止连接，不提供接受变化按钮。请独立核实后在可信主机管理使用精确人工替换流程。")
            }
            NativeButton(title: "取消连接", id: "files.trust.cancel") { model.cancelCurrent(); dismiss() }.fixedSize()
        }.padding(24).frame(width: 650)
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
                NativeButton(title: "取消本次连接", id: "files.keyboard.cancel") { clear(); model.cancelCurrent(); dismiss() }.fixedSize()
                NativeButton(title: prompt.prompts.isEmpty ? "已阅，继续" : "提交本轮全部回答", id: "files.keyboard.submit") {
                    let secrets = answers.map { OpenLXSSHSecurity.SecretBytes(utf8: $0) }; clear()
                    if model.answerKeyboard(prompt, answers: secrets) { dismiss() }
                }.fixedSize()
            }
        }.padding(24).frame(width: 650).onDisappear { clear() }
    }
    private func clear() { answers = Array(repeating: "", count: answers.count) }
}
