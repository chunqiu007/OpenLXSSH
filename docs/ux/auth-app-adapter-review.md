# 桌面认证候选接线：整合审查

日期：2026-10-30。状态：**最终正式 Debug 构建及107项定向测试通过，主管独立39项复验通过；真实App网络/键鼠/像素门仍待。** 默认会话后端仍为系统 OpenSSH 的 `DirectSessionBuilder`，没有用户可见的后端切换按钮。

## 已实现的候选边界

- `MainView` 实际注入本次密码 handler；`AppModel.prepareTransientConnection` 使用 internal native candidate，强制新会话。
- `SessionController.prepareTransient` 创建不联网、不选择页面的 prepared owner；保存/重读成功后释放准确编辑器，再同步 commit/start/route。路由拒绝会撤销并移除候选，不将秘密放入持久偏好或共享表单状态。
- 一次性意图绑定最终 host ID、连接身份、SessionToken 和唯一 primary request ID。metadata-only 改名不误撤销；真正配置或授权变化、取消和新代次拒绝旧意图。
- `NativeSessionDriver` 使用成熟 `LibSSH2ShellSession`；同 tab 终端实例、一个输出 pull、64 KiB 输出上限、256 KiB / 128 项输入准入、串行写入与 latest resize 合并。
- typed primary provider 与未知 keyboard-interactive mailbox 分离；saved read 前后及最终 material 返回前独立校验当前 metadata。未知 KI 不持有 saved reader 或一次性 intent。
- 两主认证的多字段、echo、零输入通知与取消进入实际 App model / View；当前候选预算 10 / 120 / 300 秒，liveness 为 nil。
- SSH/SFTP 首次信任三按钮、当前 owner 自动呈现以及 changed 拒绝界面已接源码；真实回调 race 尚未修复，不能据 model 测试称完整 changed 门通过。

原始 19 文件冻结与本轮 before 增量：`DerivedData/UXVerification/AuthAppAdapter-R1/source-ready-r1.json`、`source-ready-r1.patch`。联合 KeyDuplicate 7 文件后的去重 25 源摘要已另记；`SecurityCoordinator` 的变化来自已协调的独立导入任务，不假称旧摘要一致。

## 主管独立源审结论

已读取 driver、controller、MainView/AppModel 路由、VaultHostEditorModel 实际保存消费路径、SessionViews、NativeTerminalView relay 及新增 NativeSessionAdapterTests。

确认：正常保存和失败路由的 intent 撤销、单 pull、输入先准入、resize 合并、close 和 registry drained 分开记录、KI 不读取长期秘密均有实际源码接线；测试明确使用虚拟 transport，不冒充 SSH。

审查新增的具体缺口及处理边界：

1. **prepared 丢弃未自动撤销。** `VaultPreparedConnection` 原无 deinit 兜底，future consumer 若直接丢弃对象可能保留 controller preparedCandidates 和 intent。批准最小 isolated deinit 与真实 controller 丢弃回归，待最终结果。
2. **认证表单有与旧 host editor 相同的自动 fitting 风险模式。** 原 `AuthenticationChallengeView` 仅宽度、ScrollView 仅 maxHeight。实际 View 的修前 fitting 为 primary 610×199、32 prompt 610×475、zero 610×247；以420下限写的测试产生2断言失败，但**高度不足420不独自证明字段不可见或业务不可用**。已要求补实际 viewport / field / footer 的非空可见性及32项末项滚动门，并保持短通知紧凑；有界高度是防御布局选择，不用该新尺寸阈值冒产品故障实证。
3. **错误被错误归因。** 原所有 Native timeout 映为 authenticationTimeout、TCP/DNS FileServiceError 落到 authenticationFailed。批准固定类型/操作白名单的非秘密诊断、准确 status，以及可用的 Vault 配置选择路由；不透传 error.description、不扫描终端、不改变 legacy enum。
4. **runtime changed 事件和失败 registry handle。** 已独立安排只读设计；当前 runtime 必须保持冻结，等待有限活性测试后再最小修。App record 只能保存已收到的事件，无法修复 runtime 未交付。

以上追加已最终冻结并完成正式107项回归，主管独立39项复验通过；布局门采用准确自有、未显示/未激活的NSWindow，实际footer/primaryfield和32项末字段滚动均通过。曾新增但未验的“转到最后一项”按钮已撤除，仅撤本轮增量。初始420尺寸阈值失败、NSApp初始化trap、纯offscreen滚动和SwiftUI transition失败日志均保留，不据后续通过改写旧结果。

## 已执行验证及原失败

根目录：`DerivedData/UXVerification/AuthAppAdapter-R1/`，各 JSON 含真实 cwd / argv / exit / 时长，原日志保留。

### Transport

- shipping 默认 graph，arm64/macOS 26，Swift 6、完整并发、warning-as-error：首 build exit 1、第二次 exit 1。
- 有证据的最小前置修：两个有界 CChar decode、不可变 SessionWorkspace checked Sendable、PTY callback ObjectIdentifier、MainActor isolated deinit；未改 manifest、依赖、认证白名单或进程 reaper。
- shipping build-3 exit 0。
- 第一轮测试虽 12/0，但 SwiftPM probe graph 将实际最低版本降到 15；**不计作 min26**。
- 显式 Swift/C target 修正后的 relay-tests-2：12/0，exit 0；vtool/file 实核 terminal、PTY、新 test 对象与 xctest 均 arm64/minos 26.0。测试仍 probe 登记图，不冒 shipping 真实连接。
- 12 项范围：新 relay 5、既有粘贴/颜色/font/search/精确兼容白名单 6、workspace FD 1。无真实剪贴板或 GUI 动作。

### 正式 App

- `Scripts/build-app.sh Debug build-for-testing` 首次 exit 65：`NativePrimaryReply.wait` 局部 result 遮蔽 self.result，capture-before-declared。
- 一行显式 `self.result` 修复后，build-2 exit 0，27.269 秒；原 helper Swift 5 构建图亦成功。
- 正式 `test-without-building` 第一批 33/0：NativeSessionAdapter 19、EditorDraft 7、ReliabilityEditor 7。
- 第二批 68/0：FilesAuthentication 19、FilesController 18、SessionConcurrency 10、SessionController 21。
- 最终正式 build-7 exit0（5.23秒），原helper Swift5图通过；`Formal/final-product-target.json`实核App与xctest arm64/minos26.0。
- 最终 `Formal/final-targeted-tests-1` **107/0**（Native25、Editor7、Reliability7、Session21、Concurrency10、FilesAuth19、FilesController18），exit0；覆盖原101及6个追加回归，不重复累计成208项。
- 主管另在最终测试产物运行 `Primary/independent-adapter-editor-1` **39/0**（Native25、Editor7、Reliability7），exit0；同时逐项核最终25文件摘要无变化。
- 最终来源：`final-source-hashes.json`、`formal-review-increment.patch`、`final-task-increment-excluding-shared-security.patch`。对Key任务生产/App六源hash一致的结论明确记录，不将共享文件Key改动计为Auth成果。

## 未覆盖和发布边界

- 新 App 真实密码 / key / 两类 MFA、once/persistent、changed、并发取消、真实终端/TUI/粘贴/资源门均未通过。
- CUA 本次只读 list_apps 仍全部 active false；不据此推断锁屏或擅改系统权限。当前没有新版像素验收或截图通过。
- Native liveness 默认未接；normal 有限候选门见 `native-liveness-live-finite.md`，DROP 与 MaxSessions 不通过/未执行。
- 不切生产默认，不标 UX_READY_FOR_USER，不推送，不生成新最终发行包或提交 Apple 公证。
