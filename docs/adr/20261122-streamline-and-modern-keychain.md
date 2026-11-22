# ADR-20261122：原生架构精简、分屏与多窗口及现代 Keychain v2

状态：已实现并合并至 `main`（M1–M6）。历史 V1.0 阶段报告与旧实现完整归档于 Git 历史（`v2.0.4` / `084b043`）。日期：2026-11-22。

## 背景

在发布 2.0.4 之后，仓库中仍残留大量 V1.0 阶段的过渡实现与历史负担：
1. 原生 SSH 已完全切换至 `libssh2 + OpenSSL`，但旧的 OpenSSH 子进程 / Askpass 辅助进程后端、内嵌探针代码与实验工程仍占用数万行代码与构建复杂度。
2. 原生 Shell 与 SFTP 队列调度仍存在 5ms 轮询、O(n) C 层内存追踪与 64 KiB 传输块限制。
3. UI 状态层仍广泛依赖 `ObservableObject` / 手工 `objectWillChange.send()`，单窗口限制与缺少终端分屏影响日常运维效率。
4. `CredentialStore` 仍依赖已弃用的 file-based Keychain 兼容 shim，且发布打包脚本膨胀至 1,200+ 行。

围绕“轻量、顺手、易维护的 Apple Silicon / macOS 26 原生 SSH + SFTP 客户端”目标，本 ADR 记录 M1–M6 的核心架构决策。

## 核心决策

### 1. 事件驱动 I/O 与 SFTP 传输调度（M1，`46557f3`）
- **C 桥接层（`COpenLXSSHFiles`）**：将 `rf_allocation` 内存追踪升级为 O(1) 双向链表；在原生 SSH/SFTP socket 上启用 `TCP_NODELAY`，并暴露 `rf_connection_socket` 供事件驱动层监控。
- **原生 Shell（`NativeShellSession`）**：以基于独立 `dup` 描述符的 kqueue `DispatchSourceRead` / `DispatchSourceWrite` / `DispatchSourceTimer` 替代 5ms 轮询，空闲等待提升至 60s，取消信号可即时唤醒并在关闭前完整排空 FD；保留离线脚本泵测试接口。
- **传输调度（`SafeTransferEngine` / `RemoteFileService`）**：`AsyncGate` 改为无轮询 FIFO `CheckedContinuation` 队列并接入 `CancellationToken` 观察回调；默认 SFTP 读写块大小由 64 KiB 提升至 256 KiB。

### 2. 移除旧 OpenSSH/Askpass 后端与内嵌探针（M2，`f097943`）
- 彻底移除 `DirectSSHSession`、`AskpassBroker`、`COpenLXSSHAskpass`、`openlxssh-askpass` helper 可执行文件及其签名打包逻辑。
- 移除 `Application/OpenLXSSH/` 中 8 个内嵌探针/验收文件与条件编译宏分支，以及 `Experiments/` 和历史验收桩目录；`OpenLXSSHTransport` 精简为纯 Swift 6 的 `NativeTerminalView`（基于 SwiftTerm）与终端类型。
- 终端内手动执行嵌套 `ssh` 的边界保持不变：App 仅负责直连会话，绝不拦截或自动向远端输出投递凭据。

### 3. 状态层迁移至 `@Observable` 与视图/控制器拆分（M3A，`1ea1f4b`）
- 将 `AppModel`、`FilesController`、`LocalBrowserModel`、`SessionController`、`SessionTab`、`SessionBatchCloseOwner`、`VaultDesktopModel`、`PresentationOwner`、`SecurityViewModel` 与 `WorkspaceWindowChromeState` 全面迁移至 macOS 26 `@Observable`，移除手工 `objectWillChange.send()` 与多余 Combine 订阅（仅 `WorkspaceTabDragOwner` 保留以兼容 AppKit 拖拽同步测试）。
- 拆分超大单文件：`FilesController` 拆分为主体 + `+Browsing` + `+Transfers`；`DualPaneFilesView` 拆分为主体 + `FilesConnectionPanelView` + `FilesBrowserPaneView`；`VaultWorkspacePage` 拆分为主体 + `VaultSidebarView` + `VaultInspectorView`。

### 4. 原生终端分屏（M3B，`084b043`）
- 在 `SessionController`、`SessionViews`、`WorkspaceTabsView` 与应用菜单新增原生终端分屏：支持 `⌘D` 左右分屏、`⇧⌘D` 上下分屏、`⌥⌘]` 切换分屏焦点、`⇧⌥⌘D` 取消分屏、标签右键分屏以及分屏顶栏切换方向/交换/关闭。
- 引入 `TerminalAttachmentRegistry`，保证 `NativeTerminalView` 在单标签视图与 `HSplitView`/`VSplitView` 之间重挂载时不重建视图、不丢失内存滚动历史或断开会话。

### 5. 现代 `LAContext` / Data Protection Keychain v2（M4，`db5c035`）
- 将 `CredentialStore` 升级至服务命名空间 `org.openlxssh.credentials.v2`，移除 `SecurityPOSIX` 中已弃用的 file-based Keychain C/ACL 兼容代码。
- 每次 Keychain 读写使用独立的非交互 `LAContext`（`interactionNotAllowed = true`），禁用 iCloud 同步（`kSecAttrSynchronizable = false`）。
- 初始化时执行一次零写入 `SecItemUpdate` 探测：具备 Data Protection entitlement 时启用 `kSecUseDataProtectionKeychain = true` 与 `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`；在未签名或 ad-hoc 构建返回 `errSecMissingEntitlement`（`-34018`）时，自动回退至标准本机 Keychain（仍保持非交互与仅本机），不再阻断开发构建与测试。
- **升级影响**：v1（[ADR-P1-03](p1-03-file-keychain-selection.md)）中的旧凭据不会静默跨命名空间迁移；升级后如未命中 v2 条目，按既有安全契约回退为手动输入，用户勾选“记住”后写入 v2。

### 6. 多窗口工作区与发布脚本精简（M5 `b8a5449`、M6）
- `AppDelegate` 管理多个 `ManagedWorkspaceWindow`，支持 `⌘N` 新建独立窗口（独立 `AppModel`、标签页、分屏与 SFTP 页面状态），并共享单例 `AppRepository`、`SecurityCoordinator` 与 `SessionEnvironment`；关闭单窗或退出应用（`⌘Q`）时逐窗审查未保存表单与活跃传输。
- 清理已归档于 Git 历史的阶段报告与过渡文档，重写 `Scripts/package-release-candidate.py` 为紧凑、可读、默认离线签名的 Release 校验与 LZMA DMG 打包工具。

## 安全与兼容性确认

- 主机信任库（`HostTrustStore`）、SQLite 配置库（`GRDB`，`Application Support/OpenLXSSH/Data/OpenLXSSH.sqlite`）、私钥受限目录、OTP 不持久化与 SFTP 安全传输策略保持不变，兼容 2.0.4 用户数据。
- 所有原生依赖仍静态链接于单一 arm64 主程序，无第三方运行时动态库与额外 helper 进程。
