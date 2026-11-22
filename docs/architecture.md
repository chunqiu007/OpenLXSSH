# OpenLXSSH 架构说明

OpenLXSSH 是面向 Apple Silicon（arm64）与 macOS 26+ 的轻量原生 SSH / SFTP 桌面应用，采用模块化单体结构，使用 Swift 6、SwiftUI + AppKit 构建，原生传输层静态链接 `libssh2 + OpenSSL`，无需独立辅助进程或外部运行时动态库。

> 架构演进细节见 [ADR-20261122](adr/20261122-streamline-and-modern-keychain.md) 及 `docs/adr/` 下的专题决策记录；产品范围见 [需求说明](requirements.md)。

## 1. 模块划分

| 模块 | 路径 | 职责 |
| --- | --- | --- |
| 桌面应用 | `Application/OpenLXSSH` | 多窗口管理、工作区路由、终端分屏、双栏 SFTP UI、安全与信任管理页面 |
| 数据与模型 | `Packages/OpenLXSSHCore` | SQLite + GRDB 持久化（主机、分组、标签、收藏、偏好、凭据/私钥引用与迁移） |
| 身份与信任 | `Packages/OpenLXSSHTrust` | SSH 主机/用户名校验（支持 JumpServer `#` 格式）、SHA-256 指纹与 `HostTrustStore` |
| 凭据与私钥 | `Packages/OpenLXSSHSecurity` | 现代 `LAContext`/Data Protection Keychain v2 与 App 专属目录私钥管理 |
| 传输与文件 | `Packages/OpenLXSSHFiles` | `COpenLXSSHFiles`（静态 `libssh2 + OpenSSL`）、事件驱动 `NativeShellSession`、SFTP 服务与安全传输引擎 |
| 终端视图 | `Packages/OpenLXSSHTransport` | 基于 SwiftTerm 的纯 Swift 6 `NativeTerminalView`、主题调色板、输入与背压适配 |

## 2. 应用层状态与资源所有权

应用入口由 `AppDelegate` 管理多个 `ManagedWorkspaceWindow` 实例，并共享进程级底层服务，避免重复打开数据库或竞争本地资源：

- **进程共享资源**：`AppRepository`（SQLite）、`SecurityCoordinator`（Keychain 与私钥协调）、`SessionEnvironment`（信任库与运行时路径）。
- **单窗口独立状态（`@Observable`）**：每个窗口拥有独立的 `AppModel`，下挂工作区路由（固定保险箱 / 固定 SFTP / 动态终端会话标签）、`SessionController`、`FilesController`、`LocalBrowserModel`、`VaultDesktopModel`、`SecurityViewModel` 与 `WorkspaceWindowChromeState`（仅 AppKit 标签拖拽协调器 `WorkspaceTabDragOwner` 为兼容同步拖拽单测保留 `ObservableObject`）。
- **页面与资源解耦**：切换保险箱、SFTP 或终端标签只改变可见性与焦点，不中断已有 SSH 会话、不取消 SFTP 连接或丢弃传输队列。固定管理页不进入可关闭会话列表。
- **关闭与退出保护**：关闭单个窗口或退出应用（`⌘Q`）时，逐窗审查未保存的编辑器草稿与进行中的 SFTP 传输；用户可选择继续保留窗口，或取消活跃传输并等待安全清理完成后关闭。

## 3. 原生 SSH 终端与分屏

- **事件驱动连接**：原生 SSH 直接经由 `COpenLXSSHFiles` / `libssh2` 建立 TCP 与加密会话，启用 `TCP_NODELAY` 与系统内核 TCP Keepalive（`SO_KEEPALIVE` / `TCP_KEEPALIVE` / `TCP_KEEPINTVL` / `TCP_KEEPCNT`），不开启额外辅助 SSH 通道。
- **kqueue 调度**：`NativeShellSession` 使用独立 `dup` 描述符注册 `DispatchSourceRead` / `DispatchSourceWrite` / `DispatchSourceTimer`，实现无轮询 I/O、即时取消唤醒与关闭前完整排空；C 层 `rf_allocation` 使用 O(1) 双向链表追踪内存所有权。
- **终端渲染与分屏**：`NativeTerminalView` 封装 SwiftTerm，内存滚动历史有界（默认 10,000 行，上限 50,000 行），不落盘持久化终端输出。`TerminalAttachmentRegistry` 确保同一 `NativeTerminalView` 在单标签视图与左右/上下 `HSplitView`/`VSplitView` 分屏容器之间重挂载时永不重建或丢失历史。
- **直连边界**：App 只管理最外层直连 SSH 的主机验证与认证流程；用户在远端终端中手动执行的嵌套 `ssh`、`sudo` 等交互完全留在终端流内，绝不扫描终端输出或自动投递本机凭据。

## 4. 主机信任、凭据与私钥安全

- **主机信任（`HostTrustStore`）**：SSH 与 SFTP 共用 App 专属信任库，按主机、端口与密钥类型识别服务端公钥并展示完整 SHA-256 指纹。首次连接需用户明确确认；已知主机密钥变化默认拒绝，绝不静默降级或覆盖。
- **凭据存储（Keychain v2）**：`CredentialStore` 使用服务命名空间 `org.openlxssh.credentials.v2`，每次调用创建独立的非交互 `LAContext`（`interactionNotAllowed = true`）并设置 `kSecAttrSynchronizable = false`。初始化时通过零写入 `SecItemUpdate` 探测 Data Protection entitlement：有授权时启用 `kSecUseDataProtectionKeychain = true` 与 `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`；在未签名或 ad-hoc 构建缺授权时自动回退至标准本机 Keychain（仍保持非交互、不同步）。OTP 等一次性验证码从不持久化；Keychain 不可读时回退为人工输入。
- **私钥管理**：导入的 OpenSSH 私钥（RSA / Ed25519）与生成的 Ed25519 私钥均以受限权限存放在 App 专属目录中，不修改用户原始文件；配置数据库仅保存稳定引用，不存放明文密码或私钥口令。

## 5. SFTP 与安全文件传输

- **独立连接与认证复用**：SFTP 通过 `RemoteFileService` / `LibSSH2FileService` 与目标服务器直接建立连接，不依赖已打开的终端标签。连接时默认沿用所选主机已授权的密码或关联私钥，并支持仅对本次连接覆盖密码、口令或响应服务器交互式认证（Keyboard-Interactive / MFA）。
- **流式传输与调度**：`SafeTransferEngine` 与 `TransferManager` 负责目录扫描清单、冲突决策冻结与传输队列。并发闸门 `AsyncGate` 基于无轮询 FIFO `CheckedContinuation` 队列并接入 `CancellationToken`；默认 SFTP 读写块大小为 256 KiB。
- **数据安全策略**：
  - 上传与下载先写入唯一临时文件，完成后再原子提交；默认冲突策略为“每次询问”（取消 / 替换 / 都保留），自动改名采用独占提交与有界重选，避免竞态误覆盖。
  - 目录传输支持安全保留目录内相对符号链接（校验防绝对路径、越界 `..`、悬空与循环链接），并按依赖拓扑顺序创建；拒绝不安全路径逃逸与特殊文件。
  - 传输中心采用全宽 Master-Detail 视图，按项报告成功、跳过、失败与残留临时文件路径。

## 6. 构建、校验与分发约束

- **单一原生产物**：`Scripts/build-app.sh` 固定锁定 SPM 依赖与 `COpenLXSSHFiles` 静态库（`libssh2` + `OpenSSL`），产出仅含 `arm64`、最低部署目标 `macOS 26.0`、启用 Hardened Runtime 的 `OpenLXSSH.app`，并将全部第三方许可证与 `NOTICE.txt` 打包进 `Contents/Resources/`。
- **构建与打包校验**：
  - `Scripts/verify-app.sh` 验证 Debug/Release 构建、Mach-O 架构与 `minos 26.0`、零非系统动态库依赖、零 `Contents/Helpers` 残留、依赖锁定哈希与许可证完整性。
  - `Scripts/package-release-candidate.py` 负责 Release 应用复制与符号剥离（`strip -x`）、元数据/二进制/许可证复核、可选 Developer ID 签名（默认离线 `--timestamp=none`）、生成带 `/Applications` 链接的 LZMA 只读 `.dmg`、执行 `hdiutil verify` 并输出 SHA-256 校验和。
