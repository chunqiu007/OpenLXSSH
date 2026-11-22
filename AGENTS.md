# OpenLXSSH

OpenLXSSH 是一款面向 **Apple Silicon（arm64）与 macOS 26+** 的原生轻量 **SSH 与 SFTP 桌面客户端**，使用 **Swift 6、SwiftUI 与 AppKit** 构建，无 Electron 运行时、无云端账号依赖，也不依赖独立辅助进程。

---

## 核心功能与边界

- **主机保险箱（Vault）**：通过分组、标签、收藏与搜索管理本地主机配置；支持快捷连接、JumpServer `#` 分隔用户名，以及粘贴完整 `ssh` 连接命令自动拆分填入地址、端口与用户名。
- **多窗口与原生终端**：支持多窗口独立工作区（`⌘N`）、多标签 SSH 会话，以及终端内原生分屏（`⌘D` 左右分屏、`⇧⌘D` 上下分屏、`⌥⌘]` 切换焦点、`⇧⌥⌘D` 取消分屏）；基于 SwiftTerm 渲染，支持多套深色主题色卡、16 色 ANSI 调色板、查找历史与精确粘贴。
- **直连 SSH 与多因素认证**：采用静态链接的 `libssh2 + OpenSSL`，类型化区分密码/私钥主认证与服务器 `keyboard-interactive`（MFA）人工挑战；支持内核 TCP Keepalive，以及在远端终端内手动嵌套执行第二次 `ssh`。
- **双栏 SFTP 与安全传输**：独立直连远端目录，默认沿用所选主机已授权凭据并支持按次临时输入；采用临时文件上传再原子提交、同名冲突默认询问（取消 / 替换 / 都保留）、目录内相对符号链接安全保留，以及全宽 Master-Detail 传输中心。
- **不在产品范围内**：不支持自动 ProxyJump、多级跳板编排、经跳板机的图形化 SFTP 或本地/远程端口转发；应用不扫描终端普通输出，也不会向远端嵌套 `ssh` 或 `sudo` 自动投递本机凭据。

---

## 目录与模块结构

| 路径 | 职责 |
| --- | --- |
| `Application/OpenLXSSH/` | 桌面应用主体：`AppDelegate` 多窗口管理、`@Observable` 状态模型、主机保险箱、终端工作区与分屏、双栏 SFTP 与传输中心、安全/信任管理界面 |
| `Packages/OpenLXSSHCore/` | 基于 SQLite + GRDB 的持久化层（主机、分组、标签、收藏、偏好、凭据/私钥引用及数据库迁移） |
| `Packages/OpenLXSSHTrust/` | 主机地址/端口/用户名校验、SHA-256 指纹与 App 专属 `HostTrustStore`（SSH/SFTP 共用） |
| `Packages/OpenLXSSHSecurity/` | 现代 Keychain v2 凭据存取（`CredentialStore`）与 App 专属目录 OpenSSH 私钥管理（RSA / Ed25519 导入与生成） |
| `Packages/OpenLXSSHFiles/` | `COpenLXSSHFiles` C 桥接（静态链接 `libssh2` + `OpenSSL`）、kqueue 事件驱动 `LibSSH2ShellSession`、`LibSSH2FileService`、`LocalFileService`、目录清单校验与 `SafeTransferEngine` / `TransferManager` |
| `Packages/OpenLXSSHTransport/` | 纯 Swift 6 终端视图层（基于 SwiftTerm 1.99.1 的 `NativeTerminalView`）与会话基础类型 |
| `Tests/OpenLXSSHAppTests/` | 应用层单元测试与隔离窗口测试 |
| `Scripts/` | 构建（`build-app.sh`）、产物与依赖校验（`verify-app.sh`、`verify-build-plugin.py`、`verify-files-native.py`）与 DMG 打包脚本（`package-release-candidate.py`） |
| `docs/` | 架构说明、产品需求、用户指南与架构决策记录（`docs/adr/`） |

---

## 核心技术与安全设计

- **多窗口状态隔离**：进程级共享 `AppRepository`、`SecurityCoordinator` 与 `SessionEnvironment`；每个 `ManagedWorkspaceWindow` 拥有独立的 `@Observable` `AppModel`（含独立工作区路由、终端标签/分屏与 SFTP 状态），跨窗数据变更通过 `AppRepository` 广播实时同步。
- **事件驱动传输与渲染**：终端 I/O 通过独立 `dup` 描述符挂接 macOS kqueue `DispatchSource`（无轮询定时唤醒），C 层内存追踪使用 O(1) 双向链表并启用 `TCP_NODELAY`；SFTP 并发调度使用无轮询 FIFO `CheckedContinuation` 队列，默认传输块为 256 KiB；`TerminalAttachmentRegistry` 确保终端视图在单标签与分屏间重挂载时不重建、不丢历史。
- **主机身份与凭据隔离**：
  - 主机公钥首次连接必须经用户核实完整 SHA-256 指纹，已知主机密钥变更默认拒绝。
  - 凭据存于本机 Keychain 命名空间 `org.openlxssh.credentials.v2`，每次调用使用独立非交互 `LAContext` 且禁用同步；具 Data Protection entitlement 时启用 `kSecUseDataProtectionKeychain` 与 `WhenUnlockedThisDeviceOnly`，无授权的本地构建回退至标准非交互 Keychain。
  - 数据库仅存引用与配置元数据，不存明文密码、私钥内容或一次性验证码（OTP）。

---

## 常用命令与文档入口

- **构建应用**：`Scripts/build-app.sh Debug build` / `Scripts/build-app.sh Release build`
- **校验构建产物**：`Scripts/verify-app.sh build`
- **打包只读 DMG**：`python3 Scripts/package-release-candidate.py --build`（可选 `--sign "<Developer ID>"`）
- **运行包单元测试**：`swift test --package-path Packages/<PackageName>`（`OpenLXSSHFiles` 离线回归可用 `--skip ScopedTrialLiveTests`）
- **运行应用测试**：`OPENLXSSH_FILES_TARGET26=1 xcodebuild test -project OpenLXSSH.xcodeproj -scheme OpenLXSSH -destination 'platform=macOS,arch=arm64' -derivedDataPath DerivedData/Debug -clonedSourcePackagesDirPath DerivedData/SourcePackages -onlyUsePackageVersionsFromResolvedFile -skipPackageUpdates -skipPackagePluginValidation`
- **核心文档**：[docs/architecture.md](docs/architecture.md) · [docs/requirements.md](docs/requirements.md) · [docs/user-guide.md](docs/user-guide.md) · [ENGINEERING_STATE.md](ENGINEERING_STATE.md) · `docs/adr/`
