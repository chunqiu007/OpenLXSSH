# OpenLXSSH — 工程状态

更新：2026-11-22（Asia/Shanghai）。本文件记录 `main` 分支当前工程基线、验证结果与已知限制；**2.0.4 及以前的历史阶段工程日志与报告已完整归档于 Git 标签 `v2.0.4`（`ac8b967`）及提交 `084b043`**。

## 2026-11-22 原生界面视觉更新

- 保险箱、工作区标签、主机编辑器、新连接面板和 SFTP 使用统一的深青、雾绿与中性色。主机列表和卡片突出名称、端点和选中位置，连接面板按已保存主机数设置合适高度。
- 在隔离窗口使用三台虚构主机核对浅色列表、深色卡片、主机详情、编辑器、连接面板与紧凑窗口。一次截图发现 SFTP 本地类型列被截断；调整默认列宽并在 1120 点窗口确认修改时间、大小和类型完整可读。用户保存的布局仍优先。截图位于 `DerivedData/VisualFinishQA/`。
- `Scripts/build-app.sh Debug build-for-testing`、`Scripts/build-app.sh Release` 完成。`xcodebuild test-without-building` 执行保险箱、主机草稿、双栏、列宽偏好和窗口标题栏相关 51 项，全部通过。结果位于 `DerivedData/VisualFinishQA/final.xcresult`。本轮验收覆盖本机界面与交互，未进行真实服务器互通或分发验证。

## 2026-11-22 桌面操作体验验收

- 在 `1d14b11` 的多窗口基线上完成本轮界面改进。主机编辑器优先显示连接信息与认证，保留真实草稿的关闭确认。新连接面板按当前主机能否复用会话显示操作。SFTP 首次建主机后返回文件页并预选目标，本地文件夹可直接选择。
- 工作分工与复核：UI-01 主机表单由 host_editor 起草、主会话接手完成；UI-02 新连接面板和 SFTP 接线由主会话完成。QA-01 由 ui_smoke 在临时 HOME、独立 bundle 的原生窗口执行。主会话复核 Swift 差异、窗口截图和测试结果。
- `Scripts/build-app.sh Debug build-for-testing`、`Scripts/build-app.sh Release` 通过。`xcodebuild test-without-building` 运行本轮涉及的草稿、关闭、保险箱、双栏和会话路由用例，57 项通过。结果保留在 `DerivedData/UIIntuitionQA/flows.xcresult`。
- 常规窗口与紧凑窗口已实测。覆盖粘贴 SSH 命令并填表、空表单取消、有修改时保留草稿、SFTP 保存返回、路径输入、⌘T 零个／一个／多个匹配与 Esc。截图保留在 `DerivedData/UIIntuitionQA/`。SSH 入口只用回环拒绝连接验证路由；真实远端认证和文件传输不在本轮复测范围。
- 当前交付为本地 Release App，发布与双机验收状态沿用下方记录。

## 当前目标与交付基线

- **产品定位**：Apple Silicon（arm64）/ macOS 26+ 原生轻量 SSH + SFTP 桌面客户端（Swift 6、SwiftUI + AppKit、静态 `libssh2 + OpenSSL`、SwiftTerm、GRDB/SQLite、现代本机 Keychain v2）。
- **最新已发布包**：Release **2.0.4（build 7）**，标签 `v2.0.4`（`ac8b967`），`OpenLXSSH-2.0.4-arm64.dmg`（7,368,371 B，SHA-256 `37f7bc30d74b416c0980b4fdc1ea65c48fa79cf1eeefe86ac0a514c38fe2135c`），Developer ID 离线签名、未经 Apple 公证。
- **活文档索引**：[需求说明](docs/requirements.md) · [架构说明](docs/architecture.md) · [用户指南](docs/user-guide.md) · [ADR-20261122](docs/adr/20261122-streamline-and-modern-keychain.md)。

## `main` 分支里程碑（M1–M6，位于 `v2.0.4` 之上）

| 里程碑 | 提交 | 摘要 |
| --- | --- | --- |
| **M1** | `46557f3` | `COpenLXSSHFiles` O(1) 双向链表与 `TCP_NODELAY`；`NativeShellSession` 改用 kqueue 事件源；`AsyncGate` 改为 FIFO `CheckedContinuation` 队列；SFTP 默认块大小升至 256 KiB |
| **M2** | `f097943` | 移除旧 OpenSSH/Askpass 后端、`openlxssh-askpass` helper、8 个内嵌探针文件、`Experiments/` 与历史验收桩（净删 83,455 行）；`OpenLXSSHTransport` 精简为纯 Swift 6 终端层 |
| **M3A** | `1ea1f4b` | 核心状态全面迁移至 macOS 26 `@Observable`；拆分 `FilesController`、`DualPaneFilesView` 与 `VaultWorkspacePage` |
| **M3B** | `084b043` | 新增原生终端分屏（`⌘D` 左右、`⇧⌘D` 上下、`⌥⌘]` 切换焦点、`⇧⌥⌘D` 取消分屏、标签右键分屏）及 `TerminalAttachmentRegistry` 无损重挂载 |
| **M4** | `db5c035` | 升级 `CredentialStore` 至现代 `LAContext` / Data Protection Keychain v2（`org.openlxssh.credentials.v2`），零写入探测并优雅回退标准本机 Keychain，移除 `SecurityPOSIX` 旧 shim |
| **M5** | `b8a5449` | `AppDelegate` 支持多窗口工作区（`⌘N` 独立 `ManagedWorkspaceWindow` / `AppModel`，共享 `AppRepository` / `SecurityCoordinator` / `SessionEnvironment`，逐窗关闭与退出审查）并清理 `NativeControls` |
| **M6** | 本轮提交 | 清理历史阶段报告、废弃规划与退役 ADR；新增 `ADR-20261122` 并同步架构/用户指南/README/本状态；重写 `Scripts/package-release-candidate.py`（1,241 行 → 261 行） |

## 验证结果（macOS 26.7.1 / Xcode 26.3 / arm64，Swift 6 严格并发）

- **构建与产物校验**：
  - `Scripts/verify-app.sh build`：Debug + Release 双配置 0 警告、0 错误通过，核验 `arm64`、`minos 26.0`、零非系统动态库、零 `Contents/Helpers`、依赖锁与全部第三方许可证哈希。
  - `Scripts/package-release-candidate.py`：`py_compile`、`--help` 及对 Release App 的无签名端到端打包冒烟通过（`strip -x`、Mach-O/dylib/许可证校验、生成 `OpenLXSSH-2.0.4-arm64.dmg` 含 `/Applications` 链接、`hdiutil verify` 与 `shasum -a 256 -c` 均通过，临时目录已清理）。
- **核心自动化测试（M1–M5 阶段记录，M6 未改动任何 Swift/C 代码）**：
  - Swift Packages：`OpenLXSSHCore` 82/82、`OpenLXSSHTrust` 59/59、`OpenLXSSHSecurity` 45/45（含 Keychain v2 隔离测试）、`OpenLXSSHTransport` 13/13、`OpenLXSSHFiles` 离线核心组（含 `IOPerformanceTests`）77/77 通过。
  - App 测试：`SessionControllerTests` 44/44（含分屏与隔离 `NSWindow` 重挂载）、`NativeSessionAdapterTests` 104/104、`DualPaneFilesTests` 20/20、`FilesControllerTests` 37/37、`FilesTransferTests` 19/19、`FilesAuthenticationTests` 21/21、`VaultDesktopTests` 9/9、`OpenLXSSHAppTests`（含多窗口测试，排除已知无宿主 `NSApp.currentEvent` 单测）通过。
- **文档链接检查**：`README.md`、`README.en.md`、`docs/architecture.md`、`docs/user-guide.md`、`docs/adr/20261122-streamline-and-modern-keychain.md` 与本文件内部 Markdown 文件链接零断链。

## 已知限制与历史既有测试项（原样保留）

- **未覆盖范围**：M1–M6 尚未连接真实远端 SSH/SFTP 服务器复测，尚未发布高于 2.0.4 的签名/公证 DMG，也未在第二台 Mac 上做安装/升级人工回归；为保护本机真实 `Application Support` 数据，未直接启动未隔离的 `OpenLXSSH.app`。
- **Keychain v2 升级说明**：从 2.0.4（v1 命名空间）升级至 `main` 的 v2（`org.openlxssh.credentials.v2`）时，旧凭据不静默迁移，且 SSH 连接弹窗为「仅本次使用，不保存」；升级后如需重新记住密码，在「保险箱」编辑对应主机并勾选「记住密码」；如需重新记住加密私钥口令，在「密钥与凭据」选择对应私钥并点击「记住口令…」/「重新记住口令…」。
- **既有历史失败项（未改绿）**：
  - `InitialDirectoryTests.testNativeOwnerWithoutSFTPDoesNotResolveOrSendAnyBytes`（1 项，始于 `9e405ad`）。
  - `DualPaneFilesTests` 中 4 项旧计划审查用例。
  - 无宿主运行环境下的 `OpenLXSSHAppTests.testWindowTabsMiddleClickBelongsOnlyToExactNativeTargetAndNoModifierOrEditor`（`NSApp.currentEvent` 断言）。

## 下一步

- M6 已提交为 `1d14b11`。后续如需发布新版本 DMG，递增版本号、执行真实 SSH/SFTP 与多窗口/分屏手工冒烟后，使用 `Scripts/package-release-candidate.py --build --sign "<Developer ID>"` 打包。
