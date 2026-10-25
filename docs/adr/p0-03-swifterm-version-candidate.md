# ADR-P0-03-01：SwiftTerm 版本候选暂不固定，优先比较 1.20 与 2.0 前预览

- 状态：暂定，待 P2 原型固定
- 日期：2026-10-25（Asia/Shanghai）
- Task：`P0-03`
- 范围：仅依赖版本/API/构建候选调查；不代表终端功能、PTY、输入、背压、生命周期或 SSH 已通过

## 问题

OpenLXSSH 需要 PTY + SwiftTerm 承载 macOS 终端。架构基线指定 SwiftTerm 1.19.x 作为起始评估，并要求比较 2.x API/性能变化。上游当前没有可核对的正式 `v2.x` 标签；同时上游提供 `v1.20.0` 稳定 1.x 和 `v1.99.1` 的 2.0 前预览。需要避免将预览版本误记为稳定版本，也避免在没有原型证据时锁死 API。

## 候选与证据

| 候选 | 上游标签/提交 | manifest/API 事实 | 本机探针 | 主要风险 |
| --- | --- | --- | --- | --- |
| SwiftTerm `v1.19.0` | `464df5207fc2432e16c9a23abe538187196daf5f` | swift-tools 6.0；Swift language mode v5；最低 macOS 11；有 `SwiftTerm` 自动库产品 | `swift package dump-package` 和 `swift build --target SwiftTerm --triple arm64-apple-macosx26.0` 均退出 0 | 需求规定的起始候选；要与后续稳定修订比较，不能直接由 1.19 文档推断长期 API |
| SwiftTerm `v1.20.0` | `5d14406844143538cd8f8851d2d8a67c1fe443e5` | 与 1.19 同为 tools 6.0、Swift v5、macOS 11；`SwiftTerm` 自动库产品 | dump/build 均退出 0 | 稳定 1.x 候选，仍需实际终端原型覆盖 |
| SwiftTerm `v1.99.1` | `2f573f73af5e768d90847dce20c97fa9535d7164` | tools 6.2；Swift v6；最低 macOS 11；加入 traits 和 `swift-png` 路径；迁移文档明确 2.0 API 变化 | dump/build 均退出 0 | 上游发布 Atom 标题为“Preview before 2.0”；API、传递依赖和预览稳定性不能当作正式 2.x |
| SwiftTerm `main` | `c3436be32e3dc26d5e2181b1e451d91e21e50d53` | 同 2.0 API 文档/manifest 当前方向 | 未将 branch 当锁定候选构建 | branch 不可复现，不作为 App 依赖锁定来源 |

来源：<https://github.com/migueldeicaza/SwiftTerm.git>；manifest、README、LICENSE 和迁移文档均从对应 tag/raw URL 读取，命令退出码为 0。正式 v2 标签核对命令 `git ls-remote --tags --refs ... 'refs/tags/v2*'` 无输出。

## 影响比较

### 功能/API

- 1.19/1.20 使用当前稳定 1.x API；上游 README 提供 AppKit `TerminalView` 与本地进程/PTY 相关能力。
- 1.99.1 的迁移文档要求审查 `LocalProcess`/`HeadlessTerminal` 的 `directDelivery` 初始化参数、Terminal 读取接口和 `pasteText(_:)` 等方向；这会影响数据投递线程、粘贴策略和与 OpenLXSSH 自有 PTY/关闭协调器的边界。
- SwiftTerm 不是 SSH 库，不会替代系统 OpenSSH，也不携带 libssh2/OpenSSL。引入 SwiftTerm 不等于 SSH 认证或终端产品功能完成。

### 安全/资源

- 版本选择本身不改变主机密钥校验、Keychain、Askpass 或嵌套 SSH 边界；这些仍由 OpenLXSSH 设计和后续原型验证负责。
- 2.0 预览的 `directDelivery` 和更细的读取 API 可能改善线程/背压建模，但必须用真实输出压力、关闭、迟到回调和输入测试证明，不能凭 API 名称判断更安全。
- 1.x/2.0 均使用系统 Apple 框架；未发现必须随产品携带的 SwiftTerm 原生第三方动态库。

### 许可证与分发

- 两个版本的 SwiftTerm 根 LICENSE 均为 MIT。
- 1.19/1.20 的锁文件包含 ArgumentParser 1.7.0、DocC plugin 1.4.6、DocC symbolkit 1.0.0；1.99.1 还包含 `h` 1.0.1 和 `swift-png` 4.5.1。已核对这些上游许可证为 Apache-2.0。
- 这些包主要用于工具、文档和预览可移植图形路径；正式 App 只应引入 `SwiftTerm` 产品，并在最终解析后审查实际运行时依赖，不把工具依赖自动打进 `.app`。

### 迁移成本

- 从 1.x 到 2.0 预览需要按上游迁移指南更新 API 调用和并发/投递语义，且需要重新审查历史、搜索、粘贴、PTY 和关闭流程。若 P2 已基于稳定 1.20 开发，再切换预览会有适配和回归成本。
- 若最终正式 v2 API 在 P2 前发布，仍需重新跑本 ADR 的来源、manifest、许可证和构建探针，不能用 `v1.99.1` 代替正式版本。

## 暂定决定

1. 不在 P0 将 SwiftTerm 固定到 `v1.19.0`，因为它只是架构要求的起始评估候选。
2. P2 原型同时以 `v1.20.0`（稳定 1.x）和 `v1.99.1`（2.0 前预览）建立最小可替换集成；两者均不是当前最终定稿。
3. 若正式 2.x 标签在原型前出现，将正式 2.x 加入同一矩阵。若没有正式 2.x，则默认优先选择稳定 `v1.20.0`，除非预览版本在相同测试下有明确且可接受的功能/资源收益。
4. 固定版本必须以最终 `Package.resolved` 的 tag/revision 为准；禁止锁定 `main` 或把预览写成稳定版本。

## 复验计划

P2 至少覆盖：

- AppKit/macOS 26 target 的 SwiftPM resolution 和 Release 编译；
- PTY 启停、窗口尺寸、输入/控制键、中文输入法、Unicode/Emoji、Bracketed Paste；
- 10,000 行默认历史、搜索、快速标签切换、持续输出背压；
- 连接/认证/关闭竞态、旧回调隔离、终端资源和子进程回收；
- Vim/Neovim、tmux、htop/btop、Docker 日志等交互显示；
- 选定版本的许可证 notices、最终传递依赖和 `.app` 中实际文件检查。

复验结果应写入 P2 任务报告并更新本 ADR 状态。