# OpenLXSSH — 工程状态

更新日期：2026-10-25（Asia/Shanghai）。

## 当前状态

- 状态：IN_PROGRESS，P0-01 已通过主管审查，正在执行 P0-02 本地 Git 基线初始化与工作区保护。
- 本轮交付：核对已有交接文档和工作区改动，建立范围明确的 `.gitignore`，仅在 OpenLXSSH 根目录初始化 Git，并形成可复核的本地基线提交。
- 当前工作区此前没有 `.git`、Xcode 项目、Swift Package 或产品代码；已有交接文档、P0-01 报告和本状态文件必须保留。`.DS_Store` 保留原文件并由忽略规则排除，不擅自删除。

## 已确认目标与范围

- OpenLXSSH V1.0：Apple Silicon/macOS 26 原生 SSH/SFTP，供两位用户独立使用。
- 四类直接认证：私钥、密码、私钥＋OTP、密码＋OTP；支持适用的多轮挑战和手机审批。
- 用户在终端中手动嵌套 SSH；App 只管理最外层连接与直接 SFTP。
- 自动 ProxyJump、多级跳板管理、经跳板 SFTP、本地/远程端口转发不属于 V1.0。
- 其余已确认需求保留，正式名称统一 OpenLXSSH。

## 执行授权与分工

- 一个 Goal 连续执行到可安装版本，主管逐阶段验收，通过后自动继续。
- 主会话为主管；主要编码由 `software-engineer` 完成，主管独立审查并运行关键验证。
- 满足功能、安全和许可证要求时，可记录 ADR 后自主更换核心候选实现。
- 正式开发启动后允许初始化本地 Git，并由主管在里程碑通过后本地提交；没有远程推送授权。
- 新增 Linux 虚拟机/容器环境须先调查现有工具，提出具体方案由用户确认。
- 已有开发者账号；具体签名条件、公证上传授权与双机操作尚待实施时核实。

## 当前任务与证据

- 当前里程碑：阶段 0 环境、依赖与基础约束核对进行中；P0-01 已通过主管独立审查，P0-02 已完成本地 Git 基线交付。
- Task ID：`P0-02`；执行者：`software-engineer`；状态：待主管独立审查（子任务完成不代表整体 Goal 完成）。
- 证据报告：`docs/reports/p0-01-environment.md`（P0-01）；`docs/reports/p0-02-git-baseline.md`（本任务）。
- P0-02 范围：仅在 `/Users/liuwenshuo/Desktop/OpenLXSSH` 根目录初始化 Git；新增根目录 `.gitignore`；保留并纳入基线的交接文档、P0-01 报告和状态文件；排除 `.DS_Store`、构建产物、个人状态、测试输出和本地秘密/凭据文件。
- P0-02 提交：见 `docs/reports/p0-02-git-baseline.md` 中的实际 commit hash、文件清单、命令结果和无 remote 记录。
- P0-01 主管审查：已读取实际报告与状态改动，并独立复跑 `sw_vers`、架构、Xcode/SDK、Swift/Clang、OpenSSH 路径/版本、受控 `ssh -G` 配置展开和辅助工具检查；结果与报告一致。未发现无关文件或敏感信息泄漏。
- 核心事实：Apple Silicon `arm64`；实际宿主为 macOS 15.8.1 (Build 24H32)，低于需求的 macOS 26；Xcode 26.3 (17C529) 与 macOS 26.2 SDK (SDK build 25C58) 可用；Swift 6.2.4、Apple Clang 17.0.0、系统 OpenSSH 9.9p2 / LibreSSL 3.3.6、`xcbeautify` 3.2.1 可用。
- 构建证据：临时 Swift 源文件以 `arm64-apple-macosx26.0` 目标真实编译/运行成功，Mach-O `minos 26.0`、SDK 26.2；未创建 App 或执行项目构建。
- OpenSSH 边界：仅完成 `/usr/bin/ssh`、`/usr/bin/sftp` 路径/版本、签名和 `ssh -G` 受控配置展开；未连接服务器、未执行认证或 SFTP 传输。
- 工作区状态：无 Xcode 项目、Swift Package、Swift 源文件或 `.git`；本任务未初始化 Git。
- 验收对应：P0-01 五项验收标准均已在报告中逐条对应；macOS 15 与目标 macOS 26 差异、无项目及未联网限制已明确记录。

## 下一项具体工作

P0-02 完成本地 Git 基线后，由主管独立复核提交内容和状态，再继续 P0-03 依赖核对。P0-02 不创建 App、不核对依赖、不执行后续阶段工作。

1. `AGENTS.md`：角色与持续协作规则。
2. `docs/requirements.md`：已确认需求及排除项。
3. `docs/architecture.md`：技术方向、资源边界与安全约束。
4. `docs/execution-plan.md`：任务 ID、阶段门槛、授权边界与交付条件。
5. `docs/acceptance.md`：验收总表。
6. `ZCODE_SETUP.md`：配置与正式启动指令。

## 下一项具体工作

接到正式 Goal 后，核对工作区和已有改动，更新状态为执行中，调查环境并派发 P0-01。同步开展不冲突的基础调查；不要重新确认已确定的产品需求，不越过新增测试环境和外部上传授权边界。

## 待外部条件

以下是实施时需要核实的条件，不代表当前已有产品失败：隔离服务环境方案、Developer ID 可用性、公证上传授权、用户实际企业认证验收、第二台 Mac 实测安排。先完成不依赖这些条件的必要工作。

## 后续更新格式

每次重要审查后补充：Task ID、执行者、状态、修改文件、验收条目、实际命令/结果及证据路径、主管审查结论、本地提交、缺陷/阻塞、下一项任务。必要时记录长测进程与日志，避免重启重复任务；不写秘密。
