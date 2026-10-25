# OpenLXSSH — 工程状态

更新日期：2026-10-25（Asia/Shanghai）。

## 当前状态

- 状态：IN_PROGRESS，P0-01、P0-02、P0-03、P0-04、P0-05 已通过主管审查；阶段 0 调查门槛完成，进入阶段 1 直接 SSH 认证与信任原型。
- 本轮交付：完成签名身份、工具入口、helper 嵌入、Sandbox/Hardened Runtime、公证前置条件调查，并独立验证临时 arm64 ad hoc helper bundle 的签名布局与严格验证；未创建正式 App、未签名产品、未上传 Apple。
- 当前宿主为 macOS 15.8.1，低于目标 macOS 26；尚未执行产品功能测试、正式 Release 签名、公证或外部人工验收。

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

- 当前里程碑：阶段 0 环境、依赖与基础约束核对已完成；P0-01、P0-02、P0-03、P0-04、P0-05 均已通过主管独立审查，进入阶段 1，P1-01 待执行。
- Task ID：`P0-05`；执行者：`software-engineer`；状态：通过（主管已独立复核报告、工具入口、身份摘要、临时 helper fixture 和安全边界；阶段任务通过不代表整体 Goal 或产品 Release 完成）。
- 证据文件：`docs/reports/p0-05-signing-sandbox.md`。
- P0-05 主管复核：独立复跑 `codesign`/`security`/`xcodebuild`/`xcrun notarytool`/`stapler`/`spctl` 工具入口和身份数量摘要；临时 arm64 `Contents/Helpers` 与 `Contents/Library/LoginItems` bundle 按先 helper 后主 App 签名，`codesign --verify --deep --strict` 退出码 0，`spctl` 退出码 3、无 ticket 的 `stapler validate` 退出码 65，符合 ad hoc fixture 预期。报告未泄露完整 identity hash、Team ID、证书主体、Keychain 内容或凭据。
- P0-03 主管复核：独立执行 SwiftTerm `v1.19.0`/`v1.20.0`/`v1.99.1` 的 `dump-package` 和 `arm64-apple-macosx26.0` build（均退出码 0）；GRDB `v7.11.1` dump/build（均退出码 0）及 arm64 系统 SQLite C 探针（编译/运行均退出码 0，宿主 SQLite 3.43.2）；libssh2 1.11.1 发布包 SHA-256、Autotools configure/make、OpenSSL 静态链接和运行探针（均退出码 0，输出 1.11.1）；上游标签、许可证标记和 Keyboard-Interactive/SFTP API 文档抓取均成功。
- P0-03 限制：libssh2 CMake 配置因本机缺少 `cmake` 退出码 127，未安装补齐；mbedTLS/wolfSSL/Libgcrypt/LibreSSL 未完成组合构建；Homebrew OpenSSL 仅为临时探针输入，不是发行依赖；未创建 App/Xcode target、Package.resolved 或 `.app`，未进行 macOS 26 运行时、真实 SSH/SFTP/MFA、签名、公证或第二台 Mac 验收。
- 版本/许可决策：SwiftTerm 暂在 P2 比较稳定 `v1.20.0` 与 2.0 前预览 `v1.99.1`，不锁定 main；GRDB 暂用 `v7.11.1` 的 `GRDB` 产品和系统 SQLite；P3 初始候选为 libssh2 `1.11.1` + OpenSSL 3.x 静态构建，不依赖 Homebrew 运行时；详细影响与复验计划见两个 ADR。
- P0-02 提交事实：初始基线为 `4ccebe7d612afef1eaf20b890c2ce3df0b27b8d7`；R1 修正提交为 `0e136e23ab9394e6a4672c15876947c827dbcbfb`；主管审查状态提交为 `851b61283ff28c0f16926a09eed8cf043f0d5a46`；P0-03 依赖证据提交为 `68b9306`。
- P0-01 主管审查：已读取实际报告与状态改动，并独立复跑环境、OpenSSH 受控配置和辅助工具检查；结果与报告一致。
- 验收对应：P0-01/P0-02/P0-03/P0-04/P0-05 阶段证据已落盘并审查；AC-01～AC-38、性能目标、macOS 26 运行时和最终分发仍未验收。

## 下一项具体工作

执行 P1-01：在清楚标识的实验区域建立最小受控 OpenSSH/PTY 进程探针，验证参数数组（不经 Shell 拼接）、输入输出、窗口尺寸、取消、进程/PTY/描述符回收和关闭幂等；使用本机无网络或后续隔离服务条件，不能把本地进程冒烟当成真实 SSH 认证通过。

## 待外部条件

以下是实施时需要核实的条件，不代表当前已有产品失败：隔离服务环境方案、Developer ID 可用性、公证上传授权、用户实际企业认证验收、第二台 Mac 实测安排。先完成不依赖这些条件的必要工作。

- P0-02-R1（2026-10-25）：`software-engineer` 修正 `.gitignore` 的本地秘密目录覆盖，补全 P0-02 报告中的提交历史事实，并删除重复的过时下一项记录；主管已独立复核并在 `851b612` 状态提交中记录通过。

## 后续更新格式

每次重要审查后补充：Task ID、执行者、状态、修改文件、验收条目、实际命令/结果及证据路径、主管审查结论、本地提交、缺陷/阻塞、下一项任务。必要时记录长测进程与日志，避免重启重复任务；不写秘密。
