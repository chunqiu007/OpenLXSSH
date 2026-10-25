# OpenLXSSH — 工程状态

更新日期：2026-10-25（Asia/Shanghai）。

## 当前目标与范围

- 状态：IN_PROGRESS。同一个 Goal 持续推进至可安装 V1.0 Release 并完成必要验收；目前没有产品完成声明。
- Apple Silicon/macOS 26 原生 SSH/SFTP。私钥、密码、私钥＋OTP、密码＋OTP、多轮挑战/审批；终端内手动嵌套 SSH；SFTP 仅覆盖直接可达目标。
- 不做自动 ProxyJump、多级跳板、经跳板图形化 SFTP、端口转发、自动重连或会话恢复。其余完整范围见 `docs/requirements.md`。
- 主要实现交给 software-engineer，主管独立审查和复跑关键验证；本地提交已授权，不设置 remote、不 push。
- 新增 VM/容器须先获用户确认；Apple 登录/证书安全操作由用户完成，公证上传须针对具体产物确认；不接触公司秘密或生产服务器。

## 当前里程碑

阶段 0 调查门槛完成；阶段 1 认证与信任原型进行中。P1-01 仅本地无网络进程/PTY 范围通过，真实服务阶段门槛未通过。

| Task | 执行者 | 主管结论 | 证据 |
| --- | --- | --- | --- |
| P0-01 | software-engineer | 调查通过 | `docs/reports/p0-01-environment.md` |
| P0-02 / R1 | software-engineer | 基线与边界通过 | `docs/reports/p0-02-git-baseline.md` |
| P0-03 | software-engineer | 来源/许可/构建路径调查通过 | `docs/dependencies.md`、两个 P0-03 ADR、`docs/reports/p0-03-dependencies.md` |
| P0-04 | software-engineer | 环境调查通过，新增 VM 未授权 | `docs/reports/p0-04-test-environment.md` |
| P0-05 | software-engineer | 签名/辅助程序路径调查通过，产品签名未执行 | `docs/reports/p0-05-signing-sandbox.md` |
| P1-01 | software-engineer | 本地无网络 PTY 范围通过；报告已补齐 | `Experiments/P1-01-PTYProbe/`、`docs/reports/p1-01-pty.md` |
| P1-02 | software-engineer | 本地信任/配置范围通过，真实握手未验证 | `Experiments/P1-02-HostTrustProbe/`、`docs/adr/p1-02-host-trust.md`、`docs/reports/p1-02-host-trust.md` |
| P1-03 | software-engineer | 独立实验实现中；真实 Keychain 当前返回 -34018，未通过 CRUD | `Experiments/P1-03-CredentialKeyProbe/` |

## P1-01 审查与验证

- 实际修改：独立 SwiftPM 实验包，Swift actor 资源所有者、C Darwin PTY/execve glue、固定本地 fixture、CLI、14 项 XCTest；无外部依赖。实验最低 macOS 15 仅用于当前宿主，不改变产品目标。
- 主管已阅读全部 8 个实现/测试/manifest 文件；参数直接经 argv 传入 execve，不经 Shell；I/O 有界，EOF 尾部排空，TERM→KILL、waitpid、FD 关闭和迟到调用隔离可审查。
- 主管独立运行 `swift test --package-path Experiments/P1-01-PTYProbe -Xswiftc -warnings-as-errors -Xcc -Wall -Xcc -Wextra -Xcc -Werror`：退出 0，14 项、0 失败；Release CLI 退出 0，验证字节顺序、控制终端、尺寸/SIGWINCH、无网络 ssh -G、幂等取消。
- 独立 Release `--snapshot-hold` + ps/lsof：父进程仍存活时 child 已消失、master FD 无输出行、tasks=0，CLI 最终退出 0。
- 工程师 Debug/Release/TSan/重复测试日志位于 `Experiments/P1-01-PTYProbe/.build/verification/`；主管读取资源、TSan 和 target26 日志。TSan 14 项通过；minos 26.0/SDK 26.2 仅交叉编译证据。
- 限制：只回收直接 child，后代进程树未覆盖；有限输出超限终止不是正式流式背压；真实 SSH/认证/MFA、Keychain、Askpass、SwiftTerm、App/Sandbox、200 次真实 SSH/24 小时均未验证。

## P1-02 本地原型证据（主管审查通过）

- 主管已读取全部库/CLI/测试与 manifest，独立 `swift test -Xswiftc -warnings-as-errors` 22项0失败、Release CLI 退出0；读取最终TSan日志22项0失败。报告 `docs/reports/p1-02-host-trust.md` 已落盘。

- 新增独立无外部依赖 SwiftPM 库/CLI/22 项 XCTest：类型化地址/端口/用户与 prepared `-F` 配置，禁用代理、转发、复用和本地命令；单一 App 专属 known_hosts、显式首次/新算法确认、变化拒绝与指纹核对替换。
- 文件锁、0700/0600、openat/O_NOFOLLOW、原子 rename/fsync、代次与内容摘要拒绝陈旧确认；覆盖损坏/超限、symlink/hardlink/FIFO、稳定锁/目录替换、8 store 与 4 独立进程竞争。细节见 `docs/adr/p1-02-host-trust.md`。
- 工程师实际执行 Debug/Release `swift build`/`swift test -Xswiftc -warnings-as-errors`，各 22 项、0 失败；`swift test --sanitize=thread` 22 项通过；Release CLI `--self-test` 退出 0。本地 `ssh -G/-vvG` 和 `ssh-keygen -F/-l` 对照在测试内执行；日志 `Experiments/P1-02-HostTrustProbe/.build/verification/`。
- 宿主仍是 macOS 15.8.1，实验 min macOS 15 不改变产品 26 目标。未启动 sshd、未连接 SSH 服务，真实握手公钥绑定、SSH/SFTP 集成、认证、macOS 26 runtime 与掉电故障未验证；AC-04/AC-12/AC-25 不因此标产品通过。

## 已核实的环境与依赖

- Apple Silicon arm64、8 CPU；宿主 macOS 15.8.1/24H32，不是 macOS 26。Xcode 26.3、macOS 26.2 SDK、Swift 6.2.4、系统 OpenSSH 9.9p2、xctest/xctrace 可用。
- SwiftTerm 暂在 P2 比较稳定 v1.20.0 与 v1.99.1（2.0 前预览）；GRDB 暂选 v7.11.1/系统 SQLite；P3 初始候选 libssh2 1.11.1 + OpenSSL 静态库。主管独立重建探针通过，详见依赖清单和 ADR。CMake 缺失；替代加密后端/最终 App 打包未验证；Homebrew 只用于临时探针。
- 尚无 Linux guest/隔离 SSH 服务；未启动本机 sshd。推荐 UTM + 官方 Ubuntu ARM64、2 vCPU/4 GiB RAM/20 GiB 动态磁盘起步，NAT/private 网络、一次性测试账户，不暴露 LAN；方案待用户确认。
- 有 1 个 Apple Development 身份；Developer ID Application/Installer 0。正式 Team/Bundle ID、公证凭据、上传授权和 macOS 26 双机运行条件尚未准备。

## 提交与验收

- 基线 `4ccebe7`；P0-02-R1 `0e136e2`；P0-03 `68b9306`/记录修正 `8575f4a`；P0-04 `65e2edd`；P0-05 `927a84e`；P1-01 `e5e5b1a`（development/p1-prototypes）。P1-02 待本轮审查后提交，P1-03 并行目录不混入提交。
- `docs/acceptance.md` 保留全部产品 AC；P0 调查和 P1-01 本地探针不将产品 AC 标为通过。
- 尚无正式 App/Xcode target、安装包、产品签名、公证、24 小时长测或外部人工验收。

## 下一项具体工作

完成 P1-03 本地私钥/引用测试并独立审查；真实 Keychain 的 -34018 需在后续有明确签名/entitlements 的最小 App 中复验，不降级或跳过伪造通过。继续 P1-04 控制面桥接，安全约束见 `docs/adr/p1-04-askpass-authentication-context.md`：Askpass无可靠挑战类型，未知提示人工输入，自动投递前提未证实前禁止启用。真实 SSH/SFTP 握手与认证仍待隔离服务。

## 待外部条件

- 新增隔离 Linux VM/容器方案确认；确认前不安装或启动。
- macOS 26 实机运行、Developer ID 和用户 Apple 登录条件；公证上传仅在具体产物准备后集中请求。
- 第二台 Apple Silicon/macOS 26 安装与公司允许的真实认证/审批/嵌套 SSH 人工验收。

以上缺口不阻止其余本地可恢复实现；缺少必要验收时不宣布 Goal 完成。
