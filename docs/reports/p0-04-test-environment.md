# P0-04 隔离测试环境调查报告

- Task ID：`P0-04`
- 工作区：`/Users/liuwenshuo/Desktop/OpenLXSSH`
- 调查时间：2026-10-25 18:02（Asia/Shanghai）
- 执行者：`software-engineer`
- 报告状态：范围内调查完成，并通过主管独立审查；不代表 OpenLXSSH 产品功能或阶段 0 整体通过。
- 调查边界：仅执行本机只读探测和 `/tmp` 下可清理的无网络冒烟检查；没有创建产品代码、Xcode 项目、测试 target、Linux 虚拟机或容器，没有安装、启动或配置 Docker/VM/`sshd`，没有连接远程服务器，没有读取 SSH 配置内容、私钥或 Keychain。

## 1. 结论摘要

1. 宿主是 Apple Silicon `arm64`、macOS 15.8.1（Build 24H32）、8 个逻辑 CPU。Xcode 26.3 和 macOS 26.2 SDK 可用，能够为后续 macOS 26 目标构建，但当前宿主不是 macOS 26，不能替代 macOS 26 运行时验收。
2. 本机已经具备 macOS 原生测试所需的主要基础：临时目录、XCTest 入口、`xctrace`、`script`/`tty`/`pgrep`、Swift/Clang、系统 OpenSSH/SFTP 客户端，以及 SwiftLint/xcbeautify。当前没有 OpenLXSSH 项目或 XCTest bundle，因此本轮只确认工具入口和能力，不运行产品测试。
3. `/usr/sbin/sshd` 二进制存在，但没有发现运行中的 `sshd`；本机没有 Docker、Podman、Colima、Lima、nerdctl、OrbStack、UTM、QEMU aarch64、Multipass 或 Vagrant 命令，也没有对应主要应用。Virtualization.framework 和 Hypervisor.framework 只说明系统 API 存在，不等于已创建可用 Linux 服务环境。
4. 若要进行真实直接 SSH/SFTP、主机密钥、PTY、密码/私钥/MFA 和 Linux 行为测试，推荐用户确认后新增一个 Apple Silicon Linux ARM64 虚拟机：优先 UTM 的 Apple Virtualization 后端配合官方 Ubuntu Server ARM64 镜像。容器可作为快速 OpenSSH 矩阵的备选，但不应替代 Linux VM 的内核、服务生命周期和发行版差异验证。
5. 在用户确认新增环境前，可以继续推进 P1/P2 中不依赖真实 Linux 服务的 PTY 生命周期、认证/挑战状态机、凭据边界、终端渲染与输入、资源释放和本地 XCTest/xctrace 自动化；这些工作不能被记录为真实 SSH/SFTP 互通通过。

## 2. 安全边界与工作区影响

本轮未进行以下操作：

- 未安装或启动 Docker、Podman、Colima、Lima、nerdctl、OrbStack、UTM、QEMU、Linux VM、容器、`sshd` 或其他远程服务。
- 未设置网络、端口转发、防火墙或系统 SSH 服务；未连接任何服务器。
- 未读取 `/etc/ssh/ssh_config`、`/etc/ssh/sshd_config` 或 `/etc/ssh/ssh_config.d` 的内容，仅检查路径是否存在。
- 未读取私钥、私钥口令、Keychain、序列号、本机 IP 或其他秘密；报告不保存这些信息。
- 仅在 `/tmp` 创建并删除一次性目录和短暂探针输出；未向工作区写入构建产物。

初次执行四个探测循环时，脚本使用了 zsh 只读变量名 `status`，导致脚本封装层退出码为 `1`；没有执行安装、服务或写入操作。改用 `rc_value` 后重新执行，逐项结果如下；该脚本错误不改变工具探测结论。

## 3. 宿主与基础工具核对

### 3.1 主机事实

| 只读命令 | 退出码 | 结果 |
| --- | ---: | --- |
| `sw_vers` | 0 | macOS 15.8.1，Build 24H32 |
| `uname -srm` | 0 | Darwin 24.6.0，`arm64` |
| `uname -m` | 0 | `arm64` |
| `sysctl -n hw.machine` | 0 | `arm64` |
| `sysctl -n hw.optional.arm64` | 0 | `1` |
| `sysctl -n hw.ncpu` | 0 | `8` |

当前目标最低系统为 macOS 26；本机版本低于目标。后续在本机生成 macOS 26 deployment target 产物时，仍须在 macOS 26 主机补做启动、权限、UI 和 Release 运行验证。

### 3.2 Xcode、SDK、编译和辅助工具

| 只读命令 | 退出码 | 结果 |
| --- | ---: | --- |
| `xcode-select -p` | 0 | `/Applications/Xcode.app/Contents/Developer` |
| `xcodebuild -version` | 0 | Xcode 26.3，Build 17C529 |
| `xcrun --sdk macosx --show-sdk-path` | 0 | macOS 26.2 SDK 路径 |
| `xcrun --sdk macosx --show-sdk-version` | 0 | `26.2` |
| `xcrun --find xctest` | 0 | `/Applications/Xcode.app/Contents/Developer/usr/bin/xctest` |
| `xcrun --find xctrace` | 0 | `/Applications/Xcode.app/Contents/Developer/usr/bin/xctrace` |
| `xctrace version` | 0 | `xctrace version 26.0 (17C529)` |
| `swift --version` | 0 | Apple Swift 6.2.4，目标 `arm64-apple-macosx15.0` |
| `clang --version` | 0 | Apple Clang 17.0.0 |
| `command -v script` | 0 | `/usr/bin/script` |
| `command -v tty` | 0 | `/usr/bin/tty` |
| `command -v pgrep` | 0 | `/usr/bin/pgrep` |
| `command -v swiftlint`；`swiftlint version` | 0；0 | `/opt/homebrew/bin/swiftlint`，0.65.1 |
| `command -v xcbeautify`；`xcbeautify --version` | 0；0 | `/opt/homebrew/bin/xcbeautify`，3.2.1 |
| `brew --version` | 0 | Homebrew 6.0.22 |
| `make --version` | 0 | GNU Make 3.81 |

以下工具路径探测均返回 `1`，本轮没有安装：`cmake`、`ninja`、`pkg-config`、`swift-format`。这些缺口不阻止本轮隔离环境调查，但依赖后续 CMake 或格式化流程时需要单独处理。

## 4. SSH、SFTP、服务和配置路径

| 只读命令 | 退出码 | 结果 |
| --- | ---: | --- |
| `command -v ssh` | 0 | `/usr/bin/ssh` |
| `ssh -V` | 0 | OpenSSH 9.9p2，LibreSSL 3.3.6 |
| `command -v sftp` | 0 | `/usr/bin/sftp` |
| `sftp -V` | 1 | 系统 `sftp` 不支持该版本选项；不能据此伪造独立版本号 |
| `command -v sshd` | 0 | `/usr/sbin/sshd` 二进制存在 |
| `command -v ssh-agent` | 0 | `/usr/bin/ssh-agent` |
| `pgrep -x sshd >/dev/null 2>&1` | 1 | 未发现运行中的 `sshd` |
| `pgrep -x ssh-agent >/dev/null 2>&1` | 0 | 发现本机代理进程；不代表存在测试 SSH 服务 |
| `launchctl list 2>/dev/null \| grep -F -- 'com.openssh.ssh-agent' >/dev/null` | 0 | 发现 `com.openssh.ssh-agent` 服务标识 |
| `launchctl print system/com.openssh.ssh-agent >/dev/null 2>&1` | 113 | 该 system domain 查询未返回；不用于推断用户代理状态 |
| `test -e /etc/ssh/ssh_config` | 0 | 路径存在，未读取内容 |
| `test -e /etc/ssh/sshd_config` | 0 | 路径存在，未读取内容 |
| `test -e /etc/ssh/ssh_config.d` | 0 | 路径存在，未读取内容 |

结论是：系统客户端和 `sshd` 可执行文件可以作为后续本地测试工具输入，但当前没有可供 App 真实连接的隔离 SSH/SFTP 服务。不能把系统 OpenSSH 客户端版本或 `sshd` 文件存在误记为 SSH/SFTP 功能已通过。

## 5. macOS 原生隔离、临时目录、XCTest、xctrace 与 PTY

### 5.1 临时目录与沙箱入口

| 只读/临时命令 | 退出码 | 结果 |
| --- | ---: | --- |
| `command -v mktemp` | 0 | `/usr/bin/mktemp` |
| `mktemp -d /tmp/openlxssh-p0-04.XXXXXX` | 0 | 创建一次性目录 |
| `stat -f '%Mp%Lp' <临时目录>` | 0 | 目录权限为 `0700` |
| `rmdir <临时目录>` | 0 | 探针目录清理成功 |
| `command -v sandbox-exec` | 0 | `/usr/bin/sandbox-exec` 存在；该命令属于旧式入口，不作产品 Sandbox 方案决定 |
| `command -v sandbox_compile` | 1 | 未找到独立 `sandbox_compile` 命令 |
| `sandbox-exec -p '(version 1) (allow default) (deny network*)' /bin/sh -c 'test -d /tmp'` | 0 | 无网络 profile 的本地沙箱冒烟通过；未用于产品代码 |
| `command -v diskutil` | 0 | `/usr/sbin/diskutil` 可定位；本轮未修改磁盘或卷 |

临时目录适合存放测试生成的 known-hosts、一次性密钥、PTY 日志和构建中间物，但测试必须显式设置 `0700`/最小权限、结束时清理，并且不能将临时目录清理误认为 SSD 上的取证级安全擦除。

### 5.2 XCTest 和 xctrace

| 命令 | 退出码 | 结果 |
| --- | ---: | --- |
| `command -v xctest` | 1 | `xctest` 不在当前 PATH；不能据此判断 Xcode 工具缺失 |
| `xcrun --find xctest` | 0 | XCTest 可执行入口可定位：`/Applications/Xcode.app/Contents/Developer/usr/bin/xctest` |
| `xcrun xctest`（无参数） | 1 | 已定位并启动 XCTest 入口，但未传入 XCTest bundle；该返回不表示入口缺失 |
| `xctrace version` | 0 | xctrace 26.0 可用 |
| `xctrace list templates` | 0 | 可列出采样模板；本轮未启动采样进程 |

当前没有 `.xctest` bundle、Xcode project 或产品 target，因此没有执行 XCTest；未来建立项目后可使用 XCTest 覆盖状态机、参数边界、临时文件和生命周期，再用 `xctrace` 覆盖 Allocations、Leaks、Time Profiler 等实际可用模板。

### 5.3 PTY 工具

| 命令 | 退出码 | 结果 |
| --- | ---: | --- |
| `command -v script`；`command -v tty`；`command -v pgrep` | 0；0；0 | 三个工具均可定位 |
| `script -q <临时日志> /bin/sh -c 'test -t 0 && test -t 1 && test -t 2'` | 0 | `script` 能为子进程提供 PTY，临时日志随后删除 |
| `script -q /dev/null /bin/sh -c 'test -t 0 && test -t 1 && test -t 2'` | 0 | PTY 的 stdin/stdout/stderr 检查通过 |
| `tty </dev/null` | 1 | 脱离终端时按预期报告 stdin 不是 tty |

这足以先验证本地进程的 PTY 创建、输入/输出、取消和回收骨架；不等于 OpenSSH 远端 PTY、终端尺寸协商或嵌套 SSH 已通过。

## 6. 虚拟化、容器与 Linux 环境缺口

### 6.1 已有系统能力

| 检查 | 退出码 | 结果 |
| --- | ---: | --- |
| `test -d /System/Library/Frameworks/Virtualization.framework` | 0 | 系统 Virtualization.framework 存在 |
| `test -d /System/Library/Frameworks/Hypervisor.framework` | 0 | 系统 Hypervisor.framework 存在 |
| `test -d <macOS SDK>/System/Library/Frameworks/Virtualization.framework` | 0 | SDK 中有对应 framework |
| `test -d <macOS SDK>/System/Library/Frameworks/Hypervisor.framework` | 0 | SDK 中有对应 framework |

这些是可供未来工具使用的系统框架，不是已经配置好的 Linux guest、容器运行时或 SSH 服务。

### 6.2 命令缺口

以下逐项 `command -v <tool> >/dev/null 2>&1` 的退出码均为 `1`：

- `docker`
- `podman`
- `colima`
- `limactl`、`lima`
- `nerdctl`
- `orbctl`
- `qemu-system-aarch64`、`qemu-system-arm64`
- `multipass`
- `vagrant`

### 6.3 应用缺口

以下逐项 `test -d <path>` 的退出码均为 `1`，本轮没有启动或安装：

- `/Applications/Docker.app`
- `/Applications/Podman Desktop.app`
- `/Applications/OrbStack.app`
- `/Applications/UTM.app`

### 6.4 服务状态

- `pgrep -x sshd` 返回 `1`，没有运行中的 `sshd`。
- 只发现系统代理标识和代理进程；没有把代理误认为隔离服务。
- 没有通过系统 `sshd`、本机配置或真实服务器补齐 Linux 服务测试。

## 7. 新增 Linux VM/容器的待确认方案

本节只是提交给用户确认的具体方案；本轮不安装、不创建、不启动。

### 7.1 推荐方案：Apple Silicon Ubuntu Server ARM64 VM

**推荐组合**：UTM（优先使用 Apple Virtualization 后端）+ 官方 Ubuntu Server ARM64 镜像 + VM 内临时 OpenSSH/SFTP 服务。

公开来源：

- Apple Virtualization framework：<https://developer.apple.com/documentation/virtualization>
- UTM 项目主页：<https://mac.getutm.app/>
- UTM 文档：<https://docs.getutm.app/>
- Ubuntu Server ARM64 下载入口：<https://ubuntu.com/download/server/arm>

推荐理由：

- ARM64 guest 与宿主 Apple Silicon 架构一致，避免 x86 转译对 PTY、服务启动和性能结果的干扰。
- VM 有独立 Linux kernel、用户/权限模型、OpenSSH 服务生命周期和文件系统，较容器更适合验证直接 SSH/SFTP、主机密钥、权限错误、断线和资源回收。
- Apple Virtualization.framework 已在系统和 SDK 中存在；但 UTM、Ubuntu 镜像和 VM 本身当前均未安装或创建，框架存在不等于方案已实施。

建议资源（首次 P1/P2 隔离服务）：

- 2 vCPU、4 GiB RAM、20 GiB 动态磁盘作为最小起点。
- 需要并发连接、输出压力或文件传输时提高到 4 vCPU、8 GiB RAM、40 GiB 以上磁盘；宿主只有 8 个逻辑 CPU，不建议一开始把全部 CPU 分配给 guest。
- 大文件/多文件基准（AC-31）需另行确认宿主可用磁盘和内存；本建议不把小样本冒充 2 GiB/1,000 文件完整验收。

镜像与供应链：

1. 从 Ubuntu 官方 ARM64 下载入口取得镜像，并按同站官方 checksum 校验；不要使用未知第三方镜像。
2. 在 VM 内只安装测试所需 OpenSSH server、SFTP 组件和测试工具；版本、镜像摘要、安装时间和配置范围写入后续测试报告。
3. 不复用生产用户、公司账户、真实私钥、真实 OTP 或真实手机审批；每轮使用一次性测试账户和一次性密钥，测试后销毁。

网络隔离建议：

- 默认使用 VM NAT 或 host-only/private 网络，不使用 bridged networking，不让 guest 直接暴露到局域网或公网。
- 若必须从宿主 App 访问 guest，优先使用仅绑定本机回环地址的临时端口映射或私有 host/guest 通道；不开放 LAN 入站端口，不修改宿主防火墙。
- 安装更新后可断开 guest 外网；测试只保留宿主与 guest 的必要私有通道。任何需要外网的包安装先完成并记录，再关闭不必要出口。
- 测试报告不得记录 guest IP、主机密钥全文、密码或私钥；只记录脱敏的连接方式、端口策略和校验摘要。

一次性凭据与生命周期：

- 创建专用测试用户、随机临时密码/一次性 SSH key、独立 `known_hosts` 和测试数据目录；文件目录使用 `0700`，私钥最小权限，禁止写入源码、Git、普通日志或截图。
- MFA/手机审批只在合法的隔离测试服务或受控模拟器中验证交互状态机；不把真实企业 MFA 秘密、真实推送或公司账户放入 VM。
- 测试结束先停止服务和关机，再删除 VM bundle、磁盘、快照、cloud-init/安装介质、临时 key、known-hosts 和测试数据。APFS/SSD 的普通删除不保证取证级擦除，因此方案本身应避免放入任何生产秘密。
- 销毁后重新检查工作区、临时目录和 VM 管理器列表，不保留后台进程、端口映射或常驻服务。

### 7.2 备选方案：Apple Silicon 容器运行时

公开来源：

- Docker Desktop for Mac（Apple silicon 安装说明）：<https://docs.docker.com/desktop/setup/install/mac-install/>
- Lima 文档：<https://lima-vm.io/docs/>

可选路径是 Docker Desktop 或 Lima/nerdctl，在 Linux VM 中运行一次性 OpenSSH server 容器。建议起步资源为 2 vCPU、4 GiB RAM、20 GiB 磁盘上限，使用隔离 bridge/NAT、无公开端口、临时 volume 和一次性账户。

限制：容器共享 guest kernel，镜像层、PID/权限和服务生命周期与完整 Linux VM 不同；不能用容器结果替代 VM 对 Linux kernel、发行版服务启动、文件系统权限和 VM 级网络隔离的验证。若只做快速协议矩阵，容器可作为补充，不是本项目唯一真实服务环境。

### 7.3 当前不采用的路径

- 不把 macOS 本机 `sshd` 当作 Linux 服务替代；它可在未来经明确授权用于本地进程/客户端冒烟，但本轮不启动。
- 不安装多个运行时并行比较；先由用户确认一个主方案，完成可复现的最小 VM，再根据测试缺口决定是否增加容器矩阵。
- 不连接公司或生产服务器填补隔离环境缺口。

## 8. 未新增环境时可先推进的 P1/P2 工作

下列工作可在 macOS 原生临时目录、合成输入和本地 PTY 中推进；每项完成后都要注明是模拟/本地验证，不是 Linux SSH/SFTP 互通：

### P1 可推进项

- **P1-01**：本地 PTY/子进程启动、输入输出、窗口尺寸变化、取消、关闭和描述符/进程回收；使用 `script` 及无网络的受控子进程。
- **P1-02**：App 专属配置、known-hosts 数据模型、首次信任/匹配/变化拒绝状态机和参数边界；使用合成主机密钥材料，不读取系统 SSH 配置。
- **P1-03**：一次性测试私钥的导入/解析、权限和引用生命周期，以及 Keychain 访问错误的 UI/状态处理；不使用真实用户私钥或真实公司账户。
- **P1-04**：askpass/认证交互桥接的会话归属、并发隔离、取消、超时和清理；用本地 fake helper 或合成挑战驱动。
- **P1-05**：Keyboard-Interactive 多轮挑战、未知提示人工输入、拒绝、取消和有界重试的状态机；不能把模拟挑战记为真实 MFA 兼容。
- **P1-06**：最小 `.app`/辅助程序路径和本地启动、退出清理探针；不需要远端服务即可验证 bundle 内路径解析。

### P2 可推进项

- **P2-01**：在正式项目建立后比较并集成候选 SwiftTerm 版本，运行本地 XCTest 和构建验证。
- **P2-02**：用本地 PTY 验证控制键、Unicode/中文/Emoji、输入法组合、复制粘贴、Bracketed Paste、历史搜索和主题字号；不宣称远端终端程序兼容已通过。
- **P2-03**：在合法本机安装的 TUI 或合成输出上做渲染/输出压力探针；缺少 Vim/tmux/htop/btop 或指定 AI 工具时如实记录，不伪造覆盖。
- **P2-04**：只设计并测试“内层 SSH 由用户手动输入”的边界和禁止 App 自动投递凭据的 UI/状态；真实嵌套 SSH 需隔离服务。
- **P2-05**：本地会话创建/关闭循环、PTY/FD/任务计数和 `xctrace` 采样基线；没有远端连接时只能作为本地资源基线。

主机管理、凭据 UI、数据库 schema、迁移和普通 SwiftUI/AppKit 骨架等不依赖 Linux 服务的工作也可按执行计划推进，但不能以模拟数据替代后续真实 SSH/SFTP 验收。

## 9. P0-04 的明确边界

P0-04 仅表示：

- 已调查当前宿主、工具链、原生临时目录、XCTest/xctrace、PTY 和虚拟化/容器缺口。
- 已区分可立即使用的 macOS 原生能力与必须新增/用户确认的 Linux 服务环境。
- 已提出带公开来源、Apple Silicon 架构、资源、网络、一次性凭据和销毁策略的 VM/容器方案。

P0-04 **不等于**以下任何验收已通过：

- 直接 SSH 或 SFTP 连接、主机密钥首次信任/变化拒绝。
- 私钥、密码、OTP、Keyboard-Interactive、多轮 MFA 或手机审批真实互通。
- 远端 PTY、终端兼容、手动嵌套 SSH 或 Linux 文件权限行为。
- SFTP 浏览、上传/下载、冲突、安全提交、取消、断线和大文件传输。
- 200 次连接循环、5 会话 24 小时稳定性、输出压力、2 GiB/1,000 文件基准。
- macOS 26 运行时、签名、公证、第二台 Mac 或企业实际环境验收。

## 10. 验收对应关系

| P0-04 验收项 | 结果 | 证据 |
| --- | --- | --- |
| 报告落盘且仅调查隔离环境 | 满足 | 本文件；未创建产品代码或新环境 |
| 实际命令和退出码可复核 | 满足 | 第 3～6 节命令表；包含工具存在/缺失、服务状态、临时目录、XCTest、xctrace 和 PTY 结果 |
| 已有能力与缺口清晰 | 满足 | 第 3～6 节；明确 macOS 原生能力、系统 `sshd` 未运行及 VM/容器缺口 |
| macOS 原生隔离、临时目录、XCTest、xctrace、PTY 能力已说明 | 满足 | 第 5 节；明确无项目/XCTest bundle 的限制 |
| 新增 Linux VM/容器方案具体且待确认 | 满足 | 第 7 节；推荐 UTM + Ubuntu ARM64，列出公开来源、资源、网络、凭据和销毁方式 |
| 未新增环境时可推进工作已说明 | 满足 | 第 8 节；分别列出 P1/P2 的本地/模拟边界 |
| 明确 P0-04 不等于 SSH/SFTP 功能验收 | 满足 | 第 9 节；列出未通过的真实功能和长期验收 |
| 不泄露本机 IP、序列号、凭据或完整敏感配置 | 满足 | 全文仅记录版本、路径、退出码和摘要；SSH 配置仅检查存在性 |

## 11. 限制、待用户确认与下一步

- 需要用户先确认一个新增环境方案及安装授权；在确认前不安装 UTM、Docker Desktop、Lima 或其他运行时。
- 宿主内存、可用磁盘和用户是否允许下载 Ubuntu 镜像尚未确认，因此资源建议是起始值，不是已分配资源。
- 当前没有 Linux guest、隔离 OpenSSH server 或真实一次性测试凭据；所有 SSH/SFTP/MFA 互通项仍未验证。
- 下一步建议：主管审查本报告和状态更新；若用户确认，按 7.1 建立最小 ARM64 Ubuntu VM，记录镜像校验和、资源/网络边界及销毁证据，然后再开始依赖真实服务的 P1 任务。

本报告的环境调查完成不改变整体 Goal 状态，也不将任何产品验收条目标记为通过。
