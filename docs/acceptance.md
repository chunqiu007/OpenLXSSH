# OpenLXSSH V1.0 — 验收总表

当前状态：正式App/五生产包已有本地实现与分项证据，整体验收未通过。已授权Docker隔离环境上，host15独立production consumer已完成真实私钥SSH、密码/私钥SFTP微型往返及两typed认证负例；MINA真实单消息双提示、零提示接受/拒绝、8s审批接受/拒绝及等待取消已有核心证据；远端完整2GiB/1000文件往返与25%取消已主管复核。详见 `docs/reports/real-ssh-sftp-smoke.md`、`docs/reports/real-mina-kbi.md` 和 `docs/reports/real-sftp-file-acceptance.md`。正式macOS26编译与宿主15测试分开，仍无目标系统运行、完整四认证/网络文件矩阵、24h或双机验收。

当前检查点：P6B1/R1已有主管103tests/原生与签名回归；本轮五view有限渲染压力独立通过并提交ba4a2ec，见 `docs/reports/p7-app-output-stress.md`。正式Transport对抗发现的voucher检查与超时dead-name泄漏已最小修复，主管独立Release35/6/4/10/28/28及rights矩阵通过；最终C对应App105/Release/签名及退出回归已核，见 `docs/reports/p7-transport-adversarial.md`。真实网络与目标系统不因此通过。最新干净源8b63961/UUIDfdb05b4d Development内部候选已包含两修复并独立校验，仍Gatekeeper拒绝/未公证或安装；旧候选仅历史。下方阶段历史记录仅指当时状态，当前实现/委派以 `ENGINEERING_STATE.md` 为准。

用户最新已明确授权本机Docker隔离环境/必要依赖下载构建及127.0.0.1:22221～22225测试。官方Docker4.97已安装验签；首次许可页曾使引擎暂停，后续实际观察外部GUI后LicenseTermsVersion2/2CPU4GiB40GiB、AutoStartfalse，资源实物一致，当前不再待许可。固定Ubuntu ARM64/rootimage7f633d33…和MINAimage18c77956…已构建运行，五服务隔离边界及有限回环实效已有证据，不将配置PortBindings冒充可达。下方阶段历史记录只反映当时状态；当前真实分项见顶部及相应AC，不再沿用“尚未执行任何SSH/SFTP”的旧结论。安装和授权边界见 `docs/reports/env-authorized-installation.md`。

## 阶段 0 门槛与证据（不替代产品验收）

阶段任务状态只表示对应的调查、文档或环境核对完成，不表示产品功能、整体 Goal 或阶段 0 后续任务全部完成。阶段任务通过不能把 AC-01～AC-38 或其他产品验收条目标记为通过。

| 阶段任务 | 状态 | 阶段证据 | 关键限制 / 未验证范围 |
| --- | --- | --- | --- |
| P0-01 环境核对 | 通过（阶段任务） | `docs/reports/p0-01-environment.md` | 已核对 Apple Silicon、Xcode/SDK、Swift、系统 OpenSSH 和可用工具；实际宿主为 macOS 15.8.1，低于目标 macOS 26。未执行 App 构建、SSH/SFTP 互通或 macOS 26 运行时验收。 |
| P0-02 Git 基线 | 通过（阶段任务） | `docs/reports/p0-02-git-baseline.md` | 已确认项目根目录、本地 Git、忽略规则和无 remote；不代表存在产品代码、依赖可用或产品验收通过。 |
| P0-03 依赖核对 | 通过（阶段任务） | `docs/reports/p0-03-dependencies.md`、`docs/dependencies.md`、`docs/adr/` 下 P0-03 ADR | SwiftTerm、GRDB、libssh2 与候选加密后端的来源/许可证/构建证据已记录；libssh2 CMake 未执行（本机无 cmake），替代加密后端未完成本机构建，最终 App/Xcode 打包、签名、公证和真实 SSH/SFTP 互通仍未验证。依赖探针不等于产品功能通过。 |
| P0-04 隔离测试环境调查 | 通过（阶段任务） | `docs/reports/p0-04-test-environment.md` | 已以只读方式核对 Apple Silicon/macOS、Xcode/SDK、XCTest、xctrace、临时目录、PTY 工具、系统 SSH 工具、虚拟化框架及容器/VM 工具缺口；没有新增环境、启动 `sshd` 或连接远程。已提出待用户确认的 Apple Silicon Ubuntu ARM64 VM（优先 UTM + Apple Virtualization）和容器备选，包含资源、网络、一次性凭据与销毁策略。P0-04 不等于 SSH/SFTP、MFA、终端、SFTP 传输或 Linux 服务验收通过。 |
| P0-05 签名、辅助程序与 Sandbox 调查 | 通过（阶段任务） | `docs/reports/p0-05-signing-sandbox.md` | 已核对本机 `codesign`/`security`/Xcode/SDK/`notarytool`/`stapler`/`spctl` 入口、签名身份类型数量、Bundle ID/Team/证书/公证未知项、Apple helper 路径、签名顺序、Sandbox/Hardened Runtime 最小权限与公证前置条件；`/tmp` fixture 的 ad hoc runtime 深度严格验证通过。当前无正式 App/Target，Developer ID Application/Installer 摘要均为 0，未签名正式产品、未上传 Apple；AC-33/AC-34/AC-35 仍未执行。 |

阶段 0 的阶段任务状态不改变下方产品验收条目的状态。整体 Goal 仍不能因 P0-01/P0-02/P0-03/P0-04/P0-05 的阶段任务通过而宣布完成；所有必要的产品、性能、Release 及外部人工验收仍须按执行计划完成并留存证据。

## 阶段 1 局部实验记录（不替代产品验收）

| 阶段任务 | 状态 | 执行证据 | 关键限制 / 未验证范围 |
| --- | --- | --- | --- |
| P1-01 最小受控 OpenSSH/PTY 探针 | 通过（仅本地无网络原型范围） | `Experiments/P1-01-PTYProbe/`；`docs/reports/p1-01-pty.md`；macOS 15.8.1 / Xcode 26.3 / Swift 6.2.4；主管独立复跑14项 XCTest、Release CLI 和 ps/lsof 资源快照均通过；工程师 Debug/Release/TSan/重复测试见 `.build/verification/` | 无 Shell 拼接、9 类 argv 精确回传、256 输入字节顺序、128 KiB 输出尾部、窗口/SIGWINCH、超时、TERM→KILL、EOF、并发幂等关闭、20 次本地循环与对象/FD/进程/task 回收只证明本地原型范围。系统 ssh 只运行无网络 `-G -F /dev/null`。无隔离 SSH 服务、无 macOS 26 runtime（只有 minos 26 交叉编译证据）；没有认证/MFA/信任、Keychain、Askpass、正式 App、SwiftTerm 集成、后代进程树或产品性能证据。 |
| P1-02 受控配置与 HostTrustStore 原型 | 通过（仅本地信任/配置原型范围） | `Experiments/P1-02-HostTrustProbe/`；`docs/adr/p1-02-host-trust.md`；`docs/reports/p1-02-host-trust.md`；主管独立22项测试与Release CLI通过，工程师Debug/Release/TSan证据见实验 `.build/verification/`；系统ssh -G/-vvG、ssh-keygen -F/-l真实本地对照 | 仅本地配置/公钥/文件证据：显式首次/新算法确认、匹配、变化拒绝、非默认端口/地址编辑、代次与旧确认、原子写与跨进程并发、权限/链接/恶意存储。未启动 sshd 或连接 SSH；真实握手公钥绑定、SSH/SFTP 集成、认证/MFA、macOS 26 runtime 与掉电未验证，产品 AC-04/AC-12/AC-25 仍未执行。 |

| P1-03 凭据与私钥原型 | 部分本地通过，正式安全包集成中 | `docs/reports/p1-03-credential-key.md`；原DP仍缺profile失败，file-based候选主管独立真实CRUD/creator ACL/跨启动/同DR替换/错误身份拒绝/cleanup及6策略测试通过；ADR明确显式选择 | 不将DP失败改通过；不静默fallback。file-based无ThisDeviceOnly等价保证，真实用户锁定/正式macOS26/双机未验；生产串行进程非交互策略与临时自建Keychain锁定测试在OpenLXSSHSecurity中继续。 |
| P1-04A/B/C、P1-06A Askpass本机控制面/打包 | C和P1-06A本地范围通过；阶段1整体进行中 | `docs/reports/p1-04-askpass.md`；主管C双配置16单测+28Mach通过、P1-06A Release真实App readpass成功/取消/超时三场景通过；工程师最终回归29Mach场景 | 已移除旧socket回答路径。包内helper/严格系统ssh-keygen签名、控制PTY无DISPLAY+force实际触发，公钥匹配且资源/密钥清理。不是系统ssh网络认证/MFA；Finder启动、macOS26/Sandbox/DeveloperID仍未验证。 |

P1-01/P1-02 不改变 AC-04、AC-06～AC-12、AC-16、AC-25、AC-28～AC-32 等产品条目的状态；尤其“未使用 Shell”不能替代完整产品参数/配置与真实主机信任验证。阶段 1 门槛尚未达到。

## 阶段 2 本地终端记录（不替代远端/人工验收）

- P2-LOCAL-A：主管独立16项测试与真实Release原生窗口13项自检通过；稳定1.20压力尾部3断言失败已独立复现，暂选精确锁定1.99.1预览，见 `docs/adr/p2-terminal-version-selection.md` 和 `docs/reports/p2-local-terminal.md`。
- 本地资源20周期FD3→3、弱视图0；主管短时App+fixture峰RSS140608KiB，不是PERF/长测。人工IME未测，Vim严格ZWJ断言失败保留；远端TUI、嵌套SSH、macOS26、200次/24小时均未通过，AC-13/14/15/28/29等状态不变。

## 阶段 4 数据层记录（不替代App功能）

- P4-DATA-A：`Packages/OpenLXSSHCore/` 主管代码审查和独立29项真实SQLite测试通过，见 `docs/reports/p4-data-core.md`。包含主机/分组/收藏/搜索/设置、迁移回滚、共享删除票据、跨进程锁与异常退出WAL恢复；不代表UI/真实Keychain/私钥跨存储或掉电验收。
- P4-CREDENTIAL-A正式 `Packages/OpenLXSSHSecurity/` 主管审查/独立20测试与真实签名CRUD fixture通过；自建临时Keychain真实锁时回退、解锁恢复且用户default/searchlist不变。见 `docs/reports/p4-security-core.md`。App凭据/密钥UI和跨存储worker集成中，产品AUTH/KEY仍不据包测试直接通过。
- P4-SECURITY-UI/R1主管独立verify-app all/signed-security通过：32测试、GUI15+8+7、真实签名App8+15+5检查；忘记私钥口令、prepared仅丢journal、Core提交后清理失败语义与原生弹窗owner已收口，见 `docs/reports/p4-security-ui.md`。仍非macOS26运行或真实SSH认证验收。
- P4-APP-A本地最小集成已通过主管代码审查及完整verify-app all：正式Debug/Release arm64/min26编译、HostProbe13项XCTest、原生GUI14检查及新进程reopen8检查；见 `docs/reports/p4-native-app.md`。真实SSH/终端/SFTP/密钥/凭据未集成，产品AC仍不能据这次UI检查整体标通过。

## 阶段 6 文件/任务核心记录（不替代真实SFTP）

- 正式OpenLXSSHFiles+TransferManager主管完整70矩阵通过，R1修正混合成功/跳过不误报成功，主管Release16定向与工程师双配置73全量通过，见 `docs/reports/p6-files-core.md`。
- Manager应用级拥有service/job，不引用终端/panel，取消/decision/批策略/idle关闭有真实本地FD测试；App面板/生命周期尚待整合。远端互通、服务能力、网络异常与AC-17～24仍未通过。

## 阶段 5 原生会话与生命周期记录

- P5-APP-SSH-A/ACL/JournalFD/R2已完成主管审查、68测试、原生GUI15+8+7+17+17、签名App8+8+15+5独立复验，提交7ed142e，详见 `docs/reports/p5-native-session-ui.md`。
- Session使用真实Transport/NativeTerminalView，GUI网络状态明确逻辑替身；真实系统ssh-G及签名DirectSession synthetic候选待信任取消是离线证据。没有真实SSH成功、macOS26运行或人工IME通过声明。
- 本轮ACL各包、根枚举/源变化/根自拷及App并发关闭/凭据取消缺陷已复验修复，修前失败日志保留，详见 `docs/reports/p7-core-review.md`。后续新代码继续按同标准审查。

## 1. 状态与证据格式

允许使用：未执行、进行中、通过、失败、待外部条件。失败修复后复验，不删除条目。每行至少记录测试环境、对应构建/提交、实际步骤或命令与结果证据；用户实测记录日期和覆盖范围，不保存秘密。

总体完成取决于所有必要条目通过。仅优化目标采用单独报告，不因未达到努力数字自动删减功能；尚缺必要验证时不能宣称整体 COMPLETE。

## 2. 功能、安全与生命周期

| 验收 ID | 关联需求 | 必须观察到的结果 | 当前状态 / 证据 |
| --- | --- | --- | --- |
| AC-01 | 产品命名、DIST | App 显示、正式 Target、模块与文档统一使用 OpenLXSSH，平台为 Apple Silicon/macOS 26 | 进行中：正式Debug/Release arm64/minOS26/module/Info.plist已核验；宿主为15.8.1，macOS26实跑待外部条件。见 `docs/reports/p4-native-app.md` |
| AC-02 | HOST-01～02 | 主机增删改复制、单层分组、收藏、搜索与重启持久化正确 | 进行中：HostProbe真实App CRUD/分组/收藏/搜索/跨进程重启已验证，Core34项含持久化/事务；正式目标系统与整合集成回归仍待完成。见 `docs/reports/p4-native-app.md`、`docs/reports/p4-data-core.md` |
| AC-03 | HOST-03～04 | 双击定位已有活动标签，显式新建产生独立会话，切换不重连 | 进行中：App真实SessionController/NativeTerminalView集成，主管68tests+原生双击/复用/独立/退出检查通过；GUI连接逻辑替身，真实SSH/mac26仍未验。见 `docs/reports/p5-native-session-ui.md` |
| AC-04 | HOST-05～06、SEC-03 | 不改系统 SSH 配置，异常主机字段不能注入选项、配置或 Shell 指令；删除不误删共享凭据 | 未执行 |
| AC-05 | KEY-01～03 | 导入有/无口令 Ed25519/RSA，生成 Ed25519、复制公钥，权限正确，不改源文件 | 进行中：继承ACL权限缺陷已修，主管独立Release31项含11新ACL回归通过；不清用户ACL、查询失败拒绝。正式签名App/目标系统及整体认证回归仍待，不能标通过。见 `docs/reports/p4-security-core.md`、`docs/reports/p7-core-review.md` |
| AC-06 | AUTH-01 | 直接私钥认证成功，解锁错误/取消可恢复且不泄漏 | 进行中：host15生产DirectSSHSession在真实keyonly隔离服务私钥登录成功、可信outer-auth1/close/ownedPID释放通过；加密密钥/RSA/错误口令/目标系统与正式App仍待完整矩阵。见 `docs/reports/real-ssh-sftp-smoke.md` |
| AC-07 | AUTH-02、06～07 | 直接密码登录、选择保存、不保存、Keychain 不可用均符合授权与人工回退规则 | 未执行 |
| AC-08 | AUTH-03 | 直接私钥＋OTP 成功，错误/过期 OTP 可处理，OTP 不保存 | 未执行 |
| AC-09 | AUTH-04 | 直接密码＋OTP 成功；长期密码不会被误投给验证码挑战 | 未执行 |
| AC-10 | AUTH-05 | 多轮/多提示 Keyboard-Interactive、等待手机审批、拒绝和取消不挂死 UI | 进行中：host15生产libssh2真实MINA单回调双prompt/echo、zero接受/拒绝及固定8s审批接受/拒绝/等待取消通过；主管独立双prompt与pending取消且跨原decisiondue归零抽验通过。auth-only/非GUI/非SFTP，企业审批及OpenSSH多轮/产品交互仍待。见 `docs/reports/real-mina-kbi.md` |
| AC-11 | AUTH-08～09 | 未知挑战人工输入；并发认证不串用凭据；关闭后旧回答失效；重试有界 | 进行中：正式控制面/签名IPC与App未知人工挑战、代次/取消回归通过；R2修复await中取消后读凭据及并发关闭边界，主管68项和GUI/signed复验通过。真实MFA仍待，见 `docs/reports/p5-native-session-ui.md` |
| AC-12 | SEC-01 | SSH 与 SFTP 直接连接首次信任、再次匹配、变化拒绝、非默认端口均正确 | 进行中：known_hosts危险ACL边界已修，主管Trust Release46及Transport35+严格离线签名IPC通过；真实SSH/SFTP握手与App集成仍待，不算整体通过。见 `docs/reports/p7-core-review.md` |
| AC-13 | NEST-01～04 | 最外层连接后在远端手动执行 ssh，内层认证、控制键、缩放、退出返回上一层正常，App 不投递内层凭据 | 未执行 |
| AC-14 | TERM-02～04 | 有限历史、搜索、中文输入法、Unicode/Emoji、复制/多行及 Bracketed Paste、主题字号可用 | 未执行 |
| AC-15 | TERM-05 | Vim/Neovim、tmux、htop/btop、Docker 日志以及指定 Claude Code/OpenCode 版本的终端显示与输入可用 | 未执行 |
| AC-16 | TERM-06～07 | 按主机保活，断线保留当前输出且仅手动重连，连接/认证中关闭可清理 | 未执行 |
| AC-17 | FILE-01～02 | 文件面板默认隐藏，打开才直连认证；适用的密码、私钥、MFA 与信任验证通过，允许重复 MFA | 进行中：真实隔离服务密码/私钥productionSFTP微型往返及typed错误密码/未注册key拒绝已实测，host15/noGUI；原App按需/授权撤销R1已有89/signed分项。真实MFA、正式mac26/GUI全链待验。见 `docs/reports/real-ssh-sftp-smoke.md`、`docs/reports/p6a-native-files-ui.md` |
| AC-18 | FILE-03～04 | 浏览、创建目录、重命名、文件/目录删除、Finder 拖入；目标和错误信息正确 | 进行中：App本地原生浏览/安全操作与B1上传下载/fileURL注册回调主管103tests/GUI通过，人工Finder/NSOpenPanel、真实远端仍待。见 `docs/reports/p6a-native-files-ui.md`、`docs/reports/p6b1-native-transfers.md` |
| AC-19 | FILE-03、07 | 单文件、多文件、整目录往返内容一致；中文/空格/特殊字符和符号链接按明确策略处理，无越界或循环 | 进行中：本地与AppB1分项已验，真实隔离SFTP完整2GiB/1000及Unicode共1002 payload四manifest实际原名/大小/SHA一致，3链接逐项拒绝/树失败、未越界。主管独立核全部manifest，正式App/mac26/Finder仍待。见 `docs/reports/real-sftp-file-acceptance.md`、`docs/reports/p6b1-native-transfers.md` |
| AC-20 | FILE-05～06 | 覆盖/跳过/重命名及本次批量策略生效，唯一临时文件和提交不会误覆盖竞争目标 | 进行中：AppB1本地批策略及竞争目标保护已验；真实SFTP未确认noReplace拒绝0bytes、当前service真实probe/碰撞保原件、POSIX rename支持已实测。远端非原子路径检查/最终非CAS剩余风险明确，正式App/mac26及不支持扩展服务仍待。见 `docs/reports/real-sftp-file-acceptance.md`、`docs/reports/p6b1-native-transfers.md` |
| AC-21 | FILE-05～07 | 大文件取消、断线、权限不足、磁盘空间不足及不支持的安全覆盖有明确失败结果，不破坏既有文件 | 进行中：真实远端2GiB上传/下载25%取消保原target metadata/SHA且同session仍可用、permissionDenied/open/code3与无target已实测；独立真实断连16MiB case源码/离线主管审查通过，未live。网络断连/磁盘满与另一不支持扩展服务待验。见 `docs/reports/real-sftp-file-acceptance.md` |
| AC-22 | FILE-08～09 | 关闭 SSH 标签、切标签、隐藏 SFTP 面板后任务继续且可见；空闲连接可释放 | 进行中：AppB1真实Local任务跨hide/切主机/切关SSH标签继续，任务入口及定向idle/leased保护主管复验通过；真实远端/mac26仍待。见 `docs/reports/p6b1-native-transfers.md` |
| AC-23 | LIFE | 无传输时标签关闭、主窗口关闭和退出正确；隐藏/最小化保持连接；重开不恢复或触发认证 | 进行中：无传输App原生关闭/重开/带活动逻辑tab退出/重叠window+Quit及永久admission回归主管通过；真实SSH进程、SFTP整合与mac26仍待。见 `docs/reports/p5-native-session-ui.md` |
| AC-24 | LIFE、FILE-08 | 有传输时窗口关闭/退出均拦截；继续保留窗口，取消并关闭正确终止，文件不被静默破坏 | 进行中：AppB1主管103tests/原生window+Quit共享决定/继续/取消真退出、晚风险及历史集合R1复验通过；真实SSH/SFTP清理/mac26仍待。见 `docs/reports/p6b1-native-transfers.md` |
| AC-25 | SEC-02、AUTH、KEY | 源码、配置、数据库、参数、日志、测试截图和提交中没有秘密；测试不使用真实公司凭据 | 进行中：历史344tracked/index与显式出口已查；最终ba4a2ec/d331188限定15文件delta及fdb05b4d候选32文件/29文本未见实际秘密或敏感材料，未覆盖二进制内部/全历史/运行时/所有日志，不作全证明。见 `docs/reports/p7-secret-artifact-check.md` |
| AC-26 | SEC-04 | 固定依赖及传递依赖、许可证与来源记录；Sandbox/权限选择有证据，无关闭系统保护的绕过 | 进行中：正式五包/App锁图、原生输入/许可及实际候选链接来源已核；非Sandbox/Hardened Runtime/空权限决策见 `docs/adr/v1-runtime-permissions.md`。目标系统/最终发布权限回归未验，无系统保护修改，不标整体通过 |
| AC-27 | 数据一致性 | 数据迁移、异常中断、重启、重复保存、Keychain/私钥删除引用失败均可恢复，不错配凭据 | 进行中：Core迁移/真实WAL异常退出/事务与共享引用、App补偿/清理重启有局部证据；App R1提交后清理语义和prepared恢复入口主管已复验。尚缺目标系统及整体认证/文件集成回归，未标通过。见 `docs/reports/p4-data-core.md`、`docs/reports/p4-security-core.md` |

## 3. 性能与长期稳定性

| 验收 ID | 场景 | 必要证据 | 当前状态 / 证据 |
| --- | --- | --- | --- |
| AC-28 | 200 次直接 SSH 创建/认证/关闭循环，并穿插连接中取消 | 循环计数、退出结果、前后进程/PTY/FD/任务数及内存趋势，无持续累积 | 待外部条件：最终Transport修复对应新driver-71e5e2da已重建/Development严格静态签名并主管独立record核验；准备offline34+6+12已有证据。隔离服务器现已就绪，正式driver仍要求macOS26；200真实未执行，不降低平台门冒充通过。见 `docs/reports/p7-stability-driver-preparation.md` |
| AC-29 | 5 个独立普通 SSH 会话真实连续运行 24 小时 | 实际起止时间、有效连接时长、采样、负载和错误；不以短测、改时钟或重启拼接冒充 | 待外部条件：有限真实驱动/连续计时判定已准备，不是长测；隔离服务已就绪，仍缺正式driver所需macOS26实际运行条件，24h未执行 |
| AC-30 | 大量输出与快速标签切换 | 声明输入速率/持续时间；队列有界、UI 可响应，渲染与输入正确，停止压力后能恢复 | 进行中：五真实view/逻辑driver有限渲染输入压力，主管105tests及原生76检查/22轮、每view814108 bytes、heartbeat377.93ms、停止后恢复通过；不是SSH/PTY/Release性能验收，真实负载待环境。见 `docs/reports/p7-app-output-stress.md` |
| AC-31 | 大文件和多文件传输 | 默认至少 2 GiB 单文件及 1,000 个小文件测试集，记录往返摘要、速度、峰值内存、取消/断线结果；资源不够时报告实际限制 | 进行中：真实隔离SFTP完整2GiB/1000及Unicode共1002payload，4份实际原名/SHA一致、双向25%取消保原件、权限/链接/当前server提交能力/资源清理通过；主管独立核全部manifest与结果。仍缺断网/磁盘满/macOS26/正式App，非整体验收通过。见 `docs/reports/real-sftp-file-acceptance.md` |
| AC-32 | 关闭主窗口或退出后资源检查 | 无不应存在的所属 ssh/认证辅助进程、文件连接、PTY/FD 或终端对象 | 进行中：App关闭/退出Local任务及五view压力后closed/disposed5、weak0、warm/closedFD16；Transport超时泄漏已修且主管Release rights归零/子进程回收通过，见 `docs/reports/p7-transport-adversarial.md`。真实SSH/SFTP及macOS26整体资源仍未验 |
| PERF-R | 空闲 <200 MB、5 普通会话 <500 MB 的努力目标 | Release、相同负载和计量方式，App＋所属子进程；记录均值/峰值/趋势与未达原因，属于报告项 | 未完成目标测量：HostProbe有限Local TimeProfiler/Leaks采样有局部证据，Allocations exit20无trace、Leaks空表不能推零泄漏，leaks-atExit短时0仅替代结果；非Release5真实会话。见 `docs/reports/p7-local-instruments.md` |

2 GiB 与 1,000 文件是执行基准的初始定义，不扩大产品功能；环境不足时不能直接将较小样本记为完整通过。基准中记录机器内存、macOS/SDK、版本、历史行数、终端尺寸、服务器配置、采样间隔与测量方法。共享内存计量与子进程汇总口径保持一致，避免单一数字误导。

Instruments 覆盖 Allocations、Leaks 和 Time Profiler；工具或权限不可用时记录原因与替代证据，不将未运行写成已运行。优化必须提供前后可比较数据。

## 4. Release 与外部人工验收

| 验收 ID | 必须结果 | 当前状态 / 证据 |
| --- | --- | --- |
| AC-33 | Release 可重复构建，安装包包含非系统运行依赖与辅助程序，产物有版本/提交/摘要记录 | 进行中：最新干净源8b63961/最终Transport修复Development内部App/ZIP+manifest UUIDfdb05b4d-a035-4040-8ded-5d549ffadb57已生成，strict/runtime/来源许可/归档摘要独立verify通过；Gatekeeper拒绝/未安装运行min26/非正式Release。见 `docs/reports/p8-packaging-preparation.md` |
| AC-34 | Developer ID 签名、所需权限、Hardened Runtime 与授权后的公证验证完成，未关闭系统保护 | 未执行 |
| AC-35 | 开发机正常安装和运行，退出重启、升级后本机凭据读取正确，不依赖开发目录 | 未执行 |
| AC-36 | 朋友的第二台 Apple Silicon/macOS 26 正常安装，SSH/MFA、终端、SFTP 与退出实际验收 | 待外部条件：尚未安排第二台 Mac 操作 |
| AC-37 | 用户在公司允许的实际环境手动覆盖适用的认证/审批与嵌套 SSH，记录范围及结果，无秘密进入报告 | 待外部条件：尚未安排实际企业场景验收 |
| AC-38 | 安装/使用/已知限制说明、阶段审查与本地提交齐全；没有遗漏的必要未完成项 | 进行中：使用说明 `docs/user-guide.md`、候选说明与 `docs/release/acceptance-prerequisites.md` 已写，明确开发中/未验项；必要功能/Release/外部验收仍未完成 |

手机推送与公司策略具有环境差异：受控模拟验证和实际企业验收分别记录。AI 无权接触或代为输入真实秘密时，由用户自行操作并回报结果；不能因此声称“全部企业环境已兼容”。第二台 Mac 同样不能由本机重复运行替代。

## 5. 缺陷与整体结论

- 任何已知秘密泄漏、主机身份校验绕过、静默文件损坏、持续无界资源增长或无法安装运行的问题都阻止完成。
- 一般界面细节记录并按影响处理，不无限扩张首版；必要功能或验证缺失不能包装成普通已知限制。
- 整体结论：必要功能已有本地实现和分项审查，本轮Transport voucher/超时ownership修复及对应App回归已主管复核。真实互通、目标系统、长期、正式发布与外部人工验收未完成，无整体通过声明。
