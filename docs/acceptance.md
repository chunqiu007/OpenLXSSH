# OpenLXSSH V1.0 — 验收总表

当前状态：**本轮host15受控分项已收口，OpenLXSSH V1.0整体验收仍未通过。** 真实SSH/SFTP四类认证、多提示/审批、2GiB/1000及异常已有分项证据；App上传跨关闭/隐藏、关窗/Quit、原生文件操作与批skip/rename/overwrite、正字节切标签、双标签/自然断线历史/手动重连、原生搜索/内存Bracketed Paste、加密key认证UI取消恢复/并发提示归属、真实预扫变化拒绝/原生信任管理，以及Vim/tmux/htop、公钥nested、正常保活+R2黑洞均经主管独立验收。当前App160tests/0failure、最终正式Debug/Release各一次arm64/min26静态编译/运行测试代码隔离通过，**不等macOS26运行或已发布Release**。原MFA fixture取消材料cleanupIncomplete、原黑洞control/-9等失败历史保留，不被恢复或后续通过追认。当前需满足的默认Keychain动作授权、目标mac26/200次/连续24h/Release压力资源、DeveloperID/具体产物Apple上传、双机/人工/企业和剩余工具合法条件见 `docs/release/acceptance-prerequisites.md`；不把这些必要门删除或以host15短测替代。

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
| AC-03 | HOST-03～04 | 双击定位已有活动标签，显式新建产生独立会话，切换不重连 | 进行中：原逻辑/原生证据保留，新增真实App双keyonly标签各独立driver/session/view/token/PID出生身份；两轮A/B原生选择+主机双击4次均复用最近活动者、身份不变，35checks及资源清理主管独立通过。仅host15有限分项，正式mac26仍待。见 `docs/reports/app-real-sessions-reconnect.md`、`docs/reports/p5-native-session-ui.md` |
| AC-04 | HOST-05～06、SEC-03 | 不改系统 SSH 配置，异常主机字段不能注入选项、配置或 Shell 指令；删除不误删共享凭据 | 进行中（已有证据归类，非本轮新增campaign）：Trust ConfigurationTests实际系统ssh -G/-vvG固定argv/仅专属配置、地址用户路径注入拒绝已在Trust报告验证；Core共享credential/key引用删除票据及App testRegisteredKeySelectionAndDeletionDoesNotDeleteSharedKey已在既有152/156回归保留。主管本轮重读关键断言，不将本地/host15证据直接升为正式mac26总体验收。见 `docs/reports/p1-02-host-trust.md`、`docs/reports/p4-data-core.md`、`docs/reports/p5-native-session-ui.md` |
| AC-05 | KEY-01～03 | 导入有/无口令 Ed25519/RSA，生成 Ed25519、复制公钥，权限正确，不改源文件 | 进行中：继承ACL权限缺陷已修，主管独立Release31项含11新ACL回归通过；不清用户ACL、查询失败拒绝。正式签名App/目标系统及整体认证回归仍待，不能标通过。见 `docs/reports/p4-security-core.md`、`docs/reports/p7-core-review.md` |
| AC-06 | AUTH-01 | 直接私钥认证成功，解锁错误/取消可恢复且不泄漏 | 进行中：真实DirectSSHSession/SFTP有无口令Ed/RSA矩阵及wrongphrase负例保留；新真实App7599加密Edkey原生secure sheet取消0manualreads/answer→oldPIDgone，native重连gen2新request/PIDbirth→securefield唯一submit+freshouterACK、152tests/19checks/零CredentialAccess与资源主管独立通过。仅host15有限UI分项，其他错误恢复/正式mac26仍待。见 `docs/reports/app-real-auth-ui-cancel.md`、`docs/reports/real-auth-failures.md` |
| AC-07 | AUTH-02、06～07 | 直接密码登录、选择保存、不保存、Keychain 不可用均符合授权与人工回退规则 | 进行中：host15生产DirectSSHSession真实passwordonly与原gate公开SavedPasswordAuthorization两案通过（授权provider读返1/manual0；无授权manual1/provider0），仅内存provider，不是Keychain持久化消费。public CredentialStore测试消费者R1已主会话及原reviewer源审、主管65Swift17Python29CLI/368快照/增量签名通过，仅离线；未运行真实默认Keychain保存/读取/删除。正式App保存UI/不可用回退与mac26 gate仍待。见 `docs/reports/public-credential-store-preparation.md`、`docs/reports/real-saved-password-public.md`、`docs/reports/real-openssh-four-auth.md` |
| AC-08 | AUTH-03 | 直接私钥＋OTP 成功，错误/过期 OTP 可处理，OTP 不保存 | 进行中：OpenSSH key-kbd和SFTP四密钥+KBI正向通过；真实错误C单数字一次与C提前读后双时钟真实到期再答一次，均typed.authentication/SFTP0/3read3reply/无持久OTP/close/sessiongone已核。正式App错误提示/恢复、mac26仍待。见 `docs/reports/real-otp-negative.md`、`docs/reports/real-sftp-combined-auth.md` |
| AC-09 | AUTH-04 | 直接密码＋OTP 成功；长期密码不会被误投给验证码挑战 | 进行中：真实password-kbd正向primary1/OTP3/connected1，前置提示独立hash验证，三轮同ID/once-budget，未知拒绝且无saved-passwordAPI；主管同精确构建亲跑关键MFA抽验通过，server文件移除/ownedPID释放及relay4/4/0/0已核。错误边界/GUI/mac26仍待。见 `docs/reports/real-openssh-four-auth.md` |
| AC-10 | AUTH-05 | 多轮/多提示 Keyboard-Interactive、等待手机审批、拒绝和取消不挂死 UI | 进行中：host15生产libssh2真实MINA单回调双prompt/echo、zero接受/拒绝及固定8s审批接受/拒绝/等待取消通过；主管独立双prompt与pending取消且跨原decisiondue归零抽验通过。auth-only/非GUI/非SFTP，企业审批及OpenSSH多轮/产品交互仍待。见 `docs/reports/real-mina-kbi.md` |
| AC-11 | AUTH-08～09 | 未知挑战人工输入；并发认证不串用凭据；关闭后旧回答失效；重试有界 | 进行中：正式控制面/IPC代次旧回答拒绝及真实两MFA取消核心保留；原MFA整案仍cleanupIncomplete/服务端材料过TTL残留，exact恢复不是自动通过。新真实Appd25221checks同key双encryptedpending不同req/session/PIDbirth，同tick零manualanswers→native取消A/B原请求仍pending→仅B原生submit1/原PIDfreshACK、A未复活/资源全清主管独立通过（160tests）。同secret不证明不同秘密全排列/多轮MFA GUI/mac26。见 `docs/reports/app-real-concurrent-auth-ui.md`、`docs/reports/real-concurrent-auth.md` |
| AC-12 | SEC-01 | SSH 与 SFTP 直接连接首次信任、再次匹配、变化拒绝、非默认端口均正确 | 进行中：首次realApp和SFTP同握手mismatch/精确API恢复保留；新e689真实AppSystemScanner knownchanged typedtrustRejected、61有限样本未见ownedinteractivePID/auth/trustprompt、旧knownSHA不变，native管理8动作/初confirmdisabled→verifiedconfirm仅1正确record/hash变、旧gen1直到原生manualgen2/freshACK及资源主管独立过。wrongkey仅freshAppstore公开设置，不serverrotate或握手mismatch，正式mac26仍待。见 `docs/reports/app-real-trust-change.md`、`docs/reports/real-auth-failures.md`、`docs/reports/app-real-ssh-sftp.md` |
| AC-13 | NEST-01～04 | 最外层连接后在远端手动执行 ssh，内层认证、控制键、缩放、退出返回上一层正常，App 不投递内层凭据 | 进行中：真实公钥nested分项已主管核过：remoteUID10000新distinctkey/临时exactpublicappend、outerPTY真实系统ssh到1272222、inner12帧/CtrlC/resize/VimSHA/返回outer、App外层auth回调后增量0；双层关闭后auth/trust/config/master恢复baseline/密钥与staging全清。原内层password/OTP/审批与企业人工未验，不将pubkey分项等于全NEST。见 `docs/reports/real-nested-publickey.md` |
| AC-14 | TERM-02～04 | 有限历史、搜索、中文输入法、Unicode/Emoji、复制/多行及 Bracketed Paste、主题字号可用 | 进行中：既有本地PTY/主题历史分项保留；新真实App75cc24checks通过native搜索24match、next/prev真实selection变化、memory paste完整wrapper实际53B/SHA、termios readback/returned0/freshouterACK及noSFTP/credential0/资源释放，主管独立验收。131tests/原127保留与签名已审；不读写用户剪贴板，不冒GUIcopy/paste、人工IME/像素/mac26。见 `docs/reports/app-real-terminal-search-paste.md` |
| AC-15 | TERM-05 | Vim/Neovim、tmux、htop/btop、Docker 日志以及指定 Claude Code/OpenCode 版本的终端显示与输入可用 | 进行中：原失败保留；外层VimR2 strict12/输入SHA/CtrlC/size/Vim文档/termios/done-returned、tmuxR2十帧/真实Ctrl-bd/自有serverpane正常清理均主管过。htop3.3.0唯一新案strict5/准确ownPID-start与readiness/实际31x93/公开PTY q正常exit0/termios/三pidfd与自有root自然清理，主管独立验收通过。仍非全部工具/人工像素/IME/mac26，见 `docs/reports/real-remote-terminal.md`、`docs/reports/real-tmux.md`、`docs/reports/real-htop.md` |
| AC-16 | TERM-06～07 | 按主机保活，断线保留当前输出且仅手动重连，连接/认证中关闭可清理 | 进行中：真实App2e2d自然exit0/历史原生可搜/2秒有限无auto→同view手动gen2/freshACK/B不变与清理通过，配置7-2映射。另公开生产API消费者同2-2 A真实12.000103s安静/freshACK/natural0，R2 B精确tuple+PIDbirth黑洞后自然255/failedlaunchFailed2.568177s/保守5.682587s，无proxy先行EOF/error/cancel/期限/信号，FD清理主管独立过；首Bcontrol/-9历史失败保留。有限host15不等全部网络/目标mac26。见 `docs/reports/real-keepalive-blackhole.md`、`docs/reports/app-real-sessions-reconnect.md` |
| AC-17 | FILE-01～02 | 文件面板默认隐藏，打开才直连认证；适用的密码、私钥、MFA 与信任验证通过，允许重复 MFA | 进行中：host15真实密码/四密钥单方法及四密钥+KBI/密码+KBI正向均authenticatedSFTP/79IO/hash/清理通过；test尾空R1后五MFA通过且主管亲跑pw-kbd抽验。原失败/shape证据保留。真实App keyonly按需/list/awaitclose已过（testscan15），错误过期/GUI完整/mac26仍待。见 `docs/reports/real-sftp-combined-auth.md`、`docs/reports/app-real-ssh-sftp.md` |
| AC-18 | FILE-03～04 | 浏览、创建目录、重命名、文件/目录删除、Finder 拖入；目标和错误信息正确 | 进行中：真实App新5c2e24checks通过nativebatchupload2+表格多选nativedownload2、特殊原名sizeSHA、nativeRename、3审核delete/邻项保全，同bindingattempt1/openclose20/20/end0/norescue，主管独立核。旧011b校验器arguments失败及精确恢复保留；picker仍testSelection非人工Finder/NSOpenPanel，正式mac26未验。见 `docs/reports/app-real-file-operations.md` |
| AC-19 | FILE-03、07 | 单文件、多文件、整目录往返内容一致；中文/空格/特殊字符和符号链接按明确策略处理，无越界或循环 | 进行中：本地与AppB1分项已验，真实隔离SFTP完整2GiB/1000及Unicode共1002 payload四manifest实际原名/大小/SHA一致，3链接逐项拒绝/树失败、未越界。主管独立核全部manifest，正式App/mac26/Finder仍待。见 `docs/reports/real-sftp-file-acceptance.md`、`docs/reports/p6b1-native-transfers.md` |
| AC-20 | FILE-05～06 | 覆盖/跳过/重命名及本次批量策略生效，唯一临时文件和提交不会误覆盖竞争目标 | 进行中：真实App567e24checks/5jobs3batch批skip与新batchrename、原件保全；d2f6真实23checks/4jobs2batch一次applyoverwrite但每job独立新非CAS风险/回答前waiting0bytes0items0temps、final双FreshSHA及22normalcloses/norescue/精确审核删除，均主管独立通过。原142/145tests与底层currentserviceprobe/noReplace/碰撞保护保留；远端逐路径非原子/overwrite非CAS限制、正式mac26及完整能力边界仍待。见 `docs/reports/app-real-batch-conflicts.md`、`docs/reports/app-real-batch-overwrite.md`、`docs/reports/real-sftp-file-acceptance.md` |
| AC-21 | FILE-05～07 | 大文件取消、断线、权限不足、磁盘空间不足及不支持的安全覆盖有明确失败结果，不破坏既有文件 | 进行中：真实2GiB双向取消/权限、R1新16MiB断连receipt/新SFTP核原SHA与清理已过；独立/dev/shm64MiB真实ENOSPC上传write4+errno28/full0/noOOMdelta、先release/原64KiB metadataSHA不变/temp清理及资源归零已主管复核。另一能力边界/正式GUI/mac26仍待。见 `docs/reports/real-sftp-disk-full.md`、`docs/reports/real-sftp-disconnect.md` |
| AC-22 | FILE-08～09 | 关闭 SSH 标签、切标签、隐藏 SFTP 面板后任务继续且可见；空闲连接可释放 | 进行中：原f85128checks真实关SSH/隐藏上传成功保留；新8f7d31checks真实16MiB上传655360B切B/983040B切A，双SSH与同job/service/host/gen身份不变，最终原service SHA匹配/8normalcloses/rescue0/精确清理主管独立通过。任务入口明确在完成后原生hide→open核同job可见，不声称在途入口已单独核验；mac26/完整多任务排列仍待。见 `docs/reports/app-real-transfer-survival.md`、`docs/reports/app-real-inflight-tab-switch.md` |
| AC-23 | LIFE | 无传输时标签关闭、主窗口关闭和退出正确；隐藏/最小化保持连接；重开不恢复或触发认证 | 进行中：host15真实App显式testscan15首案实际SSH outerauth/ownedPID、无传输原生标签关闭closed/PIDnil、窗口awaitFilesclose、重开无SSH/SFTP恢复通过；defaultscan5认证前失败保留。隐藏/最小化/真实退出完整矩阵及mac26仍待。见 `docs/reports/app-real-ssh-sftp.md` |
| AC-24 | LIFE、FILE-08 | 有传输时窗口关闭/退出均拦截；继续保留窗口，取消并关闭正确终止，文件不被静默破坏 | 进行中：真实host15 window9baf Continue→Cancel23checks/7checkpoint及Quit3a931 Continue→Cancel22checks/6checkpoint均通过。Quit preexit完整fsync/hook1-1后实际自行退出0/无forceddrain；均cancelled/actualworker-service-SSHdrain，retained准确声明、外层fixedCID核finalabsent再FD/inode/SHA精确清，7opens/6closes/shutdown1如实。主管独立验收，正式mac26/多任务完整矩阵仍待。见 `docs/reports/app-real-window-transfer.md`、`docs/reports/app-real-quit-transfer.md` |
| AC-25 | SEC-02、AUTH、KEY | 源码、配置、数据库、参数、日志、测试截图和提交中没有秘密；测试不使用真实公司凭据 | 进行中：历史344/候选出口检查边界保留；本轮相对a535624的43公开文本变更与当前tracked路径限定规则0命中，importAuthUIKey/单auth/concurrentAuth显式secret出口复核无prompt/answer/hash/长度/logger/argv泄露，harness及主管不读真实secret，原测试App日志仅stat空。主管 `primary-final-public-exits-870cb79c-b4b7-49f7-b8c9-b6f511745412`；不覆盖全历史/任意编码/二进制内部/内存/全部ignored日志，不作全证明，见 `docs/reports/p7-secret-artifact-check.md` |
| AC-26 | SEC-04 | 固定依赖及传递依赖、许可证与来源记录；Sandbox/权限选择有证据，无关闭系统保护的绕过 | 进行中：正式五包/App锁图、原生输入/许可及实际候选链接来源已核；非Sandbox/Hardened Runtime/空权限决策见 `docs/adr/v1-runtime-permissions.md`。目标系统/最终发布权限回归未验，无系统保护修改，不标整体通过 |
| AC-27 | 数据一致性 | 数据迁移、异常中断、重启、重复保存、Keychain/私钥删除引用失败均可恢复，不错配凭据 | 进行中：Core迁移/真实WAL异常退出/事务与共享引用、App补偿/清理重启有局部证据；App R1提交后清理语义和prepared恢复入口主管已复验。尚缺目标系统及整体认证/文件集成回归，未标通过。见 `docs/reports/p4-data-core.md`、`docs/reports/p4-security-core.md` |

## 3. 性能与长期稳定性

| 验收 ID | 场景 | 必要证据 | 当前状态 / 证据 |
| --- | --- | --- | --- |
| AC-28 | 200 次直接 SSH 创建/认证/关闭循环，并穿插连接中取消 | 循环计数、退出结果、前后进程/PTY/FD/任务数及内存趋势，无持续累积 | 待外部条件：最终Transport修复对应新driver-71e5e2da已重建/Development严格静态签名并主管独立record核验；准备offline34+6+12已有证据。隔离服务器现已就绪，正式driver仍要求macOS26；200真实未执行，不降低平台门冒充通过。见 `docs/reports/p7-stability-driver-preparation.md` |
| AC-29 | 5 个独立普通 SSH 会话真实连续运行 24 小时 | 实际起止时间、有效连接时长、采样、负载和错误；不以短测、改时钟或重启拼接冒充 | 待外部条件：有限真实驱动/连续计时判定已准备，不是长测；隔离服务已就绪，仍缺正式driver所需macOS26实际运行条件，24h未执行 |
| AC-30 | 大量输出与快速标签切换 | 声明输入速率/持续时间；队列有界、UI 可响应，渲染与输入正确，停止压力后能恢复 | 进行中：五真实view/逻辑driver有限渲染输入压力，主管105tests及原生76检查/22轮、每view814108 bytes、heartbeat377.93ms、停止后恢复通过；不是SSH/PTY/Release性能验收，真实负载待环境。见 `docs/reports/p7-app-output-stress.md` |
| AC-31 | 大文件和多文件传输 | 默认至少 2 GiB 单文件及 1,000 个小文件测试集，记录往返摘要、速度、峰值内存、取消/断线结果；资源不够时报告实际限制 | 进行中：真实2GiB/1000及Unicode四manifest、双向25%取消/权限/链接/服务能力/资源已核；主管R1新16MiB断连闭环通过；独立有界真实远端ENOSPC/write4+errno28/noOOM/原件保全及恢复通过。正式App/mac26/完整能力边界仍待，非整体通过。见 `docs/reports/real-sftp-file-acceptance.md`、`docs/reports/real-sftp-disconnect.md`、`docs/reports/real-sftp-disk-full.md` |
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
- 整体结论：本轮host15受控真实集成分项、160项App回归和最终shipping D静态编译隔离均经主管独立通过，具体报告与失败历史保留。目标macOS26运行、200次/连续24h及Release真实压力/资源、默认Keychain真实持久化动作授权、正式DeveloperID/具体产物公证、双机/人工/企业及剩余工具运行条件未满足；整体未完成，当前等待必要条件，不能用本地分项或内部候选声明COMPLETE。
