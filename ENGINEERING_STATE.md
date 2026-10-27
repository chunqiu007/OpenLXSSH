# OpenLXSSH — 工程状态

更新：2026-10-27（Asia/Shanghai）。本文件是当前检查点；历史失败保留在报告和本地原始结果，不从旧阶段描述推定当前状态。

## 当前目标、范围与授权

- 同一 Goal：Apple Silicon/macOS 26 原生 OpenLXSSH V1.0 可安装 Release，并完成规定验收。**整体 NOT COMPLETE；当前 CONTINUE，定位真实 SSH 在认证后、PTY 会话 ACK 前结束。** 不虚构运行环境 Goal 状态变更。
- 范围：四类直连 SSH/MFA、多标签、用户手动嵌套 SSH、直连 SFTP、主机/密钥/凭据管理、独立传输与窗口/退出保护。排除自动 ProxyJump、经跳板图形 SFTP、转发、自动重连/恢复。基线见 `docs/requirements.md`。
- Primary 是唯一主管，主要编码交 software-engineer；工程师 DONE 不等主管验收。用户授权验收后的相关本地 Git 提交，没有 remote push、发布、生产连接或 Apple 公证上传授权。
- 用户已明确批准官方 Docker Desktop、固定 Ubuntu ARM64/必要依赖、四认证及多提示隔离服务。宿主端口仅 127.0.0.1:22221～22225，不 LAN、不真实凭据/生产挂载、不宿主 sshd、不生产连接、不 Apple 上传。Agent 不代接受法律协议或输入系统凭据。不再重复“等待 Docker 授权”。
- 许可与引擎条件已实际核验解除；公证需展示具体产物/Apple 目的地/用途后另获批准。公开 CredentialStore 持久化消费者当前仅 source/offline，未放行真实默认 file-based Keychain save/read/delete；测试事故开关不构成额外授权。

## 目前最重要的新事实

1. 原生 App 第二个真实上传案，在关闭 SSH/隐藏面板动作之前 SSH 已 failed/PID 不存在，而独立 SFTP 仍 running/720896 bytes。两个上传案均未通过，不能说关闭触发故障或跨关闭已验证。
2. 系统 `/usr/bin/ssh` 同参数/同固定远端 printf，仅 `-T`/`-tt` 不同：无 PTY exit0/6.305s/52B ACK 精确匹配；强制 PTY exit255/15.792s/stdout0/stderr0。不是外层 timeout，不等认证拒绝。
3. 同 exact 容器 UID0 和 UID10000 各一次 `pty.openpty()` 均成功，FD4→4；不能归因为“所有 PTY 无法分配”，不据 capability 名称猜加权限。
4. 新短 ACK 诊断真实单案：outer connected t12.455643，73B 非秘密命令 t12.473894 入队，t21.722916 结束，真实 `.failed(.launchFailed)`/lastExitCode255，stop=false。shellACK=false/probeEvents0/**原 loader 从未发送**。入队也不证明远端执行。
5. root 测试 runtime 已释放，自己的 SSH41010/consumer40915/relay40824 均不存在；relay4/4/0/0 wait0，FD回baseline，exact nonce driver/Vim/目录未观察到，未远端 kill/delete，keyonly仍 Healthy。没有 PTY/Ctrl+C/resize/Vim 通过结论。

详见 `docs/reports/real-remote-terminal.md` 与 `docs/reports/app-real-transfer-survival.md`。主管已读原结果、独立核时序/三PID与冻结输入/严格签名。

## 已验收的本地实现基线

以下仅各自范围通过，不替代真实网络、macOS26 或整体产品验收。

| 范围 | 已审结论/证据 |
| --- | --- |
| P0 工具、依赖、Git、隔离与签名调查 | `docs/reports/p0-*`，不从调查推定产品可用 |
| P1 PTY/信任/Keychain/认证桥 | 本地PTY14/信任22/Mach与readpass；DP Keychain -34018保留，明确选择file-based而非静默fallback；P1报告/ADR |
| P2 本地终端 | 主管16tests/原生窗口；稳定SwiftTerm1.20尾输出失败独立复现，固定1.99.1 preview；人工IME/远端TUI未验 |
| P4 Core/Security | Core ACL48、Security31/四密钥材料解析签验、隔离Keychain CRUD/锁解锁/default/searchlist不变；正式包/P4/P7报告 |
| P5 Trust/Transport | Trust Release46；最终Transport Release35/readpass6/event4/postexit10/对抗28/postexit28/rawrights，提交d331188 |
| P6 Files/Manager | service lease/shutdown/rootFD/源变化/根枚举与自拷修复；主管定向Release34/工程师完整107；`docs/reports/p6-files-core.md` |
| P5 App/R2 | 主管68tests/原生15/8/7/17/17与签名8/8/15/5，提交7ed142e；真实连接另表 |
| P6A/B1 App | 89/103tests/原生与签名分项；末次凭据撤销、late-risk/history等修复，提交90084e4/40853f3；非真实SFTP矩阵 |
| 本地文件压力 | 真2GiB/1000往返、取消/FD/精确清理，提交0e0bf7d；非远端 |
| Transport Mach生产修复 | `MACH_RCV_VOUCHER`使voucher拒绝可达；send超时pseudo-return LOCAL send-once精确释放。最终AskpassMach.c SHA256 34ee7ffbad3c2f75e60a08c308ae1e7021ae82293826b84bd327c3caa20fbb32，提交d331188 |
| 五真实view有限压力 | 105tests/原生76检查/22轮/每view814108B、closed/disposed5/weak0/FD16，提交ba4a2ec；不是SSH/PTY长测 |
| Instruments/秘密检查 | TimeProfiler/Leaks有trace，Allocations exit20无trace；短时leaks0不等零泄漏；历史344及后续限定出口检查有边界，见P7报告 |
| 稳定性driver/打包器 | 正式min26 driver-71e5e2da离线11对象/链接/Development签名已核；打包101fixtures/内部候选核验；未运行200/24h或正式发布 |

## 已验收的真实隔离分项

均 host15 的公开生产 API 消费者或明确 HostProbe，不冒充 macOS26/完整GUI验收。原失败不覆盖。

| 分项 | 实际结果与报告 |
| --- | --- |
| 系统OpenSSH四类正向 | keyonly有/无口令Ed25519/RSA、passwordonly、key-kbd三轮、password-kbd三轮；trusted outer-auth、关闭/PID释放，主管独立pw-kbd抽验。`docs/reports/real-openssh-four-auth.md` |
| MINA多提示/审批 | 同消息双prompt/echo、zero接受拒绝、真实8s审批接受拒绝/等待取消；主管双prompt与取消跨decisiondue抽验。auth-only非SFTP，`docs/reports/real-mina-kbi.md` |
| SFTP正向 | 密码/四密钥单方法及四密钥+KBI/密码+KBI：actual authenticated SFTP/79B往返/摘要/清理。真实PAM第四空尾轮先失败→shape→固定源码→测试契约R1，五MFA复验通过；产品不改。`docs/reports/real-sftp-combined-auth.md` |
| 大/多文件 | 完整2GiB/1000及Unicode共1002payload/四manifest原名大小SHA一致；双向25%取消保原件、权限/三链接拒绝、当前service probe/安全提交；12046opens/closes/end0/socket0。提交15012d3，`docs/reports/real-sftp-file-acceptance.md` |
| 真实断连 | 首案receipt缺失PARTIAL不补造；R1后主管fresh case 25%→精确TERM receipt→transport/write/-43→新显式SFTP binding核原SHA/精确清理闭环。`docs/reports/real-sftp-disconnect.md` |
| 真实ENOSPC | 独立/dev/shm64MiB/≤60MiB填充，write4+真实errno28/avail0/noOOMdelta联合，先释放/原64KiB metadataSHA不变/临时清理/6opens6closes/end0；tmpfs恢复全空。`docs/reports/real-sftp-disk-full.md` |
| 认证与信任负例 | 错密码/未注册key；正确phrase正控后wrongphrase typed.authentication；同握手knownkey mismatch拒绝/旧记录不变，另显式replacement后新SFTP恢复。`docs/reports/real-auth-failures.md`；不声称真实server rotate |
| 错误/真实到期OTP | C一次数字变更拒绝；提前读C，真实wall+monotonic等65.805s过期后原值一次拒绝；3读3reply/SFTP0/close/sessiongone。`docs/reports/real-otp-negative.md` |
| 握手timeout | fixed loopback silent peer accept1/不读写，真实timeout/handshake/-10002/2.0159s，callbacks0/SFTP0/FD4→4/socket0/close。非TCP SYN或外网。`docs/reports/real-handshake-timeout.md` |
| 公开SavedPasswordAuthorization | 原生产24H32 gate下显式授权provider读返1/manual0；无授权manual1/provider0，均outerconnected1/close。内存provider非Keychain持久化。`docs/reports/real-saved-password-public.md` |
| App真实按需读取 | defaultscan5先失败保留；独立newUUID/testscan15后实际SSH、按需SFTP/list2、原生标签关闭/窗口重开不恢复/credentialcalls0。正式scan5/connect10不改。`docs/reports/app-real-ssh-sftp.md` |

## 当前任务、文件所有权及审查

| Task ID / 执行者 | 状态与下一验收点 |
| --- | --- |
| APP-TRANSFER-DIAGNOSTIC-R1 / agent_2c8c76ef-77d1-4313-b527-8e49cfe4feae | 四源冻结；主管118tests/49输入/14命令/签名独立通过。ae16与062f两案均失败，远端已知temp/空root与本地11files+5空dirs/root均按FD/inode/字节账本恢复，raw失败报告不改。暂不重跑；需先解决共同postauth问题 |
| TERMINAL-POSTAUTH-DIAG-LIVE-A / agent_d121dcfb-d2ed-4b51-91b0-89ba0b6571ce | 九源冻结；新de94静态Core128/Python10/27命令/9快照/8父对象/strict主管通过。唯一短ACK实测failed(launchFailed)/255/loader未发，资源已释放，停止连接/构建 |
| PUBLIC-CREDENTIAL-REVIEW-R1 / agent_12500230-e749-48c1-ada3-95f1f8b3869b | 独占Tests/RealIntegration，仅source/offline修P1 stop跨await副作用/密码返回窗口、P2新run父目录fsync、P2预算error白名单映射。原57Swift17Python29CLI保留，三红source回归已落，新pure await/fsync/map tests及增量新签名审点未交。禁止真实store/Keychain/SecItem/Docker/live |
| FIXTURE-PTY-DEBUG-PREP-A / agent_80f0dacc-5fe4-42ec-ac4b-3ac1155adba0 | system-T/-tt及两UIDopenpty已结束/证据已核。仅Tests/PTYDebugAcceptance新子树准备≤100行容器内Linux客户端直连原127.0.0.1:2222的有界阶段诊断，绕开opaque relay；-i/临时server方案未实施已取消。无新端口、不重启原daemon、不改cap/PAM/生产。必须主管先审源/offline，尚未runtime |
| RELAY-POSTAUTH-TIMEOUT-REVIEW-A / agent_53e824ce-ce3e-4eeb-bcc5-92fe9ec80b25 | 四文件只读完成；未发现认证后10s定时器或PTY特判。8sreadiness不延用，pump600s idle/全局寿命不同；底层EOF/IO reason未导出为可观测性限制，未确证relay缺陷 |
| 主管 | 维护状态/验收、读实际差异/原结果、独立复验、按精确文件列表本地提交；不把任何分项或cleanup成功当整体通过 |

并发写域互不重叠。产品Packages、锁文件、认证gate与原五容器配置当前不改。默认不重建无变化的正式候选/已过大文件或OTP到期案。

## 关键架构/安全约束

- SwiftTerm1.99.1 preview固定2f573f73…（非稳定2.x），GRDB7.11.1固定b83108…；libssh2 1.11.1 + OpenSSL3.5.9 LTS静态arm64，原生160输出/7notice核验，无Homebrew运行库。
- SwiftTerm LocalProcess是同一PTY/reader/reaper唯一owner；普通输出与认证控制面分离，不按Password文字注入秘密。Mach冻结audit sender/每消息UID/identifier/同Team/owned ssh PPID-birth/session-generation。
- DirectSSHSession.connected仅可信outer-auth事件，不证明shell-ready。Saved password仅passwordOnly/显式授权/每代一次/精确OS-build+Apple ssh签名版本gate；当前仅24H32/OpenSSH9.9p2 LibreSSL3.3.6，不扩称mac26自动使用已验。
- public CredentialStore默认file-based Keychain；testNamespace只隔离service/account，不是独立物理Keychain。同步false/DPfalse/串行lease，close恢复legacy interaction。秘密不入源码/参数/日志，不承诺Swift副本完全擦除。
- App专属DB/key/trust/config/journal/store任意extended ACL或查询失败拒绝，不清用户ACL。filesec必须return0/MODE populated/ACL absent，不能靠NULL/旧errno认安全。
- 文件先unique同目录temp再安全commit；本地FD/noFollow/RENAME_EXCL。远端逐component lstat不等原子noFollow/overwrite非CAS风险明确；noReplace必须当前service实际probe确认，不造token、不先删原目标。
- TransferManager应用级拥有service/job，不依附terminal/panel；关闭必须await真实worker/service，不只snapshot.isClosed。失败精确恢复只能处理本轮已知身份资源，不广扫删/kill。
- 非Sandbox/Hardened Runtime/空entitlements决策见 `docs/adr/v1-runtime-permissions.md`；不改系统保护。

## 当前环境、Git及产物

- 实测宿主macOS15.8.1/24H32/arm64，Xcode26.3/17C529、SDK26.2/Swift6.2.4。正式App arm64/min26，HostProbe/独立消费者min15不能冒目标runtime。最新本地磁盘观察约42GiB可用，瞬时值不能沿用为下一安装许可。
- Docker Desktop4.97.0/build244584官方验签；DMG SHA256 94e4ccec4a035b7dcdf67cfff0520d4b46ee873ae04b155abc0d22b333cc90ad；Agent无sudo/accept-license。外部GUI后LicenseTermsVersion2/2CPU4096MiB/40GiB/AutoStartfalse，Engine实物一致。context desktop-linux固定unix:///Users/liuwenshuo/.docker/run/docker.sock，不建全局特权socket链接。
- Ubuntu固定24.04 digest18b33ff…，rootimage7f633d33…；project openlxssh-fixture-61ed25328c13，四原CID不重启/换key。MINA2.20.0/commit2221febd…、image18c77956…/独立原CID。internal/noegress/readonly/no-new-privileges/capdropALL+原七项/资源受限/namedvolume无hostbind；HostConfig.PortBindings不冒称实际可达，有限opaque relay仅批准回环端口。详情 `docs/reports/env-authorized-installation.md`。
- 分支 `development/p1-prototypes`；最新已确认本地HEAD **18761e6**（终端九源与真实短ACK失败报告），前一 **18ee766**（App四源及两次传输失败诊断），之前7c925fa。两项仅诊断范围验收/失败证据检查点，不宣称产品通过。尚未提交public CredentialStore新源及入口/build/tests，当前仍在R1；工程师写域不得reset/覆盖。remote为空、未push。
- 最近完整内部候选仍 `DerivedData/Distributions/0.1.0-1-8b6396199db2/fdb05b4d-a035-4040-8ded-5d549ffadb57/`，来源8b6396199db273493a438679df0020fa6ef7c3a4/dirty=false/version0.1.0 build1。arm64/min26/Development strict/runtime通过，Gatekeeper false/spctl3，未公证/上传/安装运行。ZIP7418092B/SHA256 fc927f568d50f67e8bd17a4c90f94fd666f41a3c1ba41a6d4317153755b7052e；tree499a0902be8e70b847d55b002813c748d43fc83813a0aaa0178b13b35fa45066；manifest4abd40c149a9bcd55c843bf040063d5876f005b06a9812468e32e0131fbcc63f。不能声称包含后续测试基础设施或报告。
- 正式min26长期driver `Tests/StabilityAcceptance/.build/driver-71e5e2da-b345-4c4b-ab54-53b8d128209d/wrapper/OpenLXSSHStability.app`，driver66843ddc286375de474e9823ea7353cd7d77265b5e1a8bf1cbf8a009cf7f625a/helper31d0ee0ee9d357d7edd0bfaf129a9ae4b38334fd8955184f6afc049d685a0590；未运行200/24h，不降平台门。

## 最新独立验证证据

- 短ACK单案原typed报告一致性/时序/三PID实际不存在：`DerivedData/Verification/primary-terminal-postauth-live-14a17ac5-93bd-469e-9124-092d0861ba34/`。结果为失败证据核验通过，非PTY验收通过。
- App49source/既有118tests0fail、Terminal9输入/8父对象、双App主/helper hash和deep strict签名复核：`DerivedData/Verification/primary-app-terminal-frozen-a24c034b-da4a-4254-907e-4f311351baec/`。首次复核脚本误用辅助文件名断言失败，修为实物Contents/Helpers/openlxssh-askpass后通过，无产品改动。主管随后独立再跑Terminal核心128与Python10均exit0，无文件/代次/Docker/socket/live；新日志 `DerivedData/Verification/primary-terminal-offline-checkpoint-7f690b18-1299-467b-80dc-7faaee6f9679/`。
- system-T/-tt：`DerivedData/Verification/postauth-system-ssh-control-b9a22fc3-c911-422e-86fe-c2673e46d3c8/`；两UID分配：`DerivedData/Verification/fixture-pty-metadata-507dc766-f62f-43db-98eb-9cdbfe485afe/`。不重复这些探针。

## 剩余必要工作与外部条件

- 本机可继续：最小定位/修复postauth PTY路径；真实App传输跨close/hide、活动传输window/Quit完整矩阵；远端输入/Ctrl+C/resize/TUI、手动嵌套边界、并发认证/取消late-result；public CredentialStore R1源审及真实持久化的适当授权与条件。未知提示继续人工，不通过终端扫描送秘密。
- 外部仍缺：macOS26真实运行；正式driver200次/五会话真实连续24h；DeveloperID Application/Installer当前0（仅Development1）、对应最终产物Apple上传批准；双机安装、人工IME/Finder/像素、企业允许环境。不能以缩数据/改时钟/HostProbe/多次短测替代。
- 不创建Cron/OffPeak/常驻，不改电源/保护/宿主SSH，不因普通失败停止全部工作。仅必要信息/权限/无替代外部条件才BLOCKED；整体未完成时不得称COMPLETE。

下一具体审点：80f只交最小容器内Linux SSH直连原daemon客户端诊断及离线自有Popen回收/输出白名单，主管先审后决定一次有限运行（临时sshd-i/新监听方案均未实施）；125交stop/durability/error-map纯测试红绿与增量签名审点。App/Terminal源码冻结，已保存18ee766/18761e6检查点，不重跑无新信息的旧案。
