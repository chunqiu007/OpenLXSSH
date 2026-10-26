# OpenLXSSH — 工程状态

更新：2026-10-27（Asia/Shanghai）。本文件是当前检查点；历史过程和失败证据见各任务报告及本地 Git，不从旧历史推定当前状态。

## 当前目标、授权与结论

- 同一 Goal：Apple Silicon/macOS26 原生 OpenLXSSH V1.0 可安装 Release，并完成规定验收。**整体 NOT COMPLETE；已授权的隔离环境运行就绪，当前CONTINUE真实集成验证。** 基础SSH/SFTP、MINA多提示/审批取消和远端完整文件campaign已取得实际证据；完整认证、网络异常、目标系统、长期与发布仍须实测，不虚构运行时Goal状态变更。
- 范围：四类直连认证/MFA、多个终端标签、手动嵌套 SSH、直连 SFTP、主机/密钥/凭据管理、独立传输与窗口/退出保护。排除自动 ProxyJump、经跳板图形 SFTP、转发、自动重连和恢复。基线见 `docs/requirements.md`。
- 主管负责派工、独立审查与验收；主要编码委派 software-engineer。用户允许验收后仅相关文件的本地提交，无 remote/push 授权。
- 新增 VM/容器、运行隔离服务须具体批准；不启用宿主 sshd、不连生产、不向模型提供公司秘密。公证上传须指定产物、Apple 目的地和用途的授权。没有因 Goal 恢复或子 Agent 消息获得新增授权。

## 当前实际状态

当前host15独立production consumer已真实私钥SSH成功（trusted outer-auth1、关闭ownedPID释放，12.85s），以及密码/私钥SFTP微型往返成功与typed错误凭据拒绝。MINA单消息双prompt/echo、零提示接受/拒绝、8s审批接受/拒绝及等待取消已有真实核心证据，主管独立双prompt与pending取消跨decisiondue归零抽验通过。远端完整2GiB/1000小文件及Unicode共1002 payload四manifest实际原名/大小/SHA一致、双向25%取消保原件、权限/链接/当前服务提交能力和资源清理已核并提交15012d3。不是正式mac26/AppGUI或完整AUTH/FILE验收；报告分别见 `docs/reports/real-ssh-sftp-smoke.md`、`docs/reports/real-mina-kbi.md`、`docs/reports/real-sftp-file-acceptance.md`。SFTP首轮5s测试operation握手timeout事实保留，test-only改20后实际复验通过，产品源码未因此更改。

本轮正式Transport对抗测试确证并修复两处生产Mach边界：接收未设置 `MACH_RCV_VOUCHER` 导致既有拒绝检查不可达；发送超时pseudo-return LOCAL send-once未被destroy回收。主管读完整diff与前后证据、聚焦只读复核，并独立Release35tests/readpass6/event4/postexit10/28对抗/28postexit及raw/rights矩阵通过。实际生产差异仅两处最小修复及约束注释，见 `docs/reports/p7-transport-adversarial.md`。最终 `AskpassMach.c` SHA256：`34ee7ffbad3c2f75e60a08c308ae1e7021ae82293826b84bd327c3caa20fbb32`。

五view压力已独立105tests/原生有限场景通过并提交ba4a2ec（不是SSH/PTY压力）。最终C对应App工程师105tests/Release/signed12/8/15/5和退出17/17通过；主管独立匹配九项产物hash/元数据/清理报告并再签名安全12/8/15/5通过。真实min26稳定性driver已新UUID离线重建并主管独立verify，未运行。旧候选不含本轮修复，不作当前证据；相关修复已提交d331188，主管文档检查点8b63961干净源码新内部候选fdb05b4d已生成并独立manifest/归档/签名核验，非正式发布。

## 已验收的本地里程碑

| Task / 范围 | 主管结论与主要证据 | 实现/报告 |
| --- | --- | --- |
| P0 环境、依赖、Git、隔离环境与签名调查 | 调查通过，不替代产品验收；未新增运行环境 | `docs/reports/p0-*` |
| P1 本地 PTY、配置/信任、Keychain、认证桥 | PTY14、信任22、Mach/readpass本地控制面；DP Keychain -34018保留，明确选择 file-based Keychain，非静默 fallback | `Experiments/P1-*`、P1 ADR/报告 |
| P2 本地终端 | 16 tests/真实原生窗口；SwiftTerm稳定1.20尾输出丢失独立复现，固定1.99.1 preview；人工IME/远端TUI未验 | P2 ADR/报告 |
| P4 Core 与 Security | Core后续ACL48、Security31及私钥认证材料8/四组合离线libssh2解析签验；真实隔离Keychain CRUD/锁/解锁/default与searchlist不变 | `Packages/OpenLXSSHCore`、`OpenLXSSHSecurity`；P4/P7报告 |
| P5 Trust 与 Transport | Trust Release46；最终Transport已主管独立Release35+readpass6/event4/postexit10/对抗28+postexit28/rawrights通过，voucher/timeout修复已提交d331188 | 对应正式包、`docs/reports/p7-transport-adversarial.md` |
| P6 Files 与 Manager | 根枚举/源变化/根自拷修复；service operation lease/shutdown；rootFD/targeted close；主管定向Release34、工程师完整107 | `Packages/OpenLXSSHFiles`、`docs/reports/p6-files-core.md` |
| P5 App SSH/ACL/JournalFD/并发 R2 | 主管68tests、GUI15/8/7/17/17、signed8/8/15/5通过；提交7ed142e | `docs/reports/p5-native-session-ui.md` |
| P6A App文件面板/末次凭据撤销 R1 | 主管89tests/signed，原P2定向resolved；提交90084e4；无真实SFTP | `docs/reports/p6a-native-files-ui.md` |
| P6B1 上传下载/任务/关闭 R1 | 主管103tests、GUI15/8/7/17/17/14/18/17、signed12/8/15/5；late-risk/history两P2复验resolved，提交40853f3 | `docs/reports/p6b1-native-transfers.md` |
| P7 本地文件压力 | 真2GiB/1000往返原名与SHA、25%取消、FD3/9/3、owned0/6/0、精确UUID清理；非远端/PERF | `docs/reports/p7-local-file-stress.md`；提交0e0bf7d |
| P7 稳定性driver准备/构建 | offline34+6+12原证据；最终C新driver-71e5e2da全对象min26/链接/Development静态签名已主管独立record核验；未执行driver/200/24h | `docs/reports/p7-stability-driver-preparation.md` |
| P7 有限Instruments | TimeProfiler/Leaks trace成功，Allocations exit20无trace；Leaks空表不等零泄漏，leaks-atExit仅短时0；源/原包不变 | `docs/reports/p7-local-instruments.md` |
| P7 秘密/内容检查 | 历史344 tracked/index+显式出口；最终15文件delta/候选32文件29文本未见新增秘密/敏感材料；非二进制内部/全历史/运行时证明 | `docs/reports/p7-secret-artifact-check.md` |
| P7 五view本地输出 | 主管105tests、原生76检查/22轮/每view814108 bytes，closed/disposed5、weak0、warm/closedFD16；有限HostProbe，非真实SSH，提交ba4a2ec | `docs/reports/p7-app-output-stress.md` |
| P8 打包器/内部候选 | 主管101fixtures、真实来源/许可/manifest/ZIP验证。最新既有候选见下节，不是正式发行 | `docs/reports/p8-packaging-preparation.md` |

## 当前任务与文件所有权

| Task ID / 执行者 | 当前范围与状态 | 下一验收点 |
| --- | --- | --- |
| P7-TRANSPORT-ADVERSARIAL-REGRESSION / agent_d3fd3a31-8181-40f9-b239-33a910854d24 | 两处生产C最小修复及host-only矩阵已主管独立完整Release验收；工程师Debug/Release/正式min26双配置通过；提交d331188，现停写/停build | 新candidatefdb05b4d已包含最终C，无当前工作 |
| P7-APP-VOUCHER-AFFECTED-REGRESSION / agent_68d3d86f-9ad4-43cc-af1e-d0df030e6887 | 最终34ee7f…回归105/Release/signed12/8/15/5/退出17+17通过，主管核hash/报告并独立signed通过；已释放构建树 | 候选已生成，无当前工作 |
| P7-STABILITY-DRIVER-VOUCHER-REBUILD / agent_091f9d0e-836e-4b72-9773-05cf540931ad | driver-71e5e2da新UUID离线11对象min26、链接/Development严格签名通过；主管独立record verify exit0，未运行driver | 报告及精确hash见 `docs/reports/p7-stability-driver-preparation.md`；无当前build |
| AUTH-REAL-MULTIPROMPT-PINNED-EVIDENCE / agent_87507387-f248-48e2-bcba-807bd602fef8 | 固定MINA2.20.0/commit2221febd…源码与许可研究已交付；后续真实构建/运行和六场景证据已由独立任务补齐 | 来源见`docs/reports/auth-multiprompt-backend-evidence.md`，实测见`docs/reports/real-mina-kbi.md`；原研究任务无当前写入 |
| REAL-SFTP-DISKFULL-LIVE-A / agent_80f0dacc-5fe4-42ec-ac4b-3ac1155adba0 | 十源/R1主管源审和14Python30Swift/207input29cmd/sign通过；唯一case a8fc7a19…真实protocolFailure/write4+helpererrno28/满盘0联合、先release、原64KiB metadata/SHA不变、engine temp/本地data清理、6opens6closes/handles0/socket0/noOOMdelta，主管核原result/finalpostflight通过 | relay13846 TERMwait0/1-1-0-0、shm64MiB恢复全空、exacthelpers/PID无残留；source冻结，报告`docs/reports/real-sftp-disk-full.md`，不重跑 |
| SFTP-TERMINAL-ZERO-R1 / agent_12500230-e749-48c1-ada3-95f1f8b3869b | 真实ordinal4空header/count0和固定PAM源码联合后仅testconsumer补精确尾轮，主管完整源审/独立37Swift14Python17CLI、344input36cmd/strict通过，App18b6主程序5893e87f… | source冻结，等待App释放rootruntime后先key-kbd edplain/password-kbd最小组，再key-kbd另外三密钥；必须actualSFTP+79IO，不用empty推定成功 |
| REAL-HANDSHAKE-TIMEOUT-LIVE-A / agent_80f0dacc-5fe4-42ec-ac4b-3ac1155adba0 | 八源主管源审/独立5Python50Swift5CLI/200input29cmd/sign通过，driver0d98b2cb…冻结，现单次占fixed12722221 | 已放行仅本机silentoneaccept/不readsendwire/真实2s握手timeout，全FD任务释放；不Docker/relay/凭据，不扩大TCP SYN结论 |
| REAL-AUTH-FAILURE-LIVE-A / 已验收 | drivere56dad32…真实wrongphrase在正控后authentication/authenticate、已知key mismatch实际handshake.changed/untrusted/旧record不变，另显式replacement后actualSFTP恢复；实际errorcode均nil | source冻结、runtime已释放，relay4/4/0/0wait0、trust/session/keygen/privateabsent；报告`docs/reports/real-auth-failures.md` |
| APP-REAL-TRANSFER-PREP-A / agent_2c8c76ef-77d1-4313-b527-8e49cfe4feae | 四文件最小新phase主管完整读审，独立116tests0fail/49source20cmd/min15/正式min26/sign通过，App853dd2主程序1bccd155…/helper9c85cea6… | source冻结，等待OTP释放rootruntime后唯一16MiB真实inflight关闭SSH/隐藏panel；必须同job/service/gen完成/streamSHA/精确cleanup，早完成不算覆盖 |
| SFTP-OTP-NEGATIVE-LIVE-A / agent_12500230-e749-48c1-ada3-95f1f8b3869b | 新负例源44Swift15Python/348input/sign主管核，真实bad一次24.809s和expired一次90.728s均typed.authentication/authenticate/nilcode、3读3reply/SFTP0/fileops0；C提前取后真实wall+mono过期65.805s再答，主管核两原result时序passed | relay24194 TERMwait0/2-2-0-0，exacttoken/PID/sessiongone，source198未变，runtime已释放；报告`docs/reports/real-otp-negative.md` |
| AUTH-MINA-SOURCE-FOCUSED-REVIEW / agent_d2f36ff0-8a0d-483f-8a57-48e84427d2a8 | 只读原P2已定向resolved，无确证P0/P1；新16tests/旧13failures符合证据，不等运行验收 | 本轮停写，无当前任务 |
| 主管 | 已收到用户本人授权继续，管理Docker官方安装/磁盘/签名与许可边界、文档与独立验收；此前已验本地里程碑不重做 | 安装不代接受订阅协议或系统凭据，真实SSH/SFTP分小里程碑推进，mac26/发布/人工仍待 |

当前三位工程师在互不重叠区域source/offline：App真实传输跨关SSH、HandshakeTimeoutAcceptance（固定loopback握手timeout）、RemoteTerminalAcceptance（无秘密outerPTY/Vim）。RealIntegration OTP负例源/driver冻结，125唯一占rootruntime执行bad/expired两案。AuthFailure已验收/提交5d4ce29，主管另亲跑knownkey真实拒绝/显式恢复新案已通过、relay2/2/0/0释放。共享产品Packages/安全gate/环境不改；正向/ENOSPC/Disconnect冻结，失败保留，五获批容器原CID保留。

## 关键技术决定与限制

- SwiftTerm1.99.1 preview固定`2f573f73...`，不是稳定2.x；GRDB7.11.1固定`b83108...`，系统SQLite。libssh2 1.11.1 + OpenSSL3.5.9 LTS静态arm64，原生160输出/7notice hash与工具链记录；正式App不依赖Homebrew运行库。
- 显式 file-based Keychain：namespace、同步false、默认creator ACL、串行lease；非ThisDeviceOnly/屏幕锁等价。私钥/DB/trust/config等App专属store拒任何extended ACL且查询失败关闭，不清用户ACL。
- 唯一SwiftTerm LocalProcess拥有PTY/reader/reaper。普通输出与认证控制面分离，不扫描内层提示注入秘密。Mach冻结audit sender，严格identifier/同Team/owner/代次；未知挑战人工。
- 固定LocalCommand helper事件只证明外层认证，不证明shellReady。saved password仅严格passwordOnly/显式授权/已核OS-build/signature gate；当前只24H32，macOS26自动使用仍需实测，不能盲扩白名单，AUTH02完整验收未达成。
- 文件先唯一同目录temp后commit；本地FD/noFollow/RENAME_EXCL，远端lstat不等原子noFollow、覆盖非CAS风险明确确认。noReplace能力须当前服务真实probe授权与证据，不造成功token。
- 当前非Sandbox构建决策见 `docs/adr/v1-runtime-permissions.md`；Hardened Runtime、空entitlements与严格helper身份。不是宣布Sandbox永远不可行，不改变任何系统保护。

## 产物、提交与证据

- 实际分支`development/p1-prototypes`，最新已审本地检查点`b28841e`（OpenSSH四flow与断连源码/原首案事实），前一`ed92ac9`（真实基础SSH/SFTP与MINA六场景），完整远端文件提交`15012d3`。候选来源仍`8b6396199db273493a438679df0020fa6ef7c3a4`，dirty=false生成，不声称包含后续测试基础设施/报告。全部本地提交、remote为空；R1后fresh断连完整闭环为之后主管实测记录，待下一文档提交。
- 最新完整内部候选：`DerivedData/Distributions/0.1.0-1-8b6396199db2/fdb05b4d-a035-4040-8ded-5d549ffadb57/`，version0.1.0/build1、源8b63961/dirty=false，包含最终已审C SHA34ee7f…；Development严格签名/runtime、arm64/min26、系统runtime闭包/真实依赖许可、App/ZIP/manifest独立核验通过。`spctl` exit3/Gatekeeper false，未公证/上传/安装/运行min26。
- ZIP 7,418,092 bytes，SHA256 `fc927f568d50f67e8bd17a4c90f94fd666f41a3c1ba41a6d4317153755b7052e`；App规范树摘要`499a0902be8e70b847d55b002813c748d43fc83813a0aaa0178b13b35fa45066`；manifest SHA256`4abd40c149a9bcd55c843bf040063d5876f005b06a9812468e32e0131fbcc63f`。
- 旧9fed318/0608cf64与P6A候选均保留历史不覆盖，不含本轮修复，不再用作当前候选。主程序/helper中压力/adversary专用symbol匹配0；最终内容秘密delta未见确证新增秘密/敏感材料，范围局限见对应报告。
- 历史里程碑提交和完整文件清单见`git log`及各报告，均仅本地相关文件提交。验证在`DerivedData/Verification`、各包/测试`.build`（忽略），报告不存秘密或完整终端输出。

## 外部条件与整体阻塞

- 当前已核宿主macOS15.8.1/24H32、arm64；Xcode26.3/SDK26.2/Swift6.2.4。正式min26仅编译，HostProbe min15不冒充目标runtime。
- 用户本人最新明确批准按 `docs/release/acceptance-prerequisites.md`：官方Docker Desktop安装、必要Ubuntu ARM64镜像/依赖下载构建、四认证及多提示服务，端口仅127.0.0.1:22221～22225，不LAN、不真实凭据/生产数据挂载、不宿主远程登录、不生产连接、不Apple公证上传；需要许可/系统授权由用户亲自处理。此前未作答等待记录已被这次真实授权取代，不再重复询问环境授权。
- 安装前重新核对：宿主仍macOS15.8.1/24H32 arm64，当前磁盘可用73,277,263,872bytes（68.24GiB），满足方案40GiB以上预留；Docker App/CLI/现有settings均未发现，22221～22225无监听（lsof无匹配exit1非检查失败）。先官方来源与签名核验，再安装；默认2CPU/4GiB，硬盘上限及自动启动/许可情况按实物核对，不盲写未文档化设置。
- Docker安装时序记录：官方4.97.0/build244584 ARM64安装于`/Applications/Docker.app`，DMG SHA256 `94e4ccec4a035b7dcdf67cfff0520d4b46ee873ae04b155abc0d22b333cc90ad`；hdiutil/严格Appleanchor+DockerTeam9BNSXJN65R通过，无sudo/--accept-license。首次许可页期间主会话曾停止0container引擎；后来外部GUI持久配置许可版本2/2CPU4096MiB/40960MiB磁盘/AutoStartfalse且Engine实物一致，已解除该等待。Agent未写许可/资源键。
- 官方Ubuntu24.04ARM64固定ref `docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d` 已真实build为image `sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363`，受限no-network探针确认PAM链接Python3.12/包/路径/权限且未auth，主管hash/实际image/23tests复核通过。
- 实际Engine29.9.2/Buildx0.38.1/Compose5.6.1两项兼容缺陷已按实证修复：selected inspect不支持format改严格有界文本；Compose构建context失败改wrapper内部固定builtin buildx。随后project `openlxssh-fixture-61ed25328c13` 四容器首次upHealthy，精确internal/namedvolumes/资源/caps/noegress通过；但纯internal不实际发布127ports，未将配置PortBindings冒充可达。当前采用有限测试转接保留网络隔离，来源/失败/无外网证据均本地.logs，不上传。
- Apple Development现有1，DeveloperID Application/Installer均0（仅计数）；无公证上传批准。证书/profile/登录由用户安全准备，Agent不代答系统授权。
- 已真实验证host15系统OpenSSH四flow正向（keyonly有/无口令Ed25519/RSA、passwordonly、key-kbd Ed25519无口令三轮、password-kbd三轮），MINA双prompt/zero/8s审批拒绝取消核心及完整远端2GiB/1000往返/25%取消/权限链接/当前服务提交能力。断连首案receipt缺失/PARTIAL保留，R1后主管新case完整真实25%→精确TERMreceipt→transportwrite-43→新SFTP binding核原SHA和精确cleanup闭环通过。仍缺错误口令/错误过期OTP/保存凭据gate、SFTP组合认证、hostkey变化/手动嵌套/TUI、磁盘满、正式App真实整合、200创建关闭/五会话连续24h及目标平台/发布。不能用mock/缩数据/短测/改时钟/拼接补缺。
- macOS26实机/双机安装、中文IME/像素、人工Finder/selector与公司允许环境验收待外部操作。详情与必须提供的记录见 `docs/acceptance.md` 和外部前提文档。

## 下一项具体动作

此前本地修复/候选/审计成果保留，用户本人最新明确授权环境已记录，官方Docker安装/验签、官方Ubuntu固定摘要、rootcontext/builder修复、MINA源码与导出清理R1、host15真实生产API消费者离线构建均已完成本轮可独立工作。不重复既有产品测试或重打内部候选；正式平台/信任/秘密要求不降低。

**当前已核Engine-ready：** 外部GUI操作后settings LicenseTermsVersion2/2CPU/4096MiB/40960MiB磁盘/AutoStartfalse，Engine实物2CPU约4GiB；主会话未写许可/资源键。R2修后独立22tests、真实selected builder/context及Compose四服务loopback/internal/namedvolumes/权限资源均通过，证据 `DerivedData/Environment/ready-final-307c9ef8-4dc6-456a-8a77-00a71cd4284b/`。没有再要求用户重复授权或许可。

下一项实际工作：三项source/offline审查准备并行，分别为真实OTP错误/到期、错误私钥口令与knownkey mismatch/显式恢复、App真实SFTP in-flight时关SSH/隐藏panel后继续。每项先独立源审与离线build再串行live，不能用逻辑替身、超时或unknown错归期待拒绝。前述正向SSH/SFTP全部受控矩阵、MINA六核心、完整远端2GiB1000及断连/ENOSPC、真实App keyonly按需SFTP已有报告；App默认scan5在测试relay失败保留，显式testscan15通过，失败store已精确恢复。目标macOS26/200/24h/DeveloperID公证/双机企业人工仍未满足。
