# OpenLXSSH — 工程状态

更新：2026-10-26（Asia/Shanghai）。本文件是当前检查点；历史过程和失败证据见各任务报告及本地 Git，不从旧历史推定当前状态。

## 当前目标、授权与结论

- 同一 Goal：Apple Silicon/macOS26 原生 OpenLXSSH V1.0 可安装 Release，并完成规定验收。**整体 NOT COMPLETE**；本地实现和分项证据不等于真实互通、长期稳定或发布验收通过。
- 范围：四类直连认证/MFA、多个终端标签、手动嵌套 SSH、直连 SFTP、主机/密钥/凭据管理、独立传输与窗口/退出保护。排除自动 ProxyJump、经跳板图形 SFTP、转发、自动重连和恢复。基线见 `docs/requirements.md`。
- 主管负责派工、独立审查与验收；主要编码委派 software-engineer。用户允许验收后仅相关文件的本地提交，无 remote/push 授权。
- 新增 VM/容器、运行隔离服务须具体批准；不启用宿主 sshd、不连生产、不向模型提供公司秘密。公证上传须指定产物、Apple 目的地和用途的授权。没有因 Goal 恢复或子 Agent 消息获得新增授权。

## 当前实际状态

正式 App/Target、Core、Security、Trust、Transport、Files 已集成，正式 arm64/min26。主机/安全 UI、SSH 标签、按需 SFTP 浏览/认证、安全操作、上传下载/冲突/任务/退出保护已有本地分项审查。真实 SSH/SFTP 成功互通尚未发生。

本轮正式Transport对抗测试确证并修复两处生产Mach边界：接收未设置 `MACH_RCV_VOUCHER` 导致既有拒绝检查不可达；发送超时pseudo-return LOCAL send-once未被destroy回收。主管读完整diff与前后证据、聚焦只读复核，并独立Release35tests/readpass6/event4/postexit10/28对抗/28postexit及raw/rights矩阵通过。实际生产差异仅两处最小修复及约束注释，见 `docs/reports/p7-transport-adversarial.md`。最终 `AskpassMach.c` SHA256：`34ee7ffbad3c2f75e60a08c308ae1e7021ae82293826b84bd327c3caa20fbb32`。

五view压力已独立105tests/原生有限场景通过并提交ba4a2ec（不是SSH/PTY压力）。最终C对应App工程师105tests/Release/signed12/8/15/5和退出17/17通过；主管独立匹配九项产物hash/元数据/清理报告并再签名安全12/8/15/5通过。真实min26稳定性driver已新UUID离线重建并主管独立verify，未运行。旧候选不含本轮修复，不作当前证据；相关修复已提交d331188，待主管文档检查点提交后生成干净源码新内部候选。

## 已验收的本地里程碑

| Task / 范围 | 主管结论与主要证据 | 实现/报告 |
| --- | --- | --- |
| P0 环境、依赖、Git、隔离环境与签名调查 | 调查通过，不替代产品验收；未新增运行环境 | `docs/reports/p0-*` |
| P1 本地 PTY、配置/信任、Keychain、认证桥 | PTY14、信任22、Mach/readpass本地控制面；DP Keychain -34018保留，明确选择 file-based Keychain，非静默 fallback | `Experiments/P1-*`、P1 ADR/报告 |
| P2 本地终端 | 16 tests/真实原生窗口；SwiftTerm稳定1.20尾输出丢失独立复现，固定1.99.1 preview；人工IME/远端TUI未验 | P2 ADR/报告 |
| P4 Core 与 Security | Core后续ACL48、Security31及私钥认证材料8/四组合离线libssh2解析签验；真实隔离Keychain CRUD/锁/解锁/default与searchlist不变 | `Packages/OpenLXSSHCore`、`OpenLXSSHSecurity`；P4/P7报告 |
| P5 Trust 与 Transport | Trust Release46；旧 Transport Release35+系统readpass6/event4/postexit10通过，当前 voucher 新修复仍待最终独立验收 | 对应正式包、P5/P7报告 |
| P6 Files 与 Manager | 根枚举/源变化/根自拷修复；service operation lease/shutdown；rootFD/targeted close；主管定向Release34、工程师完整107 | `Packages/OpenLXSSHFiles`、`docs/reports/p6-files-core.md` |
| P5 App SSH/ACL/JournalFD/并发 R2 | 主管68tests、GUI15/8/7/17/17、signed8/8/15/5通过；提交7ed142e | `docs/reports/p5-native-session-ui.md` |
| P6A App文件面板/末次凭据撤销 R1 | 主管89tests/signed，原P2定向resolved；提交90084e4；无真实SFTP | `docs/reports/p6a-native-files-ui.md` |
| P6B1 上传下载/任务/关闭 R1 | 主管103tests、GUI15/8/7/17/17/14/18/17、signed12/8/15/5；late-risk/history两P2复验resolved，提交40853f3 | `docs/reports/p6b1-native-transfers.md` |
| P7 本地文件压力 | 真2GiB/1000往返原名与SHA、25%取消、FD3/9/3、owned0/6/0、精确UUID清理；非远端/PERF | `docs/reports/p7-local-file-stress.md`；提交0e0bf7d |
| P7 稳定性driver准备/构建 | offline34+6+12、真实min26全对象/链接/Development严格静态签名核验；未执行driver/200/24h，旧driver待新C重建 | `docs/reports/p7-stability-driver-preparation.md`；提交8d307a2 |
| P7 有限Instruments | TimeProfiler/Leaks trace成功，Allocations exit20无trace；Leaks空表不等零泄漏，leaks-atExit仅短时0；源/原包不变 | `docs/reports/p7-local-instruments.md` |
| P7 秘密/内容检查 | 344 tracked/index与显式出口/旧候选未见实际秘密，ignore合成例验证；非全历史/运行时证明 | `docs/reports/p7-secret-artifact-check.md` |
| P7 五view本地输出 | 主管105tests、原生76检查/22轮/每view814108 bytes，closed/disposed5、weak0、warm/closedFD16；有限HostProbe，非真实SSH，提交ba4a2ec | `docs/reports/p7-app-output-stress.md` |
| P8 打包器/内部候选 | 主管101fixtures、真实来源/许可/manifest/ZIP验证。最新既有候选见下节，不是正式发行 | `docs/reports/p8-packaging-preparation.md` |

## 当前任务与文件所有权

| Task ID / 执行者 | 当前范围与状态 | 下一验收点 |
| --- | --- | --- |
| P7-TRANSPORT-ADVERSARIAL-REGRESSION / agent_d3fd3a31-8181-40f9-b239-33a910854d24 | 两处生产C最小修复及host-only矩阵已主管独立完整Release验收；工程师Debug/Release/正式min26双配置通过；提交d331188，现停写/停build | 新candidate须包含最终C |
| P7-APP-VOUCHER-AFFECTED-REGRESSION / agent_68d3d86f-9ad4-43cc-af1e-d0df030e6887 | 最终34ee7f…回归105/Release/signed12/8/15/5/退出17+17通过，主管核hash/报告并独立signed通过；已释放构建树 | 不再重复压力/无关GUI，等主管串行pack |
| P7-STABILITY-DRIVER-VOUCHER-REBUILD / agent_091f9d0e-836e-4b72-9773-05cf540931ad | driver-71e5e2da新UUID离线11对象min26、链接/Development严格签名通过；主管独立record verify exit0，未运行driver | 报告及精确hash见 `docs/reports/p7-stability-driver-preparation.md`；无当前build |
| AUTH-REAL-MULTIPROMPT-PINNED-EVIDENCE / agent_87507387-f248-48e2-bcba-807bd602fef8 | 固定MINA2.20.0/commit2221febd…源码与许可研究已交付，仅只读；public API真实单wire多/zero、protected多轮限制已记录；未运行server | `docs/reports/auth-multiprompt-backend-evidence.md`；未来批准环境后固定归档/依赖并实跑 |
| 主管 | STATE、acceptance、报告/ADR及本地审查/验证/提交，不与工程师并写源 | 本轮修复与回归验收后提交，再干净源码新候选及prompt-to-artifact审计 |

其他工程师无当前写入。默认一个业务writer；本轮并行仅分离 Transport fixture、App验证树、只读研究，不改共享锁文件，不重置工作区。

## 关键技术决定与限制

- SwiftTerm1.99.1 preview固定`2f573f73...`，不是稳定2.x；GRDB7.11.1固定`b83108...`，系统SQLite。libssh2 1.11.1 + OpenSSL3.5.9 LTS静态arm64，原生160输出/7notice hash与工具链记录；正式App不依赖Homebrew运行库。
- 显式 file-based Keychain：namespace、同步false、默认creator ACL、串行lease；非ThisDeviceOnly/屏幕锁等价。私钥/DB/trust/config等App专属store拒任何extended ACL且查询失败关闭，不清用户ACL。
- 唯一SwiftTerm LocalProcess拥有PTY/reader/reaper。普通输出与认证控制面分离，不扫描内层提示注入秘密。Mach冻结audit sender，严格identifier/同Team/owner/代次；未知挑战人工。
- 固定LocalCommand helper事件只证明外层认证，不证明shellReady。saved password仅严格passwordOnly/显式授权/已核OS-build/signature gate；当前只24H32，macOS26自动使用仍需实测，不能盲扩白名单，AUTH02完整验收未达成。
- 文件先唯一同目录temp后commit；本地FD/noFollow/RENAME_EXCL，远端lstat不等原子noFollow、覆盖非CAS风险明确确认。noReplace能力须当前服务真实probe授权与证据，不造成功token。
- 当前非Sandbox构建决策见 `docs/adr/v1-runtime-permissions.md`；Hardened Runtime、空entitlements与严格helper身份。不是宣布Sandbox永远不可行，不改变任何系统保护。

## 产物、提交与证据

- 实际分支`development/p1-prototypes`，最近代码提交`d331188`（Mach修复/对抗）和`ba4a2ec`（五view压力）；恢复时旧HEAD `9fed3180a60ab1725d876223033b9a715d8bf13a`不代表当前。`git remote -v`为空。当前仅主管文档检查点未提交，工程师均已停写，不假设clean。
- 最新既有完整B1内部候选：`DerivedData/Distributions/0.1.0-1-9fed3180a60a/0608cf64-e5ba-4ad6-953b-a726167f4b0f/`。源9fed318/dirty=false，Development严格签名/runtime true、arm64/min26；spctl exit3/Gatekeeper false，未公证/未安装/未运行min26。ZIP SHA256 `dbab8a17f3945ccb7d9a2e72b5b3bc576762f1e7ba83604971247d4d7cb7f3bd`。
- 上述候选**不含新 voucher 修复**；不得作为最终安全候选。新产物必须独立UUID，不覆盖旧候选或失败目录。
- 历史里程碑提交和完整文件清单见`git log`及各报告，均仅本地相关文件提交。验证在`DerivedData/Verification`、各包/测试`.build`（忽略），报告不存秘密或完整终端输出。

## 外部条件与整体阻塞

- 当前已核宿主macOS15.8.1/24H32、arm64；Xcode26.3/SDK26.2/Swift6.2.4。正式min26仅编译，HostProbe min15不冒充目标runtime。
- 无已验证可用的VM/container/隔离SSH服务；未新增环境/开宿主sshd/连生产。原建议UTM调查和现统一容器fixture方案详见 `docs/release/acceptance-prerequisites.md`；任何新增环境/下载运行须用户批准。
- Apple Development现有1，DeveloperID Application/Installer均0（仅计数）；无公证上传批准。证书/profile/登录由用户安全准备，Agent不代答系统授权。
- 真实四认证/MFA/多prompt/审批、主机密钥变更、SSH/SFTP、嵌套/TUI/网络异常、200真实连接/5会话连续24h尚未验证。不能用mock、本地循环、短测、改时钟或拼接补齐。
- macOS26实机/双机安装、中文IME/像素、人工Finder/selector与公司允许环境验收待外部操作。详情与必须提供的记录见 `docs/acceptance.md` 和外部前提文档。

## 下一项具体动作

完成的Transport/压力修复已分别提交d331188/ba4a2ec，最终C对应App与新UUID稳定性driver均已审查复核，所有工程师停写/停build。当前主管收敛验收/权限/多提示研究文档检查点，提交后串行生成干净源码Development内部候选并独立verify、记录prompt-to-artifact审计。仍缺隔离环境授权、目标系统、真实互通/长测、DeveloperID/指定产物公证及双机/企业人工结果，整体不能COMPLETE。不得越权新增环境或上传。
