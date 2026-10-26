# OpenLXSSH — 工程状态

更新：2026-10-26（Asia/Shanghai）。本文件是当前检查点；历史过程和失败证据见各任务报告及本地 Git，不从旧历史推定当前状态。

## 当前目标、授权与结论

- 同一 Goal：Apple Silicon/macOS26 原生 OpenLXSSH V1.0 可安装 Release，并完成规定验收。**整体 NOT COMPLETE；工程推进受外部条件 BLOCKED。** 本轮可独立本地补证已收口，不等于真实互通、长期稳定或发布验收通过；未调用或虚构运行时Goal状态变更。
- 范围：四类直连认证/MFA、多个终端标签、手动嵌套 SSH、直连 SFTP、主机/密钥/凭据管理、独立传输与窗口/退出保护。排除自动 ProxyJump、经跳板图形 SFTP、转发、自动重连和恢复。基线见 `docs/requirements.md`。
- 主管负责派工、独立审查与验收；主要编码委派 software-engineer。用户允许验收后仅相关文件的本地提交，无 remote/push 授权。
- 新增 VM/容器、运行隔离服务须具体批准；不启用宿主 sshd、不连生产、不向模型提供公司秘密。公证上传须指定产物、Apple 目的地和用途的授权。没有因 Goal 恢复或子 Agent 消息获得新增授权。

## 当前实际状态

正式 App/Target、Core、Security、Trust、Transport、Files 已集成，正式 arm64/min26。主机/安全 UI、SSH 标签、按需 SFTP 浏览/认证、安全操作、上传下载/冲突/任务/退出保护已有本地分项审查。真实 SSH/SFTP 成功互通尚未发生。

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
| AUTH-REAL-MULTIPROMPT-PINNED-EVIDENCE / agent_87507387-f248-48e2-bcba-807bd602fef8 | 固定MINA2.20.0/commit2221febd…源码与许可研究已交付，仅只读；public API真实单wire多/zero、protected多轮限制已记录；未运行server | `docs/reports/auth-multiprompt-backend-evidence.md`；未来批准环境后固定归档/依赖并实跑 |
| 主管 | STATE/验收/报告/ADR及本地验证已收口；候选独立核验、秘密delta与需求→产物审计完成，未确证新增可独立本地残项 | 整体外部条件BLOCKED，等待具体授权/设备/发布与人工结果，不改Goal为COMPLETE |

其他工程师无当前写入。默认一个业务writer；本轮并行仅分离 Transport fixture、App验证树、只读研究，不改共享锁文件，不重置工作区。

## 关键技术决定与限制

- SwiftTerm1.99.1 preview固定`2f573f73...`，不是稳定2.x；GRDB7.11.1固定`b83108...`，系统SQLite。libssh2 1.11.1 + OpenSSL3.5.9 LTS静态arm64，原生160输出/7notice hash与工具链记录；正式App不依赖Homebrew运行库。
- 显式 file-based Keychain：namespace、同步false、默认creator ACL、串行lease；非ThisDeviceOnly/屏幕锁等价。私钥/DB/trust/config等App专属store拒任何extended ACL且查询失败关闭，不清用户ACL。
- 唯一SwiftTerm LocalProcess拥有PTY/reader/reaper。普通输出与认证控制面分离，不扫描内层提示注入秘密。Mach冻结audit sender，严格identifier/同Team/owner/代次；未知挑战人工。
- 固定LocalCommand helper事件只证明外层认证，不证明shellReady。saved password仅严格passwordOnly/显式授权/已核OS-build/signature gate；当前只24H32，macOS26自动使用仍需实测，不能盲扩白名单，AUTH02完整验收未达成。
- 文件先唯一同目录temp后commit；本地FD/noFollow/RENAME_EXCL，远端lstat不等原子noFollow、覆盖非CAS风险明确确认。noReplace能力须当前服务真实probe授权与证据，不造成功token。
- 当前非Sandbox构建决策见 `docs/adr/v1-runtime-permissions.md`；Hardened Runtime、空entitlements与严格helper身份。不是宣布Sandbox永远不可行，不改变任何系统保护。

## 产物、提交与证据

- 实际分支`development/p1-prototypes`，候选来源`8b6396199db273493a438679df0020fa6ef7c3a4`；此前修复`d331188`、压力`ba4a2ec`，全部本地提交、remote为空。候选生成时dirty=false，随后仅主管验收/产物/审计文档继续更新，不声称候选包含尚未提交的后续文档。
- 最新完整内部候选：`DerivedData/Distributions/0.1.0-1-8b6396199db2/fdb05b4d-a035-4040-8ded-5d549ffadb57/`，version0.1.0/build1、源8b63961/dirty=false，包含最终已审C SHA34ee7f…；Development严格签名/runtime、arm64/min26、系统runtime闭包/真实依赖许可、App/ZIP/manifest独立核验通过。`spctl` exit3/Gatekeeper false，未公证/上传/安装/运行min26。
- ZIP 7,418,092 bytes，SHA256 `fc927f568d50f67e8bd17a4c90f94fd666f41a3c1ba41a6d4317153755b7052e`；App规范树摘要`499a0902be8e70b847d55b002813c748d43fc83813a0aaa0178b13b35fa45066`；manifest SHA256`4abd40c149a9bcd55c843bf040063d5876f005b06a9812468e32e0131fbcc63f`。
- 旧9fed318/0608cf64与P6A候选均保留历史不覆盖，不含本轮修复，不再用作当前候选。主程序/helper中压力/adversary专用symbol匹配0；最终内容秘密delta未见确证新增秘密/敏感材料，范围局限见对应报告。
- 历史里程碑提交和完整文件清单见`git log`及各报告，均仅本地相关文件提交。验证在`DerivedData/Verification`、各包/测试`.build`（忽略），报告不存秘密或完整终端输出。

## 外部条件与整体阻塞

- 当前已核宿主macOS15.8.1/24H32、arm64；Xcode26.3/SDK26.2/Swift6.2.4。正式min26仅编译，HostProbe min15不冒充目标runtime。
- 无已验证可用的VM/container/隔离SSH服务；未新增环境/开宿主sshd/连生产。原建议UTM调查和现统一容器fixture方案详见 `docs/release/acceptance-prerequisites.md`；任何新增环境/下载运行须用户批准。
- 环境授权已通过明确选择询问提交，工具返回用户未作答；这既不是同意，也不是拒绝。后续仅收到自动Goal续跑通知，没有用户本人新增授权。当前等待真实用户答复，不重复弹出同一授权问题、不自动重试安装/下载/服务启动，也不创建定时或闲时任务。此为工程等待状态，不表示已暂停运行时Goal或已完成目标。
- Apple Development现有1，DeveloperID Application/Installer均0（仅计数）；无公证上传批准。证书/profile/登录由用户安全准备，Agent不代答系统授权。
- 真实四认证/MFA/多prompt/审批、主机密钥变更、SSH/SFTP、嵌套/TUI/网络异常、200真实连接/5会话连续24h尚未验证。不能用mock、本地循环、短测、改时钟或拼接补齐。
- macOS26实机/双机安装、中文IME/像素、人工Finder/selector与公司允许环境验收待外部操作。详情与必须提供的记录见 `docs/acceptance.md` 和外部前提文档。

## 下一项具体动作

本轮修复/压力/最终App回归/新driver与干净源内部候选均已主管审查复核，秘密内容delta和需求→产物审计已完成，详见 `docs/reports/v1-prompt-artifact-audit.md`。所有工程师停写/停build，没有持续运行的测试或长测。最后仅文档记录提交，不改变候选源8b63961或重打相同代码。

下一项必要动作依赖外部条件：用户批准具体隔离runtime安装/镜像下载构建及127.0.0.1测试范围，并提供macOS26实际设备条件，才可完成AUTH02适用gate与四认证/MFA/SSH-SFTP/嵌套/TUI/网络异常以及真实200/24h；DeveloperID准备、针对对应最终产物的公证批准、双机/企业人工随后按计划。当前无这些授权/条件，不能绕过，也不能用再跑相同本地tests推进状态；整体NOT COMPLETE/外部BLOCKED。
