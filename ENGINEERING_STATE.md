# OpenLXSSH — 工程状态

更新：2026-10-28（Asia/Shanghai）。本文件是当前检查点；历史失败保留在报告和本地原始结果，不从旧阶段描述推定当前状态。

## 当前权威检查点（2026-10-29，CONTINUE）

- **23:25核对：本轮24h已中断，未通过，不再RUNNING。** 6F5F0F5C最后样本21:36:35.842，共1024完整样本/原六身份不变，connected后awake/continuous34694.635287秒、wall34694.739441秒（约9h38m14.739s），无end/cleanup，sessions目录留存。主管严格identity复核driver/五SSH/relay均GONE，22221～22225无监听；不等正常清理有证。系统记录driver55678在21:37:00 proc_exit，ChatGPT桌面端21:37:05退出并重新启动；两原exec session已Unknown process id，退出码/信号未知。疑为桌面重启关联，尚未确证因果；宿主未重启，未见该窗口sleep/wake，keyonly原容器健康/未重启/OOMKilled=false。独立报告primary-interruption-review-4ff301ea-6bf0-4718-beb0-658b0e694f11.json与primary-system-exit-6b153fbf-fd6a-4ee6-8a04-ef50197eaaf7.json。原证据保留，不拼接/不自动重跑。Terra22:00已将openlxssh-24h-terra实际设PAUSED，原200通过不受影响。下一项先确认应用重启情况并改善有限测试进程存续/退出记录，再安排新的完整24h；本轮仅调查，没有启动新测试或更改产品。

- 新200+20已完成并独立复核：6FE08664案424行/2538.540682秒、200auth/20cancel/220closed、695资源样本全complete，全部closed与cleanup均FD5/PTY0，driver47157已不在、sessions目录消失。closed RSS前20均37573427B/后20均36481434B，无本案持续增长证据；仅driver/所观察SSH与helper范围，不宣称SwiftTask全数或App零泄漏。报告primary-200-review-4d820158-588c-49eb-a310-2abb34fe0c8b.json。旧失败不改。relay42333已正常TERM/exit0，accepted898/rejected0/finished898/cleanup_failed0，原端口释放。只读pmset当前AC sleep0/displaysleep0，未更改电源设置。

- 正式产品代码仍来自3ee3a68的1.0.0/build3；候选来源4616677相对产品基线只包含长测工具串行准备及验收/指南记录，没有改产品认证或终端实现。后续源审/本地提交允许，不推送/生产连接/Apple上传。
- 成本分工：主管处理复杂诊断与关键小修；常规测试/构建/回查明确指定gpt-6.1-terra / medium。本轮两Terra已实际完成有限GUI资源、28项测试、干净源driver构建/验证；没有需交ZCode的大规模代码任务。
- 正式五会话有限场景与退出观测已独立审过，125.139 MiB均/125.516峰（App+SSH RSS）、公开输出峰135.438 MiB，五SSH正常退役，App暖态FD16/PTY0。原突发第五扫描失败仍PARTIAL，未确证拒绝原因，未改产品或扩中继限额。
- 本轮24h历史启动记录（现已中断）：2026-10-29 11:58:21.102844+0800五会话connected，driver55678/PPID55677/UID501/birth1793246237.956792，Terra session24279；relay55592/PPID55591/UID501/birth1793246174.567155/session9307，max-duration90000。新原始目录stability-6F5F0F5C-4663-4D0F-AD5A-250FAAD0F4A8（仍在既有Takeover根），handoff-30b90068-42f6-41dd-9de2-1bc9fc9b4905.json记录完整命令/日志/身份，主管primary-start-review.json实际核driver+五SSH+relay严格身份及后续样本完整。source cdf47ac dirty=false/163源核过，未重建。最早墙钟预计2026-10-30 11:58:21，最终以真实三钟/连续会话/cleanup检查为准，本轮现已中断，不能标通过。
- post-close leaks274项/9232B保留。主管自建仅17行标准SwiftUI公开控件对照（无任何产品导入/SSH/用户数据）在相同宿主也复现：baseline288项/14400B，12次展开收起后317项/15728B，并出现13个AXObserverCookie及NSArray增长；原App244NSArray+30AXObserverCookie。这是独立于SSH代码的UI/观察路径复现，不宣称原App无泄漏或最终OS归因已证；作为系统UI/自动化相关局限留档，不无根据重写产品。对照45520已正常退出，原数据不改。
- 正式App私钥MFA三轮及密码MFA三轮均已进入真实shell并有唯一公开marker；独立密码MFA SFTP也已就绪、列出根目录21项。新SFTP session b552fc09c6fff1467f984650：connect1793243113395ms、A首次见1793243129355、A/B/C提交1793243180491/3183865/3187087、zero空通知立即确认1793243189371；ready明确观察1793243258734仅145.339s上界，不能当首次就绪耗时。原过期/缺C/超时案仍PARTIAL。fixture LoginGraceTime90，原脚本C后额外等待10秒可能撞窗口，但无总时序不能确证；只改测试动作等待/空通知即时确认，没有改产品/服务器超时或安全规则。所有精确本地/服务器挑战清理，新认证自然扫掉原过期残留，原失败不改绿。
- MFA测试后正式App正常退出；200已完成，原24h现已中断，原driver/relay均消失；后续新长测仍禁止正常App/API消费者同跑。DeveloperID新签名的实际helper认证挑战留待长测后验证，不能以无口令keyonly替代动态helper门。
- 用户已明确批准长测后使用独立定时任务、gpt-6.1-terra/medium、每30分钟（可产生独立任务记录）。项目ID6ecb2326-68f3-4568-b9b0-18f3703560a1；真实启动并主管复核后已创建独立cron openlxssh-24h-terra，创建时确认ACTIVE、gpt-6.1-terra/medium、每30分钟、local原目录；发现本轮中断后22:00已实际PAUSED，主管核对保存状态一致。健康时安静，仅新异常/结束/必要人工通知，完成本轮收口后停用；旧heartbeat未恢复。
- 用户已明确批准现有1.0.0/build3候选的DeveloperID签名和Apple时间戳请求（不上传App/私钥），不含公证上传。允许Terra现有配方执行并静态验证；签后具体ZIP/摘要/Apple目的地仍须单独确认，不能因当前许可自动notary。 新DeveloperID候选已按4616677干净源唯一生成：DerivedData/Distributions/1.0.0-3-4616677a3edc/89cfceaa-a6fb-45fd-8f67-07d430438ef0，ZIP e91a18d2d75b2cef32f82b1ea1cfe9356ac3f31a24577565b07ac43ed9ccb7a8/7318818B。Terra配方及manifest复核0；主管另逐个核主/helper anchor+identifier/DeveloperID/同Team/Runtime/时间戳字段，均通过。主管最初-R少内联等号导致命令语法失败，修正记录在primary-developer-id-review.json，不当签名失败。spctl3仍拒绝，未安装/运行此签名新候选，notarized/uploaded=false。
- key-kbd新gen4ba4ddb1aa91/22223/FPzzZ9B7L8srAQFmIettj3r/r1XwuSSfvZFAs8K2SmWvE；password-kbd genfcdd0ef62707/22224/FPM89ZPAwqBO3k4+50seWt4j0oCpqAamqWCicE+q1hibc。原有限relay42333/session56672已正常退出，原90000秒relay55592也已在中断窗口消失。不得同时运行正式App与stability wrapper。
- 已允许仅自建一次性Keychain测试；DeveloperID证书现可用，签名时间戳已获本轮明确批准，具体最终产物公证授权仍待按文档处理；第二台Mac/人工IME/Finder/企业及内层密码OTP仍需用户记录。以下各节是此前证据，状态冲突以本节及未来真实结果为准。

## 后续检查点（2026-10-29）

- 新driver-c12524dc已由Terra按cdf47ac干净源唯一构建/verify，均exit0；inputSet5650161270e9a404c5c8d13a3e2e6d6df03b7ee540ba51d96f9edb1b68bd7a27，main0267f3830300503dc860a138b2e857b52645e19e5f00a498ac29d3a99a536253/helper0cd6932587b690be8fbc3b6a1594f4cffdcce14ce539231e69d1c8ec766c57de，arm64/min26/严格Development/Runtime/同Team/无权限。记录driver-c12524dc-1779-4687-82aa-a0efbe9d9090/result.json，尚未live，不再用旧a215。
- 新post-close真实leaks一次exit1：150267 malloc nodes/22396KB，274 leaks/9232 bytes。主管对原图分类：244个NSArray根和30个AXObserverCookie，没有在这份报告中列出产品会话/终端类；这提示无障碍观察相关，但**归因尚未证明，不能声称无泄漏或已修复**。原始0600日志leaks-review-93b5b6c5-c0d9-40aa-9502-34bb1e436fb6/output.log保留，先前空闲0只属于先前时点。5会话RSS预算与退出PID/PTY证据仍按原有限范围有效。
- 已通过正式guarded collect分别生成key-kbd credentials-4ba4ddb1aa91、password-kbd credentials-fcdd0ef62707，内容未打印，仅用于接下来尚未覆盖的正式App MFA UI桥接；不重建容器、不连接真实服务器。当前App零标签，接手GUI后还未执行MFA，200/24h均未开始。

## 最新验收检查点（2026-10-29）

- Terra/medium已完成正式build3串行五会话有限验收，主管独立从JSONL重算：319.865781秒/64样本，真实SSH始终5、全指标完整，App+SSH RSS均125.139/峰125.516 MiB，FD96、vnode PTY描述符35；该口径重复计算共享页/PTY描述符，不是唯一设备数或Swift任务数。
- 公开输出+快速切标签132.954083秒/27样本，仍5SSH，RSS均131.601/峰135.438 MiB；命令定义780000B/120批，末尾marker及随后输入回显实际可见，未独立逐字节核对实收。恢复marker至closed含关闭过渡，不把整段当5会话恢复；closed至finite-end204.853927秒/40样本仅App、FD16/PTY0、五SSH confirmedGone。采样自然exit0、1000.004542秒、remainingObservedChildren0。证据UUID748fbfed-3011-4e53-a4f7-672aa340a941，同gui-resource-e433目录；主管primary-review-748fbfed.json独立重算。
- 原快速连续创建案仍PARTIAL：四认证/第5扫描失败，中继18accepted/1rejected/18finished/cleanup_failed0，精确relay41403正常TERM后exit0。静态计数没有拒绝原因，不能确证并发上限或产品Bug。源审确认scanner三流/relay每端口8，本轮不改产品或扩中继限额；串行正常创建5项是有区别的新案，不回写旧失败。
- 主管亲自小修仅长测工具准备顺序：connectFiveSequentially每次要求真实认证+owner并持续检查此前连接，再建下一项；取消/睡眠/错误/此前断开拒绝，每项最多600次原50ms等待。五项全部满足后才开始原86400秒时钟，判定与cleanup保持。Terra独立一次定向XCTest28项/0失败（新增5项），真实命令/退出/cwd/output在unit-0e3a2dc6-6096-4f86-8681-f184c52aa96f，主管源审和日志核对通过。需要按新源码构建唯一新driver，旧a215不冒当前来源，尚未200或24h。
- 当前正式App25406/0标签，唯一有限relay42333（Terra session56672）继续供后续认证，完整实时tee日志gui-relay-serial-739f963d-e2ac-4f51-a41b-f33b8a3ca58d.log。runtime/GUI已交主管；后台测试进程本身不依赖模型容量。
- 用户询问的at capacity按模型服务暂时容量不足处理，不把它当作测试失败或重复已完成工作的理由；执行分工继续遵守用户指定的Terra/medium。

## 执行恢复与成本分工（2026-10-29）

- 用户已明确要求继续执行，取消上一轮“只说明不操作”的停止点。复杂Bug定位/关键修复由主管亲自处理；方案明确但大量编码的任务形成ZCode任务包，不自行扩大实施；已有脚本的常规测试和定时检查指定gpt-6.1-terra / medium。主要编码默认委派的旧约定服从这一最新分工。
- 已派 `/root/terra_gui_acceptance`，实际工具请求模型gpt-6.1-terra、reasoning_effort=medium，独占正常App GUI与普通资源验收。只复用现有build3和采样器，不改tracked代码/共享文档，不运行200/24h或新增环境；未知/失败保留并交主管，不自行修核心逻辑或重试消除失败。
- 本轮先完成真实五会话/公开有限输出/切标签/恢复/关闭释放；主管同时准备剩余认证和发布审核，不与该工程师争用GUI或测试runtime。200与24h串行跟进，必须先记录真实启动后才建立回查，不能提前宣称长测运行。
- 上轮三份未提交状态/报告改动已识别并保留；正式源码当前3ee3a68，未因恢复任务重做已验大文件或旧campaign。后续按验收证据提交相关文档，不全量暂存。

## 自动回查核对（2026-10-29）

- **24小时测试尚未启动，没有有效长测可监控。** 当前仅发现首轮cycles的原failed证据；修复后driver-a215d18a无运行进程或新evidence。未重复启动、改时钟、电源或连接服务器。
- 正式App资源短测已正常结束exit0，960.010223秒/192样本，最大观察SSH数为0；虽然写过fiveSessions阶段marker，实际未建立五会话，不能把该marker或finishedFiniteScope当五会话/输出验收。现有数据仅空闲App RSS 106.515625～111.03125 MiB、FD固定11，不证明五会话预算、输出压力或完整释放。原始行不改写。
- App原PID25406在本轮只读核对仍为同一启动时间；原有限relay PID24420已不在运行。没有将应用仍打开当作24小时五会话。
- heartbeat `openlxssh` 实际已提前ACTIVE并产生回查，与下方此前PAUSED记录不一致。因为并不存在约定的24h测试，本轮已通过工具**删除**该无效回查（deleteStatus=deleted），停止空转。用户此前同意真实长测后每30分钟回查的授权仍保留；实际启动并记录精确身份/来源/证据后再新建，不因本次删除要求重复授权。
- 下一项仍是收口正式App五会话/有限输出资源测量与剩余必要GUI桥接，随后修复后200次验收、再启动唯一真实五会话24h。整体未完成；不在这次仅监控既有测试的heartbeat中擅自启动新测试。
- 核对时间：2026-10-29T03:18:24+08:00。下方为此前接手记录，涉及“正在idle/回查PAUSED”的描述以本检查点更新为准。

## Codex 接手检查点（2026-10-28，进行中）

- 用户已要求由当前 Codex 主会话接手剩余开发和验收，不重复 ZCode 已完成且未受变化影响的工作；下方 ZCode 最终检查点保留为历史基线，不能将其中 host15/等待目标设备描述当成当前事实。
- 接手基线 `0711b24`，`development/p1-prototypes` 工作区干净。实测宿主 macOS 26.7.1 / 25G241 / arm64，Xcode 26.3 / 17C529，系统 OpenSSH 10.3p1 / LibreSSL 3.3.6，接手时磁盘约 119 GiB 可用。
- 用户本轮明确允许仅本轮新建的一次性测试 Keychain 条目保存、读取、忘记/删除及失败回退；不枚举或读取其他条目，系统交互由用户本人处理。此授权取代旧的相应待授权记录，不含 Apple 上传或账号安全操作。
- 当前仍只有 Apple Development 身份，Developer ID Application/Installer 均为零；Docker 已安装但升级重启后 Engine 尚未运行。复用原已批准隔离环境，不新增环境或连接生产服务器。
- `TAKEOVER-MAC26-AUTH-GATE-R1` 已完成兼容矩阵、扫描默认10秒与定向回归，主管源审和独立四项测试通过；`TAKEOVER-MFA-FIXTURE-AUDIT-CAP` 的最小三服务权限同步已源审、离线检查并实际应用，四服务 healthy/keyonly身份及隔离资源不变。详见 `docs/reports/mac26-takeover.md`。
- `TAKEOVER-MAC26-FROZEN-RUNTIME-BUILDS` / `software-engineer`：当前只构建新冻结源的正式 min26 稳定性驱动与测试专用 API 消费者，禁止自行 live。主管已独立验证新 driver-5ae677f7 来源、对象 min26 与严格 Development 签名。下一项为新系统真实密码/Keychain、正式App运行、200次与24h；不重复既有大文件 campaign。
- 接手修复已提交 `d35b67e`；候选版本元数据 `6124bbe`（1.0.0/build2）。新 host-65b125b1 消费者在 mac26 上真实完成一次性默认Keychain save→provider精确read1/return1→outer-auth1/manual0→deleteExact→missing→close/交互策略恢复，主管另仅查询该测试service，exit44确认不存在。无授权对照provider0/manual1/read1/reply1及释放通过；测试wrapper min15/scanner15，不冒正式AppUI/default10。独立review核367源/快照和实际摘要通过。
- **首轮200次驱动已结束exit1，不要追认为通过**：driver-5ae677f7，原session19097；证据 `DerivedData/Takeover/mac26-8834149cacad467585fd03a34f6379ec/stability-1A8BB3F2-5812-4F02-8DF0-36E8A6737BFF/evidence.jsonl`，2546.129秒，200auth/20cancel/220closed均完成；6个connected样本的短命helper PTY指标=-1/complete=false，最终failed resourceUnavailable。所有cycleClosed与最终cleanup均driver FD5/PTY0完整，但不能由此删掉坏点或改原failed。测试工具修复已独立源审及23项主管回归通过：仅精确EBADF+稳定身份+完整新列表证实FD已消失时一次真实重采；未知/权限/短读/再次竞态仍失败，已精确路径匹配helper的UNKNOWN不再静默忽略。旧坏点不能倒推为此竞态。新driver-a215d18a构建/严验0、163输入匹配、arm64/min26，尚未live。
- 有限relay PID8872已到7200秒正常退出0，relay-campaign.log记录868 accepted/finished、cleanup_failed0。四owned服务身份/隔离配置保留，keyonly CID ed38148af68e、generation c5fd32c839fc、带外FP d2G+w7lBrjYDFHHd6c6GxIhk7qzFs6df1i7EVJfeUYs。后续先恢复既有有限relay，不重建健康容器。24h尚未启动。用户允许每30分钟临时回查，本会话heartbeat openlxssh已建PAUSED；仅实际长测启动并记录精确PID/证据后激活，正常运行安静、完成后停用。
- 当前干净源内部Development候选已生成一次，目录 `DerivedData/Distributions/1.0.0-2-6124bbeb4201/47f7c768-0a3c-4ecc-a46a-c284b84e991e/`；ZIP SHA256 c23155d8ebe73610accbb9f638f74c17424cbf1fe3bfe6feb22aac3055360434，strict/min26/源码6124bbe dirtyfalse，spctl3拒绝/未公证。主管复核后待正常目标系统UI运行；不可与稳定性driver同时启动，不移除quarantine或绕过保护。
- 上述候选已用正常复制安装到 `~/Applications/OpenLXSSH.app`，签名复制后严验通过；主管经CUA首次真实GUI启动发现storage.unsafeLocation，默认ApplicationSupport父目录UID当前用户/mode0700/唯一OS标准ACL `group:everyone deny delete` 被ensureAppParent blanket noACL误拒，App专属目录尚未创建。旧候选是失败证据，已正常退出。`release_reviewer` 独占AppFileSecurity/AppRepository/AppACLTests补精确父目录保护性ACL策略，App-owned子目录仍任何ACL拒绝，不清系统ACL。修复已源审，主管独立4项新AppACL测试通过，精确允许系统父目录唯一非继承everyone deny delete、App-owned仍任何ACL拒绝，父目录不变及拒绝边界有回归。build3元数据已同步三配置，下一步提交后生成新候选重验正常安装路径，不以HostProbe临时目录代替。
- 修复提交 `3ee3a68`，1.0.0/build3 Development候选目录 `DerivedData/Distributions/1.0.0-3-3ee3a68a9e24/2d18e43a-83d8-49ee-b636-c929bd7873b2/`；主程序SHA256 e629a9984807c8c6904b104172b87df0a0c0e97a4211d96555bdeca5d4c9e3ae。正常复制/签名校验/首次启动通过，Application Support父目录mode/UID/GID/dev/inode/flags及ACL逐项未变。原build2保留独占证据目录，没有清ACL或绕过Gatekeeper。
- build3正式GUI已真实验证：主机编辑记住本轮一次性密码→带外核对22222指纹→无人工prompt outer-auth/shell；原生粘贴公开中文printf正确回显。SFTP独立连接、显式能力检查、独立风险确认后上传/下载36B，源/远端/下载SHA一致；远端只精确清理本轮专用目录及该文件。UI忘记后凭据管理不再列关联，重连出现人工challenge并实际输入成功。正常退出/重开两次只恢复两条测试配置、0会话；不冒充完整IME组合输入或四类MFA UI矩阵。
- Developer ID Application已按类型计数检测到1，Apple Development1，尚未使用Developer ID签名/请求Apple时间戳/公证上传。用户准备证书不等于具体产物上传授权。
- 正式build3准确PID24956的TimeProfiler20s、Allocations20s、Leaks30s顺序attach均exit0；Leaks trace无可导出扫描表，不凭空表称零。正常退出重启新PID25406后，另一次真实leaks扫描exit0：106811 malloc nodes/14853KB，0 leaked bytes，仅该空闲时点。随后启动未插桩阶段资源测量，独占 `Tests/StabilityAcceptance/.build/gui-resource-e433eba4-13a1-449b-9498-430a7b1e8d80/`，session37311，PID25406/UID501/birth1793198820.263134，960秒/5秒采样，阶段marker独立；未知资源/身份/时钟拒绝。当前idle，未先标PERF-R或AC30完成。
- 整体仍未完成；不把接手、升级或既有构建结果当成 Release 验收通过。所有原失败与已验收分项保留，不回写改绿。

## 当前目标、范围与授权

- 同一 Goal：Apple Silicon/macOS 26 原生 OpenLXSSH V1.0 可安装 Release，并完成规定验收。**整体 NOT COMPLETE；当前 CONTINUE，macOS26及默认Keychain授权已具备，正在补正式App资源与剩余验收。发布/人工条件继续保留，旧host15状态不得当作当前阻塞。** 不虚构运行环境 Goal 状态变更。
- 范围：四类直连 SSH/MFA、多标签、用户手动嵌套 SSH、直连 SFTP、主机/密钥/凭据管理、独立传输与窗口/退出保护。排除自动 ProxyJump、经跳板图形 SFTP、转发、自动重连/恢复。基线见 `docs/requirements.md`。
- Primary 是唯一主管，主要编码交 software-engineer；工程师 DONE 不等主管验收。用户授权验收后的相关本地 Git 提交，没有 remote push、发布、生产连接或 Apple 公证上传授权。
- 用户已明确批准官方 Docker Desktop、固定 Ubuntu ARM64/必要依赖、四认证及多提示隔离服务。宿主端口仅 127.0.0.1:22221～22225，不 LAN、不真实凭据/生产挂载、不宿主 sshd、不生产连接、不 Apple 上传。Agent 不代接受法律协议或输入系统凭据。不再重复“等待 Docker 授权”。
- 许可与引擎条件已实际核验解除；公证需展示具体产物/Apple 目的地/用途后另获批准。公开 CredentialStore 持久化消费者当前仅 source/offline，未放行真实默认 file-based Keychain save/read/delete；测试事故开关不构成额外授权。

## 历史基线：ZCode本轮最终检查点

- 当前正式App源码分项提交 `fa5191d`；最新HostProbe实际160tests/0failure（旧156保留），仅测试配置min15，不冒目标系统。公开consumer保活17Python pure/83Swift实际断言及A正常＋R2 B黑洞真实门已审，提交 `4c89e23`。
- 本轮真实分项主管独立验收：htop、原生双向搜索/53B内存Bracketed Paste、双标签复用/自然退出历史/原生手动重连、批skip→新batchrename与独立风险、批overwrite逐item风险、16MiB正字节在途切标签、加密私钥原生取消恢复、真实keyscan变化拒绝/原生信任管理恢复、双真实pending认证UI归属。
- 最终shipping D对应 `fa5191d` 源码：Debug/Release各一次真实compile/Ld、arm64/min26/SDK26.2、19cmd全0/106输入/许可/系统动态库/运行测试代码隔离，主管独立复核通过。未运行min26、未签正式产品/打包/公证。Release字节SHA仍110b2…但实际WMO27输入/Ld1有原日志。
- 本轮43个公开变更文本、当前tracked路径及显式secret消费者限定检查无秘密特征/误入运行凭据；不等全历史/任意编码/二进制/内存/所有ignored日志证明。原并发MFA cleanupIncomplete与原黑洞control/-9失败保持，恢复及后续通过不回写原结果。
- 当前无active writer/runtime，批准22221～22225无listener，已核测试所属PID/FD/store清理。容器保留原已授权隔离状态，未开启宿主SSH或更改系统网络/电源。
- 重新只按身份类型计数：Apple Development1、Developer ID Application0/Installer0；宿主仍macOS15.8.1/24H32。磁盘最近118GiB可用是瞬时观察，不沿用为新增安装批准。
- 集中必要条件见 `docs/release/acceptance-prerequisites.md` 最后章节；整体仍缺目标mac26及正式200/24h/Release压力资源报告、默认Keychain真实动作放行、DeveloperID/具体产物Apple上传、双机/人工/企业验收及剩余工具合法运行条件。不得因再次“继续”默认补齐这些授权或平台。

## 历史诊断与已验收过程（不代表当前未修）

1. 原生 App 第二个真实上传案，在关闭 SSH/隐藏面板动作之前 SSH 已 failed/PID 不存在，而独立 SFTP 仍 running/720896 bytes。两个上传案均未通过，不能说关闭触发故障或跨关闭已验证。
2. 系统 `/usr/bin/ssh` 同参数/同固定远端 printf，仅 `-T`/`-tt` 不同：无 PTY exit0/6.305s/52B ACK 精确匹配；强制 PTY exit255/15.792s/stdout0/stderr0。不是外层 timeout，不等认证拒绝。
3. 同 exact 容器 UID0 和 UID10000 各一次 `pty.openpty()` 均成功，FD4→4；不能归因为“所有 PTY 无法分配”，不据 capability 名称猜加权限。
4. 新短 ACK 诊断真实单案：outer connected t12.455643，73B 非秘密命令 t12.473894 入队，t21.722916 结束，真实 `.failed(.launchFailed)`/lastExitCode255，stop=false。shellACK=false/probeEvents0/**原 loader 从未发送**。入队也不证明远端执行。
5. 进一步容器内Linux SSH直连原daemon 127.0.0.1:2222，不经宿主relay亦exit255/0.241257s、stdout0/ACK=false。前后pids4/128/Z0/confighash不变，排除“必须经过relay才失败”，不支持PID耗尽；原sshd stderrDEVNULL，无错误日志证据，不猜根因。
6. 临时同image/caps单会话debugsshd已真实命中固定`linux_audit_write_entry failed:`（audit-fatal），server/client255、errno集合1/30，不将集合强配时序。原helper ownedProcessesReaped=false/exit2保持PARTIAL；独立外层确认无debugPID/2223listener/临时目录、pids4/Z0/原daemon20-start430及confighash不变。上游audit源码与官方cap定义支持AUDIT_WRITE bit29为最小候选，尚未改变任何cap。
7. 单变量实测已通过：fresh串行A/B同image/config/资源/internal/nohostports，A原7cap -T0/-tt255无ACK，B仅增加AUDIT_WRITE bit29、实际sshd Eff/Prm/Bnd0x200400eb，-T0/-tt0精确LF/CRLFACK。总41.350s；两临时container/vol/network已精确删除，主管独立run标签查询全0、originalUnchanged=true。证据 `docs/reports/pty-audit-capability.md`，已本地提交619f3c6。先前首pair12s元数据超时/资源0失败保留，R1专用20s前置预算与失败记录/9回归已过，不改身份门。
8. keyonly最小修复已真实落地：新CID `1253a29501483eb71f80e39b9af5c85e10c3a49329d5e93700fecd3f00f334f2`，新FP `SHA256:MHUel445tN/gQtcvZikLZVE1mlWZf7U38C0zZTTru+Q`，仅增加AUDIT_WRITE；原卷/NetworkID及另三服务CID/StartedAt不变。manager action先exit1/incomplete且新容器Created，主会话只exact start一次恢复Healthy；原失败不追认通过。新daemon-tt真实0/53B CRLFACK/.235s。报告 `docs/reports/keyonly-audit-fix.md`。端口预检reservation持有到Compose可能干扰启动，正仅source/offline最小释放顺序R1，no第二次recreate。
9. 修后Terminal单案已释放runtime：shortACK/remotePID确认、输入SHA/CtrlC及严格8帧到size31×93有真实证据，Vim前unexpectedFrame、session仍connected；原report remoteSizeMatchedfalse（旧赋值时机）与remoteCleanupfalse保留，外层精确PID/start/nonce后验无残留。新9b工程师仅source/offline定位Vim边界，不重跑/放宽12帧。
10. App真实f851上传28checks、window9baf23checks/7checkpoint与Quit3a93122checks/6checkpoint均已主管独立通过。Quit两次真正terminateContinue/Cancel/nativeexit0/forceddrainfalse、preexit完整fsync/hooks1-1，取消retained1声明保留、fixedCID finalabsent/FD-inode-SHA精确清，7opens6closes/shutdown1事实；已本地2142a32。窗口484d67a/上传03d3693保留，均有限HostProbe/mac15，不等整个AC22/24正式目标验收。
11. Vim完整R2实际已过：validsize→V确认后才启动Vim，唯一freshcase strict12、输入SHA/CtrlC/size/Vim文档SHA/termios恢复/done/returned0、资源无残留，主管独立核原JSON/事件/三PID过。tiny -eval导致原writefile错误、R1渲染size竞争等失败全保留；source163core/19pure/31cmd10snapshot8dep/newprobeembed/strict已审，已本地b2eebf3。该有限外层PTY/Vim分项不扩IME/Nest/全部TUI/mac26。root当前无测试占用。

12. 真实并发核心已验但整案PARTIAL：双password-kbd PID同时OTP-Apending/不同session与challenge，关闭A后旧.cancel stale/AOTPread0，B三轮完成。A取消后的server challenge超TTL仍留，consumerexit1/cleanupIncomplete保持；后exactFD/inode39/0600/size145/真实过期396s仅unlinkA+fsync恢复，原服务ID/FP/start/资源不变，不算自动清理通过。root当前空，见 `docs/reports/real-concurrent-auth.md`。

13. NEST首946c管理READY后relay30s失败/App0保留；EOF已还原auth/newkeygone，旧公开9+5材料经固定恢复全部精确清。R1relay先ready(实际36.873s)/追加前余283.150s、新a4e5bundle/keynoncee6ef/plan41ec后唯一f639真实publickeyNest**12帧通过**、输入CtrlCresizeVimSHA/返回outer/auth回调后增量0，双层闭后原authhash/trust/config/master完全恢复，key/receipt/staging/lock全不存在、无SSH/SFTP/UID进程/端口。主管独立原JSON/planwrapper绑定及恢复后验通过，已本地15e55a6；内层passwordOTP/企业人工仍未覆盖。

14. 真实App小数据GUI闭环已过：fileops首011b测试绝对路径校验拒$失败与精确恢复保留，专用FDleafR1保持特殊名/globalpath门后新5c2e24checks/四distinctjobs/nativebatchup-down/原名字节sizeSHA/nativeRename/三审核plan四路径删除/未选邻项SHA同/attempt1/20正常closes-end0/norescue及local-remote根清理主管独立过；已本地b5e6e9e。
15. tmuxR2完整十帧已通过（旧九门不减、新resize-ready同步），真实inputSHA/31x93/realCtrl-bd-detach/clients0单pane/ownserverkill+serverpanePIDfd/termios/done-returned；三remotePID15913/15916/15917后验absent、socket/status/root自然全消失，无手工清/信号，三localPID/FD端口释放，主管独立验收，已64312bb。旧首与R1失败/stalesocket恢复保持，不等htop/全部工具/视觉/IME/mac26通过。

16. htop3.3.0独立程序化分项已过：新853d6ab5/actualprobe4c78、35core8pure/strict后唯一838db0真实case strict5/readiness/actual31x93/PTYq正常exit0/termios/自有sleep及htop pidfd清理返回outer，准确PID/start已取得。nonce root/status/htoprc自然消失，无手工远端清理；主会话独立核原JSON/当前源对象签名/三pidfd、本地PID端口通过，已2f6e00f。像素/内部显示/IME/全部TERM05/mac26仍未验。

详见 `docs/reports/real-remote-terminal.md`、`docs/reports/app-real-transfer-survival.md` 和 `docs/reports/real-htop.md`。主管已读原结果、独立核时序/三PID与冻结输入/严格签名。

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
| APP-REAL-QUIT-LIVE-A / agent_2c8c76ef-77d1-4313-b527-8e49cfe4feae | 五源HOST_PROBE钩子主管源审/123test49hash14cmd/sign，真实3a93122checks6checkpoint/hook1-1/nativeexit0/noforceddrain/资源与精确retained恢复均主管独立验收；已本地2142a32，source/runtime冻结 |
| TERMINAL-SIZE-VIM-SYNC-R2 / agent_9b78446f-cc66-499c-bdff-efc846e3db1c | 89033mainba6d/helperb7d/probea21、163core19pure31cmd10snapshot8dep/strict主管过；新204dbfa4真实strict12/VimSHA/termios/done-returned/closedFD/无残留主管独立通过；已本地b2eebf3，冻结 |
| REAL-CONCURRENT-AUTH / agent_369d5187-6c93-46dc-919a-2d30ffa4faf6（已冻结） | 新signed62d4 d82/95eb、13复用objects/29cmd/inert与typedoffline主管核过。唯一真实f000案双PID同时OTP-Apending→关闭A/旧.cancel stale/AOTPread0→B3OTP+outerauth1核心成立；原consumer1/cleanupIncomplete因A过TTLserver材料仍留，按exactFD/inode39/expiry仅管理恢复，旧raw不改。已提交13a21da，自动fixture清理缺口保留，无active资源 |
| NEST-RELAY-READY-R1-LIVE-A / agent_80d0c8b6-66f0-49b5-879b-24d9625ea419（已冻结） | root/keyledger/integrated/runtimeharness主会话全关键源审/独立75→87pure，newa4e5consumer9reuse/21cmd/54readonly/sameTeamstrict/actual20482wrapperplan41ec审过。首946c/App0失败+精确public恢复保留；新f639真实publickeynested12/返回outer/auth0/原授权及基线恢复/knownkey与材料全清主管独立过，已15e55a6。innerpasswordOTP/企业人工未涵盖 |
| SHIPPING-HOOK-CONFIG-REGRESSION-A / agent_2c8c76ef-77d1-4313-b527-8e49cfe4feae | Debug/Release各一次真实incremental compile/link arm64min26/无HOST_PROBE define/hooks符号0、19cmd106hash/native160，主会话独立binaryhash/vtool26/nm核过；未运行/签名/打包，报告 `docs/reports/shipping-hook-isolation.md` |
| APP-FILEOPS-LEAF-R1-LIVE-A / agent_2c8c76ef-77d1-4313-b527-8e49cfe4feae（冻结） | 原011b校验器拒$失败/remote-local精确恢复保留；专用heldparentFD exactleafR1不放宽globalpath、126test49hash14cmd/sign主管过。新5c2e真实24checks/4jobs/2rawdownload原名sizeSHA/rename3plan4delete/邻项保全/20normalcloses/norescue/根与PIDstore全清主管独立验收，已本地b5e6e9e。人工Finder/冲突/正式mac26未涵盖 |
| REAL-TMUX-RESIZE-R2-LIVE-A / agent_9b78446f-cc66-499c-bdff-efc846e3db1c（已验收冻结） | R2原9门+新增resize-ready总10，C确认/ED2-3清已验history/SIGWINCHselfpipe12sactual31x93/firstpanefailure，138core13pure/31cmd10snap9obj/signed72eeb主管过。唯一8168真实10帧/inputSHA/31x93/realCtrl-bd/clients0单pane/ownserverkill+3pidfdtermios/done-returned/资源自然清理主管独立过，已64312bb。old2fail/stale外恢复不改，pixels/htop false |
| HTOP-CONSUMER-BUILD-A / REAL-HTOP-OWN-CHILD-LIVE-A / agent_9b78446f-cc66-499c-bdff-efc846e3db1c（已验收冻结） | 新853d6ab5 App main7f1e1b/helperd86e/probe4c78，11snapshots/9readonlyobjects/3compiles/31cmd（29logs+2签名记录）、35core/8pure/完整typecheck/strict主管过。唯一838db0 fresh案collect/relay/consumer各1、consumer0/strict5、own readiness→actual31x93→PTY q/normalexit→termios/cleanup/returned，remote parent17886-start10752218、htop17888与sleep17887-start10752231均pidfd absent；nonce root/status/htoprc自然gone，无手动remote清理。local81938/82038/82109gone/FD端口释放/4-4-0-0，fixture/source/bundle未变，主管独立验收primary-htop-pass-173f7f6f-9cc0-4cec-8d51-118c3a0fca2d；报告 `docs/reports/real-htop.md`。pixels/internal/IME/mac26 false，runtime交回。 |
| APP-REAL-TERMINAL-REVIEW-R1 / APP-REAL-TERMINAL-R1-LIVE-A / agent_cef8d152-7e03-48fc-a57a-fbac0729e614（已验收冻结） | R1 actualCapture/termiosreadback +4test，原127保留共131/df21014cmd49source160native/strict主管过。原指纹整行harness错误、未知外部ssh pre-live两拒绝均0/0/0保留；ssh自然结束后唯一75cc真实collect/relay/App1-1-1、App0/15.277s24checks：native24match index1→24/range变化，实际53B/SHA3f491c71…完整wrapper、termios/returned0/freshouterACK/samePID，SFTP/credential0、关闭重开/storeclean；三PID87531/87457/87556gone/4-4-0-0/端口空/fixture-source-bundle不变。主管独立primary-app-terminal-pass-2bfe1f68-7bde-4595-8693-647b078da65e，已e980ea2。报告 `docs/reports/app-real-terminal-search-paste.md`；人工clipboard/IME/mac26未验。 |
| APP-REAL-SESSIONS-RECONNECT-PREP-A / LIVE-A / agent_cef8d152-7e03-48fc-a57a-fbac0729e614（已验收冻结） | 0d280137tests原131保留/新58f13main2e689helper/strict经主管过；唯一2e2d案35checks/App0/44.889s：A89051/B89088双独立、4原生选择双击复用不变，A自然exit0/旧PIDgone，2.045976s40samples无auto，原生manualA新89152同view/sessionID精确gen2/freshACK/旧history1match、B不变；closeboth/无SFTPcredentials/重开store清，5PIDgone/端口空/relay12-12-0-0/fixture源签名不变。主管独立primary-app-sessions-pass-6f11e7f4-08cd-4b64-b0a6-3c2a9c50dfde，已659f273，报告 `docs/reports/app-real-sessions-reconnect.md`；keepalive7-2仅mapping非黑洞，有限观察非无限证明。 |
| APP-REAL-BATCH-CONFLICT-PREP-A / LIVE-A / agent_cef8d152-7e03-48fc-a57a-fbac0729e614（已验收冻结） | 首module-testability65保留；actualadapter修复后9f46142tests原137/49source160native/14cmd/strict主管过。唯一567e24checks/App0/34.103s：5jobs3batch8decision(6risk+skip1applytrue+rename1applyfalse)，两skip0byte保oldSHA/新batchalternate正确，3manifest独立公式SHA过，nativeexact4pathdelete/local6nodes与store清，25normalopenscloses/handles0/rescue0/credential0、三PIDgone/relay5-5-0-0/fixture源bundle未变。主会话独立primary-app-batch-pass-f63ee62e-8a33-4d59-8e78-c1bb81e751e4，已1021032，报告 `docs/reports/app-real-batch-conflicts.md`，不扩overwrite/inflight/mac26。 |
| APP-REAL-BATCH-OVERWRITE-PREP-A / LIVE-A / agent_cef8d152-7e03-48fc-a57a-fbac0729e614（已验收冻结） | 首a681missingtry编译65保留，6d908145tests原142/49source14cmd/932cmain688bhelperstrict主管过。唯一d2f6案23checks/App0/32.374s：4jobs2batch7decision，一次applyoverwrite不代每job独立非CASrisk，回答前actualwaiting/0bytes/items/temps；final双FreshSHA同名size异Seed、exact3native审核delete/local6nodes清，22normalopenscloses/end0/rescue0/credential0，三PIDgone/ports空/relay5-5-0-0/fixture源bundle未变。主管独立primary-app-overwrite-pass-2815a787-cc2d-42dd-a80d-f3ccbaf3d4ab，已3e63433，报告 `docs/reports/app-real-batch-overwrite.md`；不声称等待期独立SHA或CAS/mac26。 |
| APP-REAL-INFLIGHT-TAB-SWITCH-PREP-A / LIVE-A / agent_cef8d152-7e03-48fc-a57a-fbac0729e614（已验收冻结） | 53ef148tests原145/49source14cmd/a6dcmain-e3fdhelperstrict主管过。唯一8f7d31checks/App0/46.146s，无pause/throttle：actual655360B切B/983040B切A均正running<size、双PIDbirth/token/view及原jobrequestservice不变，final16MiB源公式和原serviceSHAe3a417…同；task入口如实完成后同job可见，8normalopenscloses/end0rescue0credential0/双tabclosed/四PIDgone/端口store远端root清/fixture源bundle未变。主管独立primary-app-switch-pass-5a9026e2-7684-4f06-bdb5-d1561f167834，已793f472，报告 `docs/reports/app-real-inflight-tab-switch.md`。 |
| SHIPPING-FIXTURE-CONFIG-REGRESSION-B / agent_cef8d152-7e03-48fc-a57a-fbac0729e614（已验收冻结） | currentDebug3sourcecompile/Ld1、ReleaseWMO27/Ld1各一次arm64min26/SDK26.2无HOST_PROBE，BatchGate/SwitchGate/hooks/runtime nm0、native160/7licenses/PBX实际2notice/Info26系统链接过，HostProbe15文件未变。初AppNOTICE误比nativeNOTICE的harness失败保留，13cmd只读复用后首次Release6，合19唯一cmd全0不重build。主管独立primary-shipping-fixture-b-2366defe-1611-4318-a4e6-a159b830e8fc，报告 `docs/reports/shipping-fixture-isolation-current.md`；无运行签名打包。 |
| APP-REAL-AUTH-UI-CANCEL-PREP-A / LIVE-A / agent_cef8d152-7e03-48fc-a57a-fbac0729e614（已验收冻结） | 73a685152原148/49source14cmd3327main7e5helperstrict主管过；唯一7599真实19checks/App0/31.179s，encrypted原内容公钥匹配/import1read，firstnativecancel manual0answer0/old96804gone，newgen2/newreq96839born/sameobjects安全字段submit1/recoveryread1/outerauthfreshACK/2.013s39samples，SFTPcredential0/windowreopenstore清。四PIDgone/8-8-0-0/fixture源bundle不变，harness主管不读秘密/日志只stat空；主会话独立primary-app-authui-pass-4026bb77-57a0-4cf7-887d-c3f98c616d4b，已cbc604a，报告 `docs/reports/app-real-auth-ui-cancel.md`。 |
| APP-REAL-TRUST-CHANGE-PREP-A / LIVE-A / agent_cef8d152-7e03-48fc-a57a-fbac0729e614（已验收冻结） | 74d4唯一156tests原152/49source14cmd/aea-main5409helperstrict主管过。唯一e68915checks/App0/21.453s：公开wrongkey仅freshstore，realkeyscan typedtrustRejected/61samples6.344s未观ownedPIDauthprompt，旧公有knownhash30cfc…同；native8actions/confirm先disabled核验后exactrecord/hash980db…，gen仍1直到native重连gen2/new98313birth+freshACK。SFTPcredentialphrase0/三PIDgone/portsstore清/7-7-0-0/fixture源bundle不变；主管独立primary-app-trust-pass-3574a9c3-74cb-457c-92c7-483b5c5fda8e，已3adb274，报告 `docs/reports/app-real-trust-change.md`。不claimserverrotate/握手mismatch/采样间隙absence。 |
| KEEPALIVE-BLACKHOLE-PREP-A / BUILD-A / CAMPAIGN-A / CLOCK-R2 / R2-LIVE / agent_cef8d152-7e03-48fc-a57a-fbac0729e614（已验收提交） | 13pure+83Swift实际decoder/nonce/d185App2aace-helperb7d48copy/9obj39cmdstrict主管过；首A12.000103s225samples/freshACK/natural0/FD过，首B混进程clockcontrol失败/-9原PARTIAL与52hash保留。R2只3Python实际relayclock转发/失败cleanupACK+最小B-onlygate，17pure原13/consumer不变主审；新Bf2dff collectrelayconsumerarm各1/A重跑0，actualnatural255/failedlaunchFailed2.568177s/保守5.682587s/clockdiff1e-5；discard[2176,0]/drop[52,0]/forward不增[4101,4511]/9TCPsnap/firstclientEOF且backendnull/同remoteBridgePIDstart活至结果。consumerrelay自然0无signals/closedFD/5PIDgone/ports0/exactrunroot清、tombstone保留、fixture源App旧52不变。主管独立primary-keepalive-r2-pass-bd65b34c-699e-404c-9b56-ba55a662eed5，已4c89e23，报告 `docs/reports/real-keepalive-blackhole.md`，仅有限host15/2-2不数加密probe/mac26。 |
| SHIPPING-FIXTURE-CONFIG-REGRESSION-C / agent_cef8d152-7e03-48fc-a57a-fbac0729e614（已验收冻结） | current3adbApp AUTH/trust源码Debug11.372s3compile/Ld1、Release21.421sWMO27/Ld1各一次，19cmd19log全0/noHOST_PROBEactualdefines，runtimeAuthTrustEvidence/hooks/BatchSwitchGate nm0纯types允许，106input/native1607license2PBXnotice/Info26系统链接及HostProbe15/Keepalive4保护通过。主管独立primary-shipping-fixture-c-452b2b7d-acac-4a3a-98b6-eb629599a6e7，报告追加C；无运行签名发布。 |
| APP-REAL-CONCURRENT-AUTH-UI-PREP-A / LIVE-A / agent_cef8d152-7e03-48fc-a57a-fbac0729e614（已验收提交） | 376de160tests原156/49source14cmd/c558mainb0fhelperstrict主管过；唯一d25221checks/App6533自然0/29.7263s，A6559/B6594不同req/session/birth同tickpending，nativeA空securecancel/0manual0answer/B原request不变→nativeBsubmit1/manual1/原identityfreshACK/A不复活，import1。SFTPcredential0/双tabclosed/4PIDgone/portsstore清/fixture源bundle不变，relay6438 ownedTERM后0无KILL/8-8-0-0非自然退出；主管独立primary-app-concurrent-auth-pass-4f158532-30d2-4a14-a7d6-66be62ca2c9c，已fa5191d，报告 `docs/reports/app-real-concurrent-auth-ui.md`。共享同key/同秘密非differentsecret/MFA全矩阵。 |
| SHIPPING-FIXTURE-CONFIG-REGRESSION-D / agent_cef8d152-7e03-48fc-a57a-fbac0729e614（已验收冻结） | currentfa519源码Debug10.573s3compile/Ld1、Release21.513sWMO27/Ld1各一次/19cmd19logs0，arm64min26/实际noHOST_PROBE/整ConcurrentruntimeEvidence与hooks nm0纯Gate允许，106源/native1607lic2PBXnotice/Info26系统links及HostProbec558-b0f15/Keepalive2aace-b7d4保护过。只读inspection最初错按-filelist提取，改实际@SwiftFileList核27输入，不重build。主管独立primary-shipping-fixture-d-f1c13ad5-32d3-4a3b-83ed-df3b50e12c7c；160tests仅复用，no签名运行打包；所有执行者停写。 |
| REMAINING-AUTONOMOUS-AC-ASSESS-A / agent_efdcaac5-23d9-4b20-a6fc-b45cfb47cbac | 只读完成，优先补真实GUI文件操作闭环与剩余TUI工具，不重已过项。外部门仍mac26/长测/DeveloperID公证/双机IMEFinder企业及默认Keychain真实动作授权 |

| PUBLIC-CREDENTIAL-REVIEW-R1 / agent_12500230-e749-48c1-ada3-95f1f8b3869b | 三原缺陷主会话/原reviewer定向复审resolved；主管独立8pure及完整65Swift17Python29CLI/368快照12复用对象18命令/strict/inert0/0/2通过，仅离线准备，已本地提交6a65bb1。新f201 driver3526b308…；source/build冻结，禁止真实store/Keychain/SecItem/Docker/live。报告 `docs/reports/public-credential-store-preparation.md` |
| KEYONLY-RECREATE-PORT-R1 / agent_fce7a218-7787-48e4-bee6-96d709d2b320 | 六环境源主会话审/39静态28relay35MINA离线过，端口预检R1追加时序断言主会话39/28过；真实action失败后exactstart恢复Healthy/PTY0/卷网络other3不变，旧incomplete保留，R1 action未重跑。已本地59c898c，source/runtime冻结 |
| KEYONLY-REBIND-LOCATE-A / agent_6fd8346f-0175-4028-b0e5-0cbe2f3744e5 | 六文件只读完成，App仅Contract常量148/149需future新CID/FP+重新签名/collectafterbuild；Terminal动态freshcontract无需source literal。旧campaign pins不改不重跑 |
| FIXTURE-AUDIT-PAIR / 原agent80f已停写 | helper/client/server/pair审查及真实失败、A/B结果已存检查点d118000/619f3c6。主会话仅极小R1收口；不再用该writer推进，旧raw不改 |
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

- 实测宿主macOS15.8.1/24H32/arm64，Xcode26.3/17C529、SDK26.2/Swift6.2.4。正式App arm64/min26，HostProbe/独立消费者min15不能冒目标runtime。最终本地磁盘观察约118GiB可用，瞬时值不能沿用为下一安装许可。
- Docker Desktop4.97.0/build244584官方验签；DMG SHA256 94e4ccec4a035b7dcdf67cfff0520d4b46ee873ae04b155abc0d22b333cc90ad；Agent无sudo/accept-license。外部GUI后LicenseTermsVersion2/2CPU4096MiB/40GiB/AutoStartfalse，Engine实物一致。context desktop-linux固定unix:///Users/liuwenshuo/.docker/run/docker.sock，不建全局特权socket链接。
- Ubuntu固定24.04 digest18b33ff…、rootimage7f633d33…、project openlxssh-fixture-61ed25328c13。keyonly已按A/B实证仅加AUDIT_WRITE重建为1253CID/MHU指纹（见上），原key-data/network保留；另外三个原CID/hostkeys/start未改，仍七cap。MINA2.20.0/commit2221febd…、image18c77956…/原CID不变。internal/noegress/readonly/no-new-privileges/capdropALL+按服务精确集合/资源受限/namedvolume无hostbind；HostConfig.PortBindings不冒称可达，有限opaque relay仅批准回环端口。
- 分支 `development/p1-prototypes`；最近状态提交 `07d74ce`、已验收App源 `fa5191d`、保活源 `4c89e23`；历史信任/认证/传输源分项均见报告。本文件最后更新将另作仅文档本地提交，不用文件内自引用追逐commit。当前无writer/runtime，全部工程师冻结；状态/验收/指南由主管维护，remote为空、未push。
- 最近完整内部候选仍 `DerivedData/Distributions/0.1.0-1-8b6396199db2/fdb05b4d-a035-4040-8ded-5d549ffadb57/`，来源8b6396199db273493a438679df0020fa6ef7c3a4/dirty=false/version0.1.0 build1。arm64/min26/Development strict/runtime通过，Gatekeeper false/spctl3，未公证/上传/安装运行。ZIP7418092B/SHA256 fc927f568d50f67e8bd17a4c90f94fd666f41a3c1ba41a6d4317153755b7052e；tree499a0902be8e70b847d55b002813c748d43fc83813a0aaa0178b13b35fa45066；manifest4abd40c149a9bcd55c843bf040063d5876f005b06a9812468e32e0131fbcc63f。不能声称包含后续测试基础设施或报告。
- 正式min26长期driver `Tests/StabilityAcceptance/.build/driver-71e5e2da-b345-4c4b-ab54-53b8d128209d/wrapper/OpenLXSSHStability.app`，driver66843ddc286375de474e9823ea7353cd7d77265b5e1a8bf1cbf8a009cf7f625a/helper31d0ee0ee9d357d7edd0bfaf129a9ae4b38334fd8955184f6afc049d685a0590；未运行200/24h，不降平台门。

## 最新独立验证证据

- 短ACK单案原typed报告一致性/时序/三PID实际不存在：`DerivedData/Verification/primary-terminal-postauth-live-14a17ac5-93bd-469e-9124-092d0861ba34/`。结果为失败证据核验通过，非PTY验收通过。
- App49source/既有118tests0fail、Terminal9输入/8父对象、双App主/helper hash和deep strict签名复核：`DerivedData/Verification/primary-app-terminal-frozen-a24c034b-da4a-4254-907e-4f311351baec/`。首次复核脚本误用辅助文件名断言失败，修为实物Contents/Helpers/openlxssh-askpass后通过，无产品改动。主管随后独立再跑Terminal核心128与Python10均exit0，无文件/代次/Docker/socket/live；新日志 `DerivedData/Verification/primary-terminal-offline-checkpoint-7f690b18-1299-467b-80dc-7faaee6f9679/`。
- 凭据R1：主管独立8pure→完整65Swift17Python29CLI、368输入/12复用对象/18构建命令、strict及inert0/0/2；`DerivedData/Verification/primary-credential-r1-{pure-52bbbe08-d489-48f8-bf79-61f9929b2d60,signed-d57f1a91-975d-4924-bcc5-417ee78b0d50,full-5140868d-a8f4-42ae-831d-e0eb6903ba8f}/`，未真实Keychain。详细 `docs/reports/public-credential-store-preparation.md`。
- 容器内原daemon直连255与临时audit-fatal/PARTIAL已独立核：`DerivedData/Verification/primary-internal-pty-client-d2e43ea0-70ac-41b9-9736-cc14bd1e18ed/`、`primary-server-pty-live-12eba838-b5b2-41ba-a8cf-d393c1ba2116/`。不重写内部cleanupfalse，外层无残留另记录。
- system-T/-tt：`DerivedData/Verification/postauth-system-ssh-control-b9a22fc3-c911-422e-86fe-c2673e46d3c8/`；两UID分配：`DerivedData/Verification/fixture-pty-metadata-507dc766-f62f-43db-98eb-9cdbfe485afe/`。不重复这些探针。

## 剩余必要工作与外部条件

- 当前授权内的小范围host15自动分项已收口，不重已过campaign或为旧案改绿而重复执行。恢复后先核当前代码/实际环境，不从历史任务表的“准备/未覆盖”重开已过项。默认Keychain真实持久化仍需明确动作授权；若选择继续补完整App密码/OTP shell链，须先审目标cap7服务AUDIT_WRITE最小环境修正与fresh身份方案，不把现outer-auth冒ready。PAM取消材料自动卫生缺口保持，管理恢复非自动通过。
- 当前已过host15有限分项：上传/window/Quit/外层PTYVim/公钥nested/原生文件与批skip-rename-overwrite/正字节切标签/tmux/htop/搜索memorypaste/双标签naturalmanualreconnect/认证cancel恢复/真实knownchanged原生管理及正常保活+R2黑洞、并发MFA核心。它们不自动变正式mac26验收。
- 外部仍缺：macOS26真实运行；正式driver200次/五会话真实连续24h；DeveloperID Application/Installer当前0（仅Development1）、对应最终产物Apple上传批准；双机安装、人工IME/Finder/像素、企业允许环境。不能以缩数据/改时钟/HostProbe/多次短测替代。
- 不创建Cron/OffPeak/常驻，不改电源/保护/宿主SSH，不因普通失败停止全部工作。仅必要信息/权限/无替代外部条件才BLOCKED；整体未完成时不得称COMPLETE。

恢复后的下一项由必要条件实际变化决定：取得Apple Silicon/macOS26设备后按正式min26 driver执行200次/连续24h及Release真实压力/资源和安装验收；取得默认Keychain一次性命名空间动作授权后才运行已冻结公开消费者；DeveloperID可用且最终产物明确后才生成正式候选并就该产物单独申请Apple上传。双机/IME/Finder/clipboard/企业内层秘密由用户安全操作；工具合法条件单列不补装/登录/出网。当前无待执行普通编译错误或未清本轮测试进程，无自动scheduled/常驻续建任务；Goal未完成，不宣布COMPLETE。
