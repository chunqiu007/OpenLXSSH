# OpenLXSSH — 工程状态

更新：2026-10-26（Asia/Shanghai）。

## 当前目标与授权

- IN_PROGRESS：同一Goal持续至Apple Silicon/macOS26可安装V1.0并完成必要验收；整体尚未完成。
- 已确认四类直连认证/MFA、多终端标签、手动嵌套SSH、直连SFTP、主机/密钥/凭据管理和独立传输生命周期。范围见requirements；不做自动ProxyJump/经跳板图形SFTP/转发/自动重连/恢复。
- 主要编码由software-engineer，主管独立读差异和复跑关键验证；可本地提交，不remote/push。新增VM/容器须用户确认；不生产连接、不读公司秘密；Apple账号/证书安全操作由用户完成，公证上传需具体产物授权。

## 当前实际状态

正式OpenLXSSH Xcode App/Target已存在，arm64/min26。主机/安全管理、SSH、SFTP浏览/安全操作与上传下载/独立任务/传输关闭保护均已完成本地分项审查；B1含late-risk/history R1主管103tests/原生GUI/签名回归通过并提交40853f3。有限Instruments已记录成功与失败局限；签名稳定性driver仅静态准备未运行。整体待真实互通/目标mac26/长测/正式发布与人工验收，不是完成V1.0。

| Task | 实际结果/主管证据 | 主要文件 |
| --- | --- | --- |
| P0-01～05 | 环境/依赖/Git/隔离环境/签名路径调查均审查通过 | docs/reports/p0-* |
| P1-01/02 | 本地PTY14项、信任22项主管独立通过 | Experiments/P1-01、P1-02；对应报告 |
| P1-03/R1 | DP真实Keychain -34018保留，签名有效仍需profile | docs/reports/p1-03-credential-key.md |
| P1-03/R2 | file-based候选主管真实CRUD/ACL/跨启动/同DR升级/错误身份拒绝/清理通过，ADR显式选择，不自动fallback | docs/adr/p1-03-file-keychain-selection.md |
| P1-04C/P1-06A | Mach冻结身份/不同镜像签名本地测试通过；主管真实App内OpenSSH readpass与控制PTY成功/取消/超时3场景通过；非SSH服务器认证 | Experiments/P1-04；docs/reports/p1-04-askpass.md |
| P2-LOCAL-A | 主管16测试+原生窗口通过，稳定1.20丢输出独立复现，精确选1.99.1预览；人工IME/Vim严格ZWJ/远端未过 | Experiments/P2；P2 ADR/报告 |
| P4-DATA-A/R1 | 真实DB主管29全套+新5定向通过；工程师双配置34；迁移/WAL/并发/共享保护/受检口令解除 | Packages/OpenLXSSHCore；docs/reports/p4-data-core.md |
| P4-APP-A | 主管verify-app all通过：正式双配置min26编译，HostProbe13测试/GUI14+8；当时未接transport | Application/OpenLXSSH、OpenLXSSH.xcodeproj；docs/reports/p4-native-app.md |
| P4-CREDENTIAL-A | 主管20项+真实签名CRUD通过，自建Keychain锁回退/解锁恢复/default-searchlist不变 | Packages/OpenLXSSHSecurity；docs/reports/p4-security-core.md |
| P4-SECURITY-UI / R1-RESUME | 主管独立32测试、GUI15+8+7、真实签名App8+15+5检查通过；AppKit owner修复/口令解除/恢复核对/提交后cleanup语义已收口 | App安全文件；docs/reports/p4-security-ui.md |
| P5-TRUST-A | 主管30项通过，正式共享信任，PID-safe固定工具runner；SSH/SFTP只依赖同一library | Packages/OpenLXSSHTrust；docs/reports/p5-shared-trust.md |
| P5-TRANSPORT-A/R1 | 主管Release23测试+6真实系统readpass/4签名event/10postexit通过；字体6～72、保活0～3600、三色外观修正；真实SSH/mac26未验 | Packages/OpenLXSSHTransport；docs/reports/p5-transport-core.md |
| P3-LOCAL/R1 | 主管完整46矩阵通过，OpenSSL改3.5.9LTS、typedTCP/同握手信任/显式风险策略；真实SFTP未测 | Experiments/P3；docs/reports/p3-local-files.md |
| P6-FILES-A / TRANSFER-MANAGER-R1 | 正式Files/Manager主管完整70矩阵通过，R1混合skip修正后主管Release16定向通过、工程师双配置73通过；真实SFTP未验 | Packages/OpenLXSSHFiles；docs/reports/p6-files-core.md |

| P5-APP-SSH-A/ACL/FD/R2 | 主管HostProbe68/GUI15+8+7+17+17/签名8+8+15+5通过并提交7ed142e；真实网络/mac26未验 | Application/OpenLXSSH；docs/reports/p5-native-session-ui.md |
| P6-FILES-SERVICE-OPERATIONS-A | 主管Release97通过提交7a574ab；服务操作与jobs共享lease/idle/shutdown | Packages/OpenLXSSHFiles；docs/reports/p6-files-core.md |
| P7-ACL | Security31、Core48、Trust46、Transport35+严格IPC主管通过；前后检查/拒任意ACL策略，不改用户ACL | docs/reports/p7-core-review.md及各包报告 |
| P7-LOCAL-FILE-STRESS-A | 主管独立Release2GiB/1000逐项SHA+25%取消+FD3/9/3+owned0通过，非远端/PERF | Tests/LocalFileStress；docs/reports/p7-local-file-stress.md |
| P8-PACKAGING-R1/R2 | 主管101fixtures及真实unsigned P6A候选打包/verify-manifest通过，UUID996cff64；Gatekeeper false/无有效发布签名/未公证，非最终Release | Scripts/package-release-candidate.py；docs/reports/p8-packaging-preparation.md |

| P6A-APP-FILES/R1 | 主管all/signed85与LocalGUI14通过，随后末次saved授权R1主管89/signed通过；提交90084e4，无真实SFTP | Application/OpenLXSSH；docs/reports/p6a-native-files-ui.md |
| P6-LOCAL-ROOT-FD/TARGETED-CLOSE | 主管Release34通过提交b034db2；工程师双配置107，新增10重复200为本地tests非SSH | Packages/OpenLXSSHFiles；docs/reports/p6-files-core.md |

## 正在委派与文件所有权

- 复核外部条件：宿主仍macOS15.8.1；docker/podman/colima/lima/UTM/QEMU/multipass命令均未发现，未新建SSH服务。已有AppleDevelopment1、DeveloperID Application/Installer均0（只报告计数）。未收到新增环境/Apple公证上传授权。
- B1已交付13文件/工程师99/all+GUI/signed，主管独立all/signed99通过，尚未提交。专项审查agent_3c20bdec-4492-4c08-9774-eb257ad1236a确证两P2：late-risk窗口关闭可新挂continuation导致清理等待环；历史移除未绑定已显示终态集合、后续snapshot可能吞新retained报告且跨freeze。已派App68 P6B1-LATE-RISK/HISTORY-R1先红测/最小修复，未算里程碑通过。
- P6A认证撤销R1已主管独立89tests/signed通过，原P2定向resolved，整合提交90084e4。App工程师agent_68d3d86f-9ad4-43cc-af1e-d0df030e6887现获P6-APP-TRANSFER-B1唯一App/xcode/构建脚本/AppTests写范围，实现raw选择入队、任务/冲突风险UI、FinderfileURL、window/quit有任务保护；不改Packages/文档，不提交。
- Files新增agent_876bf232-8daa-4307-9bff-57fa44d40b1c，原7b不可恢复：TARGETED-IDLE-CLOSE-R1+LOCAL-ROOT-FD-R1已交付4文件，主管独立Release34通过并提交b034db2（工程师双配置107/新增10重复200），App可接两兼容API，当前无包写入。
- 打包实际R2 agent_409da4aa-9f36-42fe-86e8-3b96d7419bf6已交付5文件，主管独立101tests与真实unsignedpack重跑exit0。P6A时点候选UUID996cff64-e5cc-4efe-b4b3-80b3b0a3e4e5，Gatekeeper false/无有效发布签名/未公证上传，非最终Release。首失败UUIDadc54006保留。证据适配精确hidden-native/archive映射，不称strip；当前无写入。
- B1含R1已主管验收：独立103tests/GUI15/8/7/17/17/14/18/17/signed12/8/15/5 exit0，原两P2专项复核resolved，本地提交40853f3；无App业务写入。P7-PROFILING-LOCAL-A有限采样已结束：TimeProfiler/Leaks trace成功、Allocations exit20歧义无trace、Leaks空表不能推零泄漏、独立leaks-atExit短时0；源/原HostProbe包hash未变、自有PID均结束。详见docs/reports/p7-local-instruments.md。
- 只读安全审查 agent_4e309475-302a-47cd-bc5d-e86f2a60203d：三项缺陷已交付，最小复现细节已记录；主管已读对应实现确认，后续修复只读复核。
- 安全修复 agent_d1ddbcb3-c32e-4b6f-9666-78ea5055f4bb：P7-SECURITY-ACL-R1已交付7文件，主管读差异/11新ACL tests并独立Release31全部通过；拒任意ACL/查询失败、不改用户ACL，正式签名App待统一复验。原Security工程师不可恢复，不覆盖其他区域。
- 打包准备 agent_ea4ea432-0755-41f2-9899-9a167506dcb2：P8-PACKAGING-R1四项已修，主管独立83fixtures与只读定向复核均通过，5源码/说明+报告提交f1802e2；尚未真实候选build/pack，当前无写入。
- 本地文件压力 agent_f1657cb3-9d7d-4e94-8d88-1de2cde3a1d4：P7-LOCAL-FILE-STRESS-A已交付；主管读5文件与修正版证据，独立Release完整2GiB+1000/25%取消/逐项SHA+原名/ownedFD0与精确cleanup通过，提交0e0bf7d；旧ownedFD别名计量结果不可引用，详见docs/reports/p7-local-file-stress.md，无当前写入。
- 稳定性驱动 agent_4e082810-2a2c-43c9-bba7-e8c87f671a0b：P7-STABILITY-DRIVER-PREP/R1已交付；主管独立offline34+6/typecheck/C通过、只读两P2复核resolved。仅驱动源码/准备，未真实链接签名运行、未200/24h；早期离线CLI隐式adhoc偏差保留，最终plan禁签名。详见docs/reports/p7-stability-driver-preparation.md，无当前写入。
- 主管维护STATE/acceptance/reports/跨模块决策，不与工程师并写文件；恢复核对实际git/代码，记录不是验证替代。
- 隔离fixture agent_bd3797d8-e478-431b-9566-e7e1b3d5c7a7：源码准备已返回，主管静态13项通过并提交a65bfa2，未启动环境。
- Transport修复 agent_578fc3b2-d17f-4706-8265-8ee17ae89848：P7-TRANSPORT-ACL-R1已交付4文件，主管独立Release35+6readpass/4签名event/10postexit通过；min26工程师双配置通过，无写入。
- Core修复 agent_76c08d53-23ed-4690-bb98-f95e60b9b52c：P7-CORE-ACL-R1已交付6文件，工程师双配置/TSan各48，主管独立Release48/真实F_GETLK持锁通过，无写入。
- Trust修复 agent_fb65477a-6758-4b70-92c4-2a71930302dc：P7-TRUST-ACL-R1已交付2文件，主管独立Release46通过；三包合并只相关15文件提交1e275b1，publicAPI兼容，不改共享锁文件。
- App P5审查闭环：主管完整读差异，R2 independent HostProbe68/GUI15+8+7+17+17/signed8+8+15+5均exit0，读者定向确认两P2resolved，提交7ed142e。无真实SSH网络或mac26runtime。
- Security新增 agent_d1：P6-SECURITY-AUTH-MATERIAL-A已交付；主管独立Release8与真实四组合libssh2离线memory解析/签验通过，提交b0c3f4d，当前无写入。API仅精确UUID→SecretBytes、caller核Core授权，不经任意路径读私钥。
- Files下一接口 agent_7b：P6-FILES-SERVICE-OPERATIONS-A已主管读两文件、独立Release97通过，提交7a574ab，当前无写入。withServiceOperation raw默认serialized、安全操作/probe callerScheduled；有界128、activework含ops、shutdown单flight等待cleanup，禁closure自等待shutdown。
- Security工程师 agent_54e6a1a7-3a1a-4f21-ab8f-438c0aa9a942：原正式包已完成；本次SendMessage不可恢复，ACL修复已交agent_d1，不重试旧ID。
- 稳定性驱动构建 agent_091f9d0e-836e-4b72-9773-05cf540931ad：BUILD-B已交付6文件，主管独立真实record来源/11对象min26/linkmap/严格Development签名verify及offline34+6+12通过，提交8d307a2。成功UUIDdriver-8f5d1fcc，signed-static-only-not-run；没有执行driver/网络/长测，无当前写入。
- P7秘密/候选内容只读agent_478检查344tracked/index、显式secret出口与P6A候选，未见实际秘密；根ignore合成路径缺口已主管小修12敏感/7source例通过，不等全历史/运行时泄漏证明，详见docs/reports/p7-secret-artifact-check.md。
- 当前活动提交：c9d5c07稳定性驱动准备/R1（主管offline34+6/typecheck），之前fb388a4工程检查点；P6A尚未提交。完整历史使用git log，不用旧状态文字推定工作区clean。
- 整体相关本地提交后续：f1802e2候选打包器（83fixtures，未实际pack）、ff00e7d根自拷边界、1e275b1三包ACL、0e0bf7d本地大文件压力夹具、b0c3f4d认证专用内存私钥、7ed142e原生SSH集成/ACL/R2、7a574ab文件操作生命周期。所有本地提交仅相关文件，没有远程推送。

## 关键技术决定与边界

- SwiftTerm1.99.1 preview固定2f573f73...，正常输出完整性优先，不能称稳定2.x；最终包锁/ThirdParty notices已保存。
- GRDB7.11.1固定b83108...，系统SQLite；libssh2 1.11.1 + OpenSSL3.5.9 LTS，SHA/tag/官方checksum/工具链固定，维护至2030-04-08。P0旧3.6模糊hash不作生产输入，后续来源已独立核对。
- 凭据显式file-based Keychain，稳定namespace、同步false、默认creator ACL、串行lease；非ThisDeviceOnly/屏幕锁等价。DP实验失败不隐藏，profile不再阻止V1默认路线。
- Askpass未知挑战人工；固定LocalCommand签名helper事件只证明外层认证，不证明shellReady；单次saved password严格封闭配置+已核build gate。当前只24H32，shipping26自动凭据仍人工回退，AUTH02未完成验收。
- SSH唯一SwiftTerm LocalProcess拥有PTY/reader/reaper；只保证直属child/正常helper，任意逃逸后代树未验。远端/内层提示绝不扫描自动注入秘密。
- 文件copy先唯一temp再commit；本地FD/noFollow/RENAME_EXCL，远端lstat/非CAS覆盖剩余风险必须明示确认；服务noReplace能力probe显式批准且只自有UUID目录。无真实服务能力证据，不能自动造通过token。

## 环境与外部条件

- 宿主macOS15.8.1/24H32、arm64、8CPU、16GiB；Xcode26.3/SDK26.2/Swift6.2.4。正式min26只编译，HostProbe15本地运行单独标注。
- 无现成VM/container/隔离SSH服务；未启动系统sshd。建议UTM+官方UbuntuARM64、2vCPU/4GiB/20GiB动态盘起步、private/NAT、不桥接LAN、一次性账号/密钥。未获新增环境确认，不安装。
- 有Apple Development身份1，DeveloperID Application/Installer0；用户自行准备DeveloperID/登录。无Apple公证上传授权/执行。
- 真实四类认证/MFA/审批/主机变更/SSH-SFTP/嵌套/TUI、200循环/5会话真实24小时仍缺隔离服务；不能mock或短测替代。
- 人工IME/像素、macOS26实机/双机安装/公司允许场景待用户操作。当前模型不支持图像像素，原生行为自检不等于主管人工视觉通过。

## 提交与证据

分支development/p1-prototypes，无remote/push。近期：19c2c78 Core、0ee6b7d Mach/readpass、9f4c81f原生App、fc16dc4显式Keychain候选、c183591共享Trust、c110ebd正式Security、cc559d4 P3LTS实验、fd005f5正式Transport/Core引用更新、47ffd78正式Files/Manager、6ab185d安全UI/R1、a65bfa2未运行隔离fixture。当前AppSSH整合、各ACL修复与新测试/打包脚本改动属各自工程师，不重置。最近主管提交25f802d已独立Release57复验的Files根枚举/源一致性修复及报告、8fffea4已独立Release31复验的私钥ACL加固；无remote/push。

验证日志在各包/实验 .build/verification 与 DerivedData/Verification（忽略），报告含命令/结果/限制。产品AC总表在docs/acceptance.md，不以包测试或build替代整体验收。

## 下一项具体动作

当前无代码写入。先提交已核对状态/验收/有限采样报告，基于干净源码生成包含B1/R1的最新Development离线严格签名内部候选并独立verify，更新交付检查点与prompt-to-artifact审计；不是DeveloperID/Gatekeeper通过。然后集中记录真正外部阻塞：新增隔离运行环境授权、目标macOS26、真实200/24h、DeveloperID/具体产物公证批准、双机/企业人工。不得为补缺擅自安装VM/起宿主sshd/连生产/上传，整体不能COMPLETE。
