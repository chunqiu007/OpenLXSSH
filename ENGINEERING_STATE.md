# OpenLXSSH — 工程状态

更新：2026-10-26（Asia/Shanghai）。

## 当前目标与授权

- IN_PROGRESS：同一Goal持续至Apple Silicon/macOS26可安装V1.0并完成必要验收；整体尚未完成。
- 已确认四类直连认证/MFA、多终端标签、手动嵌套SSH、直连SFTP、主机/密钥/凭据管理和独立传输生命周期。范围见requirements；不做自动ProxyJump/经跳板图形SFTP/转发/自动重连/恢复。
- 主要编码由software-engineer，主管独立读差异和复跑关键验证；可本地提交，不remote/push。新增VM/容器须用户确认；不生产连接、不读公司秘密；Apple账号/证书安全操作由用户完成，公证上传需具体产物授权。

## 当前实际状态

正式OpenLXSSH Xcode App/Target已存在，arm64/min26。主机/安全管理与SSH标签/终端/信任认证已完成本地审查提交7ed142e，主管68测试、原生GUI和严格签名离线验证通过；无真实服务器互通。正式Core/Security/Trust/Transport/Files已修本轮ACL与文件完整性缺陷并提交。当前进入P6-App文件面板首个里程碑，整体并非可用完整SSH/SFTP Release。

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

## 正在委派与文件所有权

- 恢复核对：用户发送“继续”后重新核对HEAD `fd005f5` 与实际未提交App/Files改动；旧agent不可恢复，重新委派同范围，不重建或覆盖工作。
- App工程师 agent_f6776fa3-ff7f-4432-9226-b8a46b9feef8：P5含ACL/JournalFD/R2主管验收提交7ed142e。现P6-APP-FILES-A，只App/xcode/根构建验证脚本/AppTests；实现默认隐藏右文件面板、独立认证/共享Trust、目录和安全操作，不上传下载/退出任务决策（P6B后续）。不改Packages/实验/全局文档。
- Files工程师 agent_7b556d2b-7a15-416f-9e3f-cd1ac6a69082：P7-FILES-INTEGRITY-R2主管Release57通过提交25f802d；R3同service根自拷组件边界修正/新3测试，主管Release16通过提交ff00e7d，工程师双配置89；无当前写入。
- 只读安全审查 agent_4e309475-302a-47cd-bc5d-e86f2a60203d：三项缺陷已交付，最小复现细节已记录；主管已读对应实现确认，后续修复只读复核。
- 安全修复 agent_d1ddbcb3-c32e-4b6f-9666-78ea5055f4bb：P7-SECURITY-ACL-R1已交付7文件，主管读差异/11新ACL tests并独立Release31全部通过；拒任意ACL/查询失败、不改用户ACL，正式签名App待统一复验。原Security工程师不可恢复，不覆盖其他区域。
- 打包准备 agent_ea4ea432-0755-41f2-9899-9a167506dcb2：P8-PACKAGING-R1四项已修，主管独立83fixtures与只读定向复核均通过，5源码/说明+报告提交f1802e2；尚未真实候选build/pack，当前无写入。
- 本地文件压力 agent_f1657cb3-9d7d-4e94-8d88-1de2cde3a1d4：P7-LOCAL-FILE-STRESS-A已交付；主管读5文件与修正版证据，独立Release完整2GiB+1000/25%取消/逐项SHA+原名/ownedFD0与精确cleanup通过，提交0e0bf7d；旧ownedFD别名计量结果不可引用，详见docs/reports/p7-local-file-stress.md，无当前写入。
- 隔离fixture agent_bd3797d8-e478-431b-9566-e7e1b3d5c7a7：源码准备已返回，主管静态13项通过并提交a65bfa2，未启动环境。
- Transport修复 agent_578fc3b2-d17f-4706-8265-8ee17ae89848：P7-TRANSPORT-ACL-R1已交付4文件，主管独立Release35+6readpass/4签名event/10postexit通过；min26工程师双配置通过，无写入。
- Core修复 agent_76c08d53-23ed-4690-bb98-f95e60b9b52c：P7-CORE-ACL-R1已交付6文件，工程师双配置/TSan各48，主管独立Release48/真实F_GETLK持锁通过，无写入。
- Trust修复 agent_fb65477a-6758-4b70-92c4-2a71930302dc：P7-TRUST-ACL-R1已交付2文件，主管独立Release46通过；三包合并只相关15文件提交1e275b1，publicAPI兼容，不改共享锁文件。
- App P5审查闭环：主管完整读差异，R2 independent HostProbe68/GUI15+8+7+17+17/signed8+8+15+5均exit0，读者定向确认两P2resolved，提交7ed142e。无真实SSH网络或mac26runtime。
- Security新增 agent_d1：P6-SECURITY-AUTH-MATERIAL-A已交付；主管独立Release8与真实四组合libssh2离线memory解析/签验通过，提交b0c3f4d，当前无写入。API仅精确UUID→SecretBytes、caller核Core授权，不经任意路径读私钥。
- Files下一接口 agent_7b：P6-FILES-SERVICE-OPERATIONS-A已主管读两文件、独立Release97通过，提交7a574ab，当前无写入。withServiceOperation raw默认serialized、安全操作/probe callerScheduled；有界128、activework含ops、shutdown单flight等待cleanup，禁closure自等待shutdown。
- Security工程师 agent_54e6a1a7-3a1a-4f21-ab8f-438c0aa9a942：原正式包已完成；本次SendMessage不可恢复，ACL修复已交agent_d1，不重试旧ID。
- 打包只读复核 agent_5378a30d-53de-41cf-99ec-6c0caf895221：只审候选打包器/fixtures，不实际构建签名或上传。
- Core工程师 agent_73af9b8f-ecfa-48f0-8fff-a89712f8abeb、Trust工程师 agent_e26e9287-a223-4ff6-a7ea-3a3dfd19d4f0：已返回，无写入。
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

继续P6-APP-FILES-A受控认证/浏览/安全操作，交付后主管独立审查与native行为验证，再同工程师P6B上传下载/Finder拖入/独立任务/窗口退出保护。保持包API/文档与本地压力边界真实；P8打包器83fixture已审，实际候选等App全部集成结束、工作区稳定后生成。真实互通需新增环境授权，目标mac26与DeveloperID/公证具体产物/双机企业人工仍外部条件；先做完所有独立本地工作，整体未完成。
