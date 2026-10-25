# OpenLXSSH — 工程状态

更新：2026-10-26（Asia/Shanghai）。

## 当前目标与授权

- IN_PROGRESS：同一Goal持续至Apple Silicon/macOS26可安装V1.0并完成必要验收；整体尚未完成。
- 已确认四类直连认证/MFA、多终端标签、手动嵌套SSH、直连SFTP、主机/密钥/凭据管理和独立传输生命周期。范围见requirements；不做自动ProxyJump/经跳板图形SFTP/转发/自动重连/恢复。
- 主要编码由software-engineer，主管独立读差异和复跑关键验证；可本地提交，不remote/push。新增VM/容器须用户确认；不生产连接、不读公司秘密；Apple账号/证书安全操作由用户完成，公证上传需具体产物授权。

## 当前实际状态

正式OpenLXSSH Xcode App/Target已存在，arm64/min26；已集成真实GRDB主机管理。安全管理UI正在R1收口，正式SSH与Files包已本地实现/审查，等待App整合。当前并非可用完整SSH/SFTP Release；无真实服务器互通。

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
| P4-SECURITY-UI | 主管已独立26测试、GUI15+8、真实签名App保存/跨启动读取/清理通过；R1私钥忘记口令/未知intent核对/提交后清理结果修正中 | App安全4文件/测试/脚本 |
| P5-TRUST-A | 主管30项通过，正式共享信任，PID-safe固定工具runner；SSH/SFTP只依赖同一library | Packages/OpenLXSSHTrust；docs/reports/p5-shared-trust.md |
| P5-TRANSPORT-A/R1 | 主管Release23测试+6真实系统readpass/4签名event/10postexit通过；字体6～72、保活0～3600、三色外观修正；真实SSH/mac26未验 | Packages/OpenLXSSHTransport；docs/reports/p5-transport-core.md |
| P3-LOCAL/R1 | 主管完整46矩阵通过，OpenSSL改3.5.9LTS、typedTCP/同握手信任/显式风险策略；真实SFTP未测 | Experiments/P3；docs/reports/p3-local-files.md |
| P6-FILES-A / TRANSFER-MANAGER-R1 | 正式Files/Manager主管完整70矩阵通过，R1混合skip修正后主管Release16定向通过、工程师双配置73通过；真实SFTP未验 | Packages/OpenLXSSHFiles；docs/reports/p6-files-core.md |

## 正在委派与文件所有权

- 恢复核对：用户发送“继续”后重新核对HEAD `fd005f5` 与实际未提交App/Files改动；旧agent不可恢复，重新委派同范围，不重建或覆盖工作。
- App工程师 agent_f6776fa3-ff7f-4432-9226-b8a46b9feef8：P4-SECURITY-UI-R1-RESUME，仅Application/OpenLXSSH、根xcodeproj/构建验证脚本、AppTests。收口后继续SSH标签/认证UI，再文件UI，避免同工程并写。
- Files工程师 agent_7b556d2b-7a15-416f-9e3f-cd1ac6a69082：P6-TRANSFER-MANAGER-RESUME，仅Packages/OpenLXSSHFiles；不碰App或共享文档。
- Transport工程师 agent_8f3982f0-44d8-479d-a5f4-35a383d4401c：A/R1已返回，当前无写入；后续必要修复通过SendMessage。
- Security工程师 agent_54e6a1a7-3a1a-4f21-ab8f-438c0aa9a942：正式包已返回，无写入。
- Core工程师 agent_73af9b8f-ecfa-48f0-8fff-a89712f8abeb、Trust工程师 agent_e26e9287-a223-4ff6-a7ea-3a3dfd19d4f0：已返回，无写入。
- 主管维护STATE/acceptance/reports/跨模块决策；不与工程师并写拥有文件。所有记录是线索，恢复后先核对实际git/代码。

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

分支development/p1-prototypes，无remote/push。近期：19c2c78 Core、0ee6b7d Mach/readpass、9f4c81f原生App、fc16dc4显式Keychain候选、c183591共享Trust、c110ebd正式Security、cc559d4 P3LTS实验、fd005f5正式Transport/Core引用更新。未提交AppR1/Files属当前工程师工作，不重置。

验证日志在各包/实验 .build/verification 与 DerivedData/Verification（忽略），报告含命令/结果/限制。产品AC总表在docs/acceptance.md，不以包测试或build替代整体验收。

## 下一项具体动作

等待/审查App安全R1，独立复跑后提交；给同App工程师派P5标签/认证/TerminalView真实集成（只读Transport/Trust/Security），随后P6右侧文件面板/独立任务入口与关闭退出保护。FilesManager返回后审查真实本地任务生命周期。继续所有可本地推进的安全/压力/打包/使用说明。真实互通需要新增环境授权，最终集中说明且整体未完成。
