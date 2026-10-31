# UX 本地体验候选：验收与交付映射

日期：2026-10-31。状态：进行中；不是完成证明。最新窄门与失败边界如下，后文较早审计仅作历史：

- 本次passwordonly与key/password两类KI真实App认证、113×37终端、exit7分项成立；两KI四轮字段[1/1/1/0]、OTP3/零输入1/late0、serverstatusremoved及管理4次reap成立。仍分别weak或FD资源门failed，不报整体通过；见`app-password-transient-review.md`、`app-mfa-real-review.md`。
- 保活合法数值映射与原pump离线6门已主独立复验并本地47757ad/ca58c70，包全209/0；新版有限真实mixedload+同连接tmux已过其transport门，不代App图形资源或默认替换。
- 子矩阵现86（43 VERIFIED /42 IMPLEMENTED /1 INVESTIGATED），新增信任/并发归属/finite mixedload/真实登录目录均只窄门，父116仍全部INVESTIGATED；13列/ID/parent完整，证据SFTPLoginDirectory-R1/Primary/matrix86-integrity.json。窄门数量不作产品完成率。
- 新双keyKI真实A取消/B原owner继续、cross/late拒成立，但A挑战present/Bremoved且Bweakalive，逐owner清理和整案仍failed，见`app-concurrent-mfa-real-review.md`。三serialleg有限mixedload门完整passed，详见`native-finite-mixedload-review.md`；不代Appweak/GUI/长期pendingtimeout。
- 真实App资源：精确baseline20→23（或密码19→22）；一readonly已匹配QuartzCore default.metallib，两RW与间歇UI持有仍unknown。停止重复probe；恢复图形调查需actual occlusion可见及ACK后真实frame，当前窗口isVisible不等此条件，官方CUA全inactive不推锁屏根因。原weak/FD门不改、不按+3豁免。
- 新Files logicalApp真实SFTP清单往返、rename加skip和受控取消重试三单案已完整passed，均精确清理/实际serviceclose/FD20→20身份相等/自然exit0；见`app-files-manifest-real-review.md`、`app-files-conflict-real-review.md`、`app-files-cancel-retry-real-review.md`。取消是受控localread节奏，不冒nativeblockedIO。三案不代GUI/Finder/批传播/其他策略或旧shell资源。中键、SaveDiscardCancel、CmdV/IME、三尺寸截图与像素仍未过，未UX_READY_FOR_USER。

- Trust M3批准前实际provider/KI/shell0与typedchanged来源门已审；Host172/0、Debug147/0、主管独立28/0与Python136/0。三fresh实网once2/persist2/changed1信任认证分项均成立，close/drain/queue/registry真但都weakcleanup整案failed；三App/relay自然0/noSignal/counters2/2/1清理全0、端口free。见`app-trust-real-review.md`。普通主机仍Direct、本次密码才Native，是实际入口一致性缺口，不因探针成功视作默认已切。
- R12先只消歧过期描述、校正重复公钥导入归属DX-K02，原116父/80子状态逐行不变（MatrixR12/after-integrity.json）；其后新增Trust三条、并发归属和mixedload为85子。只有55父项具有子索引，61父项仍需明确合适共享证据或缺门，不能以子项数量当完整覆盖。

- 本轮建立 `acceptance-coverage.md`，116父ID恰一次、UX-01～14映射及所有报告引用已逐项结构核验；所有父行链接共享索引，原需求文字/状态未改。R15一项realpath实网证据措辞MED已修，不用SFTP传输案代登录目录。另当前入口四项逻辑契约与PAM finally公开模型已主独立通过，分别4/0与3/0，均不冒真实GUI/残留修复。

- 真实SFTP登录目录包层门已补：actualrealpath非root `/fixture/home`直接list3项/knownmetadata匹配、preCancelled typed拒、freshtoken同service恢复、publicclose/weaknil/socketgone/FD计数4→4，consumer/relay自然0。见`sftp-login-directory-real-review.md`；不代App正常候选显示或在途取消。

## 目标与停止边界

交付完整、真实运行的 OpenLXSSH 本地体验候选，覆盖 `desktop-experience-spec.md` 全部116条R、`termius-redesign-handoff.md` UX-01～14、操作位置表、通用状态表，以及U0发现的日常交互。只能在每项有相应实现及实测证据、实际界面检查通过后标记UX_READY_FOR_USER。该状态等待用户体验，不等于V1.0全部人工验收完成。

不连接生产、不读取真实凭据、不推送、不重新跑24h或无关历史大文件campaign、不新增虚拟化环境、不重建健康fixture；不向Apple上传、请求新时间戳或生成最终分发包。旧公证build3和历史失败证据保持原样。仅本地构建/既有身份离线签名和正常运行验证。

## 证据规则

- 父矩阵为 `termius-parity-matrix.csv`；子项记录逐入口、触发、前置条件、校验、输出、副作用、适用状态、owner、数据/资源生命周期、行为证据和图像证据。
- 状态仅NOT_STARTED / INVESTIGATED / IMPLEMENTED / VERIFIED / BLOCKED；R只有VERIFIED才计完成。父项不能因子集通过而升级。
- 原有功能先核代码和影响后复用。旧证据只证明旧范围，不冒充新版GUI；对未变化底层不机械重跑历史campaign。
- 所有新截图只含虚构主机和批准隔离fixture；不复制用户参考图里的地址、名称、路径或文件列表。
- 视觉证据必须看见实际像素。原始六图的直接Read仍被运行模型省略；本次新增 `visual-reference-text.md` 是 Codex 实际查看六图后的逐图文字转写，可作为布局/视觉设计依据，但不能替代新版App像素对照或把视觉条目标为VERIFIED。

## 从请求到产物的检查清单

| 输入/要求 | 目标产物或证据 | 当前状态 |
| --- | --- | --- |
| AGENTS、状态、requirements、architecture、execution-plan、acceptance、UX handoff、完整spec、CSV | 主管已显式Read；实际Git/工具链核对 | 已读取；不代表功能验收 |
| 六张本地参考图01～06 | 图号→控件/状态/视觉观察记录 | 已接纳Codex实际看图的文字转写；新版App像素门仍待 |
| Termius官方导航及桌面资料 | 官方URL、可证事实、未知与设计选择、额外R/A/P | U0调查见u0-reference-and-differences；不补造未知状态 |
| 116条DX R | 每一父项及必要子项的实现位置、状态与实际验证 | 父项保留116；子矩阵已增加Core/仓储/终端/双栏/信任/真实认证窄门，未批量升级 |
| UX-01～14 | 新版端到端操作、资源与安全证据 | 部分实现/分项实证；整体未过 |
| 操作位置表（标签/主机/分组/详情/密钥/已知主机/终端/文件/队列/菜单） | 实际显示顺序、分隔、启用条件和动作结果 | U1已验部分；新页菜单仍待实际GUI |
| 状态表（空/无选择/忙/禁用/输入错/失败/部分成功/取消） | 每个适用入口状态和恢复路径；共用组件可共享证据 | 逐子项记录；不能以编译或已有底层测试补造GUI证据 |
| 视觉与布局、标签与窗口 | U1 + 三尺寸/全屏/连续缩放/拖动分隔/溢出/焦点 | U1六项175/0、主管69/0、原生34；新页与像素需复验 |
| Vault主机/分组/标签/多选/列表卡片/编辑草稿 | U2 + 合成旧数据迁移与保存/放弃/失败回归 | Core68/0及原子copy71/0；新页App209/0、主管关键37/0；新GUI待 |
| 密钥/凭据/已知主机 | U2/U5 + 引用保护、精确忘记、生成/导入/重复/取消 | label/引用数据与重复公钥复用本地门已验，精确remove及搜索复制已接；真实控件/系统picker另验 |
| 两类认证及真实附加挑战 | U0最小实证→U5四组合、多提示/通知/审批/并发/取消 | 本次密码/两KI/双KI A取消B继续归属分项成立；A挑战清理与Appweak/FD整案仍failed，普通入口一致性未过；finite mixedload只transport门通过 |
| 三按钮首次信任 | 一次不落库、持久复用、变化拒绝、同握手绑定、陈旧代次 | Store59/0、OpenSSH离线11/0及M3真实once/persist/typedchanged分项已验；三案整体weakcleanup失败，真实按钮点击待 |
| 配置变化不假复用 | 连接快照指纹、metadata忽略、同配置复用/显式新会话 | U1逻辑/原生替身分项通过；真实新认证配置组合仍待 |
| 完整终端 | U3实际SwiftTerm、序列色彩、键鼠剪贴板、搜索/字号/IME/TUI | Transport严格51/0；新原生精确CmdV握手未过；三尺寸截图未像素审 |
| 双栏SFTP与操作 | U4真实本地/远端导航、排序/过滤/拖放/精确目标/错误 | 双栏已接、登录目录能力及App默认消费者本地门已验；新三案logicalApp SFTP通过，完整GUI/Finder/路径显示另验 |
| 传输队列/冲突/取消/重试/清记录 | U4受影响小批量摘要、原件保全、切页/关SSH独立性 | 清单往返、rename加skip、受控取消后新清单重试严格资源通过；批传播/其他策略和完整队列GUI待 |
| 设置/菜单/快捷键/空错态/可访问性 | U1～U6共享动作与焦点路由，真实设置持久化/重开 | 六分类设置/类别重置/关闭owner及Core持久化本地门已有；完整原生焦点、CmdW/红点/CmdQ和像素未过 |
| 本地可运行体验候选 | 新源构建记录、离线签名、正常启动、路径与摘要 | 正常Debug工程预览已独立构建/离线签名，见normal-engineering-preview-review；未正常启动/GUI验收，不当体验候选，不覆盖旧包 |
| 新版实际截图 | Hosts/编辑/Keys/SFTP未连与已连/队列/终端/认证/信任/设置/窄窗 | 待捕获和视觉检查 |
| 功能差异与人工体验项 | R/A/P差异表、未覆盖项和简短操作路径 | `local-candidate-walkthrough.md`已整理目标路径/已知失败/人工边界，`../adr/ux-native-ssh-entry-consistency.md`记录真实入口缺口；不是已交付身份单或体验通过 |
| 数据保护与授权边界 | 不清用户DB、不读取真秘密；保留旧产物；本地相关提交 | 持续遵守 |

### 接续会话的实物审计（2026-10-30）

- 逐项解析规格与父矩阵：116个DX编号与116行R一一对应，无缺项/重复；父项仍116个INVESTIGATED。50子项仍17 VERIFIED / 29 IMPLEMENTED / 4 INVESTIGATED。此为索引完整性，不是体验完成率或功能通过。
- 当前RELIABILITY-R1六类本地门已收口：工程师正式min26 App119/0，主管关键32/0加准确导航symbol1/0，Core双方各3/0并本地提交5e73f7c；详情见`reliability-app-review.md`和`reliability-core-review.md`。父矩阵仍116 INVESTIGATED。最近新增候选typed事实/sealed排空、有限关闭和布局窄门后，子矩阵69项（28 VERIFIED / 40 IMPLEMENTED / 1 INVESTIGATED）；其后补递归Manifest包/App入口/窄窗几何三项，现**72项（29 VERIFIED / 42 IMPLEMENTED / 1 INVESTIGATED）**。主管实际CSV解析核13列、ID唯一、parent有效且全部116父项与规格一一对应，见UnifiedFilesNative-R1/Primary/matrix72-integrity.json。这是索引完整性和窄门证据，不是整体完成率，不把逻辑范围冒原生/网络；新AppNative case2因weak释放cleanup失败未标通过。
- 新原生R0真实启动冻结接续前HostProbe，结果见`resumption-native-discovery.md`：AX只得递归菜单、窗口级无AX内容、像素不可见；动作未核验。ready/finish字段通过不等控件通过；存储清理后未自然退出、精确TERM exit-15保留。NATIVE-PROBE-R1仅工具写域准备，构建须等业务writer释放。
- 历史静态设置缺口现已实现六分类/类别重置及近黑默认预览，Core18/0、App99/0和主管关键复验见`preferences-help-review.md`；此处保留原差距发现记录，不再将单页Grid描述为当前实现。真实设置控件、跨页焦点、保存/重开及像素仍不能因本地门而将DX-P01～04改绿。
- **新候选活性分项（不代正式后端）：** normal、独立MaxSessions与严格DROP有限真实门通过；同连接7次确认全释放或7次真实拒绝后fresh shell/exit7。R4保原预算/门，实际DROP后5.917秒自然sshroundtrip超时、保守arm年龄0.109秒≤1.5，转发不变/noFIN/backendalive/FDdrain和guardian远端精确终止均通过。两次旧失败不改写。见`native-liveness-live-finite.md`。App typed adapter最终正式107/0、主管独立39/0（含自有NSWindow布局/末项滚动），真实网络及像素仍待；重复导入主管App34/0、严格包29/0已本地ed281c3，不冒实际GUI。
- **本轮有限关闭/布局检查点：** R1正式严格构建及唯一228个受影响方法通过，主管另独立Retirement15+FilesLayout10+FilesReviewOwner15共40/0。布局本地门见`files-layout-preferences-review.md`，不等实体拖拽/像素。关闭源审发现的取消重复join主线程空转、通用错误被过宽当无native证明已R2最小修复；严格build0、受影响88/0，主管独立关键13/0。Window Middle原红项、真实Delegate退出与App网络仍未过。见`native-app-retirement-review.md`。
- 静态确认已有队列入口、速度/总量未知、定位/重试/清记录路径；仍需新版GUI验证冲突/风险、记录移除owner与迟到回调、长路径/窄窗和批次呈现。仅检查源码不升级DX-Q。

### 116父项的共享证据与真实缺门（R13只读审计）

85子索引覆盖55父，另外61父不等无实现，也不需要新增61个独立probe。以下分组源自R13（当时83子/54父），只定义最小剩余证据，不升级父项；已有底层回归在无变化时复用。

- 组织与表单H05/H09～11、E02/E04、X10：复用Core排序/层级/循环拒绝、迁移与陈旧保存/失败保快照；补新列表/卡片、展开选择、空错入口、删除配置展示和字段错误定位的实际消费者。
- 密钥与秘密E07/E08、K01/K03/K05/K06：复用生成/引用保护/精确忘记/重复导入/迟到owner门；补inline picker返回草稿、生成后引用、共享删除的实际控件。新版系统授权拒绝呈现仍unknown，不用旧包补证。
- 认证与信任H12、T06、A01/A04/A05/A07/A08：复用typed阶段、primary/KI隔离及M3三案；接到当前普通入口/错误界面。M3不覆盖T06全部多算法/并发/扫描握手不一致。A06真实并发归属已成立，但A挑战清理与GUI未过，不将auth-only升级整体完成。
- 终端V01、N01/N03/N06～08/N12：复用深色/ANSI/字节/历史/每tab搜索与输入控制；补真实选择滚动/焦点/两次CmdV/正常候选网络与退出。N04/N09～11的键鼠/IME/TUI不由renderer代验。
- 文件与队列F02/F03/F08/F10、Q02/Q04/Q06～08：复用catalog、精确target、迟到拒绝、记录owner和真实SFTP三窄门；补双栏导航/右键/定位/清记录/切主机确认。最后一项skip不证明批传播或覆盖风险自动拒绝，F06多选与文件双击单列。
- 设置帮助P02/P03/P08：复用六分类/范围/字体光标/迁移和白名单诊断离线许可；补实际picker、帮助许可显示和正常入口保活文案。
- 跨页面V03/V04/V07/V08、E01/E12、X01/X03～08：合并代表性空→输入错→忙→失败→恢复→确认/取消的真实页面与截图，不逐按钮造新框架；VoiceOver实际朗读、较大文字/滚动条/焦点环/提示持续时间仍unknown。

体验操作清单明确规定1000×650、1280×800、1440×900逻辑尺寸与全屏，920×580仅附加边界；HostProbe只有精确验证flags/contract模式隔离自退，不是可双击的空白体验环境。R13两项文档MED已修，记录`DeliveryDocsR13/primary-review.json`。

## 里程碑与验收范围

1. U0：官方与图像证据、实际代码/入口/状态调查、认证/临时信任最小接口实证，拆子项并定义owner。
2. U1：统一工作区/设计token、固定页与真实会话标签、排序/溢出/菜单、焦点快捷键和生命周期。DX-V/W及共同P/X的一部分；不把此范围称全部UX完成。
3. U2：Vault主机/分组/标签/列表卡片/多选、详情草稿、两类编辑配置、密钥/凭据/已知主机管理、合成旧数据迁移。DX-H/E/K/T管理面。
4. U3：全页真实终端、深色默认与已有自定义迁移、键鼠/复制粘贴/搜索/字号/滚动、真实尺寸与有限TUI。DX-N。
5. U4：本地/远端双栏、主机选择、导航/文件操作、拖放、队列与任务动作。DX-F/Q。
6. U5：协议可靠的初始秘密与KI、三按钮真实一次信任、配置快照、失败/取消/并发与资源。DX-A/T及UX-03～08。
7. U6：设置/帮助/菜单/微交互剩余项、全项审计、实际GUI端到端、截图/候选/差异/人工体验项。每项不确定视为尚未达到。

每轮由一个software-engineer写代码（如必要并行必须先隔离文件所有权）。主管读取实际diff、关键源码与输出并独立复验；普通错误继续修，不依靠代理自报DONE。实际命令从仓库脚本核对后写入各轮记录。
