# UX 本地体验候选：验收与交付映射

日期：2026-10-31。状态：进行中；不是完成证明。最新窄门与失败边界如下，后文较早审计仅作历史：

- 本次passwordonly与key/password两类KI真实App认证、113×37终端、exit7分项成立；两KI四轮字段[1/1/1/0]、OTP3/零输入1/late0、serverstatusremoved及管理4次reap成立。仍分别weak或FD资源门failed，不报整体通过；见`app-password-transient-review.md`、`app-mfa-real-review.md`。
- 保活合法数值映射与原pump离线6门已主独立复验并本地47757ad/ca58c70，包全209/0；不代真实mixedload/默认替换。
- 子矩阵现79（36 VERIFIED /42 IMPLEMENTED /1 INVESTIGATED），父116仍全部INVESTIGATED；13列/ID/parent完整，证据AppFilesConflict-Live-R5/matrix79-integrity.json。窄门数量不作产品完成率。
- 真实App资源：精确baseline20→23（或密码19→22）；一readonly已匹配QuartzCore default.metallib，两RW与间歇UI持有仍unknown。停止重复probe；恢复图形调查需actual occlusion可见及ACK后真实frame，当前窗口isVisible不等此条件，官方CUA全inactive不推锁屏根因。原weak/FD门不改、不按+3豁免。
- 新Files logicalApp真实SFTP小目录清单往返已完整passed：2plans确认各1、prepareΔ内容IO0/jobs0、12KiB双向SHA同、精确nonce清理、remote1/local2实际close、FD20→20身份相等、自然exit0；见`app-files-manifest-real-review.md`。不代GUI/Finder/冲突取消重试或旧shell资源。中键、SaveDiscardCancel、CmdV/IME、三尺寸截图与像素仍未过，未UX_READY_FOR_USER。

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
| 密钥/凭据/已知主机 | U2/U5 + 引用保护、精确忘记、生成/导入/重复/取消 | label身份与引用数据层已验；重复导入后端、精确removeUI仍待 |
| 两类认证及真实附加挑战 | U0最小实证→U5四组合、多提示/通知/审批/并发/取消 | 新NativeShell四真实positive已验；Appadapter、负例和保活门未过 |
| 三按钮首次信任 | 一次不落库、持久复用、变化拒绝、同握手绑定、陈旧代次 | Store59/0及主管13/0；OpenSSH严格临时快照离线11/0；新UI/真实once待 |
| 配置变化不假复用 | 连接快照指纹、metadata忽略、同配置复用/显式新会话 | U1逻辑/原生替身分项通过；真实新认证配置组合仍待 |
| 完整终端 | U3实际SwiftTerm、序列色彩、键鼠剪贴板、搜索/字号/IME/TUI | Transport严格51/0；新原生精确CmdV握手未过；三尺寸截图未像素审 |
| 双栏SFTP与操作 | U4真实本地/远端导航、排序/过滤/拖放/精确目标/错误 | 真双栏已接新页、DualPane10/0；真实realpath实施中；GUI与真实remote待 |
| 传输队列/冲突/取消/重试/清记录 | U4受影响小批量摘要、原件保全、切页/关SSH独立性 | 原底层证据复用；新双栏入口/队列GUI及有限实传待 |
| 设置/菜单/快捷键/空错态/可访问性 | U1～U6共享动作与焦点路由，真实设置持久化/重开 | 新页面类型通过，旧NativeSmoke字段查找失配导致native-dismiss首步失败，正在真实AX确认 |
| 本地可运行体验候选 | 新源构建记录、离线签名、正常启动、路径与摘要 | 待生成；不覆盖旧最终包 |
| 新版实际截图 | Hosts/编辑/Keys/SFTP未连与已连/队列/终端/认证/信任/设置/窄窗 | 待捕获和视觉检查 |
| 功能差异与人工体验项 | R/A/P差异表、未覆盖项和简短操作路径 | U6交付 |
| 数据保护与授权边界 | 不清用户DB、不读取真秘密；保留旧产物；本地相关提交 | 持续遵守 |

### 接续会话的实物审计（2026-10-30）

- 逐项解析规格与父矩阵：116个DX编号与116行R一一对应，无缺项/重复；父项仍116个INVESTIGATED。50子项仍17 VERIFIED / 29 IMPLEMENTED / 4 INVESTIGATED。此为索引完整性，不是体验完成率或功能通过。
- 当前RELIABILITY-R1六类本地门已收口：工程师正式min26 App119/0，主管关键32/0加准确导航symbol1/0，Core双方各3/0并本地提交5e73f7c；详情见`reliability-app-review.md`和`reliability-core-review.md`。父矩阵仍116 INVESTIGATED。最近新增候选typed事实/sealed排空、有限关闭和布局窄门后，子矩阵69项（28 VERIFIED / 40 IMPLEMENTED / 1 INVESTIGATED）；其后补递归Manifest包/App入口/窄窗几何三项，现**72项（29 VERIFIED / 42 IMPLEMENTED / 1 INVESTIGATED）**。主管实际CSV解析核13列、ID唯一、parent有效且全部116父项与规格一一对应，见UnifiedFilesNative-R1/Primary/matrix72-integrity.json。这是索引完整性和窄门证据，不是整体完成率，不把逻辑范围冒原生/网络；新AppNative case2因weak释放cleanup失败未标通过。
- 新原生R0真实启动冻结接续前HostProbe，结果见`resumption-native-discovery.md`：AX只得递归菜单、窗口级无AX内容、像素不可见；动作未核验。ready/finish字段通过不等控件通过；存储清理后未自然退出、精确TERM exit-15保留。NATIVE-PROBE-R1仅工具写域准备，构建须等业务writer释放。
- 静态确认仍需实现的具体设置差距：`SettingsEditor`仍是单页显式保存Grid，无通用/终端/连接/传输/隐私/快捷键统一分类及偏好类别重置；配色预览仍把默认组映到系统textBackground/textColor，且帮助文案声称默认跟外观，与新终端近黑基线不一致。不得因设置能打开就将DX-P01～04改绿。
- **新候选活性分项（不代正式后端）：** normal、独立MaxSessions与严格DROP有限真实门通过；同连接7次确认全释放或7次真实拒绝后fresh shell/exit7。R4保原预算/门，实际DROP后5.917秒自然sshroundtrip超时、保守arm年龄0.109秒≤1.5，转发不变/noFIN/backendalive/FDdrain和guardian远端精确终止均通过。两次旧失败不改写。见`native-liveness-live-finite.md`。App typed adapter最终正式107/0、主管独立39/0（含自有NSWindow布局/末项滚动），真实网络及像素仍待；重复导入主管App34/0、严格包29/0已本地ed281c3，不冒实际GUI。
- **本轮有限关闭/布局检查点：** R1正式严格构建及唯一228个受影响方法通过，主管另独立Retirement15+FilesLayout10+FilesReviewOwner15共40/0。布局本地门见`files-layout-preferences-review.md`，不等实体拖拽/像素。关闭源审发现的取消重复join主线程空转、通用错误被过宽当无native证明已R2最小修复；严格build0、受影响88/0，主管独立关键13/0。Window Middle原红项、真实Delegate退出与App网络仍未过。见`native-app-retirement-review.md`。
- 静态确认已有队列入口、速度/总量未知、定位/重试/清记录路径；仍需新版GUI验证冲突/风险、记录移除owner与迟到回调、长路径/窄窗和批次呈现。仅检查源码不升级DX-Q。

## 里程碑与验收范围

1. U0：官方与图像证据、实际代码/入口/状态调查、认证/临时信任最小接口实证，拆子项并定义owner。
2. U1：统一工作区/设计token、固定页与真实会话标签、排序/溢出/菜单、焦点快捷键和生命周期。DX-V/W及共同P/X的一部分；不把此范围称全部UX完成。
3. U2：Vault主机/分组/标签/列表卡片/多选、详情草稿、两类编辑配置、密钥/凭据/已知主机管理、合成旧数据迁移。DX-H/E/K/T管理面。
4. U3：全页真实终端、深色默认与已有自定义迁移、键鼠/复制粘贴/搜索/字号/滚动、真实尺寸与有限TUI。DX-N。
5. U4：本地/远端双栏、主机选择、导航/文件操作、拖放、队列与任务动作。DX-F/Q。
6. U5：协议可靠的初始秘密与KI、三按钮真实一次信任、配置快照、失败/取消/并发与资源。DX-A/T及UX-03～08。
7. U6：设置/帮助/菜单/微交互剩余项、全项审计、实际GUI端到端、截图/候选/差异/人工体验项。每项不确定视为尚未达到。

每轮由一个software-engineer写代码（如必要并行必须先隔离文件所有权）。主管读取实际diff、关键源码与输出并独立复验；普通错误继续修，不依靠代理自报DONE。实际命令从仓库脚本核对后写入各轮记录。
