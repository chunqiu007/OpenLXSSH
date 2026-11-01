# OpenLXSSH：Codex Desktop 接续开发与交付

日期：2026-11-01。用户明确要求由Codex Desktop新对话接续App开发，继续使用Goal模式。本文是当前恢复入口，覆盖旧ZCode会话交接里的运行方式和过期待办；不改用户需求、不抹历史失败，也不表示迁移文档的会话已经启动开发。

## 1. 角色与真实运行能力

- 主会话负责目标、优先级、关键判断、派工、独立审查和最终验收。需要执行/调查/审查时，直接使用当前对话可用的子智能体工具按职责委派，不需要预创建固定名称的角色文件。
- 主要编码默认交执行子智能体；小改、需要主会话强上下文的复杂修复或无子智能体工具时可直接处理，并做同样验证。默认一个writer，独立写域才并行；当前对话最多3个子智能体，等待/重试/未确认停止仍占位，禁止子智能体再派生。
- 不调用ZCode用户级配置、历史Agent/SendMessage接口或旧代理ID。历史任务ID、PID、截图窗口ID仅是调查线索；不能在Codex里原样恢复，也不能凭旧PID对进程发信号。
- 这里的子任务不是新建用户可见聊天；不要为普通实现另建对话、定时器或自动化。模型/推理档位尊重用户当前选择和已确认成本偏好，旧报告里的某次执行模型不是必须安装的依赖。
- 新主会话收到明确启动请求后，核对本对话真实Goal能力和现有目标。可用时实际创建或按工具规则接续，不用普通TODO、历史状态或其他客户端斜杠命令冒充已开启Goal；无能力时明确说明限制。目标未完成不能因单轮结束/子任务DONE/编译通过标完整完成。

## 2. 首先接稳现场

仓库：`/Users/liuwenshuo/Desktop/OpenLXSSH`。本交接读取时分支`ux/termius-desktop`，HEAD`f41f485`；main仍为旧UX基线。后续文档适配提交仅改指令，不代表产品源码已重新验证。接手以真实git status/log/diff为准，不切回main、reset、clean、删分支或创建不必要的新worktree。

旧会话最后记录有1个R2隔离预览writer，写域8个App源及新EngineeringPreviewIsolationTests/project membership。**先确认用户已停止ZCode写入，或当前相关文件已稳定，再修改同一文件。** 这只是写入所有权交接，不尝试恢复旧运行时；本迁移会话没有代为停止任何代理/测试/App。

已有大量未提交App/终端/双栏/Native候选/测试，都是必须保留的资产。先分类为已有且可复用、待修、待验；不要只看Git HEAD推断产品输入，也不要一次性全量stage未审改动。部分已通过成果已经提交，按最近日志核对，不从U0重建。

## 3. 阅读顺序：不要把全部历史当当前待办

1. 根AGENTS.md、本交接、ENGINEERING_STATE.md顶部Codex入口与最近两三个实际检查点。
2. docs/requirements.md、architecture.md、execution-plan.md、acceptance.md，明确范围与用户已有授权。
3. docs/ux/desktop-experience-spec.md、termius-redesign-handoff.md、visual-reference-text.md；仍覆盖116条DX R、UX-01～14与操作/状态合同。
4. docs/ux/acceptance-coverage.md、local-candidate-walkthrough.md、termius-parity-matrix.csv、termius-parity-subitems.csv、verification-plan.md。
5. 当前具体问题再读normal-engineering-preview-review、entry-routing-contract-review、native-default-switch-gates、app-concurrent-mfa-real-review，以及相关资源/文件传输报告。

旧zcode-fresh-session-handoff、codex-zcode-checkpoint-review保留为历史，它们的旧HEAD、“UI未写”“本次密码未接线”等待办可能已被后来实现取代。先查实际代码，不按旧快照重做。

## 4. 当前产品做到哪里

| 区域 | 当前源码/证据 | 不能冒称的范围 |
| --- | --- | --- |
| 管理工作区 | 顶部固定Vault/SFTP、稳定会话页；新主机卡片/列表/分组/标签/编辑/密钥与设置已接主界面 | 正常候选完整鼠标键盘/视觉尚未验 |
| 终端 | 深色完整区域、搜索、字号/菜单/生命周期与新Native adapter已写 | CmdV/IME/中键/全部TUI和窗口交互未收口 |
| 数据与凭据 | 旧数据迁移、分组/标签、密钥去重、陈旧编辑/commit后恢复等已有修复与证据 | 不据此授权读取真实用户凭据，正常启动仍可能读写/迁移用户数据库 |
| 信任 | 三按钮和once/persistent/changed真实行为分项成立 | 三案整案weak cleanup仍失败，非完整资源通过 |
| 文件传输 | 真正双栏、清单审核/冲突/取消/重试已写；真实小清单往返、rename/skip、受控取消后重试通过 | Finder拖放、双栏实际显示/完整GUI未验；受控取消不是所有阻塞IO取消证明 |
| 登录目录 | 包层realpath返回非根`/fixture/home`并直接列目录、预取消及同service恢复通过 | 正常App双栏显示不能由包层探针代验 |
| MFA与传输候选 | 两类主认证UI、一次性本次密码handoff、libssh2候选，多轮KI、finite混合负载和tmux已有真实分项 | 普通Direct/本次密码Native仍不同路；默认后端未正式统一 |

父矩阵116条仍INVESTIGATED，最近86子项43 VERIFIED/42 IMPLEMENTED/1 INVESTIGATED；接手时重新核，不能当整体完成百分比。原24h未完成事实保留，但用户已接受约9h38m稳定门，不能因此重新开长测。

## 5. 预览现物与正在写的R2

- R1：`DerivedData/UXPreview/Engineering-R1/OpenLXSSH.app`，正常Debug/arm64/min26、离线Development签名，身份在同目录identity.json。是已构建工程实物；没有正常无参启动/完整GUI通过的证据。
- R1无参使用现有Application Support/偏好，可能初始化/迁移数据库。不能当空白测试环境双击启动。旧安装、已公证build3、构建原件均保持。
- R2：PREVIEW_ISOLATED独立bundleID/临时root/离线拒绝器/无真实Keychain与偏好写入/受限本地目录，正在工作区编写，最近是SOURCE_ONLY。**未证明已能构建/运行，也不是可连SSH的产品版。**
- 原SOURCE_ONLY是旧任务的实施阶段；Codex取得写入所有权并审查源码后，可按既有本地开发授权构建/测试，不再向用户索取“能否编译”的重复许可。用户数据/系统授权/环境变更等边界仍保持。
- 优先复用已有R2完成一个有限的可看可操作预览；不先造第二套产品、插件、启动器或无限合同系统。离线页态预览与使用真实fixture的完整连接候选分别记录，后者仍必须交付。

## 6. 实际剩余工作与优先级

### A. 先让界面可观察、可体验

核当前Codex图片与原生操作工具。旧ZCode allactive=false/CG-only/无像素结论仅对当时工具有效，不能直接继承；不要一开始又跑多轮同样的窗口调查。读现有截图/六图、核候选来源与数据路径，用当前工具实际查看界面。

在不触真实数据的现有隔离路径完成R2必要源码审查/构建/运行/三尺寸和主要页态截图；保留原R1。需要系统授权或真实用户数据迁移时，指出具体步骤与影响、由用户处理，先做不依赖它的工作。像素、输入法或实体键鼠确实必须人工时集中给清单，不假通过也不为单项人工作业无限造探针。

### B. 统一普通连接与本次密码入口

当前普通新建/无新密码保存连接走Direct；本次输入密码的prepared handoff用Native候选；reuse可选已存在owner，reconnect保留原driver/builder。先按entry-routing-contract-review和ADR明确统一方案。

用户已经允许有实证/ADR的核心实现调整，无需仅为选择成熟后端再次询问。实现必须覆盖密码、密钥、各自追加KI、一次/持久信任、changed拒绝、并发归属、超时/取消/保活与关闭；不能只隐藏四枚举、把未知KI当OTP或偷换为两次连接。

### C. 有针对性解决资源与测试服务清理

- Native App仍有间歇weak保留与FD20→23等整案失败。既有计数/断言/失败保留；重点查产品owned socket/PTY/task/对象和重复连接增长。一项readonly已知为QuartzCore文件，另两RW未知；不能凭计数认定产品泄漏，也不能直接加白名单。调整不合适诊断门须明确依据和影响，记录新判定，不能改写旧案或偷偷降低要求。
- 取消A、B继续的认证归属成立，但A测试服务挑战残留。A没有读取OTP，不能据此声称App持久化OTP。测试服务依赖finally的清理与客户端取消分开调查；若需更换fixture源码/image/pin/container，先整理明确最小变更与授权边界，不热改健康服务或用TTL/sweep清记录追认通过。
- 不无限卡在一个完整FD数量门；同问题两轮无新证据就改方法，继续独立UI/其他功能收尾。资源释放的实质问题仍必须解决或如实列阻塞，不能以“为了体验”消失。

### D. 完成真实产品回归与验收收口

在统一的完整候选上验证四认证组合/多轮与并发、信任、SFTP必要路径与冲突/取消、标签切换/关闭、Save/Discard/Cancel、CmdW/红点/CmdQ、真实CmdV/Bracketed Paste、IME/Finder/中键、1000×650/1280×800/1440×900及全屏/长内容，保存新版实际截图。

按影响选择有意义回归，复用同源有效证据，不为每个状态反复全量构建。矩阵用具体实现/证据更新；已有覆盖索引不等新界面已用过，独立审查未发现新问题不等原失败已修。

## 7. 授权、Goal与最终交付

- 当前会话按明确启动提示实际进入Goal；阶段通过自动继续，不逐阶段问“是否继续”。遵守当前Goal工具状态条件，真实阻塞集中说明，不用自动化或新对话伪造持续执行。
- 保留代码、用户数据、旧安装/公证build3和所有失败证据。不生产、不读取真实用户密码/私钥/OTP、不push、不新增虚拟化环境、不重开24h/无关大文件campaign。真实互通只用现有已批准fixture，先核现状。
- 允许必要本地编辑/构建/测试、既有身份离线Development签名、阶段验收后相关本地提交。系统与账户授权由用户操作；此前一次性自建Keychain测试授权按精确范围使用，不扩大为其他条目访问。
- 先完成真实可运行的`UX_READY_FOR_USER`体验里程碑，交付候选路径、源码/产物身份、截图、验收矩阵、已知差异与人工项。用户确认体验满意后，再接最终版本/签名、公证、安装与分发；新的Apple时间戳/上传仍按具体产物授权。离线R2预览、计划、build0、窄门DONE不能作为整个App完成。
- 资源/时间/用量不足就准确交接，不擅自缩小目标宣布完成。缺用户反馈/公证授权时不以整体COMPLETE结束；按实际工具规则进入等待/阻塞并报告下一步。
