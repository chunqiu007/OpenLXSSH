# 116条要求：共享证据与剩余验收索引

状态：**覆盖索引，不是完成证明。** 116父项均保留 INVESTIGATED；子项 VERIFIED 只表示该行明确列出的窄门。2026-11-01。

本索引把没有独立子行的要求关联到已有共享组件证据，不新造61个probe、不用单测替代GUI。逐入口触发/owner/副作用详见 `termius-parity-subitems.csv`；父项原文及状态详见 `termius-parity-matrix.csv`。用户规定的1000×650、1280×800、1440×900逻辑尺寸及全屏、操作位置与通用状态表均不缩减。

## V：视觉与响应布局（8条）

覆盖ID：DX-V01、DX-V02、DX-V03、DX-V04、DX-V05、DX-V06、DX-V07、DX-V08。

- V01/V02：共享token、固定工作区与默认近黑renderer的已有窄门见 `u1-workspace-review.md`、`desktop-integration-review.md`、`preferences-help-review.md`。原ANSI/默认主题测试不证明管理页密度、色彩对比或全局token一致。
- V03/V04/V07：新表单/挑战/审核面板的自有AppKit几何、长内容滚动见 `close-management-review.md`、`auth-app-adapter-review.md`、`files-transfer-manifest-review.md`。共享几何不能覆盖所有长值、图标/字号、禁用及焦点像素。
- V05/V06/V08：真实双栏稳定宿主、列宽/列序/分栏偏好和窄审核面板见 `files-layout-preferences-review.md`、`window-tabs-review.md`。规定三尺寸、全屏、连续缩放、实际页截图与像素尚未通过；920×580只附加最窄边界。

## W：工作区、标签与窗口（10条）

覆盖ID：DX-W01、DX-W02、DX-W03、DX-W04、DX-W05、DX-W06、DX-W07、DX-W08、DX-W09、DX-W10。

- W01/W04/W08：固定页/连接目录/选择路由及每tab稳定terminal、页状态、隐藏焦点共享证据见 `u1-workspace-review.md`；不能把逻辑替身当所有真实会话/输入已验。
- W02/W03/W05/W06/W07：标签名称/状态/快照与展示元数据分离、overflow、immutable批关闭和菜单状态见 `window-tabs-review.md`。真实自有窗口中部分滚动/箭头门成立，不代实体拖排/悬停/像素。中键原7断言红保留，ADD-10不能从覆盖范围消失。
- W09：关闭邻项与固定页路由共享U1；closed/retired/incomplete、observer取消及有限registry见 `native-app-retirement-review.md`。新版App SSH整体仍weak或FD失败，不能以closed/drained或进程自然exit0认定完整释放。
- W10：Core非秘密启动偏好、windowframe clamp及管理导航见 `preferences-help-review.md`、`window-tabs-review.md`。正常实例三尺寸重开/跨屏仍待，不恢复秘密、会话或输出。

## H：主机、分组与标签（12条）

覆盖ID：DX-H01、DX-H02、DX-H03、DX-H04、DX-H05、DX-H06、DX-H07、DX-H08、DX-H09、DX-H10、DX-H11、DX-H12。

- H01/H02/H03/H07：已接Vault侧栏/检查器、列表卡片、多选与目标数，见 `desktop-integration-review.md`。主体控件、键盘、右键、卡片信息一致性和窄窗需真实操作，source-only不升父项。
- H04/H05/H08/H09：Core本地字面搜索/多tag AND/稳定排序、层级路径/循环拒绝、删组保主机与原子copy见 `u2a-core-review.md`、`u2b-repository-review.md`；公开metadata更新与失败保快照见 `reliability-app-review.md`。UI展开/选择恢复、chips/清除及排序标识另验，不引入凭据继承。
- H06/H11：复制不扩授权、共享引用与删除快照/展示badge见 `u2b-repository-review.md`、`close-management-review.md`、`window-tabs-review.md`。实际菜单和已删配置呈现未由底层事务代验。
- H10：加载失败保最后快照、筛选空不等0主机见 `reliability-app-review.md`；首次空/无选择/创建入口仍需实际页态。
- H12：实际authenticated回调与最近时间更新、immutable连接身份见 `u1-workspace-review.md`、`auth-app-adapter-review.md`；真实候选primary/shell阶段见认证实网报告。普通Direct/本次密码Native仍不同路，不把SFTPready/标签存在当新SSH认证成功。

## E：主机编辑与秘密（12条）

覆盖ID：DX-E01、DX-E02、DX-E03、DX-E04、DX-E05、DX-E06、DX-E07、DX-E08、DX-E09、DX-E10、DX-E11、DX-E12。

- E01/E02/E03/E04：稳定草稿、字段校验、明确保存、Save/Discard/Cancel、保存冻结/准确presentation见 `desktop-integration-review.md`、`reliability-app-review.md`、`close-management-review.md`。实际分区/错误焦点/Tab与Enter/Escape/原生关闭仍待；不能把模型7项当按钮已点击。
- E05：旧四枚举/ID/key与credential引用/授权保留见 `u2a-core-review.md`；两主方式UI与runtime候选见 `auth-app-adapter-review.md`。普通入口和本次密码入口不等价，当前缺口见 `../adr/ux-native-ssh-entry-consistency.md`，不以迁移过关替产品接线。
- E06/E08：一次性intent的prepare/dismiss/commit与saved授权/未知KI隔离见 `auth-app-adapter-review.md`；真实本次密码分项见 `app-password-transient-review.md`。秘密掩码/显示/失焦及真实UI仍未验，App整体资源失败保留。
- E07：共用公开密钥目录、duplicate复用、准确UUID的label completion见 `key-duplicate-import-review.md`、`close-management-review.md`；实际inline picker/生成返回草稿、取消与系统选择器另验。
- E09：Core同事务陈旧拒绝、commit后只读恢复不重复保存凭据见 `reliability-core-review.md`、`reliability-app-review.md`，不重同无变化事务测试。
- E10：连接身份与展示metadata分离见 `u1-workspace-review.md`、`window-tabs-review.md`；改变参数/授权后新代次真实消费者与所有普通入口仍需统一。
- E11/E12：保活合法数值/范围兼容见 `native-liveness-compatibility-review.md`；字段/快捷键/密码焦点与高级显示仍需真实控件，不新增无后端开关。

## K：密钥、凭据与信任管理（8条）

覆盖ID：DX-K01、DX-K02、DX-K03、DX-K04、DX-K05、DX-K06、DX-K07、DX-K08。

- K01/K03/K04：成熟密钥生成/导入、公开label/指纹/引用和label失败只重试同UUID见 `close-management-review.md`、`desktop-integration-review.md`。生成后选中与inline关联的实际控件待；不改支持算法为未实现入口。
- K02：重复规范公钥识别/明确复用/取消/源陈旧拒绝已本地验，见 `key-duplicate-import-review.md`，对应子项已校正为K02不是K03。Finder/NSOpenPanel实际交互未验。
- K05/K06/K07：共享引用保护/精确忘记、metadata单向失效、取消及迟到owner见 `u2b-repository-review.md`、`reliability-app-review.md`、`close-management-review.md`。不读/枚举整个Keychain；新版系统授权拒绝呈现仍unknown。
- K08：本地Vault/Keychain边界与排除项见 `u0-reference-and-differences.md`、`local-candidate-walkthrough.md`，这是范围说明而非独立锁屏加密或云同步功能。

## T：首次信任与变化拒绝（6条）

覆盖ID：DX-T01、DX-T02、DX-T03、DX-T04、DX-T05、DX-T06。

- T01/T02/T03：底层confirmOnce与临时strict快照见 `u5-trust-store-review.md`；新版App once2/persist2两fresh握手/记录字节证据见 `app-trust-real-review.md`。三动作UI已接但真实按钮/像素未验；三案weakcleanup整体失败。
- T04：包typed端点/算法/新旧指纹事实见 `native-failure-package-review.md`、`native-changed-app-review.md`；App typedchanged前primary/KI/shell0真实分项见Trust报告，不允许普通继续或静默替换。
- T05：精确remove原子比较见store报告，搜索/复制/提交后重读恢复见 `close-management-review.md`；实际管理控件与系统剪贴板另验，不改系统known_hosts。
- T06：陈旧/过期/并发/取消本地门分散于store、changed与retirement报告。M3三个场景不是全部多算法、扫描/握手不一致与并发组合证明；未关联的新版本实网部分标unknown，不机械重跑所有历史Trust。

## A：认证、取消与归属（10条）

覆盖ID：DX-A01、DX-A02、DX-A03、DX-A04、DX-A05、DX-A06、DX-A07、DX-A08、DX-A09、DX-A10。

- A01/A04/A05/A07/A08：typed阶段/错误分类、长期材料与manual KI分离、旧代次拒绝、手动重试状态见 `auth-app-adapter-review.md`、`native-changed-app-review.md`、`native-app-retirement-review.md`。普通入口与错误界面、真实掩码/焦点及恢复仍待；不扫描普通终端提示。
- A02/A03/A10：真实本次密码、key/password四轮KI与challenge清理分项见 `app-password-transient-review.md`、`app-mfa-real-review.md`。code−18/−19当时未authenticated，不自行称协议partial-success；KI成功后才authenticated/shellReady。手机厂商/真实企业审批未由fixture代验。
- A06：真实双keyKI同时pending、cross/late拒、取消A/B原owner继续见 `app-concurrent-mfa-real-review.md`。A从未读OTP，但服务端challenge present/B removed，逐owner清理失败，不能升级完整A06。
- A09：准确有限关闭/canonical drain/观察者取消见retirement/package报告；旧Appweak/FD失败仍在。保活数值、原pump离线与有限transport真实mixedload见 `native-liveness-compatibility-review.md`、`native-pump-offline-review.md`、`native-finite-mixedload-review.md`；不代App图形资源或长期pending超时。取消fixture卫生问题独立保留，不能TTL/sweep/unlink消绿。

## N：终端（12条）

覆盖ID：DX-N01、DX-N02、DX-N03、DX-N04、DX-N05、DX-N06、DX-N07、DX-N08、DX-N09、DX-N10、DX-N11、DX-N12。

- N01/N02/N03/N06：真实SwiftTerm默认深色/ANSI/字号、精确UTF8/Bracketed Paste/有界输入见 `desktop-integration-review.md`、`auth-app-adapter-review.md`、`preferences-help-review.md`。截图存在不等看过像素。
- N04/N05/N07/N08：每tab搜索/选择/滚动、隐藏页焦点与精确paste方法见 `u1-workspace-review.md`、adapter报告；真实选区复制、两次CmdV、上下结果/Escape焦点/实时底部操作另验，不读用户剪贴板来伪造测试。
- N09/N10：Ctrl与Cmd分离、IME组合/候选窗/键盘布局必须实际输入；模型和headless不代验。
- N11：新Native transport同连接tmux十帧/31×93/实际detach/outer返回已有finite门；Vim/htop历史记录只保原范围，当前App与像素未由此全部覆盖。
- N12：有界pull/input/保断线历史与显式新代次见adapter/retirement/U1；真实finite输入输出resizeprobe并进和drain见mixedload报告。长期/全部服务器/完整App搜索响应与weak/FD不外推。

## F：双栏浏览与文件动作（12条）

覆盖ID：DX-F01、DX-F02、DX-F03、DX-F04、DX-F05、DX-F06、DX-F07、DX-F08、DX-F09、DX-F10、DX-F11、DX-F12。

- F01/F02/F03/F05/F06/F07：双栏共用catalog、本地metadata懒加载、raw路径/URL身份、导航失败保成功位置、过滤/隐藏/排序和多选模型见 `desktop-integration-review.md`、`reliability-app-review.md`；稳定分栏/列布局见 `files-layout-preferences-review.md`。实际键鼠、多选、双击文件只详情、路径编辑/Enter/Escape与截图需GUI。
- F04：realpath生产能力实现和默认App消费者本地门见 `u4-realpath-review.md`，不猜/home或修改服务器。实际服务器realpath(.)、非根返回后的listing、取消清理及正常候选显示仍未关联实证，不能以API存在代实网。
- F08/F10/F11：不可变target、陈旧owner拒绝、聚合删除/取消与partial见 `files-review-owners-review.md`，不以metadata属性冒CAS。Finder显示/右键/系统picker、完整目标对话框与远端错误呈现待。
- F09：包immutable manifest/source复核与App只读审核见 `files-transfer-manifest-review.md`；真实12KiB往返/确认前零内容IO见 `app-files-manifest-real-review.md`。不代Finder/跨栏拖放和所有来源竞争。
- F12：SFTP应用级独立owner、metadata不假失效、切页/SSH不换目标见 `u1-sftp-identity-review.md`、`u1-workspace-review.md`。三真实SFTP窄案不自动证明所有UI切页/主机改变状态。

## Q：任务、冲突与恢复（8条）

覆盖ID：DX-Q01、DX-Q02、DX-Q03、DX-Q04、DX-Q05、DX-Q06、DX-Q07、DX-Q08。

- Q01/Q02：全局任务入口/独立manager及unknown总量模型见U1、manifest与 `files-review-owners-review.md`；完整队列层级/速度/等待决定的真实显示需验，不能以任务存在判UI可达。
- Q03/Q04：原安全提交/独立risk及新真实rename+skip、原件保全见 `app-files-conflict-real-review.md`。末项skip的apply=true不证明后续批传播，overwrite/risk不被批策略自动接受不能由此补证。
- Q05/Q06：真实正字节受控localread取消/保first4KiB/精确partial/新清单retry见 `app-files-cancel-retry-real-review.md`。不冒自然抢中/native阻塞IO中断/断点续传。重试必须新审核确认。
- Q07/Q08：记录删除owner、immutable目标、切页/关闭/传输确认模型见files-owner/close报告；真实清记录不删文件/不取消活动、切主机/断开确认、定位和菜单状态需实际消费者。非秘密逻辑缺门可本地补，不能因为像素不可用一概停止。

## P：设置、菜单与帮助（8条）

覆盖ID：DX-P01、DX-P02、DX-P03、DX-P04、DX-P05、DX-P06、DX-P07、DX-P08。

- P01/P02/P03/P04：六分类、真实字体/光标/默认预览、类别草稿reset、Core v4偏好迁移见 `preferences-help-review.md`。没有假并发/超时开关；保活非OpenSSH次数等价文案/普通入口须在切换时准确说明。
- P05/P06/P07：共享菜单命令/当前页搜索、编辑焦点、Ctrl优先及模态保护见 `u1-workspace-review.md`、close/window报告；完整菜单启用/真实Cmd键/IME与多层关闭尚未由模型代验。
- P08：白名单诊断预览与显式复制、离线许可/版本见prefs报告，不读终端历史/用户Keychain或自动上传。实际帮助许可窗口/可访问性需验证。

## X：通用状态、可访问性与数据保护（10条）

覆盖ID：DX-X01、DX-X02、DX-X03、DX-X04、DX-X05、DX-X06、DX-X07、DX-X08、DX-X09、DX-X10。

- X01/X03/X04：以各代表页“空→无选择→输入错→忙→失败→重试恢复”合并实际操作与截图矩阵，不为静态按钮各造框架。已有失败保快照/就近issue模型来自reliability/adapter/prefs报告，但成功提示时间、禁用原因可发现与像素仍待。
- X02/X05/X06：save token/presentation epoch、commit后只读恢复、exact delete/conflict owner、不可变批关闭/类别关闭registry见 `reliability-app-review.md`、`files-review-owners-review.md`、`close-management-review.md`、`window-tabs-review.md`。模型不代真实默认按钮/Escape/焦点归还/红点CmdQ。
- X07/X08：AX名称/角色和自有控件几何可共享局部门；真实VoiceOver朗读、完整核心键盘、大系统字/滚动条偏好/对比/焦点环仍unknown，不宣称已有全证据。
- X09：只非秘密偏好、隐藏SFTP短期输入清理、准确prepared intent撤销见reliability/prefs/window/adapter报告。不声称Swift所有副本可完全擦除，不恢复回答/输出/连接。
- X10：合成旧库v1/v2/v3/v4兼容、DDL回滚、ID/ref/授权保留见 `u2a-core-review.md`、`u2b-repository-review.md`、`reliability-core-review.md`、`preferences-help-review.md`；不清用户数据库或旧候选让页面看起来干净。

## UX-01～14及操作位置/状态表

UX-01工作区→W及U1；UX-02三尺寸与布局→V/N/F；UX-03本次密码→E06/A02；UX-04旧四类兼容与metadata→E05/E10/H；UX-05四组合及并发→A；UX-06未知KI/OTP/内层不投秘密→A04/A05/X09；UX-07首次信任→T及SSH/SFTP各自握手；UX-08连接参数变化→E10/H12；UX-09终端主题/输入→N02/N05/N09/N10；UX-10两会话/TUI/释放→W08/W09/N11/N12；UX-11双栏传输→F/Q01；UX-12冲突/取消/错误/旧响应→F11/F12/Q/X02；UX-13数据/旧产物/秘密边界→K/X09/X10；UX-14新版真实构建/GUI/截图/交付→V08/P/X及候选清单。此为导航索引，精确UX原文仍以 `termius-redesign-handoff.md` 为准，不把本映射当逐条验收。

普通**新建连接**用当前默认Direct；reuse可能选中最近有效的Native候选标签，重连保持原driver及tab.builder，不因点击列表悄换后端。所有操作位置/状态应在正常候选上按 `local-candidate-walkthrough.md` 记录真实结果，不能用HostProbe无参数作空白环境。未完成项包括普通入口一致性、PAM取消卫生、旧App资源失败，以及需要实际前台/像素/实体键鼠的门；整体尚未交付，未 `UX_READY_FOR_USER`。
