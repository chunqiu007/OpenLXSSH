# U0 应用入口盘点与接口约束

日期：2026-10-30。基线152489c；本轮U1改动尚在审查。本文为源码实证，不等像素/真实互通验收。原有后端与旧测试证据保留，不从初始NOT_STARTED推定全无实现。

## 页面和动作：当前可复用与差距

| 页面/入口 | 源码动作与owner | 现有正常/异常路径 | 本轮缺口 |
| --- | --- | --- | --- |
| 主窗口 | OpenLXSSHApp/AppDelegate owns NSWindow、AppModel、关闭流程；MainView观察 | 无任务await连接close；活动传输Continue/Cancel；retained临时路径；quit与window overlap admission freeze；重开不恢复连接 | 原仅File/Edit菜单；无统一顶部页；窗口与布局偏好未恢复；各上下文快捷键缺失 |
| 主机侧栏/列表/详情 | AppModel / AppRepository / Core；HostTable原生NSTableView | 所有/收藏/未分组/单层folder；名称地址用户名过滤；双击只打开一条；选择详情；无数据/加载/存储错误保留前快照 | 卡片、排序切换/稳定选中、多选/批操作、tags、嵌套组/移动、完整右键与搜索分组缺失；狭窗最小宽度叠加 |
| 主机编辑 | Editors/HostDraft/SecurityCoordinator | 添加/编辑/取消/保存；旧四认证枚举；授权remember/forget；共享引用不误删；错误保留非秘密草稿 | 仅两主认证与KI真实接线；不记住密码连接内存交接；save&connect；字段近旁验证/草稿离开确认/密码显示；高级收起/密钥搜索就地管理 |
| 密钥凭据 | SecurityViews / SecurityViewModel / SecurityCoordinator / SecurityJournal | RSA/Ed导入副本，Ed生成；encrypted/passphrase；可取消；公钥显示复制；key引用阻止删；精确forget/unused delete/recovery；失败不自动清外部资源 | 标签、指纹/算法行、搜索排序/duplicate公钥识别、详情/解除关联与受影响清单；工程提示过密 |
| 已知主机 | TrustManagementView/TrustManagementModel/HostTrustStore | 独立记录/算法/指纹；替换需要旧fingerprint+新pubkey+核验，token/revision/expiry保护 | 搜索/复制/精确删除API、首次三按钮、真正一次trust；旧管理模型close不能在切页误永久关闭 |
| SSH连接与标签 | SessionController/SessionTab/DirectSessionDriver/DirectSSHSession | per tab真实NativeTerminalView、owned PTY/OpenSSH；state/current-token；preparation cancel/reconnect gen；closed await driver；认证事件才markConnected | 原reuse只hostID；跨页可见性；拖排/后缀/tooltip/右键/批close确认；页面选择邻项；本轮U1已写实现但未验收 |
| SSH信任与认证 | DirectSSHSession/HostTrustStore/AskpassBroker | 预扫→evaluate→实际strict known_hosts/受信算法；changed拒绝；unknown masked/manual/notice/confirmation；MFA手动；保存密码exactOS/SSH白名单仅passwordOnly首request预算 | 当前UI先手点打开，额外核实声明；无一次信任；系统Askpass不能可靠区分KI与初始密码。不能仅启用KI后扩大首masked自动填密码 |
| 终端 | NativeTerminalView/SwiftTerm固定1.99.1、PTYGeneration | VT/ANSI真实解析；IME/TextInput由SwiftTerm；font/history/theme；copy/paste/search；保留view，release only关闭；output与控制面隔离，clipboard/URL远端默认拒绝 | 默认三色组被解释system→浅色白底；常驻按钮/说明；Cmd+F/字号/右键/回底/搜索状态持久等需完整接线；实际像素/键盘/IME待验 |
| SFTP连接与浏览 | FilesController owns request/gen/service/TransferManager；LibSSH2FilesConnector/FilesAuthenticationPlan | 独立手动连接，typed password/publickey/KI，有多prompt/echo/zero；同握手hostkey共享store；取消/close/idle及旧回答失效；浏览逐段lstat/noFollow；精确原始文件名 | 旧sidepanel；本地pane、主机chooser/导航history/realpath登录目录、过滤隐藏/排序宽列/键鼠/右键；纯metadata整行比较造成陈旧/假变化风险 |
| SFTP文件操作 | FilesController/SafeFileOperations；FilesDialogs | mkdir、rename、delete plan精确范围/链接策略、capability probe、risk/token；错误保留原件；取消不冒全部回滚 | UI多工程按钮；本地对应操作、聚合删除/详情与统一导航；普通双击非目录不能误报symbolicLink |
| 传输/队列 | application-level TransferManager + FilesController；FilesApplicationUI在root，不依赖tab | unique temp/safe commit/current probe/冲突skip-rename-overwrite、batch、独立risk、取消/失败/从零retry；history exact removal只删记录；部分跳过不标成功 | 总量/速度/方向/结果定位、批次/子项信息层级、菜单与折叠；等待/空/禁用说明；切host影响确认；简洁必要风险不删安全语义 |
| 设置 | SettingsDraft/Core AppSettings + sessions.updateSettings | font/size/theme/colors/history/keepalive；校验/preview/save后立即应用terminal、不重建；错误不写坏配置 | categories、defaults/reset范围、光标/真实可支持设置、menu Cmd+,、帮助版本许可证/快捷键/隐私诊断预览 |

## U1界面实现边界（未当全部完成）

- 顶部页为vault/sftp/session(id)，固定两页不在SessionController.tabs，因此close/reorder不可能删固定页。
- 原资源唯一owner不变；路由仅呈现和visibility。切页必须保持search/selection/scroll、认证归属和TransferManager。
- 新ConnectionIdentity仅非秘密字段：address/port/user/auth/keyRef/credentialRef/save授权/keepalive。显示name/folder/favorite/lastConnectedAt不参与。Key实体口令引用变化仍需要后续授权再核，不借此放宽凭据读取。
- 配置切换新tab而不杀旧；同host同fingerprint才reuse；显式new总独立。SFTP已连接快照与pending新配置分离。
- 原有NativeSmoke按旧布局/按钮/手动弹窗路径，新UI应增加/适配真实动作，不降低断言、不删除失败；测试用合成隔离数据。

## 认证最小实证候选（尚未决策/实施）

实际源码：`AuthenticationPolicy.SavedPasswordBudget.claim`只依据控制面首masked/hint、`DirectSSHSession.launch`严格仅`.passwordOnly` eligible；开启KI即不能可靠把编辑器初始密码投给服务器请求。不应将此限制改名掩盖。

现有libssh2同握手typed password/publickey + KI已用于SFTP；`LibSSH2FileService.establish`基于明确方法调用，KI始终独立handler，支持多prompt/echo/zero，最多三种不同方法，不按文案分类。现有C bridge没有shell channel，仅SFTP。官方成熟API提供channel_open_session/request_pty/shell/request_pty_size/read/write/keepalive/close。候选为复用成熟native连接实现新增真实SSH shell/remote PTY接线到同一SwiftTerm视图，不自研SSH/crypto，或通过有同等可靠阶段信息的成熟客户端适配。必须先有限真实fixture证明单连接初始密码→KI，而不是两个SSH连接或故意错误探测；实施前单列ADR、API与许可证/资源/取消回归。未实施、无新真实连接，不能称候选已选定或通过。

## 实际核对命令与证据

- `Scripts/build-app.sh Debug build`：U1首轮exit0，`DerivedData/UXVerification/U1/debug-build.log`。
- `Scripts/build-app.sh Debug test`：正式min26 Debug155 tests/0fail/exit0，`DerivedData/UXVerification/U1/debug-tests.log`。原历史160是HostProbe另一配置，不强称此次覆盖相同数目。
- build脚本使用固定SPM pins、native160输出/7notice验证、reviewed plugin hash；不重建原生库。Resolve首次受用户Xcode外部DerivedData偏好产生日志目录警告，后续实际构建使用workspace明确`-derivedDataPath`成功；不擅改系统偏好。
- 新单元覆盖：20次workspace visibility保view/driver/connectCount、tab排序与临时rename、邻项close、metadata identity忽略/connection change新tab、固定路由/chooser不依赖筛选、command每次新id。是逻辑driver非真实网络/像素。
- 本机CUA可以启动旧OpenLXSSH，但当前AX树异常仅重复menus、无主内容可操作节点，截图同样无法交给本模型像素。Codex已提供六图文字转写 `docs/ux/visual-reference-text.md`，因此视觉设计已有可读依据；仍没有新版像素验收，不能据此声称GUI通过。后续用可核的原生动作smoke并保留视觉门。
