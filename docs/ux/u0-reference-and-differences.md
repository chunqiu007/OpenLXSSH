# U0：Termius 官方桌面资料核对与差异

核对日期：2026-10-30。仅使用官方公开资料；以下事实来自实际WebFetch正文，不凭记忆补菜单。官方说明并非完整UI规格；没有记载的尺寸、颜色、悬停、错误、取消及快捷键均不能称已核对。用户文字与本项目明确规格优先。

## 1. 已查导航与页面

| 引用ID | 官方URL | 直接可证实的桌面事实 | 未知/本项目选择 |
| --- | --- | --- | --- |
| REF-INDEX | https://docs.termius.com/llms.txt | 导航包括连接、Groups/Tags、Keychain/Identity、SFTP、Workspaces、Logs、Snippets、Autocomplete、环境变量、云/团队/Passkeys等 | 未提供完整桌面菜单、快捷键、手势、设置总目录；不能因此断言相关交互不存在 |
| REF-HOST | https://docs.termius.com/organize-and-connect-to-hosts/connecting-to-a-server.md | Vault→Hosts→New Host，地址/端口/用户名/密码或密钥→Connect；host自动保存；Key显式Save。高级包括Agent Forwarding、Host Chaining、Proxy、Mosh、Telnet；Serial；Local Terminal。桌面本地终端Cmd+L，串口Cmd+Option+S | 首次信任、密钥变化、MFA失败/取消、host右键完整列表未说明。本项目用显式保存；不增加高级协议/转发假按钮 |
| REF-GROUP | https://docs.termius.com/organize-and-connect-to-hosts/groups-and-tags.md | New Host旁chevron→New Group，Label/Parent Group，自动保存；嵌套组，父视图显示子组主机。host右键Edit→Parent Group。多选host拖到group。Tags字段输入/建议；搜索检索tags，Tags多选按全部标签匹配；去掉关联不删tag，Tags悬停Delete删除。Group右键Quick Connect每host新标签。组参数逐字段继承 | 删除/重命名/移动组具体交互、循环校验、失败/取消未说明。本项目必须做本地分组/标签与范围约束，不自动继承凭据或批量发起连接 |
| REF-SFTP | https://docs.termius.com/organize-and-connect-to-hosts/managing-files-with-sftp.md | Desktop two active panes，本地默认；pane选主机后必要认证。点击路径旁区域编辑、Enter提交；点击路径当前目录刷新；Actions→Show Hidden Files，默认隐藏。跨pane/Finder拖入；右键Copy to target directory。双击文件或Open/Open with下载临时副本，修改后提示上传；Settings→SFTP保留应用关联 | 后退前进、桌面队列/冲突/重试/取消、列宽/排序未记载；不得引用移动端描述冒充桌面。本项目文件双击仅详情不自动下载/执行；双栏限本地↔直连远端 |
| REF-KEY | https://docs.termius.com/keychain/ssh-keys-and-certificates.md | Keychain→New key，粘贴/拖入/Import from key file，Label，自动保存；可记住Passphrase。Generate key→Label/Key type/passphrase/Save passphrase→Generate & save；列Ed25519/ECDSA/RSA/ML-DSA。右键Export to host→Select Host→Export and Attach会更改远端authorized_keys。Certificate、FIDO2、macOS Touch ID也有独立流程 | duplicate识别、引用数/解除/删除、复制公钥详细菜单未记载。本项目RSA/Ed25519导入和Ed25519生成，公开复制而不自动写远端、不导出私钥 |
| REF-IDENTITY | https://docs.termius.com/keychain/identities.md | Identity包含username/password/key，可用于多host/group；Keychain→New Identity→label/username/password或key，自动保存；host右键Edit Host Details→credentials username选identity；vault作用域，Credentials from选择来源；terminal sudo等提示可建议identity | 编辑传播/删除/解除关联与具体建议交互未说明。本项目保存授权精确到host，不按终端文字自动投递秘密；不增加完整共享Identity编辑 |
| REF-WORKSPACE | https://docs.termius.com/terminal/workspaces.md | Cmd+T/+→New Tab；两连接Create workspace，name Enter；拖connection到tab创建split。terminal右键Rename只改当前label，不改hostname；view切换保留session；分隔拖动；状态点分别表示输出/输入/错误；Settings→Shortcuts可自定义。workspace可保存template、目录/命令恢复、broadcast | 固定Vault/SFTP布局仍据用户图而非此页；普通tab完整右键/关闭others等未知。本项目drag排序、重命名、不恢复连接；排除分屏/广播/template/自动目录命令恢复 |
| REF-LOG | https://docs.termius.com/organize-and-connect-to-hosts/session-logs.md | 日志是terminal全文录制，默认vault启用；Settings→Logs按vaultEnable/Disable。关闭会删含bookmark的记录；一般保留每host最近完成一次，bookmark保留更久；可能包含显示出的秘密 | 不等于连接诊断。本项目不启用/实现全文录制，不能仿侧栏偷偷留存内容 |
| REF-SNIPPET | https://docs.termius.com/terminal/snippets.md | Vault→Snippets→New Snippet，description/script自动保存；terminal Cmd+. sidebar，Snippets；Paste/Run/双击执行；右键Run in all tabs；Host Details→Startup Command每连接自动执行。package与多目标/同步/AI生成 | 独立能力P，不放假入口，不扫描历史或自动执行 |
| REF-AUTOCOMPLETE | https://docs.termius.com/terminal/autocomplete-and-shell-integration.md | Settings→Terminal或rocket启用；snippet/identity建议。remote Bash/OpenSSH7.2+，额外exec channel读取history/path；可关闭 | acceptance/navigation/dismiss快捷键未说明，历史留存未知；本项目P，不额外读取远端历史、不识别sudo投秘密 |
| REF-SFTP-PATH | https://docs.termius.com/help-center/faq/how-to-set-a-default-sftp-path.md | 官方明确未直接支持客户端设置该路径，仅给修改服务器Subsystem sftp -d的绕行 | 本项目不修改服务器；若本地实现明确起始路径是适配，不宣称完全照搬官方 |
| REF-CHANGELOG | https://docs.termius.com/changelog/desktop.md | 9.42.2 host右键打开新/现有workspace；9.37.0快捷键与Settings→Shortcuts；9.34.3修Select All；9.31.5搜索焦点/拖动group/鼠标选择修复；9.2.0中键关tab。多个SFTP导航、排序、切连接修复 | release notes仅证明版本特定行为，不构成完整当前菜单。OSC52/URL打开是额外能力，不从终端完整性要求自动放开 |
| REF-ENV | https://docs.termius.com/terminal/environment-variables.md | Host details→Show more→Environment Variable→Add a variable→Save，组继承，连接时SendEnv，服务端AcceptEnv决定接受 | 独立配置/远端传递能力P；不修改远端sshd或额外注入环境变量 |

最初key/workspace各一次WebFetch超时，第二次正文成功；失败不算调查通过，成功正文为上述范围。未使用页面问答接口或发送本地配置/原图/秘密。

## 2. 六张本地原图

Codex 已实际查看六张原图，并将逐图布局、颜色起点、信息层级和反例记录在 `docs/ux/visual-reference-text.md`；该文件是本轮可读的间接视觉依据。主管与general-purpose视觉调查在本会话中分别对01～06逐一Read，仍收到 `Media omitted ... selected model does not support image input`，因此当前没有主管模型直接像素证据。**文字转写可以指导实施，不能替代新版App实际截图/像素验收，也不能把视觉条目标为VERIFIED。**

六图的当前可读要点：图一是旧多栏挤占/裁切反例；图二是三动作首次连接卡；图三是Vault侧栏与Keychain空状态；图四是整页深色真实终端；图五是本地/远端双栏SFTP空远端状态；图六是Hosts列表与右侧Host Details检查器。不得将图中真实地址、用户名、路径、文件名或指纹复制到代码/fixture/报告。

## 3. 新发现日常细项（R/A）

| ID | 范围 | 来源 | 本项目动作与原因 |
| --- | --- | --- | --- |
| ADD-01 | R | REF-GROUP | 删除tag实体与仅解除host-tag关联是不同操作，确认影响范围；不把去关联误删全局tag |
| ADD-02 | R | REF-GROUP | Tags多选AND筛选，显式显示筛选chips与清除；无结果可恢复；不探测主机 |
| ADD-03 | R | REF-SFTP | 路径条当前folder可刷新，作为刷新按钮的同一动作；失败保留成功位置 |
| ADD-04 | R | REF-WORKSPACE | tab重命名仅本次显示，不能写回host；重名后缀与tooltip继续可辨别 |
| ADD-05 | A | REF-KEY | 用本地NSOpenPanel导入管理副本而不是表单私钥粘贴/拖入；减少秘密驻留；文件格式/重复公钥结果真实反馈 |
| ADD-06 | A | REF-HOST/IDENTITY | 明确保存替代自动保存；草稿保存/放弃/取消，密码本次连接与记住分离 |
| ADD-07 | A | REF-WORKSPACE | 输入等待和错误用符号/文字加颜色，不只状态点；后台挑战可达，不抢正在输入的另一挑战 |
| ADD-08 | A | REF-SFTP | 双击文件不自动下载/编辑，显示详情；上传下载/覆盖是明确动作，避免引入远端编辑器与新临时内容留存 |
| ADD-09 | A | REF-SFTP-PATH | 默认远端登录目录用SFTP真实路径解析；不强制/home，也不更改服务器配置 |
| ADD-10 | R | REF-CHANGELOG 9.2.0 | 中键关闭普通会话标签，同普通关闭；固定两页不可关闭；不增加新的远端动作 |
| ADD-11 | A | REF-CHANGELOG OSC52/OSC8条目 | 保留默认拒绝远端剪贴板读写/自动打开URL；普通显式复制粘贴R，远端控制本机剪贴板和浏览器单列P，防止额外外发 |

这些细项作为父DX对应的子项进入矩阵，不替代父项全部验收。

## 4. 独立能力与明确排除P（无假入口）

| 能力 | 官方依据 | 本轮处理与理由 |
| --- | --- | --- |
| 嵌套group协议/凭据/theme继承 | REF-GROUP | 本地组织与引用为R；整套继承P，不按group隐含扩大秘密授权。嵌套组织与标签的UI/迁移按spec实现 |
| 共享Identity整体编辑、跨vault凭据 | REF-IDENTITY | 现有host范围引用A，独立Identity实体编辑P；保留授权，不制造第二真源 |
| Snippets/package/多目标脚本/Startup Command/AI生成 | REF-SNIPPET | P；自动执行与脚本库是独立能力 |
| Autocomplete/shell integration/远端history/path读取 | REF-AUTOCOMPLETE | P；不额外开exec，不按文字推荐或投递密码 |
| Logs/录制/回放/bookmarks | REF-LOG | P；仅非秘密连接诊断A，无终端全文新留存 |
| 分屏/Focus编排/template/自动目录与命令恢复 | REF-WORKSPACE | P；标签切页与排序R不扩大为会话恢复 |
| broadcast、terminal sharing | REF-WORKSPACE / INDEX | P；不广播用户秘密或命令 |
| Host Chaining/自动ProxyJump | REF-HOST | 已明确P，手动内层ssh保留 |
| 本地/远端端口转发/隧道 | INDEX | 已明确P；不摆入口 |
| HTTP/SOCKS代理 | REF-HOST | 新独立网络能力P，本轮直连 |
| 经跳板图形SFTP | 本项目范围 | 已明确P；不误用terminal cd推测目标 |
| 远端↔远端双pane | REF-SFTP | P；本地↔直连远端R |
| pause/resume/复杂断点续传 | REF-SFTP未明确桌面语义 | P，不能声称Termius此页已证实；本项目显式从零重试R |
| 自动后台重连 | 原需求明确排除 | P，手动重试R，不恢复连接 |
| 远端编辑/Open with/文件应用关联 | REF-SFTP | P；新临时内容与远端修改行为，不自动启用 |
| SSH Certificates | REF-KEY | P，新增证书实体与生命周期超范围 |
| FIDO2、Touch ID/Windows Hello设备密钥、SSH ID passkeys | REF-KEY / INDEX | P，新增认证能力；Keychain现有秘密访问不等价此功能 |
| Agent Forwarding | REF-HOST | P；默认禁止 |
| Mosh、Telnet、Serial、本地shell | REF-HOST | P，独立协议/本地执行目标；不抢Cmd+L等未实现操作 |
| 环境变量/启动脚本/命令自动执行 | INDEX / REF-SNIPPET | P；不自动执行 |
| Cloud账号/同步、多Vault共享、team/subscription/AI/通知中心 | INDEX | 本地单Vault适配A，其余P；不显示登录/付费占位或发送本地数据 |
| AWS/DigitalOcean/Azure云导入/同步 | INDEX / REF-GROUP | P，独立外部服务 |
| 快速ssh命令导入、批量导入/导出 | INDEX仅host import目录 | P，具体交互未查实不凭记忆；搜索配置与复制端点R |
| 私钥导出/备份恢复/自动写authorized_keys | REF-KEY | P；仅复制公钥R，不操作生产 |
| SSH config导入 | INDEX host import | P；维持App独立配置，不改系统 |

## 5. 明确未知

未核实Termius当前所有版本的精确像素token、完整应用/窗口/编辑菜单、所有tab context items、hover/disabled/focus、桌面队列冲突/取消恢复的完整路径以及中文IME细节。按spec已有明确设计实现和实测，记录“OpenLXSSH设计选择”，不以未知为理由省略R。官方导航仍有待按必要性深查页面；不能把本记录称“全部页面调查完成”。
