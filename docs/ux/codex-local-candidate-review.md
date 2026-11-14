# Codex 完整本地候选实际验证

日期：2026-11-01。整体 Goal active，尚未 UX_READY_FOR_USER。本页记录当前真实结果，不替代116父项、也不冲销历史失败。

## R15退出修复验收（2026-11-02，仍未UX_READY）

R15完整候选`Local-589e76ae/R15/OpenLXSSH.app`，main SHA256 `2c1dd24e336d116a180e3360f1287556dd3326989042f9949fc82e4c331def56`；8项实际8/0、0skip、exit0，输入b75caa…db2cd前后不变。主管独立strict/deep及SHA核对通过。已无OwnedQuit/Tab诊断日志；具体测试与装配见r15-host-quit-281a4fb7-result.json和20261102/r15-local-assembly-58/result.json。

R14真实菜单退出取消、保存退出后重开、放弃退出后重开均符合草稿语义；嵌套key picker与系统NSOpenPanel在CmdQ后保原面板，取消/关闭返回原草稿且没有迟到退出。R15去日志后新Host CmdQ审核/Escape取消/保持焦点/放弃草稿回6主机也实际通过，截图`r15-quit-review-full-text.jpeg`显示说明完整换行，修复R14实际截断。全部无活动SSH/传输，活动传输退出仍需单独旅程；不扩为所有生命周期已验。

原R14/R14b失败停在Host挂载等待。新测试只修SwiftUI accessibilityIdentifier与NSView.identifier混用，改用真正显式设置NSView.identifier的NativePopup；等待预算、退出属性/嵌套保护/取消保留/零凭据副作用断言不变。正常空草稿try?产生的invalidUser关联错误不作为产品异常结论，原log/xcresult保留。

R14帮助菜单实际打开快捷键、版本数据与可滚许可；诊断选择版本和数量后复制，并在已聚焦搜索框真实CmdV得到完整预览，随后清搜索。首批CmdF+CmdV未等焦点而未粘贴的操作也保留。只读帮助NSAlert的Escape未关闭，CmdW可关闭；许可截图到中段，未宣称已滚至末尾。相关AX与截图位于candidate-live-5和screenshots/candidate/r14-help-*、r14-diagnostics-*、r14-licenses-*。

服务生命周期/fresh retry包层2源及审查报告已本地提交f9513c9，无push；R15基于此前ef09882+dirty源，代码字节相同，产物身份明确区分。当前冲突UI误述正在单独最小修复；跨栏/Finder、批策略传播、同暖态资源、人工项与116收口继续，不宣布完整App完成。

## 2026-11-02 R13实测与R14退出诊断（未UX_READY）

R13去Tab Logger后实际前向/反向拖排、终端区无效落点后再次拖动均通过；右键只重命名B、实体中键只关闭后台A、普通点击/AX选择/关闭按钮及最后CmdW回Vault也实际通过。证据位于candidate-live-5/r13-drag-*.json、r13-invalid-then-repeat-drag.json、r13-tab-context-rename.txt、r13-middle-close-exact-target.txt、r13-left-ax-close-last.json。范围是真实产品的三个失败状态标签，无relay；不冒真实SSH重排互通。按住时Escape/关源没有当前工具实体组合证据，复用生产事件回归。原OS拖动失败与unhosted中键失败保留。

R10虚构主机分组/标签/复制/解除副本标签/切页筛选，R11标签Return保存均已补入矩阵；父116仍INVESTIGATED，子110（65 VERIFIED/42 IMPLEMENTED/3 INVESTIGATED），不是完成率。

R13 dirty Host的CmdQ和真实Quit没有进入退出代理；限定trace只看到sheet_created/began=true。Task50仅明确Host sheet opt-in允许全局草稿审查，默认/嵌套保护与原退出guard不改。R14编译成功但实际8项7过1失败：新增Vault新建Host测试unexpected invalidUser，原log/xcresult保留，尚未确定测试失败原因或真实Quit行为。当前只装配诊断候选，不宣称退出修复验收。临时OwnedQuitTrace最终须移除；后续日期化结果覆盖此状态。

## R10 实际重试窄门（2026-11-02；当前仍未UX_READY）

R10输入`758f9547…defa8805`，main SHA256 `c7401012939d11e596ee801284c7d604e0b51a8a749624d51ba66a7ea0c06374`；Task36十项10/0，主独立五项5/0。原崩溃已保留，当前修复的原geometry及真实hosting teardown门均过；独立源审未见新问题。

R10真实新目录任务取消后手动断开/同身份重连，重试选择器取消保旧任务，错目录明确拒绝，原根重新授权产生fresh 4项59B审核且确认前0活动；确认后新job逐独立风险，改名nested行文件并跳过中文文件，UI明确“部分跳过，未全部成功”、14/59B。两原SHA不变，新14B副本相等，见candidate-live-5/r10-retry-files-sha.json及r10-retry-*.txt、对应JPEG。原任务与新任务UUID不同；不是续传/自动重连或59B全成功。期间慢观察触发原60秒idle取消picker，fresh手动连接后成功，没有更改策略。

真实拖排仍未过：源完整down/drag/up已到，系统会话却在up之后开始并停留原按下点；Task39正在按已审设计改为单一窗口内mouse tracking，所有build一致，删除旧OS拖放栈和临时日志，不降低身份/范围/取消守卫。旧失败保留。

R10在拖动残留后关闭主窗口，进程保持后台、网络FD0；正常重开同PID0会话、3测试key、无模态，未崩溃。内存任务按既有设计重置，原结果已存。不能据此宣布所有资源门通过。

## 2026-11-02 补充验证（未UX_READY）

Task29重试修复已完成源码主审和独立审查，包18/0；R10c真实App编译成功、两项新重试用例通过，完整xcresult为83尝试/82通过/1几何测试崩溃。Files五个已编入类75项全部通过；Native7过1崩溃。旧条件HOST_PROBE内的FilesManifestCancelRetry类未编入，不能计通过。R10/R10b原两次编译失败均保留。

崩溃是确定产品路径：无活动lease时sessionEnded(nil)因nil==nil通过，source.dispose在NSHostingView销毁graph时冗余发布false触发Swift独占冲突。Task35仅两文件修非nil租约、状态未变零通知、拆卸同步撤权且有代次保护的延后UI发布，正常结束仍同步；原91测试正文保持。Task36只重十项相关Native门，尚未得到验证结论，不用82通过掩盖崩溃。

R9未变化页面另验：虚构长名称主机草稿展开高级并滚至底，保活两字段及固定底部按钮实际可达，草稿已放弃；密钥页真实生成本轮测试Ed25519后自动选中详情(0引用)，没有写服务器授权或记住口令。证据candidate-live-5/r9-editor-long-advanced.txt、r9-generated-key-selected.txt及同名截图。不是认证成功或完整密钥生命周期验收。

## R9 最新结果（23:35；覆盖下方各旧待验时态）

- R9是完整本地诊断候选，路径`DerivedData/UXCandidates/Local-589e76ae/R9/OpenLXSSH.app`，main SHA256 `e3c26fad6e876520c1d81f6580232579c79c22348ab2bce45d687e822ab27c13`。三真实密码会话已连接；定向几何/lease4/0。临时有界原生拖动Logger必须在最终体验候选前移除；R9不是UX_READY交付。
- R5 Unicode小目录下载完成，与R3上传构成2文件/2目录59B真实GUI往返，逐字节/SHA一致，见`candidate-live-3/sftp-roundtrip-sha.json`。任务右键Finder定位及清完成记录后文件集合/SHA不变已实测。下载后本地列表需手动刷新。
- R5草稿Save/Discard/Cancel、组名Enter、密码字段Enter仅保存；R7六设置类别、字号5拒绝/14保存读回和既有三会话即时生效、类别重置取消/确认恢复13；R7批关闭其他取消保3/确认仅关2/最后CmdW回Vault；R8终端真实选词CmdC→搜索框CmdV得到R8_SESSION_A均有实际操作证据。Vault列表/卡片三规定尺寸已截图；其他页/长内容继续。
- R8 SFTP idle后主动未连接及issue单处显示已验；下载pending时关闭SSH C不影响原SFTP job，继续至真实同名冲突，取消后原文件/集合SHA保持。重连后的retry在刚ready约10秒内仍files.closed，Task28源码确定旧serviceID校验必拒新连接；Task29安全重绑定实现中，未验修复。
- R9两次drag未改序：源启动及末尾接受均通过，未收到prepare/perform/source.end，末尾提示残留；第二次只有hit无down。真实visibleRect比bounds大，末尾overlay命中和dest结束清理已有确定缺口；第一次无perform根因仍待。日志`candidate-live-4/r9-drag-diagnostic-gesture1.log`/`gesture2.log`。
- 原测试失败保留：R5 260/253过7败（6刷新竞争+1旧中键）；刷新修复后R6 199/198过1败，R7 92/91，R8 131/130，均余同一unhosted中键7断言；新R9定向4/0不冲销原失败。原ACK115/116、fixture取消残留与旧资源失败也保留各自范围。
- 子矩阵现101行（56 VERIFIED/42 IMPLEMENTED/3 INVESTIGATED）；父116仍未逐项完成。fixture四旧镜像未部署lease修复。拖排、retry、完整GUI冲突操作、Finder拖放、其余窗口菜单及人工IME/布局/VoiceOver和相关本地提交仍待，不提前最终签名、公证、分发。

## 18:55 最新实际结果（覆盖下方较早的待验描述）

- 当前运行R4/PID75308：`DerivedData/UXCandidates/Local-589e76ae/R4/OpenLXSSH.app`，main SHA256 `e41cff3048c38d1cf30dea19f123412539bfbd4f746787f54c5d01221a5f08b0`，4958输入SHA256 `588739822241cf09198c4156837ea5ea02ac0a2d2b5155b84f2f71943569a96a`。定向103/0，主独立嵌套窗口/永久拆卸5/0；同测试root，离线签名，无Apple请求。
- E07/K07：真实key picker取消、重新选择均保原草稿；新MFA草稿中就地导入对应key并返回，也可保存并连接。没有新增崩溃；R2/R3原ips保留。
- A02/A03：普通密码、普通密钥及各自追加A/B/C三轮与零输入通知均已在当前完整候选进入真实shell。两MFA会话同时连接，公开`KEY_MFA_R4_OK`及`PASSWORD_MFA_R4_OK`实际可见。成功案时序约33.9秒准备材料、38.2秒完成A到零通知；此前超时保留，不倒推全部原因或宣称企业/手机认证兼容。
- N06/N07：多行真实系统粘贴先停在高亮输入，显式Return后才执行；CmdF输入查询、Enter后显示1/2与实际高亮，Escape关闭。
- V03/V06：终端实际拖动到1000×650、1280×800、1440×900并进入/退出全屏，实际JPEG与尺寸证据保留；其他页与长内容仍需尺寸验收。
- N12/W09/A09：有限relay71559自然exit0，两MFA标签均显示connectionLost并保留各自历史，无自动重连；逐个CmdW回Vault，FD16/网络FD0/RSS215936KiB。实体区域中键关闭keyonly也成立；AX索引middle动作仅选择，不作为中键证据。单批样本不独自证明零泄漏。
- F09/Q01：真实GUI上传2文件/2目录、59字节已全部成功，4项均报告成功，刷新远端看到结果。下载遭闲置关闭，往返摘要仍待。
- SFTP状态层4文件已修且冻结，原60秒/活动lease/无自动重连保持；包层17/0。5项UI交互缺口14文件已修且冻结，当前R5统一定向构建/测试进行中；这些修改尚未计GUI通过。

实际截图均在 `DerivedData/CodexTakeover/20261101/screenshots/candidate/`。R5完成后更新下表及子矩阵，不以测试数量代替体验里程碑。

## 当前来源

- 分支 `ux/termius-desktop`，HEAD `ef09882`，包含既有未提交整合实现；不覆盖旧安装。
- 完整候选使用 `DEBUG LOCAL_CANDIDATE`，普通SSH和本次密码共用真实NativeBuilder，SFTP使用独立LibSSH2FilesConnector；不是HOST_PROBE或离线预览。
- R3路径：`DerivedData/UXCandidates/Local-589e76ae/R3/OpenLXSSH.app`。main SHA256 `7869c3e78b4c19338a1a5bb9dc5e2f02ef898ab7b3a84823c03be8564a9a9439`；4958输入SHA256 `83ad198b4792e21606593293e2b328847658297e1c8ab82443e7acf968a5f8b4`。身份见同目录identity.json。
- 独立bundle/data/测试Keychain namespace为 `589e76ae-80dc-4f42-8470-d8c212353717`。仅本轮自有临时根，不读取既有用户数据库/密钥/凭据。
- arm64/min26、既有Apple Development离线签名、无时间戳请求，strict校验通过；最终签名、公证和分发等待用户体验确认及具体产物授权。

## 已观察的产品行为

| 要求 | 实际范围 | 结果与证据 |
| --- | --- | --- |
| E05/E06/A02 | 主机编辑本次密码→不记住→保存并连接 | R2真实登录，不重复索要相同密码；普通列表双击/手动重连再用系统粘贴+Enter成功 |
| T01～03 | 首次密码主机指纹、添加并继续、之后普通连接 | 真实指纹和带外fixture一致，后续不重复信任；不代表一次信任/变化拒绝所有GUI分支 |
| N01～03/N06 | 真实终端系统粘贴与远端printf | 中文、Ω、Emoji、ANSI红色实际可见；普通error不染红；stty回41×139。不冒人工IME或所有颜色模式 |
| W09/A09 | 密码SSH标签CmdW | 回Vault，所属网络FD0，暖态FD16；还需密钥/MFA/多次新标签及SFTP增长趋势 |
| A07/N12 | 有限relay自然到期 | 历史ENTRY_ORDINARY_OK保留，无自动重连。原错误归网络不可达；R3已改此前连接后的connectionLost，真实新分类GUI待验 |
| K02 | 原生文件选择器导入本轮加密Ed25519 | 创建候选自有副本，公开标签和指纹可见，不记住口令；不打印或查看私钥正文 |
| F01/F03/F04 | R3密码SFTP独立连接 | 初始密码框Enter实际连接，显示真实登录目录 `/fixture/home`；本地面板继续可用 |
| F08/F11 | 新建自有远端目录 | 精确时序新案成功创建 `/fixture/home/openlxssh-codex-3baf35c6db9e`；之前两案files.closed保留，不倒推全部原因 |
| F09/Q01 | 小Unicode目录上传清单 | 本地2文件/2目录，共59字节，真实GUI显示源/目标并经明确提交；传输与摘要核验尚待完成 |

截图：`DerivedData/CodexTakeover/20261101/screenshots/candidate/`，包括真实终端、首次信任、普通密码marker及R3上传清单JPEG。不是静态mock。

## 必须保留的失败与剩余工作

- R2 PID70178 17:21:04、R3 PID73716 17:29:41真实SIGABRT。分别发生在选择密钥、取消key picker后；两份原始ips位于 `nested-key-crash/`。共同栈是SwiftUI焦点拆卸重入 `NativeSheetPresenter.Coordinator.update`，向正在析构NSWindow注册弱引用。最小修复已冻结，尚待测试及完整GUI复验；不能把自动重启后的Vault误写成正常关闭。
- SFTP manager按原60秒策略释放无任务闲置服务，但UI无服务生命周期通知，会继续显示ready到下一操作失败。源码确认独立缺口，不能通过取消/延长超时或自动重连绕过；前两次mkdir关闭原因未能仅凭文案确定。
- fixture逐认证lease源码已提交 `ef09882`，原40测试不变、新增12，主管独立52/0；真实四容器仍旧7f镜像。取消A/B继续的服务端挑战卫生尚未修验。已收敛仅三源码COPY覆盖层与原四服务受控stop/build/up方案，未执行或改变测试身份。
- HostProbe真实绘制ACK门原115/116，唯一unhosted前台/occlusion不足仍失败；正常App看见新输出是独立证据，不改旧门。
- CmdF页面路由、标签末尾拖放、编辑表单Enter、任务右键菜单/批次表达有源码缺口。其余中键、Finder、拖放、菜单/设置/草稿关闭、三规定尺寸及全屏继续实际验证。
- 两类主认证下的新完整MFA、一次/持久/变化信任、并发取消、保活/关闭，以及SFTP往返摘要/冲突/取消/独立生命周期仍未收口。实体输入法、实体键盘布局和VoiceOver最终体验由人工核验。

## 验证口径

R3定向测试164/0（NativeAdapter75、Bootstrap10、DualPane19、FilesAuth19、FilesController22、Transfer15、PlanPanelHeight2、默认工厂2），主独立新7项7/0。构建前后4958公开输入一致，无vendor/native漂移。真实命令、日志、xcresult位于 `DerivedData/CodexTakeover/20261101/local-candidate-build/r3-*`。没有重跑24h或无关大文件，没有生产连接、推送或Apple上传。

