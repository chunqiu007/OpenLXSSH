# 当前桌面剩余实现审计（接续会话）

日期：2026-10-30。初始只读审计不是116项行为通过证明；以下原始条目保留作为来源，**当前实施状态以本节、ENGINEERING_STATE和后续实证为准，不重派已完成项。**

## 本轮已收口与仍在执行的范围

- 六类可靠性、Core原子陈旧检测、提交后实际credentialRef与只读恢复已审；本地5e73f7c/4749897。
- 全局dirty host窗口/quit预检逻辑Close18/0、主管Close/Trust/Label39/0及真实host高度修已过；真实红点/CmdQ仍另验。
- 已知主机搜索/复制/精确remove、管理readTask恢复竞态和keylabel准确owner已过；本地ad36b13，实际新UI另验。
- 重复公钥导入review/reuse模型门主管App34/0、严格包29/0并实核min26，本地ed281c3；下方第2节不是“仍无API”。实际picker/复用UI另验。
- MainView本次密码handler已真实接线到internalNative候选，prepared精准dismiss后commit、新代次/token/request一次消费、typedprimary/manualKI、多字段/echo/zero、三按钮信任和自动owner呈现已实现。正式107/0及主管独立39/0；下方第3节旧nil描述不再适用。默认Direct仍不变，真实App四组合/once/changed/终端门未过。见auth-app-adapter-review.md。
- 候选normal/独立MaxSessions/严格DROP有限门已过；R3两次failed精确定位后，R4仅测试infra预热guardian+保守实际arm年龄门修复，严格DROP5.917秒/actualarmAmax0.109秒/natural0/精确remote清理通过，runtime未改。见native-liveness-live-finite.md。
- FILES-REVIEW-OWNERS-R1精确target/迟到owner/空错态/queue记录已过86/0和主管owner15/0，rawfixture按本机EILSEQ事实分层保精确字节逻辑与合法复杂名真实IO，不冒物理非法UTF8或SFTP。新增FilesLayout10/0及主管独立10/0已过，实体拖拽/像素仍待。递归Manifest包层现唯一writer实施中，尚未接App审核，见files-transfer-plan-design.md。
- DESKTOP-PREFERENCES-HELP-R1分类设置/等宽字体/真实光标/类别reset/本地帮助及固定管理页启动偏好已实现，Core18/App99/Transport12实际min26通过，主管Prefs/Close关键43项及Core18独立通过；真实设置GUI仍待。Window13本地门过，Middle一方法仍红，现只准备准确NSApplication.sendEvent测试路径，不放松产品/假称实体输入。
- runtime typedchanged与sealedcanonicalhandle包层strict180+主管22、App typedchanged53+主管53均过；新版immutable consumer五真实分项主管亲跑通过，见native-failure-live-finite.md。已本地e806551提交Files候选包18项，不含App/实验目录。App finite close/retired/incomplete R1严格唯一228项与主管40项、R2受影响88项与主管关键13项通过；取消重复join和未知资源证明两处源审遗漏已精准修复。真实Delegate退出/App互通不因此通过，见native-app-retirement-review.md。

原生键鼠/像素/CmdV/三尺寸/最终用户体验、全部116父项仍未验收，不以以上分项计整体完成。

## 已有可复用功能

- 固定Vault/SFTP与新连接选择器、保留页面、相邻会话选择；列表/卡片共用原生NSTable多选/键盘/菜单，组织搜索/排序/分组/tag/批量目标已有。
- 两种主认证展示、saved不读回、密钥内联生成后返回草稿、公钥/指纹复制、查看/解除引用、引用中阻止删除、忘记密码/口令已有。
- 实际SwiftTerm深色、自定义色、复制空选不清剪贴板、精确粘贴、右键/搜索/字号/清历史/实时底部已有，不能重写以代验证。
- 双栏导航/路径Enter-Escape/筛选hidden/排序调列横滚/精确路径/文件仅详情/聚合删除已有；realpath能力及5消费者本地门已过，真实服务器显示另验。
- job速度/总量未知/部分跳过/四类冲突/从零重试/定位/精确清已完成记录已有，不再泛派“实现清空队列”。

## 最小任务划分与缺口

### 1. DESKTOP-CLOSE-PREFS（先只做全局关闭保护）

- **最高优先：** AppModel workspace guard只保护requestSession/showWorkspace；AppDelegate红点/CmdQ requestClose只问传输，不先问dirty/writing editor。须在freeze admission或cleanup前接准确owner异步预检，Save成功再继续，Discard清输入，Cancel完整保留；复用唯一close task，重复quit/window升级不重复清理。
- 后续同域：标签overflow可发现左右导航、resize/reorder ensure active、中键关闭、selected trait和批量清单；展示名称/配置删除标记与不可变连接快照分开。
- 非秘密恢复：窗口frame、布局比例、管理子页/有效选择/文件列宽列序；坏偏好/失效ID回退，零连接恢复。
- 设置仍单Grid，默认预览/文案与实际终端深色不一致；补分类、等宽picker、类别reset、真正接renderer的光标/粘贴偏好。帮助已有标准About，另需本地数据说明/第三方许可/最小脱敏诊断范围预览，不能自动上传/采全文。

源码入口：OpenLXSSHApp.swift:127–180、233–240；AppModel workspace guard；MainView.swift:47–105；Editors.swift:47–106；VaultPreferences；DualFilesEntryTable列默认。

### 2. KEY-TRUST-MANAGEMENT（先已知主机与label owner）

- TrustViews仍声称无remove API，只有列表/替换。接已存在HostTrustStore精确remove、endpoint搜索、完整复制、失败非空态、来源如实为App专属库，不造时间。取消/陈旧确认不删替换的新记录。
- KeyCreation create success即便label失败也dismiss；管理创建后只换selectedKeyID未同步labelDraft。需准确key owner、label失败只重试标签，不重建；原load不清issue，不能谎报错误丢失。
- 重复公钥导入只查UUID未按规范公钥识别。应注册/保存口令前产生复用/取消review，清本次材料走原journal；不同文件名同公钥保同一实体、不扩大授权。
- 内联生成回草稿已有；独立管理页生成后引用主机入口仍需共用entity/草稿，不写远端authorized_keys。

源码入口：SecurityCoordinator.createKey、KeyStore.importKey、SecurityViews创建完成/label、TrustViews.swift:61–99；精确remove在HostTrustStore.swift。

### 3. AUTH-APP-ADAPTER（等待已派Native readiness/ADR）

- MainView仍transientConnection:nil；有本次输入时禁用保存并连接，是缺功能不是静默丢输入。
- DirectSessionBuilder仍默认，普通legacy方法KI仍关闭；两个UI选项不代表两类MFA。
- 自动活动owner认证sheet、多字段/echo/zero、typed primary/keyphrase、三按钮信任及错误恢复/编辑/脱敏详情尚未App接线。底层候选positive不代新App gate；未知KI不自动收到长期密码。
- 必须正式App四组合、一次性intent一次消费、并发取消/迟到、once/persistent/changed/实际key不符、资源回收及有限TUI/输出复验；不重24h/无关大文件。

### 4. FILES-REVIEW-QUEUE（先目标owner和迟到review）

- upload/download/drop直接enqueue，目录无用户可见只读递归计划/数量；入队锁context已有，保留引擎，增加有界plan/确认/取消零变更。
- 本地首读失败也显示空目录覆盖层，错误/空/筛选空需分别呈现。
- 新文件详情/rename/delete对话框需要冻结endpoint/parent/generation并拒迟到；旧界面显示当前model.path有误投风险。
- 队列取消/host change说明须如实解释共享服务影响，不能泛称保留任务就不受断开影响。
- task已有速度；当前子项/枚举结束摘要公开有限状态不足，补有界进度/逐项原因/已接受风险/残留详情，不编每子项速度或未知百分比。
- View清记录await后无条件removalReview=nil，可清后来的review；补reviewID/in-flight，复用controller精确快照保护。

## 必须真实验证的边界

三尺寸/连续缩放/全屏/分隔/长文本、新截图像素、VoiceOver与核心键盘焦点、较大文字/滚动条、真实CmdV/IME组合/实体符号/TUI鼠标缩放均不能由本次静态审计改VERIFIED。第二台/企业/用户最终体验是人工边界，不以单机fixture替代。
