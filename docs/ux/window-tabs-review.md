# 窗口与标签：源码审查待验证项

日期：2026-10-31。状态：**最终统一Debug构建已过，Changed53/0及关键回归/Window13共107/0；完整Window14仍因中键实际currentEvent命中3断言失败，PARTIAL。** 不把13个绿色方法或静态保护区当中键验收。

来源：`DerivedData/UXVerification/DesktopWindowTabs-R1/source-ready.patch`、`source-ready-sha256.json`，9源、14新方法（Session6/App4/Vault4），原73方法保留。

## 实现方向

- 公开ScrollGeometry与真实tabframe左右导航，不使用假固定宽度滚动；固定Vault/SFTP留在scroll外。
- 中键仅单SSH标签自有透明hit target，button2且准确window/bounds/无modifier；普通click、右键、drag、focus fall-through，未装全局monitor。
- 批关闭immutable requestUUID/entrytabIDs/名称/端点/初始状态，当前状态实时读，syncinFlight防重复/旧确认。
- displayMetadata与不可变tab.host实际连接快照分开；纯改名/收藏/删除badge不读取秘密或重连，customtabtitle优先；连接info明确实际snapshot和当前saved配置差异。
- frame autosave只正常用户实例，isolatedprobe/test不写系统UserDefaults；恢复几何clamp/屏幕变化不改已审closeflow。
- Vault管理子页及有效UUID选择独立非秘密导航key，坏值/失效ID回退，不恢复search/dialog/editor/secret/session。

## 主审已指出的重点

1. `onPreferenceChange(tabFrames)`当前每次都revealActive。如果命名content坐标随滚动报告变化，用户箭头/手滚非活动tab会被拉回；须实际ownedNSWindow验证，不能仅按坐标预期判通过。复现后最小pendingReveal token只由activeID/orderedIDs/viewportSize/首个frame触发。
2. 中键要测真实NSView.hitTest父坐标→子bounds，而不只调用owns(event)；fixedpages、背景window、sheet/modal、修饰键及dragout不能关闭。
3. 批审核长列表ScrollView仅maxHeight可能需真实fitting/viewport/按钮可见性，已确认close任务期间不能新owner被旧finish清除。
4. savedframe小屏与min920×580冲突必须如实处理；不移动其他App窗口、不绕系统full screen，未授权改变系统显示。
5. displayMetadata刷新与reuse/savedcredential校验必须保持tab.host/configuration不变，不将已删配置重建；旧auth/prefs/close回归需复验。

## 已执行与保留的失败

- 首build65：新几何测试`.nan`在NSRect参数歧义，显式CGFloat最小修。
- 第二build65：Changed新增helper调用内部wait，由原owner只改公开resolve取消断言；Window未越域。
- 真实WorkspaceTabBar组件原样移至WorkspaceTabsView.swift并双target登记后，第三build65为SwiftUI类型检查超时及TabRenamePresentation非MainActor读模型；只拆body和标actor，不裁根页面/删menu。
- 第四正式Debugbuild0，Native31+Files22 **53/0**；主审已核原日志。
- Window14首轮14tests/4断言fail：中键fixture用NSEvent.mouseEvent创建的otherMouseDown实际buttonNumber0，不能代表button2；严格生产拒绝正确。之后CG公开字段修复后button2/windowNumber成立，但owns仍拒，原因未定，不能仍称夹具错误。
- owned-window两项首红：标准SwiftUI箭头未暴露可匹配公开语义，未走到滚动门；准入真实nativeNSButton箭头替换以改善实际可访问性，不扩AX树。随后真实WorkspaceTabBar的箭头/clip手滚不回弹/resize/select/reorder reveal已到达并通过，仍非像素或实体鼠标。
- 中键button2和windowNumber成立后，事件fixture公开locationInWindow持续比输入y少755；生产bounds严格拒绝正确。缩小公开AppKit事件工厂复现：otherEvent触Invalidparameter/WeirdMask exit-6保留，freshCG中心window0；仅保原ownedcgEvent并单次公开location差校准后probe exit0能保window/button2/expectedpoint。最后真实hit/currentEvent门待完成，不据此放松生产check或声称真实鼠标。
- 主管发现Vaultfolder/tag/requestFocus可能绕普通sidebar已有预检；工程师核主sidebar原guard有效，只补遗漏入口同实际modelpreflight。dirty Cancel不改页，Save/Discard释放owner后用户再次点击导航，不用迟到自动路由；真实owner链测试已通过。

## 最终本轮结果与剩余红门

`UnifiedVerification/verification-results.json`和`final-window11-sha256.json`记录最终11源（含真实WorkspaceTabsView拆分及双target登记），主审已读精确差异/保护区。

- 最终正式Debug build-for-testing exit0，App/xctest及新真实组件对象实核minos26.0。
- 最终Changed53/0、关键旧回归加Window13共107/0；主管另独立Changed53/0，无重建读取最终产物。
- 完整Window14最后仍exit65：13方法通过、中键1方法3断言红，没有skip或删断言。直接owneddown/up准确关闭及排除边界、button2/window/point验证通过；`NSWindow.sendEvent`没有建立`NSApp.currentEvent`，依此的实际hitTest未通过。该事实不证明实体鼠标必不可用，也不能称中键完成。
- 所有首红/公开工厂probe崩溃/坐标失败保留；不再为这一门扩globalpost/privateAPI或放松owner。
- 原10个认证/关闭/设置/editor保护区和Changed4/Package7摘要均未变，已STOP释放共享Controller/AppModel/Delegate供准确Retirement后续串行。

## 中键R2最小测试修正（仅源码，未运行）

主管独立源审后只批准将准确自有窗口测试的三处`NSWindow.sendEvent`换为公开`NSApplication.sendEvent`，验证真实App分发是否建立`NSApp.currentEvent`。保原closeA=2/B=0、parent坐标、修饰键/editor/fixed/hidden边界，另加实际currentEvent===传入事件、准确window/windowNumber/button2、真实resolved child及三事件顺序断言。没有改生产hitTest、伪写currentEvent、全局post或monitor。

`WindowMiddleEventLoop-R2-Source/source-ready.patch`及`source-ready.json`记录唯一文件唯一方法增量，授权方法外逐字不变，原其余37方法和51个App/Test/project保护源不变；最终testSHA `f4bf931be4c98985a27b5af9b3821cddd59a66f893624b88cd4b225665ef61ad`。source-only执行者已STOP，包Manifest当前唯一builder，等待包freeze后精准1门/Window14统一验证。现仍保旧红状态，不能把预期修正当实际中键或实体鼠标验收。

后续中键需实际应用事件分发或官方GUI验收；overflow/重开/批量sheet像素门仍待。分栏比例与Files列宽列序已完成10项本地门及主管独立复验，见`files-layout-preferences-review.md`，仍不称完整V06/X09。defaultDirect不改。
