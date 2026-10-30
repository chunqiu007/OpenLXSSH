# 接续会话：原生控件发现 R0

日期：2026-10-30。结论：**未通过控件交互/视觉验收；已保留限制及探针结束异常。**

## 来源与范围

- 冻结接续前的 HostProbe `.app` 独立副本，主程序 SHA256 `347e068d0b2d1958e54602b8c4a4324835a04ef1bbec700e606a8c80a6519369`。它不是正在修复的 RELIABILITY-R1 源码，也不是正式 min26 后端验收。
- 新建 marked 0700 临时数据库/文件根，以已有 `desktop-cua` 阶段启动。该阶段不种主机、不连接 SSH/SFTP、不读取 Keychain；网络边界仍是显式 Probe 替身。
- 主进程 PID23817 及完整启动命令记在证据目录。未沿用旧PID、未覆盖原生失败证据。

证据根：`DerivedData/UXVerification/DesktopIntegration/Primary/cua-discovery-2457169a-f722-44d0-b3a7-61aa3e6b52f8/`。

## 实际观察

主管通过官方 Computer Use 绑定本次准确 PID：

1. 能定位 CG 窗口6151，逻辑内容1120×720（窗口含标题区1120×752）。
2. 请求截图后当前模型收到“raster is not visible”，无像素判断能力；没有使用坐标操作，没有再次委派无图像模型。
3. 绑定准确窗口的可访问性观察返回 `cg-only-no-ax-window`。按App观察则为重复嵌套application与菜单节点，没有实际主机字段或工作区内容节点。
4. 对当前树里的“新建主机…”菜单动作请求被工具接受，随后观察仍无可核验编辑器；测试Cmd+T亦未核验选择器出现。因此不能声称新建、快捷键、焦点或保存成功，更不能由此断言产品未呈现控件。
5. `.desktop-cua-finish` 结束信号经临时根标记、owner/mode和Ready PID核对后精确创建。探针写出 `finished-desktop-cua`，两项 **ready/finish生命周期检查** true，报告明确 `interactions not asserted`；该passed字段不是GUI验收。
6. 清理完成后的App未自然退出。真实2秒sample显示主线程停在AppKit普通事件循环，不支持“主线程死锁”的结论。保存sample和结束异常，精确复核PID/UID/可执行路径后只对此本轮探针发SIGTERM，外层实际exit **-15**。不把它改写为自然exit0。

## R1：实际原生控件探针仍失败，未改绿

后续冻结新HostProbe`5bbf90717a96efa3e59d756a7b427ae4b81dcd4017419a3405b9219657605781`后，主管实际执行新的`native-discovery`，有限40秒。结果不是超时：进程自行exit1，前3项启动/空合成库通过，`discovery-unique-host.address`失败。

证据：`DerivedData/UXVerification/NativeProbe-R1/native-discovery-b58444be-2a2f-4cfc-9954-5298b3426d9c/`。

关键诊断：owned editor sheet实际已呈现、visible/current owner均true，但tree只遍历1节点、accepted0、rejectedForeignOwner1。只能支持“探针在内容root就拒绝”的事实，不能宣称字段不存在。需要区分原生NSView.window的精确sheet归属与合法AX顶层主窗口关系；不得跨owner放宽或写editor状态绕过。NATIVE-PROBE-R2限定工具修复继续，构建需等Files候选写域冻结后串行。

## R2：owner修正有效，实际字段仍待定位

主管源审了精确content子树与双向sheetParent链的窄修，冻结`470be73202296d15fd15d03a6c5853c16f6964abab854c914e56762161ac4e6c`后实际重跑`native-discovery --timeout 35`。仍自行exit1/非超时，失败`check.discovery-unique-host.address`，原断言未弱化。

证据：`DerivedData/UXVerification/NativeProbe-R1/native-discovery-8fc54a16-f4e4-4c4e-86e9-093050849738/`。

本次rootNativeWindowMatches=true、rootAXWindowIsParent=true、rejectedForeignOwner0、accepted64/traversed65，证明上轮过度owner拒绝已解决；但固定控件匹配仍0，另有1个hidden节点被拒。下一轮改变假设，诊断固定容器类别/原生实际hidden与AX-hidden关系、native/AX字段role与标识挂载位置；不盲目重复放宽owner、不遍历后台页、不直接写ViewModel。源码准备与Files候选写域分离，构建继续串行。此结果不是产品无字段的证明，更不是原生门通过。

## R3：改查实际布局，发现sheet高度塌缩

主管按冻结artifact源码摘要与各writer的before复制141公开输入到独立ignored快照，只替换R3安全诊断，不读取活动writer半成App/Files。固定native库只读symlink、依赖pins保持。首构建65为快照漏两个许可资源；补原公开资源后第二次65为`NativeSmoke.type`遮蔽全局`type(of:)`，主管只加两处`Swift.`，第三次build0。原失败及argv/退出记录保留在`NativeProbe-R1/R3-source/isolated-build-{1,2,3}.*`。

实际R3 frozen`2f81cf84...`发现5个原生输入控件+5个完整协议virtual AXTextField，桥接/hidden不是缺字段原因；白名单identifier未出现且所有native visibleRect为空。再只加脱敏geometry诊断、build0后fresh`native-discovery-6ca9b780-dd15-4258-912b-94eda6ebe1fa`实际exit1不改断言。

**确定事实：编辑器window/content frame均500×119；五个field实际24pt高但visibleRect全0，AXframe位于窗口外。** 长ScrollView只有maxHeight没有合理ideal/min高度，hosting自动fitting将sheet压至头尾。后续先在独立快照以单一有界表单高度做A/B，确认可见布局后再将合理产品布局修复交实际writer，不能仅放宽测试可见性或硬按测试ID找隐藏控件。此时仍未原生通过，像素门保持待验。

单变量A/B已实际完成：隔离快照只加与父内容高度适配的有界表单高度，build0，fresh`native-discovery-9f58f7e4-afad-4be5-998c-f3283003b78c`将sheet/content恢复到**500×660**且原生字段visibleRect非空、真实field editor出现，证实高度塌缩修复方向。唯一字段身份断言仍失败（identifier均none），未放宽，候选不改绿。NATIVE-PROBE-R4在该快照继续依据固定公开placeholder/label做唯一语义匹配与可见滚动，正式产品VaultEditors仍由Closewriter持有，尚未接此高度修复。

## R4～R7：字段语义可定位，激活前置仍不满足

R4真实公开placeholder诊断与actual native输入一一匹配，才启identifier优先、唯一NSTextField固定placeholder fallback；actual viewport改visibleRect∩bounds、用公开滚动使字段可达，未按索引猜/写VM。R4/R5 discovery三字段唯一性均true（前6/8），Save按钮仍无固定语义。公开untyped children/visible/contents/unignored均未得新按钮；typed navigation getter曾因NSAccessibilitySegment→NSAccessibilityElement数组桥接exit-5，已删除，原崩溃保留且不归因业务。

R6只做小A/B准确ownedwindow激活，未改接受/断言；8s复合wait超时，B未执行，不能说激活后仍无按钮。R7拆前置新证据：App在before/call/timeout三个样本始终inactive/keyWindowPresent=false；owner canBecomeKey=true、titled/docModal、非nonactivatingPanel、双向parent/root/currentOwner正确、主线程defaultRunLoop；真实fieldeditor就是owner/firstResponder，不是childkey。未记录mainWindowPresent，不推断其nil。

主管保持R7 binary `d40c90c1…` 不变，以正常LaunchServices `open -n -W -a <exact frozen.app> --args <marked isolated4args>` 新实例对照：同样inactive/keynil、复合wait超时，B未执行。openExit0不是AppExit0；App报告明确failed且无willTerminate，不能改绿。证据`NativeProbe-R1/LaunchServices-a21c1de1-0cbb-46a7-8ade-a00655c58feb/`。官方CUA getState也显示当前全部应用active=false，仅提示桌面前台上下文可用性需核，不构成产品配置故障证明；不擅改系统权限/登录/锁屏。

当前停止继续泛扩遍历，保原生焦点/SaveDiscardCancel/真正CmdV和像素待验，推进独立本地/协议工程。后续需要实际可用前台图形会话或能验证的官方CUA激活证据，不能canBecomeKey强制override、假按钮或删keywindow断言来通过。

## AuthFinal 新冻结版本：激活前置已成立，保存语义/CUA仍未通过

主管从Files/Prefs writer的修前快照建立111公开输入的独立副本，逐项核Auth最终生产源码SHA一致，不构建活动业务writer半成源。目录为`NativeProbe-R1/AuthFinal-frozen-source-bc2fbb30-0474-40f3-9de0-0207187680af`，HostProbe条件/min26显式构建exit0，主程序SHA `0a4a27ee3acb909fc95ddaaee73c9bfb21f2ed02193941466a801595b4b7ee9e`。

- 新fresh native-discovery原始目录`native-discovery-57685462-c54f-4a51-858d-50da1f6eae7e`；有限35秒内自然exit1，前三启动项与三字段唯一性共6项true，`check.discovery-unique-save`失败。
- 本次准确owned编辑器500×660，appIsActive=true/keyWindowIsOwner=true/实际fieldeditor归属正确；父主窗main=true。**旧R7的inactive不是当前阻塞。** 保存按钮语义仍未过，不把激活成功推作控件/关闭门通过。
- 公开CGSession只读selectedbool显示onConsole/loginDone=true；不据此推断系统是否锁定或调整权限。
- 主管另开同binary的隔离desktop-cua，准确PID50989/主窗6717。官方CUA截图返回raster不可见，没有坐标动作；AX仍只重复App/菜单。按观察菜单点击“新建主机…”后实际WindowServer列表出现500×660 sheet6724，但准确窗口观察返回cg-only-no-ax-window，仅菜单，无字段/保存语义；没有重试该准确窗口读取或改用其他UI自动化。
- desktop-cua 300秒期限到，由原runner只对其Popen-owned子进程TERM收尾，exit-15；无finish/自然AppKittermination证据。目录`desktop-cua-b7d48c91-d0ba-4b5d-8ec2-6c6ed2cc1980`保留timeout失败，不能以窗口存在或菜单动作接受冒GUI通过。当前进程已结束。

后续实际GUI需要可读的控件语义或像素证据；不再把inactive旧假设带入，也不反复启动同样失败来凑结果。

只读根因调查未发现产品显式AXparent/children或可证循环，给出的最小standalone A/B已由主管在独立ignored目录实现并编译：`NativeAccessibilityAB-R1/MinimalProbe.swift`，同一标准TextField/Button保存，A直接/B只多嵌套Hosting，不依赖业务或网络。Swift6完整严格并发/warnings-as-errors/arm64-min26编译exit0，binarySHA `e8310c8de497842203dfcc85eafb7aa5b455a1948861f5aeaafb9c81323313d5`。两案各5秒前置后自然exit0，但ready=false，保存语义0、无selfparent，**有限语义门均false**；它们没有有效激活前置，不能支持嵌套因果结论或当作产品通过。仅记录字段存在、未触动作；不再扩诊断或调整系统权限。子代理的原较大Probe草稿未编译/运行，未作为该实测来源。

## 本轮接续图像能力复核

2026-10-31主管只读重开已知合成旧U1截图`/private/var/folders/qh/g2p3kxks0s75gc6kz08kvtn00000gn/T/OpenLXSSH-AppTests-fd0q3ubw/workspace-r5.png`，Read返回明确`Media omitted from provider request because the selected model does not support image input`。不能判断图像内容，也不能把读文件动作称看见像素；没有重派视觉模型、坐标猜测或修改系统显示/权限。官方CUA本轮listApps仍全部active=false，但不将其当锁屏或产品根因证明。

当前新的实际App screenshot/三尺寸/全屏视觉验收仍未过。中键仅准确App事件分发test已source-ready，必须独立实测，不由这一图像能力复核补足。

## 后续验收门

- 先完成 RELIABILITY-R1 并冻结新源码，再构建串行新探针。
- 检查实际可见SwiftUI字段的AX身份/可设置动作，适配旧NativeSmoke的 `NSTextField.identifier` 单一路径；不修改产品来迎合旧探针，不直接写ViewModel。
- 单独补Save/Discard/Cancel、真正普通/Bracketed Cmd+V、三尺寸/全屏/拖动布局及新截图。像素无法查看时继续保留视觉待验。
- 新版正常退出也需复核；本次结束异常不能以ready/finish green掩盖。

无生产、真实用户数据/凭据、健康fixture重建、网络连接、Apple操作、最终出包或长测。
