# Typed主机变化事实与sealed drain handle：包层审查

日期：2026-10-31（沿10月30日同一Goal）。状态：**包层离线门和新版五个真实消费者分项已通过；App typed变化本地门已过，有限关闭R2修复中。不是完整关闭/后端替换验收。**

## 修改和准确边界

五个生产源：NativeShellTypes、NativeShellAuthentication、NativeShellSession、SharedHostTrust、RemoteFileService；新22项NativeFailureObservabilityTests及旧Readiness一行真实close/seal事实补充。CBridge/vendor/pins/manifest/Trust/Core/Transport/App不改。

- FileServiceError保留旧四参public init精确函数引用兼容，新增显式changed字段重载；NativeShellError保Kind、旧调用默认值，public init新增可选changedHostKey与interactionDrain。
- 每次实际connect独立锁记录，真正store rejected先记ChangedHostKey，再跨Bool false；typed convert/catch/close保事实。nilhandler和迟到/被撤销handler不再是事实唯一来源。
- changed informational reply排队前已cancel，handler不能resolveconfirm或confirmOnce成功；不修改known_hosts或提供接受变化入口。尚未观察的预取消不造事实。
- session和error使用同canonical只读drain handle；稳定UUID equality，不按动态snapshot比较。handle不持nativeowner/session/socket/secret或认证回答权限。
- registry在创建Task/dispatch前登记；begin与revoke/seal同锁，sealed后拒新producer。只有实际defer finish移除，queuedcallback未运行仍pending。生产登记与lateinstall总计限256，重复install拒，取消闭包清空后锁外调用。
- drained要求真实dispose返回/nativeClosed、producersSealed与pending0，瞬时0不是终态。session/error释放后handle仍可观察非合作provider稍后完成，材料前后取消复核拒收。
- wait以单调DispatchSource事件驱动，0…5秒合法，NaN/inf/负值/超界显式invalidConfiguration；64waiter/observer容量及进程通知256槽，满时显式resourceLimit。取消仅移除该waiter。
- completion异步且不阻塞nativequeue，queued/running通知保额度直到返回；通知不是interactionproducer，drained不代表任意外部observer已返回。主审要求的阻塞observer对照已通过。
- SFTP只在同SharedHostTrust Bool边界补typed事实，不扩SFTP完整registry/retirement架构。

精确before/final diff与SHA：`DerivedData/UXVerification/NativeFailurePackage-R1/{before-sha256.json,final.patch,final-sha256.json}`。

## 验证与原失败

- 严格首轮exit1：新增测试局部weak变量触Swift6.2 WeakMutability警告即错；未执行tests。保日志与fix1before；仅用weak-referencebox保原sessiondealloc断言，生产源未变。
- 新 **22/0**、受影响 **55/0**、全包 **180/0**，均exit0。全包为已有本地/loopback有限fixtures，不是远程SSH互通；不重复累计成257种独立覆盖。
- Swift6完整strictconcurrency/warnings-as-errors、Swift target arm64-macos26、C最低26；vtool实核五Swift对象、两个test对象、CBridge对象及最终xctest共9项minos26.0。
- 主管读取关键代码/差异及实际22/55/180日志，并独立`--skip-build`新 **22/0**，见`Primary/independent-failure-22-1.{json,log}`。
- 原C/manifest/未用候选文件与before摘要一致；未触旧R4真实receipts，不用旧candidate的正常/MFA/DROP实证覆盖这版代码。

## 覆盖的关键强制顺序

nil/delayed changed、reply预撤销、实际Bool/convert/close、同端点/raw算法/预取消、封口竞态、cancel锁外/重复install、queuedwork不能早drain、非合作provider超boundedclose后session释放而handle仍pending/laterfinish、独立waiter、容量、error equality稳定、blockingobserver不挡close、真实socketpairclose和deinit返回事实、旧initializers/Sendable/Kind switch兼容。

## 尚未完成

1. App NativeDriver/FilesController已消费typedchanged，精确去重/拒迟到显示；正式53/0及主管独立53/0，后续关闭整合定向组继续保护。见`native-changed-app-review.md`，真实新界面仍另验。
2. App失败connect/close的finite retired/incomplete结果与App级票据已实现，R1严格构建/唯一228个定向方法及主管40项通过；源审两个未覆盖边界正在R2修复，不宣称最终关闭验收。见`native-app-retirement-review.md`。
3. 新版独立consumer已按精确五源差异和其余208非实验输入不变重新冻结；475输入、14纯检查、15个Mach-O实核min26。主管亲跑Native changed无handler、非合作provider取消/laterdrain、SFTP changed、keyKI/passwordKI五案全部通过，前两次5秒handshake失败保留。受控测试operation5→10后新consumer通过，不改产品/服务器预算。见`native-failure-live-finite.md`。旧R4 ledger未改，旧活性结果不自动覆盖新源。
4. 默认builder替换/保活设置兼容/真实终端与GUI门按native-default-switch-gates.md另验。

无新环境、真实用户凭据、生产连接、Apple、push或长测。
