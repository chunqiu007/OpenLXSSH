# 双栏递归传输计划：下一项实施约束

日期：2026-10-30。**主管设计笔记，尚未实施，不是验收通过。** 当前 FILES-REVIEW-OWNERS-R1 只修对话框目标与记录审核，不能把该任务结束当成 DX-F09 已完成。

## 当前已核事实

- 新双栏按钮、右键与跨栏/Finder drop 最终调用同 `FilesController.enqueueUploads/Downloads`，同步 capture `FilesTransferContext`，入队后的端点/service/path 不能被切页改投。
- 目录目前以 `TransferKind.tree` 直接入队；UI没有用户可读的递归数量计划。`SafeTransferEngine.copyTree` 在执行期间动态walk，默认maxDepth32/maxItems10000，不跟随链接，逐项安全提交。
- `TransferManager.withServiceOperation` 可借现source service做只读lstat/list并持有服务寿命；caller只取消该operation token，不能为了取消计划关闭共享service。
- Manager/Engine 已有冲突、风险确认、从零retry、部分结果和精确残留信息，必须复用，不重造传输实现或伪装文件夹整体事务。

## 最小实施方向与验收条件

1. 所有新增目录入口统一进入同一只读计划；文件入口也可展示根项目摘要，但不强制多余确认。
2. Plan为App级单owner，准确绑定lifetime/generation/serviceID/hostID/connectionIdentity、源根原字节、目标根原字节、方向、reviewUUID；取消/新owner/切服务/关闭拒旧confirm，纯展示改名不误换连接。
3. 只读枚举仅lstat/list，不read文件内容，不mkdir/openWrite/rename/remove；目录、文件、链接/unsupported、问题数、depth/item上限与已知bytes分别呈现。未知总量不能用0冒完整；超过界限不能只展示已扫部分再允许“全部传输”。
4. 符号链接沿已有reject策略，重复rawname/路径逃逸/目录替换必须拒绝。目录大批次不读所有文件内容做hash。
5. 确认前全量只读复核已见属性和目录children集合。对变更需重新计划，不能用新目录列表静默扩大旧确认范围。
6. **不能只plan后调用现动态walk就声称执行严格锁定计划。** 若要求确认范围不扩展，应给Engine增加可选immutable source manifest，执行只遍历已审项，逐项再核；新增子项停下、不悄悄追加。没有接此能力时UI须如实写“只读估算”，不能伪称精确执行计划。
7. Manifest若进入TransferRequest，需限制尺寸/总storedjobs与队列内存，不能每job复制万项无界；引用只含非秘密metadata/service identity，不持App view或credential。
8. 入队前0写入；取消0job；成功确认一次enqueueBatch，doubleconfirm/latecallback不能新开第二批。已入队任务不因隐藏view释放。
9. Source manifest/plan不免除现冲突与逐项风险确认；目录合并/overwrite/cancel和partial outcomes仍按真实结果，不宣称整体rollback。
10. review及registered local source服务要有准确过期/释放；未confirm只清本次owned资源，不关闭别的service/job。关闭流程等待实际只读operation排空而非Task.cancel视为完成。

## 验证范围

- 实际临时目录metadata计划、两方向逻辑service、同名不同rawbytes、非法UTF8名称、隐藏项不遗漏、链接reject、depth/items边界、来源变更、取消gate、stale target、doubleconfirm、sharedservice B不受伤。
- 用mutation计数证明准备/取消无任何文件写入；用准确目录集合/bytes证明已存在文件不变。
- 有限既有fixture真实目录传输、冲突/取消/重试/清记录，以及计划显示与目标锁定另验。不重跑2GiB/1000文件或24h。

## 只读准备后收敛的接口约束

工程师 `FILES-TRANSFER-MANIFEST-R1 readprep` 已完成/STOP，无修改、构建或网络。准备结果建议复用实际Manager寿命和engine，而非View另持服务：

- `TransferRequest`可新增默认nil的不可变共享`sourceManifest`，保留原包调用兼容；Manager新增`prepareBatch`、`prepareRetry`、`confirmPreparedBatch(planID)`、`discardPreparedBatch(planID)`。准备/确认须支持准确取消token，取消不关闭共享service。
- Manifest由真实只读枚举产生，不能由UI构造任意假计划；绑定source service/raw root及目标描述，App另绑定lifetime/generation/host连接身份/方向/reviewUUID。对外确认只用planID，不接UI改写后的requests。
- 每计划depth≤32/items≤10000/expiry≤300秒；Manager整体准备中、待确认和仍持清单的历史共享预算建议≤20000 entries，另限metadata字节与并发prepare数。入队/快照/重试共享不可变引用而非每job复制万项；准确discard、到期、清历史后归还预算。必须先预留有界准备容量，不能多个prepare先无限枚举再事后计数。
- 确认前全量只读复核、复核成功后原子队列准入；执行仍逐项核已审attrs/childsets，只走清单，任何新项不扩大范围。所有风险/冲突await后，首次目标写入前和读取源内容前需再核适用来源事实；计划不提供CAS或内容锁保证。
- Manifest完成后可按完整保守计量收缩准备预留，覆盖entries、rawpaths/names、indices、anchors、plan/request/issue/container开销，不能漏问题计划或让零entry计划零预算。历史仅保实际共享清单额度到最后相关job清记录；不能把满预留永久保留导致任意两次小目录传输后就拒第三次作为默认UX。全局20k/16MiB保持，不靠扩大配额避问题；tinyhistory连续操作与容量拒绝/准确归还要实测。
- 逐文件多次复核ancestor childsets可能产生O(n²)目录行返回，尤其远端平铺大目录；有界metadata不等于总耗时有界。安全门不可为速度删减，本轮有限测试不重1000文件campaign；最终报告须披露实测范围和成本。
- `retry`遇manifest目录不得静默动态walk：重新prepare→明确confirm，从字节零开始；旧非manifest包调用保兼容，App目录入口必须统一新review。
- 旧App普通目录测试仅将arrange改prepare→显式confirm并保原内容/资源断言。strictplan遇链接应明确issue/零job零写；旧engine动态walk部分失败单测保留。若旧App预期随需求改变，精确记录改变，不谎称旧断言原封未动。

最小新门14项：只读准确计数、取消零写、确认前children变化、attrs/root替换、入队后新增不追加、执行中替换、链接/特殊项拒绝、depth/items边界、重复rawname/非法UTF8、doubleconfirm、stale/expiry/迟到owner、共享B隔离和真实operation drain、容量原子拒绝、retry从零及历史预算归还。本机物理非法UTF8受EILSEQ限制，继续分层raw逻辑namespace与合法复杂名真实本地IO，不删既有raw断言。

## 调度

该任务涉及Files包Engine/Manager接口，不能在Native R4当前冻结source receipts仍需live时直接改包；须先完成R4有限门或独立冻结真实consumer再串行解冻。App接线也须等FILES-REVIEW-OWNERS-R1 freeze，避免共享FilesController/Views/tests并写。默认一个业务writer，不为并发而拆共享接口。
