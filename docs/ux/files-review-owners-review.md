# 双栏操作目标与队列记录 owner：本地门审查

日期：2026-10-30（验证跨至31日零点）。状态：**正式构建和受影响86项回归通过，主管独立15项owner复验通过；实际双栏GUI和真实SFTP仍另验。**

## 实现与主审

主管已读本轮实际diff、FilesController/LocalBrowser target guard、DualPaneFilesView真实展示接线和FilesTasksView记录owner。

- 每次details/name/deleteOptions是新presentation UUID，内容持不可变FilesOperationTarget，冻结endpoint、原始parent、entries/attrs、host连接身份与generation/lifetime/service/revision；不从当前页面新path重建旧目标。
- controller/本地model显式capture/consume/confirm，过时owner/浏览切换/host配置变化/重复确认拒绝，metadata-only改名不误改连接；pending target最多8个，exact discard释放，不无限字典。
- mutation前复核父目录和选中attrs；rename风险等待后再核。属性检查不是CAS、远端稳定对象ID缺失，同attrs ABA和最终检查后窗口不能保证消除，UI如实说明。
- hide/离页只撤未确认target/plan，不暗取消已确认mutation；实际partial报告保留，即使刷新失败也不冒回滚。
- 本地/远端加载、尚未读取、首次错误、保最后成功快照、真空/过滤空分开，刷新可恢复。
- 队列记录移除真实View使用FilesHistoryRemovalOwner，reviewID/inFlight防双确认及旧completion清新review；复用controller既有exactrecords移除，不改TransferManager。
- 切连接/取消文案解释共享service可能影响其他任务、已提交项目不回滚、不自动重连/续传。

六源冻结、before增量：`DerivedData/UXVerification/FilesReviewOwners-R1/source-ready.json`、`source-increment.patch`、`after-hashes.json`；原FilesControllerTests/FilesTransferTests/Auth View块保持。

## 保留失败与精确修复

1. 统一Debug首exit65，测试引用DualFilesDialog但其在未共享View源中。由本owner将**实际View使用的同一type**原样移至已登记LocalBrowserModel，不造测试helper、不改语义/断言/工程；`dialog-source-fix-1/`保before/diff。
2. 主管独立首86项有2fail，均在新fixture setup以Foundation写FF20410A文件名，还未进入owner consumer。
3. 改descriptor-backed LocalFileService后同86仍2fail，native openat在系统tmp及工作区均errno92/EILSEQ，对照中文/空格/newline成功；证明本机文件系统能力限制，不据此重写生产URL桥。
4. 按明确测试分层：真实本地临时IO使用复杂合法Unicode/组合/空格/newline，保同名替换与held-old/newbytes不变；非法UTF8使用显式RawNameRemoteFileService逻辑协议命名空间→实际UUID backing文件，不声称物理rawFS或真实SFTP。raw list/lstat请求和响应字节/次数均有断言，stale零mutation保留，没有skip/fallback或删断言。

两轮失败、descriptortrial和native探针原样保在`raw-fixture-fix-1/`；最后仅改DualPaneFilesTests，无产品source变更。

## 实际验证

- 正式 `Scripts/build-app.sh Debug build-for-testing`：最终exit0。
- 正式min26 `test-without-building`同五类：**86/0、exit0**，Owner15、Dual19、Auth19、Controller18、Transfer15。
- `raw-fixture-fix-1/files-targeted-3.{json,log,xcresult}`含完整argv/cwd/exit；`actual-min26-layered.json`实核App/xctest minos26.0。
- 最终测试SHA `7d68f1ff576b0c169e21569d8df321eece37fea5bf094b699af70f8bf8cd5332`。
- 主管独立 `DesktopPreferencesHelp-R1/Primary/independent-preferences-close-files-1`内Owner **15/0**，与设置/关闭合计43/0；实际条目和退出已核。
- 主审读取最终测试分层diff，原字节身份与真实文件IO覆盖边界明确；不将模型替身称网络互通。

## 未覆盖

- 实际双栏dialogs、Finder drag/drop、宽窄窗/VoiceOver/焦点、真实SFTP同名竞争仍待。
- 递归传输用户可见精确计划和manifest执行未实施，见files-transfer-plan-design.md，不在本任务Done范围。
- 非法UTF8服务器真实互通另需既有Linux fixture有限门；本机APFS物理存储不支持的事实不能由逻辑测试冒充。
- 新UI仍未像素验收，不标完整DX-F/Q或UX_READY。
