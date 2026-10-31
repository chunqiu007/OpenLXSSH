# App Files conflict — rename then skip real case

日期：2026-10-31。结论：**logical App real SFTP两次上传、重命名＋跳过、原件保全、精确清理及严格资源门通过。** 不验证GUI/Finder、批策略传播、overwrite、cancel/retry或旧SSH资源。

## 实现与本地审查

新独立闭scenario `keyonly-direct-sftp-manifest-conflict`，旧passed roundtrip合同、报告及判定保持。复用同连接/helper/能力probe/生命周期；Seed/Fresh为两个精确批准的本地parent FD，不绕过FilesController。

open首个await前冻结phase，pending-open纳入切换门禁；confirm后绑定实际job/generation。累计事实不清零，按phase/side/rawpath核stream，不能用Seed首条SHA冒Fresh。新增verify phase实际有界读取最终三文件，独立证明原两项未变及alternate为Fresh。

首次12KiB Seed全部成功；第二Fresh对4KiB先rename/applyToBatchfalse，再对8KiB skip/true。准确mixed状态`completedWithSkips`与4096B，不冒全树12KiB成功，且最后skip没有后续项，因此不声称批策略传播。

原nonce/capability mutation guard保留，alternate风险/清理精确路径，最终按当前三文件/目录删除review及空nonce根重新capture。完整lossless wire v1宽报告15,857B≤原16KiB；首17,251B失败保留。测试历史快照时序首失败按实际activeTransferSnapshot同步修正，consumer只新增conflict分支同步，不称已证产品实网bug修复。

本地严格Host139/0、Debug129/0、退役22/0；Python35严格schema通过，旧34函数AST不变仅3处dispatch增量。旧55契约/Files77保留，新契约6+本地冲突1；主管独立7/0。独立phase/scope审未见HIGH/MED问题，不能代真实运行。

## 真实通过结果

正确来源`DerivedData/HostProbe26-AppFilesConflictR5/Build/Products/HostProbe/OpenLXSSH.app`，独立候选`DerivedData/UXVerification/AppFilesConflict-Live-R5/OpenLXSSH.app`。mainSHA`1750409d3a8ec52b7bd56ffc148b99dbee19db382c8a2523d5ca90e178aee1c4`，helperSHA`e222b751a5c5b18588bc161f54113d122e1edb57ac5caa5a201d95989b78f24f`。新构建图未附helper，首打包失败未启动；显式复用原已审SFTP fixture helper后离线Development/timestampnone，固定ID严格验证，无Apple请求。

run `f47bef29-3cec-4a72-b537-a5f27d0b9e1d`，App18187，supervisor **passed=true**、9.034585秒、natural exit0、无signal：

- 两次独立immutable manifest，prepare内容I/O差值0/jobs0，confirm各1；原binding保持。
- Seed job succeeded/12288B；Fresh job completedWithSkips/4096B，目录2成功、文件1成功/1 skipped。
- 精确两个decision：rename/false，skip/true；独立verification phase读16KiB三文件，原4KiB和8KiB SHA保持，新增4KiB为Fresh SHA。跳过项没有Fresh源内容读取。
- 原nonce测试树及本地payload/Appstore精确清理，remote1/local2全部实际close，handles0/rescue0/closefailure0。
- **FD20→20且entry身份完全相等**；ready、before/afterstores、willTerminate与外部自然exit0完整。
- `batchPropagationVerified=false`保持，不扩张本案结论。

relay18017自然exit0（204.746293秒含预检）、accepted1/finished1/rejected0/cleanup_failed0、无signals；主管核批准端口free。全部公开收据归档`AppFilesConflict-Live-R5/public-receipts/`，秘密仅consumer内存使用。

## 保留缺口

在途取消/真实partial与重新prepare/confirm重试另案；其他策略/批传播不由本案证明。SFTP attrs与manifest/delete非CAS。旧SSH weak/FD、可见绘制上下文、原生键鼠/IME/截图像素与整体116项验收仍未过，未UX_READY_FOR_USER。
