# App真实文件操作：首案失败与特殊叶名校验R1检查点

日期2026-10-28，Task APP-REAL-FILE-OPERATIONS-A / LIVE-A / FILEOPS-SPECIAL-LEAF-FD-R1 / APP-FILEOPS-LEAF-R1-LIVE-A。**首案校验器arguments失败保留并精确恢复；FD叶名R1后新5c2e唯一案24checks/4jobs/真实特殊原名下载SHA/rename/3审核delete/邻项保全与资源全通过主管验收。** 仅HostProbe/mac15小数据GUI接线，不覆盖人工Finder、冲突或整个FILE验收。

## 限定新phase

仅AppRealIntegration.swift/Contract.swift、契约测试及verify脚本四文件新增file-operations。固定newUUID根、4KiB未选中邻项+子目录内8KiB组合Unicode/NFD/空格/`[#; $]`叶名；native mkdir/risk/currentservice probe、native批上传2选择、多选native下载2选择/testpicker、真实原名字节/size/SHA、native改名、3次精确root/items审核delete、删除目录后邻项SHA保全、同服务binding/attempt1与已知清理。摘要/不存在后验可用API，不能代GUI动作。不重2GiB/1000，不声称人工Finder。

主管完整读四文件实际diff和原控件接点，初125tests/49输入/14命令/native160/strict已核：`DerivedData/Verification/primary-app-fileops-static-8dac6a67-cdc5-4390-9050-a51fb36d39df/`。

## 首次真实案（失败保留）

run `011b71bd-6f10-4c30-82bb-8f26397ce3cc`，App75467 exit1/31.365s，原report failureCode=arguments、lastcheck native-batch-upload-two-selections通过、fileOperations=null/localStoreRemoved=false、剩余owned4paths。无法用最终缺失证据宣称4job完整/rename/delete通过。

实际下载目录确有邻项4096B、NFD特殊child8192B；外层精确恢复前读其非秘密内容与数据公式相符。但原report没有4job快照，代码中terminalJobs(4)先于校验不被包装成已完整记录的任务验收。

原因是测试校验器 `verifyDownloadedFiles → AppRealPrivateInput.read → pathSyntax` 对绝对路径中的`$`静态拒绝.arguments，和特意含`$`的数据集冲突；不是证实生产SFTP无法处理特殊名。不删除特殊名、不放宽全局参数/配置路径门。

所属App75467/relay75386/SSH75501已结束、服务awaitclose1/attempt1、open12/close12/end0/shutdown0/credential0，relaywait0/5-5-0-0/批准端口无listener。原report SHA256 `5bd735a72074770d9dfa09ed3b083e1619b46fef4b8a679a04f101f02ac11941`保留。

## 精确失败恢复

只对原base64账本root/neighbor/folder/child四项fixedCID逐dirfd/nofollow/UID/mode/nlink/完整目录名单、公式SHA和held/named inode核后，仅两文件/两空目录删除。neighbor SHA256 `c2b173143c71723d526feade9512735f692530f9f11e5ddde357e9d369f90793`；child `1a5e95e02e79d4201700688a69741b1f924d4cac2960c82c64171f82a505d14a`。远端root不存在。

本地原canonicalroot dev16777228/inode114468132，原marker/noACL/owner/mode/link/全部heldFD及原PIDgone、四非秘密数据leaf公式SHA核过，仅14knownfiles/9emptydirs/root精确删除。私钥只核metadata、不读内容或摘要，generation/rawinputs/results不动。原report failed/remainingledger/localStoreRemovedfalse不改。

恢复helper首轮因左9字段identity/右误用5字段比较安全拒绝无删除，实际metadata一致；修为同9字段、保纳秒mtime/ctime后完成，拒绝证据保留。恢复原记录：`DerivedData/AppRealIntegration/fileops-live-ec7ef9a2-7ae8-43d2-b89e-62f0768adceb/{failed-remote-precheck,failed-remote-exact-cleanup,failed-local-precheck,failed-local-exact-cleanup}.json`。主管已读全部清理结果与原报告不变，不把恢复当case成功。

## R1专用FD读取

只对封闭数据集known neighbor/child叶名，从已验证held downloads/folder目录FD `openat(O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)`，regular/noACL/UIDmode/nlink1/精确4096或8192/上限16384、EINTR/partialread全读、FD与当前named dev/inode/UID/GID/mode/nlink/size/mtime/ctime前后相同；账本直接取读取FD身份，不再绝对路径read/stat。全局pathSyntax继续拒`$`，叶名中`$`仍是literalPOSIX字节，不进入shell/config。

原125+1=126tests通过，49hash/14cmd/native160/strict重签；当前App `60aeb59991d8060a7fed1567e69645e88d78a8a8cf4587ebf1c77eadabe91951`、helper `1a8f6c8afb87faef53d53ae50460d7f88110fbd9618c32511402066b5e8f2345`。旧310b/6721保历史。新证据diagnostic-543cacd4-9155-4139-82a4-27b5d00f06b3；主管独立source/摘要/126/签名核验 `DerivedData/Verification/primary-fileops-leaf-r1-9008bb1b-f0ac-472f-8464-5c272eb7be59/`。

## R1唯一真实成功案

provider短时失败恢复后，确认00b9目录此前只有预备文件/没有setup/collect/case/PID，再沿原派工首次执行，非重跑。freshgenerationpostbuild/newUUID `5c2e0a7d-be2a-4302-be08-db0449cc2a6d`，App77308 exit0/38.697s、24checks全过。

- 原生批上传2不同job，原生表格多选下载2不同job，完整4个distinctID保存原JSON。
- 实际download manifest原POSIX bytes与expected完全同：邻项4096B/SHA c2b17314…，子目录NFD/`[#; $]`child8192B/SHA1a5e95e0…；主管从base64原名字节独立重算数据公式SHA一致。
- 原生rename旧目录消失/newname出现；3个不同审核planID/精确root+items删除child、改名目录、neighbor、空UUIDroot4paths；目录删除前后未选中邻项SHA一致。
- 同service/host/binding/lifetime、attempt1/returned1/awaitclose1，20opens20正常closes/endhandles0/shutdown0/forbiddencredentialcalls0，无第二SFTP或外层补操作凑GUI。
- remainingownedpaths空，远端root由生产service在原生删除后lstat notFound；本地数据集及canonicalstore实际不存在，App77308/relay77218/SSH77331实际不存在/nochildren，relaywait0/5-5-0-0/批准端口无listener。

原report `DerivedData/AppRealIntegration/Inputs/run-5c2e0a7d-be2a-4302-be08-db0449cc2a6d/app-result.json`，SHA256 `5d7dba72d383ec3f8fca32bc442351b86c520c922ba3c0d597ceecdf78706153`。完整命令/资源 `DerivedData/AppRealIntegration/fileops-leaf-r1-live-00b9fde6-756e-4b2c-97b9-f35ac14008e9/`。

主管独立验收原24checks/4jobs/3plans/原名sizeSHA/邻项/正常close、实际三PIDgone与canonicalstore不存在：`DerivedData/Verification/primary-app-fileops-pass-4a123c31-e705-4958-9977-fccf8651ed4a/`。旧011b失败及其外层恢复不追认成功。原report通用boundary沿旧Quit说明不改，本案范围明确由phase=file-operations与完整fileOperations字段证明。

此有限AC18/19/20 GUI接线分项通过，正式mac26/人工Finder、冲突矩阵和完整FILE仍未通过；shipping本轮不重建，既有双配置隔离证据另报。整体Goal NOT COMPLETE。
