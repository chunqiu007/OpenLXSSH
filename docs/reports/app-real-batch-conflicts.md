# 真实批冲突：本批跳过与新批次单项改名

日期2026-10-28，Task `APP-REAL-BATCH-CONFLICT-PREP-A` / `APP-REAL-BATCH-CONFLICT-LIVE-A`。

**唯一fresh案已主管独立验收：一次原生本批skip令两项实际skipped/0bytes；新batch仍询问，单项transfer rename及alternate独立风险成功；原件SHA保全、精确审核删除及资源释放通过。** 仅HostProbe/macOS15，不包含overwrite、在途切标签或完整AC20。

## 实现与静态审查

四文件新增closed `batch-conflicts`，不修改生产包、控件、依赖或fixture。固定UUID远端根；本地Seed/Fresh各a.bin4096B、b.bin8192B，确定性内容/SHA、FD/inode/noACL/精确6节点账本，未知项保留。native mkdir/currentservice probe→seed上传2→fresh同批2 applyskip→新批次Fresh/a单项改名→native精确4路径审核删除。摘要通过原service lease，不外层SFTP或救援清理。

运行时的Gate Snapshot/Decision只由公开TransferJobSnapshot/TransferDecisionRequest逐字段复制；记录job/generation/batch/host/service/path/decision问题及原生回答，纯测试构造Gate值，不伪造实际快照或能力确认。路径风险在冲突前、alternate风险在rename后，均单独原生确认；第二skip冲突直接失败，不补第二答案冒充批策略。旧fileOperations/terminalJobs/终端和sessions函数逐字不变。

初858cd950构建App成功，但新增@testable import因缓存包不启用testing导致测试模块扫描exit65，未运行tests。原失败保留；仅改正常import和只读Gate转换，不改变package/testing构建设置。

复验 `python3 -B Scripts/verify-app-real-integration.py diagnostic` exit0：142tests/0failure，原137名称完整保留；新增5项覆盖scope/formula/exactdelete、admission/stale/duplicate/wrongbatch、决策类型与代次/独立风险、skip零字节与失败/mixed/pending/temp拒绝、rename正确目标和三batch。49source/native160/14命令（12日志+2私有签名记录）符合expected。

冻结 `diagnostic-9f46f6b9-2390-4421-99c7-f812095b5a87`（私有853缓存内）：main `ba831a204b2a348f6b26bd8f75398e0bf78a3618c88829e004a71e455ee205da`；helper `e00eeec1b223c7bc8121f0850145639d894ec5d656b460c312a496dd54774741`；manifest `ae49c7b353c336911c90ef03c99d514bea6085baa63adbaa095a2b9c835ec628`。

主管完整源审、独立核实际mapping/142原137保留/native160/当前49输入/签名同TeamDevelopment-Runtime-空权限-strict及inert0-0-64：`DerivedData/Verification/primary-app-batch-static-9d7400a1-0f53-401f-af79-79c1ea6b4582/`。

## 唯一真实结果

runID `567efefc-62e4-4267-a78e-138373229d6e`，collect/relay/App各1，无失败或重试。App90947自然exit0/34.103s，24checks全通过；显式testscan15，生产scan5/connect10不改。

- Seed2 succeeded4096/8192；batch A343D06A-1917-40E8-AF1D-B85F0C4BB702。
- Fresh2 skipped/0bytes、无pending/temp，只一次原生applyToBatch=true/skip；batch A79C3D49-B791-4653-BABE-40F1A56E462A。
- 新batch DA937FF5-A11B-4AE2-AB50-5DDEB3BFA9AB重新出现冲突，原生transfer rename applyfalse，alternate成功4096B。
- 5个不同job/generation、3batch、8不同decision ID，6个准确路径风险和2个conflict；alternate风险在rename冲突后单独确认。
- 三个remote manifest中原a/b bytes/SHA始终相同；alternate SHA等于Fresh/a。主管从runID公式独立重算全部4个local及最终remote摘要，均一致。
- 同manager/service/lifetime/host/serverBinding、attempt1/returned1/awaitclose1，25opens25正常closes/endhandles0/shutdownrescue0/credential0。
- native审核计划只含a/b/alternate/UUIDroot四路径，全部成功；remoteledger空/rootnotFound、本地6节点和store清理完。

原报告：`DerivedData/AppRealIntegration/Inputs/run-567efefc-62e4-4267-a78e-138373229d6e/app-result.json`；SHA256 `8e93b376e20c1ab9c06321af09f7b948e99671e2ccc9b75e108c0a974998fd0c`。

命令/资源/41文件证据：`DerivedData/AppRealIntegration/batch-conflict-live-924d2eab-6e5f-4ca5-a295-634db72e83fb/`；manifest SHA256 `f258c0085b083d92a8a9cf6a759e45ce44eba1e7bed728658b66e83fce452e0a`。

## 资源与主管结论

relay90880有序exit0/5accepted5finished0rejected0cleanupfailed，无强制KILL；App无外层TERM/KILL。App90947/relay90880/SSH90983均不存在/逐PID FD0，22221～22225无listener，准确store不存在/app-tmp空。fixedCID/UID10000只读lexists确认native已删除的精确root不存在，没有外层删除。远端UID10000进程0、daemon21/start7980921/FD4及四服务/CID/start/caps/network/volume/config/auth/known前后快照相同。49source/5fixture/15bundle不变。

主管独立读取原24checks/全部41摘要、5job3batch8decision绑定、原生skip唯一回答/新batch隔离、alternate风险顺序，重算数据公式SHA，再核当前三PID/端口/store及冻结源签名，证据：`DerivedData/Verification/primary-app-batch-pass-f63ee62e-8a33-4d59-8e78-c1bb81e751e4/`。

**有限真实batch skip→新batch单项rename分项通过。** 原通用App taskID保留，以phase/runID/batchConflicts和命令绑定；不等overwrite、正字节传输切标签、人工Finder、正式macOS26或整体Goal通过。
