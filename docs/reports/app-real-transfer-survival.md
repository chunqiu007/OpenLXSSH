# 原生真实上传跨标签关闭：首案失败检查点

日期2026-10-27，Task APP-REAL-TRANSFER-PREP-A / LIVE-A。**首个真实16MiB phase失败，不能证明关闭SSH/隐藏面板后传输继续。** 已保留原报告与精确残留账本，正在仅补封闭阶段元数据定位；未放宽生产或测试进度门。

## 已审实现与准备证据

仅修改既有AppRealIntegration.swift/Contract.swift、契约测试及独立构建脚本四文件，新增封闭phase `transfer-survives-close`；缺省仍read-only。生产Packages/P6/NativeSmoke/认证与环境不改。

真实原生路径：mkdir风险明确确认→当前service生产probe原生prepare/review/approve/execute→原生upload按钮→HostProbe测试picker URL选择→正式FilesController/Manager。测试picker不当人工Finder/NSOpenPanel。

生成/真实分配16MiB非秘密source，64KiB增量SHA；真实exclusive-temp成功账本存在且close/hide动作前各自snapshot必须running且0<bytes<16MiB，过早完成明确失败。同job/request/service/host/generation/binding及connectionattempt1完成后，同service lease流式SHA和精确knownpath清理才通过。不能用waitingRisk或静态演示冒在途I/O。

主管完整读四文件与差异、复核安全probe/风险/UI/动作时序/后验SHA与ledger，独立116tests（原113+3）/49sourcehash/20命令、HostProbe15与正式Debug/Release26、strictDevelopment签名通过：

`DerivedData/Verification/primary-app-transfer-static-158dbb70-6eed-461f-89c0-169be3ced380/`

精确App `DerivedData/AppRealIntegration/offline-853dd2e8-feff-4491-bc00-cf97bedfbfe4/HostProbe/Build/Products/HostProbe/OpenLXSSH.app`。

- 主程序SHA256 `1bccd1558595afde6e4076da76bf96cf301a295cde9e1f731025c8c8ac87019c`
- helperSHA256 `9c85cea633faa44ed0d8d2092224f5f167b82c67227cfe4573e3c9441ad9542a`

静态通过不是runtime通过。

## 唯一首案真实失败

新freshgeneration/带外trust/固定CID/image/internal/资源及hostfree46,820,093,952bytes/卷free35,148,218,368bytes核验后，run `ae16c0b5-9ad9-4bc2-baca-939e37343722`，phase固定、显式testscan15/connect10，一个600s有限rootrelay。

- App PID26914 exit1/25.466s，failureCode=failedCheck。
- 实际SSH PID26958已建立，productionSFTP1/list4，禁止CredentialAccess调用0。
- 18个已记录检查通过，最后为new-transfer-phase-no-previous-jobs；此前mkdir/root初空/生产probe通过，16MiB source已分配。
- transfer证据为null；原代码未serialize guard标签/job snapshot，无法由现结果区分firstjobidentity、tempcount、precloseinflight、prehide或其他后续守卫。
- **没有close/hide动作时进度或完成证据，不能说该行为通过。** 失败cleanup关闭SSH/PIDnil不等同测试动作覆盖。
- 公开handles最终0，但open7/正常close6、shutdown归账1，不能称全部正常关闭。
- files awaitclose1；自有App/SSH/relay PID均不存在、无directchildren，端口无LISTEN。relay26843 TERM/waitexit0、accepted5/finished5/rejected0/cleanup_failed0。

原result：`DerivedData/AppRealIntegration/Inputs/run-ae16c0b5-9ad9-4bc2-baca-939e37343722/app-result.json`。

命令/cwd/exit、fixedpubliccontract/资源及失败inspect：

`DerivedData/AppRealIntegration/transfer-live-0521e061-a808-4ff6-bf3e-c763605c0f21/`

## 精确残留与主管独立恢复

原report的base64账本明确root和成功exclusive-open temp；手写消息曾把尾E416误抄成F416，第一次主管只读断言因此拒绝，无写入/删除。后续从原base64字节解码，不猜名或宽扫描：

`/fixture/home/openlxssh-app-transfer-ae16c0b5-9ad9-4bc2-baca-939e37343722/.openlxssh-transfer.31E50F3F-18AB-4A4B-B495-31002F50E416.part`

主管固定exactCID/UID10000管理通道逐组件dirfd/O_NOFOLLOW只读核：root UID10000/0700/dev65025/inode23382，仅一个已知temp，finalpayload不存在；temp regular0600/单链接/dev65025/inode23383，真实750,896bytes，SHA256：

`7ab9b448ff0a1fba85098cd004c8235cf0053840d690cc2b5adbd2211f544cd5`

再次核held FD与当前path identity/属性/摘要后，仅unlink该temp和rmdir空UUID根，确认不存在。不将temp字节数反推原close/hide步骤，不把外层恢复当首案成功。

独立后验与删除命令：

`DerivedData/Verification/primary-app-transfer-failure-postcheck-4d9ff98c-e66e-49f4-850f-17d7f44c573e/`

本地canonical markedstore原dev16777228/inode114281690、16MiB source与managed key先只读metadata确认。主管随后核原App PID不存在、固定layout/noACL/UID/mode/单链接、各heldFD/pathidentity及非秘密marker，仅删除11个已知生成文件（含source原inode114281784/managedkey副本/marker）及五个空目录/root；canonical路径确认不存在。未读取私钥内容或摘要、不改fixturegeneration/corpus/raw结果，原report的failed/localStoreRemoved=false原样保留，外层恢复另记 `local-metadata-precheck.json` / `local-cleanup.json`。

原probe已清成功，但其临时目录名未serialize，不事后重建或扫描未知项。

## 后续诊断边界

只新增封闭stage标签与最多8个纯metadata任务快照，记录具体firstjob/tempcount/preclose/prehide/finalstate/cleanup守卫、实际state/bytes、身份与已知风险路径；无rawerror/terminal/secret/privatekeyhash，不改变断言、伪慢速/伪进度或生产P6代码。原ae16结果不覆盖，不自动重跑。诊断源码/离线审后，由主管决定新案验证。

AC-22/24仍未整体通过；macOS26/人工Finder/IME/嵌套、窗口/退出活动任务矩阵未被本phase覆盖。整体Goal NOT COMPLETE。
