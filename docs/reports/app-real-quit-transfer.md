# 真实活动上传：Quit继续、取消与原生退出

日期2026-10-27，Task APP-REAL-QUIT-A / LIVE-A。**唯一host15/HostProbe真实案通过Continue→第二次Quit取消、生产资源drain、退出前完整回执与实际原生进程退出联合核验。不是外层kill或测试末尾exit冒充退出；retained temp由外层精确恢复另记。macOS26/完整产品验收仍未完成。**

## 实现与独立源审

仅AppRealIntegration.swift/Contract.swift、OpenLXSSHApp.swift、原契约测试及verify脚本五文件，封闭 `quit-continue-cancel`。一个16MiB真实上传，动作前/按钮决定时均核running/0<bytes<total/同job-request-gen-service/原SSH与attempt1。

两次通过真正 `NSApp.terminate`，common Timer对原Manager fresh snapshot，回native run-loop模式同步验证/点击原生Continue或Cancel。Continue必须恢复admission/保原窗与任务；Cancel后run交接不走末尾exit。HOST_PROBE退出前后hook只此phase安装，正式构建无hook，nilhook原行为不变。原生产drain后，retained精确路径checkpoint先fsync再原生ack；before钩子核cancelled/Managerclosed/noactive/Filesclose/SSHnil/handles0并删本案host/key/source；原delegate唯一close Security/Repository；after钩子核一次顺序、清store并exclusive/fsync完整report后才允许原native reply。失败拒绝Quit且静态failreceipt/缺成功回执由外层判失败，不伪成功退出。

主会话完整读五文件实际diff和原delegate close-flow，核nilhook/正式编译边界、drain/单close/Timer/回执时序。123tests（原121+2）/49hash/14cmd/native160/strict通过，旧Swift Sendable编译错误保留：`DerivedData/Verification/primary-app-quit-static-d5c2995f-8042-494f-9d9b-7095f53a5c51/`。

复用原853私有树增量，新证据diagnostic-ff638f18-670d-4384-8a9f-bb92b7aa86a0；App SHA256 `3198b9e4857d03f2ca59c363ec05c78c70c3f194f888e09f4ff1516f228eb6d4`，helper `e22cd3b0f9495f58e865d432b2d32292bbc6f2ff1e40e39d1870742e504dd9cd`。同路径已替代窗口c325/acb，旧结果保其原hash；正式min26旧证据沿用非本轮重建。

## 唯一真实单案

run `3a931127-c0c3-4226-b0ec-a129a87e7f6e`，freshcollect postbuild、current1253 CID/MHU FP/原隔离门，testscan15/connect10、relay600/App480上限。

| 动作 | 实际上传字节 |
| --- | ---: |
| 首次NSApp.terminate | 786432 |
| 原生Continue | 917504 |
| 第二次NSApp.terminate | 983040 |
| 原生Cancel | 1048576 |

全为真实inflight/小于16777216。Continue保窗/同任务，最终cancelled/原Managerclosed/noactive/Filesawaitclose1/SSHclosednilPID，before/afterhook1/1，22checks/6exclusive checkpoint。报告nativeReplyStillPending=true表示回执在原native reply之前；随后外层实际观察App65416自行退出0/26.106s，`appNativeExitObservedBeforeDrain=true`、`appForcedTerminationRequired=false`，无末尾exit或外部强制终止。

provider临时失败中断了工程师对话，恢复仅收既有后台已完成原案结果/清理，不重新setup、collect、run或重建。

## 取消安全与资源后验

App准确保留唯一temp声明，ack前checkpoint持久化，闭服后不做SFTP IO/重连。fixedCID管理后验：正式payload不存在，父仅原byteledger temp/unknown0；parent dev65025/inode12958/UID10000/0700；temp dev65025/inode12959/UID10000/0600/link1/1310720B，SHA256 `79ed60c61d7bc4032558ee082365058a2616b2b72d7e3b67f2fea5aed3391f47`。再次FD/inode/SHA核后仅unlink本temp+rmdir空根，确认不存在，不改原retainedreport。

App65416/SSH65455/relay65309实际不存在/无其directchildren，relayTERMwait0/5-5-0-0、批准端口无listener，canonicalstore不存在。open7/正常close6/shutdown归账1/endhandles0，取消dispose事实保留，不冒全部正常CLOSE；credentialcalls0。

## 证据与验收

- 原pre-exit report/6checkpoint：`DerivedData/AppRealIntegration/Inputs/run-3a931127-c0c3-4226-b0ec-a129a87e7f6e/`，无quit-failure.json；report SHA256 `ee2c5b0bf61ad06eab6821f0d054fea47aa9988acb9b25c399752713d81a40a1`。
- 原setup/run/nativeexit/资源与外部精确恢复：`DerivedData/AppRealIntegration/quit-live-98964dc2-8c36-421d-885d-699961b3b61d/`，`remote-exact-owned-cleanup.json`标明externalManagementRecoveryNotConsumerCleanup和原reporthash前后一致。
- 主管独立核22checks/6checkpoint/严格进度/oncehooks、外层nativeexit与无forceddrain、实际三PID与store不存在、finalabsence与精确恢复：`DerivedData/Verification/primary-app-quit-live-7aa7b4a7-f580-41bc-98fc-93eeef9576dc/`。首次只读核验脚本cleanup字段名误用触发KeyError，按原字段重核通过，无任何状态动作或报告改写。

此有限分项通过；不将外层清理当App自动清净，不宣称macOS26/人工Finder/IME/完整认证/下载与多任务矩阵或PERF通过。整体Goal NOT COMPLETE。
