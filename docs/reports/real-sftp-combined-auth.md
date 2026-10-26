# 真实 SFTP 密钥/密码与组合认证矩阵

日期2026-10-27，Task REAL-SFTP-COMBINED-AUTH-PREP-A / LIVE-A。**当前PARTIAL：五个单方法正向通过，一项私钥+KBI因额外第四回调被严格拒绝，四项依赖MFA未尝试。** 不用OpenSSH outer-auth或MINA auth-only结果代替SFTP成功。

## 实现与主管源审

`Tests/RealIntegration/` 独立 `--sftp-auth` / SFTPAuth* 六文件，旧OpenSSH*/Mina*实现冻结。严格四服务/端口、精确generation/CID/image/project/network/base及带外trust；有无口令Ed25519/RSA密钥从本代私有文件读取到内存，不写argv/env/日志/Keychain。

生产公开 `LibSSH2FileService.connect` 使用显式ordered publickey或password、再optional keyboardInteractive；**只有实际authenticated guard与SFTP init后返回才能报告authenticatedSFTPConnects1**。其后独占UUID小目录、79bytes写/读、list2/lstat5、SHA与精确cleanup/awaitclose均须通过。没有通用 -21/auth-only 旁路。

MFA测试预算当前严格空name/instruction、原始单prompt A→B→C、echo=false、同24hex session、本地一次current-index管理读取与回复。未知即取消，不猜类型；这只适用固定fixture，不是产品通用提示分类。

主管完整读契约/策略/callback锁/once/取消drain/消费者和小文件清理，并独立29Swift/12Python/17CLI、343输入/快照/36命令与strict签名通过：

`DerivedData/Verification/primary-sftp-auth-static-a635a145-716c-4307-a887-e3f4c4c477bd/`

精确host15测试App：`Tests/RealIntegration/.build/host-62b5285a-ece1-44eb-b49b-394bcf082d9a/OpenLXSSHRealIntegration.app`

- 主程序SHA256 `b0958f56135390698cf9d58b92b35cbefde8751032131614f5922c172c0c590b`
- helperSHA256 `8c3d0842f648955021c7601387acc21a578fd2e7deb4b80e2ecc8f108f9e6c73`
- 静态准备记录 `Tests/RealIntegration/.build/sftp-auth-preparation-0a6507c8-d9ff-4ab1-94ab-d652dce239b8/verification.json`

正式产品仍arm64/min26；此消费者非GUI、非目标runtime。

## 真实分组结果

五个原CID容器未重启/构建/旋转；fresh四服务collect与带外公开trust/provenance/权限核验后，仅启动一个1200s上限rootrelay。每项一次无retry；先passwordonly和key-kbd Ed25519无口令最小组。

| 已执行分案 | 退出/耗时 | 实际结果 |
| --- | --- | --- |
| passwordonly | 0 / 12.652s | authenticatedSFTP1、79bytes写读/SHA/list2/lstat5/cleanup/close |
| keyonly Ed25519无口令 | 0 / 12.466s | 同上，callback0 |
| keyonly Ed25519有口令 | 0 / 12.713s | 同上，内存口令，不经Askpass提示 |
| keyonly RSA无口令 | 0 / 12.541s | 同上，callback0 |
| keyonly RSA有口令 | 0 / 12.691s | 同上，callback0 |
| key-kbd Ed25519无口令 | 1 / 21.626s | 三轮后收到第四callback，unknownChallenge拒绝，SFTP成功0 |

失败案前三个callback的promptCounts[1,1,1]、echo[[false],[false],[false]]、同session `2391d80a2a993130c050815c`，current-index管理读取3及回复3；随后callbackCount4被预算拒绝，fileErrorKind=cancelled，authenticatedSFTPConnects0，文件操作0。不是服务器明确拒绝密码，也不是第四次已回答。旧报告没有第四回调形状字段，**不能断言它是零提示、通知、重认证或可安全忽略**。

按早停条件，password-kbd与key-kbd另外三密钥未尝试（4项）。只继续不依赖MFA的四种keyonly矩阵，不能把5/6写成10/10或整体验收。

## 资源、并行变化与独立结果审查

所有6案closeCompleted/managementChildrenReaped/policyVerified=true；失败案创建远端文件前已终止，不把remoteCleanupCompleted=false误当未知远端残留。失败对应server session文件后续已不存在。

自有relay PID4660精确TERM/waitexit0，accepted6/finished6/rejected0/cleanup_failed0；6个精确token目录/owner/tombstone均不存在，所属Docker/relay PID消失、root端口无listener、五容器Healthy。App62及本任务源码/契约hash未变。

最后全域source-baseline收尾脚本因另一已派工工程师正常修改 `Application/OpenLXSSH/OpenLXSSHApp.swift` 退出1，事实保留。它不是本任务源码漂移或资源清理失败；不能删除该检查记录或把实际exit1说成0。任务文件区域独立，主管已核具体差异归属。

实际命令/cwd/exit、六个原result/契约、四个public generation及cleanup：

`Tests/RealIntegration/.build/sftp-combined-live-c458985e-e2de-4f9a-9a4c-2e474a61596b/`

主管逐个重新读取原consumer result并核contract/成功79IO/SHA/list2/lstat5/cleanup，失败callback4/reply3/unknown且SFTP0和未执行列表；不是只看退出摘要。独立结果审查：

`DerivedData/Verification/primary-sftp-partial-results-4712aadd-a461-470f-acba-9d1eb5e4ad86/`

## 下一诊断边界与未完成

只新增脱敏、有界的未知callback形状（长度/SHA/count/echo/ordinal）并保持原claim失败/不回答/不追加秘密读取；源和离线审后再单次诊断。另只读研究固定libssh2/OpenSSH源码，不在观测前放宽budget/改服务器来凑通过。

尚缺组合MFA完整成功、错误/过期/并发边界、目标macOS26/正式App按需整合与其他必要验收。整体Goal NOT COMPLETE。
