# 真实 SFTP 密钥/密码与组合认证矩阵

日期2026-10-27，Task REAL-SFTP-COMBINED-AUTH-PREP-A / LIVE-A / SFTP-TERMINAL-ZERO-R1 / LIVE-A。**修正测试契约遗漏的精确尾空轮后，五项MFA实际SFTP与79bytes往返全部通过；结合此前五单方法，受控正向矩阵已覆盖。** 原5pass/1fail/4未试矩阵与严格拒绝诊断仍原样保留，不追认旧失败、不冒称GUI/mac26或完整AUTH通过。

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

## 第四回调：独立形状诊断与固定源码

仅metadata诊断App经主管源审/独立32Swift13Python/17CLI、344input/36cmd及strict通过；原三轮预算本体逐字未改。精确App `Tests/RealIntegration/.build/host-eb1bfbaa-c0b5-4926-a348-569b42b1745f/OpenLXSSHRealIntegration.app`，主程序SHA256 `728f9dcea9b027d0b37879beb4bdd15aceb5203d5c38da6cf3b9ab9ac459a6e4`。

固定key-kbd Edplain仅一次新generation诊断：实际/预期exit1，21.748645s，callback4/reply3/secretread3/SFTP0、unknownChallenge不变。真实ordinal4的name/instruction均0bytes且SHA256为空值 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`，promptCount0/prompts[]、invalid/truncated=false。没有额外答案或秘密管理读取。自有180s relay10407 TERM/waitexit0、1/1/0/0，精确token/PID/监听与server session文件清理；并行App验证脚本变化触发的收尾exit1另行记录，不误称资源失败。

诊断证据：`Tests/RealIntegration/.build/sftp-shape-live-1b0d74a9-a0b5-43b4-8b8f-23b7543a2f83/`。独立静态审查：`DerivedData/Verification/primary-sftp-shape-static-c5e9c254-c807-4d3c-bf01-a44733a433da/`。

只读固定源码研究同时确证：OpenSSH V_9_6_P1 `auth-pam.c` 的 `sshpam_query` 在PAM_SUCCESS时name/info为空、num0、pam_done1（857～858、924～937）；`auth2-chall.c` 261～278没有nreq>0过滤，照发INFO_REQUEST；收到count0回复后 `sshpam_respond` 990～993才设置authenticated，并由AuthenticationMethods/account检查和最终USERAUTH_SUCCESS决定认证结果。失败信息分支亦可能发送非空instruction的零提示，不能只凭count0认成功。

固定源码来源与研究摘要：
- [OpenSSH V_9_6_P1 auth-pam.c](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/auth-pam.c)，取回SHA256 `c7cadf29cbd4ef55442d6737c8b4629009c11afe814c4fa5b2389f9dbfbf2033`。
- [OpenSSH V_9_6_P1 auth2-chall.c](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/auth2-chall.c)，取回SHA256 `61f108b148905f5e9e7e712183d46599134a98e67f1f1f1598d10b8f09252724`。
- 固定libssh2 1.11.1本地 `userauth.c` 2236～2249对每INFO_REQUEST都callback，2288～2295按count发response；`userauth_kbd_packet.c` 116～117允许零prompt。归档hash与lock一致且两源码与归档逐字节相同，主管另读关键行复核。只有收到USERAUTH_SUCCESS才置认证状态。
- OpenSSH9.9p2控制客户端count0时不调用read_passphrase，直接回空列表，所以外层Askpass只见三问题不排除协议有尾空轮。不是本次wire抓包结论。
- [RFC4256](https://www.rfc-editor.org/rfc/rfc4256)允许零prompt并要求零responses；这是count0、无字符串，不是count1的空密码。

研究只证明上游路径，未逐补丁核Ubuntu9.6p1-3ubuntu13.20源码完全一致；本次typedcallback形状由独立实际诊断补证。现选择只为固定fixture测试补精确预算：A/B/C三次同session之后，恰一次ordinal4全空header/count0回复[]、不读秘密；earlyzero、重复/第五、非空header、额外prompt仍拒绝。生产已有typed zero处理，无产品修改。此R1尚待源审/真实SFTP成功，不预判通过。

## 精确尾轮R1与五项真实MFA复验

R1只为固定rootfixture测试定义typedphase secret(session,index)/terminalZero。三次同ID A/B/C秘密响应均成功resolve后才允许恰第四全空name/instruction/count0/echo[]，仅reply.resolve([])，不reader。earlyzero、重复/第五、非空header、第四prompt、跨ID/replay/closed/deadline/未resolve均拒绝；empty不设置认证成功。报告拆总reply4、secret3、terminalZero1、managementReads3、late0，prompt[1,1,1,0]。没有修改生产Files/服务器/正向认证默认。

主管完整读Policy/Callbacks及新拒绝矩阵，独立37Swift/14Python/17CLI、344input/36cmd、strict签名通过：`DerivedData/Verification/primary-sftp-terminal-zero-static-83164a17-052e-45e2-a5e1-263bacde9833/`。精确新App `Tests/RealIntegration/.build/host-18b6b488-18a2-4b3d-a054-cc4dd2663bd7/OpenLXSSHRealIntegration.app`，主程序SHA256 `5893e87fb88375a8aa01fc3b626161da2ee99280384019a540a02da26337d420`，helper `dfa7b557c429ceb73d1f44427e28a90149ade927c83864ffa640d9e2fc985767`。已审源码本地提交52f358a，非产品发布。

两MFA服务freshgeneration/带外trust及原CIDpolicy核验后，各案一次无重试，先最小两案成功再补另外三种密钥；未重跑五个单方法：

| 新MFA分案 | 实际耗时/退出 | 结果 |
| --- | --- | --- |
| key-kbd Ed25519无口令 | 24.965s / 0 | authenticatedSFTP1、79IO/hash/list2/lstat5、精确清理/awaitclose |
| password-kbd | 24.960s / 0 | 同上 |
| key-kbd Ed25519有口令 | 25.148s / 0 | 同上 |
| key-kbd RSA无口令 | 24.954s / 0 | 同上 |
| key-kbd RSA有口令 | 25.128s / 0 | 同上 |

五案均callback4/总reply4/secret3/terminalZero1/read3/late0、prompt[1,1,1,0]/echo[[false],[false],[false],[]]、无unexpected；每个精确server session文件随后不存在。唯一900s有限relay16441 TERM/waitexit0，accepted5/finished5/rejected0/cleanup_failed0；5token/owner/tombstone和所属DockerPID消失、端口无listener、五服务Healthy。193受检依赖源与App/契约hash不变，Git检查点变化仅元数据。

原报告/契约/cwd/exit/cleanup：`Tests/RealIntegration/.build/sftp-terminal-zero-live-aa46be86-ec4b-421e-9483-54d7fe0f0751/`。主管独立重读五个原result并核预算/actualSFTP/79IO/hash/精确清理，证据 `DerivedData/Verification/primary-sftp-mfa-results-907bc22f-8961-46b4-8de5-146179aaa3c0/`。

主管另用同精确App、新独立case亲跑password-kbd一次：actualSFTP1、79bytes写读/hash/list2/lstat5、callback4/secret3/empty1/read3、sessionfileRemoved/close通过；自己180s有限relay1/1/0/0 TERM/waitexit0，端口释放。证据 `DerivedData/Verification/primary-sftp-mfa-live-07febd37-da0c-4d27-a871-16758915a503/`。没有机械重复全部十项。

## 未完成

受控正向SFTP认证矩阵已覆盖，不代表错误/过期OTP、并发/迟到、目标macOS26/正式App完整文件交互或企业环境。错误/真实过期OTP独立负例另准备，严格判typed.authentication而非timeout/transport。整体Goal NOT COMPLETE。
