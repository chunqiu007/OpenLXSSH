# 真实认证负例与已知主机密钥不匹配

日期2026-10-27，Task REAL-AUTH-FAILURE-PREP-A / LIVE-A。**宿主15生产Files API两项真实负例及独立显式信任替换正控通过；主管已源审、独立离线复验和原结果核验。不是正式App/macOS26或实际服务器轮换事件验收。**

## 范围与实现

仅新增 `Tests/AuthenticationFailureAcceptance/` 八文件，封闭bad-key-passphrase/known-host-mismatch两case，默认/help/validate纯解析、双运行门，fixed fixture@127.0.0.1:22221/原CID/image/project/base及构建后新generation/带外fingerprint，复用PrivateInput nofollow/noACL/0600/owner/singlelink。

生产公开LibSSH2FileService connect，只有publickey计划，无KBI fallback、Keychain或远端写。错误口令只在内存改单byte，不改源文件、不输出值或摘要。mismatch仅本case Trust同endpoint/algorithm预存另一把由系统ssh-keygen生成的公开测试key；临时私钥在prepare发布元数据前按exactinode删除，保持服务器不变。

callback始终reject，不自动替换。只有负例完整结束、旧known_hosts hash仍未变，外层另明确执行独立 `--replace-and-control` 命令，才调用正式prepareReplacement/confirm(带外精确fingerprint)，再新连接正控。

## 源审与独立离线证据

主管完整读八文件，核正控失败不能进入wrongphrase、negative类型/错误分类、changed双FP/旧record、显式replacement隔离、临时私钥/Trust精确清理。独立5Python/55Swift synthetic及真实本地Trust API/6CLI、198输入与快照/30命令/160native、strict ad-hoc通过。精确Core只Contract.swift/PrivateInput.swift，不扫并行OTP源。

driver：`Tests/AuthenticationFailureAcceptance/.build/host-65030f42-e0f0-4be7-b1e5-63f193bb8616/artifacts/OpenLXSSHAuthenticationFailure`

SHA256 `e56dad32ab9a33c4504161947f64c65f4af4887795e992d2972dfe54ad3b37cf`。

独立静态审查：`DerivedData/Verification/primary-auth-failure-static-e112e8a9-10ed-4f52-a40b-f8e4e423216a/`。未把本地Trust测试当真实握手证据。

## 真实三阶段

fresh fixedCID/资源/internal/无hostmount/Healthy/空端口和带外公开key核验后，新generation `credentials-001ba3afa4a7`；两prepare各一次，mismatch的keygen临时private/public/目录均已不存在，仅保留公开key。

| 独立命令阶段 | 退出/耗时 | 实际证据 |
| --- | --- | --- |
| bad-key-passphrase negative | 0 / 12.970s | 同encryptedkey正确phrase先actualSFTP1/list1/close/socket0，再一次wrongphrase得到authentication/authenticate，SFTP/list/write/KBIplan0 |
| known-host-mismatch negative | 0 / 6.251s | actualhandshake后的.changed精确两FP，untrusted/host-key、SFTP0/文件操作0、旧record hash不变/close/socket0 |
| 外层显式replace-and-control | 0 / 6.359s | 先核负例receipt/已close/旧recordhash，再独立命令显式替换，newSFTP1/list1/awaitclose/socket0，knownhash变且精确cleanup |

**两个typed error的code实际均nil（JSON省略），不是−19。** libssh2内部可把本地解密/签名失败折PUBLICKEY_UNVERIFIED，但本报告只说“正确key对照下错误口令不能认证”，不称服务器拒绝该口令。public API未暴露wire认证次数，KBIplan0不是伪造服务器KBI包计数。

## 信任前后

实际带外key：`SHA256:oCBbJaAjOZMzrKEnj+Z4iHSn74Qc+0tTu9bOzfpwJ5w`。

本case旧测试公钥：`SHA256:+pViNcsgALPCJs5kDehxV2zJwvOMMjbNSqAlLYfCsN4`。

实际.changed为127.0.0.1:22221/ssh-ed25519、expected旧FP/presented带外FP，恰1次，无pending。负例known_hosts前后SHA256同为：

`24f2a1e7c5dc131716989c30d8469dc8b0d10b9ce5ade08c308d2f9dac452132`

外层明确核完负例后才运行替换，SHA256变为：

`f1aeacf424e9091ddec2ea8b8c0ce72c5633269041268a59917db7df5fbde1c8`

这是existing-record mismatch的真实握手拒绝与恢复，不是服务端真实rotate或DirectSSH actualhandshake拒绝；DirectSSH预扫拒绝语义另验。

## 资源与证据

单600s上限relay PID18708，实际62.543s后TERM/waitexit0；accepted4/finished4/rejected0/cleanup_failed0。三个driver18784/18808/18829均exit0/后验不存在。两case trust/session/keygen/private均不存在，仅0600单链接非秘密metadata/publickey保留。容器内bridge0/newtoken0、无listener/残留TCP，keyonly仍Healthy，shm64MiB空；原tombstone不扫删。

真实argv/cwd/exit、原报告/negative receipt/公开材料hash与postflight：

`Tests/AuthenticationFailureAcceptance/.build/live-6332fe90-61aa-4506-a606-8158b1b63c01/`

主管逐项读三原报告与实际命令，核正确phrase正控、wrong typed及noSFTP、双FP/旧hash、负例SHA绑定receipt与独立replacement新连接、原实际nilcode、sourcehash/精确清理和relay，未机械重跑完整三阶段：

`DerivedData/Verification/primary-auth-failure-results-a3fe9ec0-fc8f-4456-a9be-a3ae2434862f/`

## 未覆盖

错误/真实过期OTP、真实handshake timeout、OpenSSH解锁错误/恢复UI、实际serverkey轮换、正式GUI/mac26/企业环境仍需独立验收。close依据生产await契约和零peer sockets，不声称所有内部协议CLOSE都另有计数。整体Goal NOT COMPLETE。
