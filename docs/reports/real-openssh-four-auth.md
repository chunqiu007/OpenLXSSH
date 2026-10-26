# 真实系统 OpenSSH：四类认证与密钥格式矩阵

日期2026-10-27（Asia/Shanghai），Task OPENSSH-FOUR-AUTH-A / LIVE-A。**宿主15测试专用消费者的真实生产API分项通过，不是macOS26正式App/GUI、保存密码或整体验收。**

## 入口、来源与审查

使用生产公开 `DirectSSHSession.connect`、受控系统OpenSSH9.9p2及包内已验签Askpass。没有 `startProbe`、终端文本解析、猜测秘密类型或saved-password自动化。测试的显式回答通过 `.manual`，不外推AUTH-02的保存凭据自动使用条件。

固定四服务 `fixture@127.0.0.1:22221～22224`、rootimage `sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363`、project `openlxssh-fixture-61ed25328c13`、internal网络及原四CID不变。每服务新独立0700 collect代次、带外hostkey/fingerprint/provenance与精确CID/image/network核验，无跨代fallback；未重启、重建或旋转服务密钥。MINA原服务保留。

源码只在 `Tests/RealIntegration/` 新增独立OpenSSH*契约、预算、管理读取和消费者；产品包不改。主管读完整实现与测试，独立24Swift/11Python/13CLI通过、338输入/快照与36构建命令核验、主App及helper严格签名通过，静态证据：

`DerivedData/Verification/primary-openssh-static-e1d97809-69cd-48ea-9a89-f24c3db82add/`

精确App：`Tests/RealIntegration/.build/host-d48d5bec-0602-4d5b-ba44-3495a165162c/OpenLXSSHRealIntegration.app`

- 主程序SHA256：`5066db05dd12917dd99c94e9bc51ea6bdebdf14d597e2bd526a02b996076c89d`
- helperSHA256：`0cb01e0fbd990c40154976cea460da7051e9eaed899130a440637f67c66a9f0e`
- min15仅测试专用；正式产品仍arm64/min26。

## 精确挑战观察，不猜答

先对密码、有口令Ed25519/RSA及两MFA入口执行五次observe：只输出prompt UTF-8 SHA256/字节数/kind/hint与fixture envelope是否匹配，然后取消并等closed/nilPID，零回答。observe不是认证通过；密钥校验与系统ssh仍正常读取所选密钥，不声称“零秘密文件读取”。

前置密码和口令预期摘要由已审OpenSSH9.9p2公开格式、HostKeyAlias和精确本代路径独立计算，再与观察结果比较，不复制观测hash作为唯一依据；本机 `/usr/bin/ssh` 的三条公开格式字符串亦独立核对。当前重取上游网页两次ECONNRESET如实保留，不称本轮重新下载源码成功。

- 密码格式 `%s@%s's password: `，passwordonly38bytes，SHA256 `7ae56f86343d23625f49ed78e8fb2429423a023fb6e64967263ff07e8113d1b3`。
- 密码+KBI前置38bytes，SHA256 `cbc6a396f8a1212da2e012e5dc6356a3a1af12f66e2ddde0752d7dd959b5c348`。
- 私钥口令格式 `Enter passphrase for key '%.100s': `，两案129bytes，SHA256 `51f535a2c3764b2ab4a3a509710b53e10bedc6eae7a6560960ee0d5572dc0b0a`。本代路径前100bytes相同，故hash相同；它不单独证明密钥种类，完整路径/所选类型另由严格契约及生产配置绑定。

均kind=unknownMasked、hint无。MFA只接受fixture专用完整A→B→C提示、同24hex session、本地单调index与一次回答预算；服务器sessions文件没有round字段，不声称验证了服务器round counter。每次仅通过固定UID0/no-follow/0600/single-link/TTL私有PIPE读当前答案到内存，无host OTP文件、argv/env或日志秘密。

## 真实12案

均实际exit0、无重试；五observe均connected0、回答0并取消关闭。

| 正向分案 | 耗时 | 必须观察到的生产结果 |
| --- | --- | --- |
| passwordonly | 19.139s | 外层connected恰1，primary回答1 |
| keyonly Ed25519有口令 | 19.132s | connected1，口令回答1 |
| keyonly RSA有口令 | 19.109s | connected1，口令回答1 |
| keyonly Ed25519无口令 | 18.922s | connected1，无认证回答 |
| keyonly RSA无口令 | 18.825s | connected1，无认证回答 |
| key-kbd Ed25519无口令 | 31.402s | connected1，同session三轮OTP，管理读取3 |
| password-kbd | 31.581s | connected1，primary1及同session三轮OTP，管理读取3 |

五observe耗时19.548/19.553/19.432/19.456/19.484s。所有12案closeCompleted/ownedPIDReleased/managementChildrenReaped/policyVerified=true。connected来自可信outer-auth helper事件，不是PID产生、睡眠、终端输出或shell-ready保证。primaryAnswers只是consume/respond预算，不是额外秘密文件读取遥测。

两MFA成功后对应精确server session文件均不存在。实测未触发此前担心的PAM prior/prefix不符，没有修改策略或扩大匹配来换成功。

## 证据与资源

完整实际命令/cwd/exit、12份原消费者result与契约索引、独立prompt对照、公共带外核验和结束检查：

`Tests/RealIntegration/.build/openssh-four-live-58bb5433-e12c-4e07-9131-c739978288c7/`

唯一有限1200s rootrelay PID98411，TERM自有Popen/waitexit0；accepted48/finished48/rejected0/cleanup_failed0（每消费者包含扫描和实际认证，不能把48当成功认证次数）。48精确token无owner、所属host子PID消失；47目录已删，1无owner取消tombstone按防迟到exec设计保留，不扫删。五容器仍原CID/Healthy，端口释放并已串行交给独立断连任务。

主管独立读取12个原result而非只看summary，核对应显式contract、手算prompt字节与SHA、七正向预算/可信事件、五observe零回答、MFA三轮/current-index读取及server文件移除、完整relay计数/收尾与actual source hash。结果复核：

`DerivedData/Verification/primary-openssh-results-23bcd030-fc12-447b-892f-7749918dd258/`

主管另用新0700case/0600contract、同精确d48构建亲跑password-kbd一次关键抽验：真实exit0、connected1/primary1/OTP3/requests4，管理读3、精确server session文件移除、close/ownedPID释放；自己180s有限relay accepted4/finished4/rejected0/cleanup_failed0，TERM/waitexit0及lsof无listener。证据 `DerivedData/Verification/primary-openssh-mfa-live-ba91153e-8b30-46d7-bb7d-1d7973a8841e/`。没有机械重跑全部12案。

## 尚未完成

- 正式App/GUI、目标macOS26、首次信任UI与保存密码/Keychain自动使用条件。
- 错误私钥口令、错误/过期OTP、并发/迟到及真实失败/超时完整OpenSSH矩阵。
- key-kbd本轮只Ed25519无口令，不是所有密钥×MFA笛卡尔积；SFTP组合认证须另测。
- 单消息原始多prompt/echo/group/language不是Askpass所能完整暴露，相关多prompt证据来自另行MINA生产libssh2验证，不互相冒充。
- 手动嵌套SSH、真实TUI/IME、200次/五会话24小时、企业提供方和双机安装。

整体Goal仍NOT COMPLETE。
