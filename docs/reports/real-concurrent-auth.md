# 真实双会话MFA：取消隔离成立，服务器材料清理未通过

日期2026-10-28，Task REAL-CONCURRENT-AUTH-PREP-A / BUILD-A / LIVE-A / CONCURRENT-EXACT-CANCELLED-RECOVERY-A。

**同进程两个公开DirectSSHSession的真实并发、取消A不影响B、旧A回应typed.stale均已成立；原完整case仍exit1/cleanupIncomplete，因为取消A留下服务器挑战文件。过期后已精确管理恢复，不追认为自动清理或整案通过。**

## 实现与独立离线审查

新 `Tests/ConcurrentAuthAcceptance/` 固定password-kbd@12722224/current精确CID/带外trust，同一MainActor启动两session，复用既有OpenSSHAnswerBudget精确38Bprimary模板SHA/专用A-B-C/24hex challengeID/currenttoken预算与PID-safe管理通道。不是扫描普通终端Password提示；无saved-password/Keychain/sendInput秘密/答案摘要。

两会话均停在OTP-A且handler为空后，在同一无await回合核不同session/request/challengeID、不同ownedSSHPID且kill(pid,0)均存活。关闭A并await closed/PIDnil/handlerdrain，旧requestID/token经公开respond(.cancel)必须抛TransportError.stale（非Bool）；A不读OTP，B随后三读三回+outer-auth。成功终态再核当前token/state/stop/Task取消，精确runID/runDirectory与exclusive非秘密receipt用于恢复归属。只验证outer-auth，原password-kbd七cap的shell/PTY不在此案覆盖。

主管完整读3Swift/后续builder/边界测试，独立源码8门与实际Swift `--offline-check`、签名/来源/inert模式通过。builder精确f201 manifest `1130bd88aae8c286f2271cff2cee7c67caa3f915c508d17dc4187ea1cd93225c`，不是其c76父manifest；只编译新3Swift/原管理/guard前缀，复用12依赖objects+Core/3nativearchives/既有helper，845跟踪hash前后不变。首Swift区域隔离编译错误以显式Sendable捕获修复、未串行化，失败日志留存。最终29命令预期通过/9Python、unique exclusive日志。

App：`Tests/ConcurrentAuthAcceptance/.build/host-62d4c46a-8b48-4666-9905-da34cb2c6d31/OpenLXSSHConcurrentAuth.app`，driverSHA256 `d82f95bd641480061b51de99101277de79692b846a7b012c81f012749a3dda9c`，helper `95eb72a29ddb2707c5c1e12edf4c12835a006b71bbd74ea277dcf0cc890c9f62`。arm64/min15测试、sameTeam Development/Runtime/emptyentitlements/strict，正式min26未改。主管独立来源/13objects/29cmd/CLI/签名证据：`DerivedData/Verification/primary-concurrent-auth-static-8a5c42a8-b8c8-4bbe-80c0-63fdc9138e6a/`。

## 唯一真实案

fixed password-kbd CID `b2ed801a870aeabdd7965d48033e105f5726f101713eb5a061bfa36a251ce29c`，原image/project/internal/network/七cap不变，freshcollect/relay/consumer各一次，无重跑。

- A PID68912、session11FCEA33-93FF-4606-8485-4FD4BF970EA7，challenge469d478f7f3c84500aca2092。
- B PID68911、sessionC9983A6A-1610-46C6-8FAC-3578C947B5F5，challengefde783e17313159c4d4456df。
- 两generation均1但sessionID不同，token完整绑定，不能只凭generation数字认为串用。
- A/B同时OTP-Apending时刻517912.668458/517912.866847；同livePID barrier517912.877172；A closed517912.897595；B connected517922.238130。
- A primary读答1、OTP读答0、connected0；关闭后旧.cancel得到typed.stale，提交计数未增。
- B在A关闭后仍原request/token/PID pending，随后primary1/OTP三读三答/成功提交4/outerconnected1。

consumer68544实际exit1/32.099834s，failure=cleanupIncomplete/serverSessionsRemoved0，原报告不改。最先核A存在即抛错，计数0不表示B也未清；外层实际核B已不存在。

## 取消材料残留与资源

A `/run/openlxssh-fixture/sessions/469d478f7f3c84500aca2092.json` 在实际expiry后73.23s仍存在，UID0/0600/inode39/nlink1，B已删。无证据将其归管理timeout。PAM模块写challenge后阻塞原生conversation，Python finally只保证正常返回/异常展开，不能覆盖所有原生进程终止；本案信号未采到，不编造SIGTERM。过期清扫仅新认证入口触发，TTL本身不自动删除；监督器不处理单会话。该fixture卫生缺口保留，未通过重启/新认证/改信号handler抹去。

A/B本地sessionclosed/PIDnil/handlerdrain，relayaccepted8/finished8/rejected0/cleanupfailed0，全部8exacttoken目录/owner无，host五knownPIDgone/端口空；同资源采样UID10000process0/sshdchildren0/sshdFD4 baseline4，无僵尸。宿主fresh14凭据文件与精确localrun按receipt清理，保留receipt副本。

主管独立读原typed结果/实际时序/不同ID/PID/核心flags和A过期残留：`DerivedData/Verification/primary-concurrent-auth-partial-ac9a478c-bdcc-4b9a-a6a1-5374051ecc6f/`。

## 显式精确管理恢复（不是自动清理）

在无会话/进程/relay条件且CID/image/Healthy/start不变时，仅对该exact A做UID0 dirfd/nofollow heldFD+当前path校验dev88/inode39/uid0/gid0/0600/nlink1/size145、mtime/ctime及sessionID。expiry1793119394.0082948，恢复wall1793119790.562125，实际过期396.554s。仅unlink该文件、fsync持有sessionsdir、heldFD nlink0/精确A与B路径不存在，不扫描删其他挑战或输出responses/秘密摘要。

恢复前后sshdFD4/用户与sshdchild/zombie0、8token无/端口空。原consumer report SHA256 `c895bf456fd173b3d40d1bc71ce0c18e36912112d69044129d18d08c70de9634`未变，仍exit1/PARTIAL。曾有进度消息误报size/wall，均以该原JSON145B/1793119790.562125为准，不沿错误数字推结论。

## 证据与未完成项

- 原案与前后结果：`Tests/ConcurrentAuthAcceptance/.build/live-f00068bb-bbab-4b08-98c6-f464eb47190b/`。
- exact管理恢复：`Tests/ConcurrentAuthAcceptance/.build/recovery-b299b7cc-8ff1-4ce9-aa31-3d50a27a9d45/managed-recovery.json`，SHA256 `588a7f2af5a6066435adf0ad174b672ab03f61547f6c0356b3900a2dff419450`。

并发核心分项可接受，完整case/服务器自动取消材料清理不能标通过。当前无残留资源，未修改生产App/Transport，也不以.cancel stale证明OS秘密副本已擦除。正式App并发UI/目标macOS26、更多排列/手动嵌套/凭据持久化仍待。整体Goal NOT COMPLETE。
