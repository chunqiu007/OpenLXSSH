# 真实错误与到期 OTP：只提交一次的负向认证

日期2026-10-27，Task SFTP-OTP-NEGATIVE-PREP-A / LIVE-A。**固定key-kbd隔离服务上，错误OTP与真实到期OTP均得到typed authentication拒绝，未返回SFTP；主管已源审、独立离线复验及两原结果/时钟证据核验。** 非GUI/macOS26或企业所有MFA提供方声明。

## 独立负例契约

`Tests/RealIntegration/` 新独立 `--sftp-otp-negative`、封闭bad-otp/expired-otp schema/预算/回调owner，不扩大已验正向SFTP预算，不修改产品/服务器/TTL。固定fixture@127.0.0.1:22223、key-kbd Ed25519无口令、新exactgeneration/CID/image/network/带外trust；未知callback只记bounded长度/SHA/count/echo后取消，不猜通知答案。

A/B正确后，C仅在仍有效时用既有fixedUID0/no-follow/0600/singlelink/TTL reader**读取一次到内存**：bad只改一个数字，expired不修改答案而真实等待到期后只提交一次。OTP值/摘要不写argv/env/普通文件、日志或报告。OpenSSHOTP只增加expiresAt非秘密元数据，原reader的expired拒绝门不放宽。

专用测试operation85s/active100s/full140s/external170s容纳服务器真实TTL75；正向operation20/active45保持。提交到期答案须同时满足wall≥expiresAt+0.05和monotonic≥readUptime+(expiresAt−readWall)+0.05，不能改时钟、缩TTL或等待后重读新答案。

只有typed `authentication/authenticate`（本公共路径实际code=nil）、成功提交三次秘密/读取三次、注入或真实expiry证明、SFTP0/fileops0、精确sessionfile移除与close/drain联合才算负例通过。timeout/transport/cancelled/早失败不算。

## 源审与独立离线验证

主管完整读Contract/Policy/Callbacks/Consumer、expiry元数据最小diff及测试，独立44Swift/15Python/21CLI、348输入及快照/36命令/strict签名通过；原正向实现/reader冻结。

精确测试App：`Tests/RealIntegration/.build/host-5c78f066-cfeb-4a0e-98d5-32b62a3b12da/OpenLXSSHRealIntegration.app`

- 主程序SHA256 `5f649be94679af378c8a5597d1f05028b4c836d78dded50e1bdfb0bbceeb4739`
- helperSHA256 `26feae1eea9301578bc7beee3f42036b750460da01f31e7e92223ac1e486493b`
- 仅host15测试，正式min26不变。

独立证据 `DerivedData/Verification/primary-otp-negative-static-18740cd3-ed5a-44f2-9738-38b10e1a22d3/`。

## 两案真实结果

freshgeneration `credentials-a2b91ed7da08`、fixedidentity/trust/permissions与App/sign/snapshot核验后，一个420s上限rootrelay，两案各一次独立session，未重试或修改场景。

| 分案 | 实际退出/耗时 | 负向证据 |
| --- | --- | --- |
| bad-otp | 0 / 24.809s | typedauthentication/authenticate，C有效期内单数字错误只提交一次，wrongCVerified=true |
| expired-otp | 0 / 90.728s | typedauthentication/authenticate，C提前取到后持有至真实期限，realExpiryWaitVerified=true，未改答案 |

两者均callback3/secretReply3/managementRead3/late0、actualSFTPConnects0/fileOperations0、closeCompleted/managementChildrenReaped/serverSessionFileRemoved=true，无unexpected callback。公共error code实际nil，不从native假定补值。

### 错误C时序

- readWall1793056717.268367 < expiry1793056783.0406835。
- submitWall1793056717.268426 < expiry。
- mutatedDigitCount1，仅一位内存变更；不是过期或timeout负例。

### 到期C双时钟

- preExpiryReadWall1793056742.184424 < expiry1793056807.9284623。
- submitWall1793056807.989612，实际晚于expiry0.061150s。
- heldMonotonic65.805392s ≥ expiry−readWall+0.05 =65.794038s。
- mutatedDigitCount0，无重读；响应发生在真实服务器TTL后，结果为认证拒绝而非budget timeout。

## 原始证据与独立结论

真实argv/cwd/exit、两个原consumer result/契约、公开generation、relay与最终清理：

`Tests/RealIntegration/.build/sftp-otp-negative-live-72812a7f-b4a1-4d14-90d8-08da978fc73d/`

主管重新读取两个实际result，核typed分类/三次读答/注入一次、真实read-expiry-submit与单调时长、SFTP0/fileops0和close/sessionfile，非仅信exit0。没有机械重跑90秒到期case。独立核验：

`DerivedData/Verification/primary-otp-negative-results-23c19411-472a-4147-ac8f-3def717f6b0d/`

自有relay24194精确TERM/waitexit0、accepted2/finished2/rejected0/cleanup_failed0；主管另读最终cleanup，确认两精确token目录/owner/tombstone与两server session文件均不存在，所属PID消失、端口交接前无监听、198受检任务/Packages/root源未变。App/契约hash不变、五服务Healthy，不把子任务DONE当整体完成。

## 限制

只验证隔离fixture的错误/真实到期OTP；实际企业厂商、正式App交互/重试提示、并发和强制late-result竞态、macOS26与双机仍待。Data/Swift/native副本不能保证全面擦除，已限制读取/复制与输出。整体Goal NOT COMPLETE。
