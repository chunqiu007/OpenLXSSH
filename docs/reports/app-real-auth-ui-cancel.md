# 加密私钥真实原生认证 UI：取消与手动恢复

日期2026-10-28，Task `APP-REAL-AUTH-UI-CANCEL-PREP-A` / `LIVE-A`。

**唯一fresh案已主管独立验收：真实加密Ed25519挑战打开安全输入框后原生取消，旧进程/请求清理；原生手动重连出现新请求/代次，经安全字段提交一次后真实认证与fresh shell ACK成立，生命周期和资源释放通过。** 仅HostProbe/macOS15，不等企业MFA、Keychain持久化或完整AUTH/mac26通过。

## 安全实现

只四文件新增closed `auth-ui-cancel`，不改fixture、生产包、认证gate或contract schema。仅此phase使用本代固定encrypted Edkey，其余仍plain；保留原plain-public/provenance门，额外成熟PublicKey解析同generation encrypted public key，与实际导入公钥匹配。

导入传 `.passphrase(SecretBytes)`、remember:nil，验证并保留原encrypted bytes，managed/source摘要只在App内存比较、不报告。测试口令仅App进程通过noFollow/owner/mode/noACL/身份稳定读固定leaf，严格单个末LF、有效UTF8、1..1023B、无NUL/CR/内嵌LF。可变缓冲短作用域尽力清理，Swift/String/SwiftUI副本不承诺完全清零。

首次真实unknownMasked challenge只打开NSSecureTextField并取消，不填写/读取手动答案。原生重连要求同对象/sessionID、generation精确+1、新requestID与进程出生身份；原生securefield target/action写Binding、同步原生submit，不用直接respond或扫终端prompt代UI。connected另需fresh ACK及有限无额外挑战。CredentialAccess/SFTP/clipboard始终0。

## 静态与签名

4新puretests覆盖phase/key/closed schema、严格口令格式、真实状态所需的challenge/cancel0answers/newgen新request、connected不是shellACK和有限观察门；只用显式synthetic dummy bytes，不读真实fixture。

唯一 `python3 -B Scripts/verify-app-real-integration.py diagnostic` exit0，`diagnostic-73a685d8-4b08-4d24-a98c-f3b5adf716d8`：152tests/0failure，原148names和43Contract主体保留；49source/native160/14cmd（12log+2私有sign）通过。

main `3327e52e8162d411dbd8657bb15ce251d1091e40f1abc56039f9b45a3643ebec`，helper `7e5ae6a3c0a8e9601ebc61c2708fdb85b95c0715540b4cafa6a40043682a85ed`，manifest `81f2fee1d549f19685974ef67e492c8e6a6e077b25eb02938b27a4d0e60d632d`。Development/sameTeam/Runtime/空权限/strict及inert0-0-64主管独立核过：`DerivedData/Verification/primary-app-authui-static-d29e0fc1-9d92-4b62-97a8-da021c5a9cd7/`。

## 唯一真实案

runID `7599fc9f-b7fc-45f9-8c74-0fff3fd1d3ab`，collect/relay/App各1，无失败/重试/追加答案。App96775自然exit0/31.179s，19checks通过；显式testscan15，production scan5/connect10不改。

- 加密导入原内容/公钥匹配/无保存凭据成立，importPhraseReads1。
- first request92338A98-2F03-4BF2-9EF1-72408EFF61D8，generation1/PID96804，出生1793149917.701481；真实masked secure sheet存在，nativecancel，manualreads0/submissions0、oldgone/pendingnil/canReconnect成立。
- native手动reconnect同tab/driver/session/view/sessionID，generation2/PID96839，出生1793149931.247907，新request330FAC6E-3443-4DEC-838F-10CE65C9CE91。
- recovery manualRead1/nativeSubmit1，真实outerconnected+freshACK；2.013035s/39samples无额外挑战，原生关闭/重开不恢复/store清理通过。
- “first manualRead0”不隐瞒此前导入验证read1，报告明确区分两个读取阶段。
- SFTP/services/handles/CredentialAccess全0；不dump视图/terminal、无截图或clipboard。

原App metadata报告：`DerivedData/AppRealIntegration/Inputs/run-7599fc9f-b7fc-45f9-8c74-0fff3fd1d3ab/app-result.json`，SHA256 `ad895dbe09e22559d42d55aaf4a5f44a815482a2b8f3c7fbc00c1f002d2acc5a`。

命令/后验/40文件清单：`DerivedData/AppRealIntegration/auth-ui-cancel-live-01bb09a6-1e4b-40e0-8383-b285abe9e31c/`，manifest SHA256 `feeb3c94fd8ff8ab08682eae99a0654cad6a3f3f16dfa7f810812a6cde68c08a`。

## 资源与主管验收

App96775/relay96698/两ssh96804/96839不存在、逐PID FD0，22221～22225无listener，准确store消失/app-tmp空。relay有序exit0/8-8-0-0，无强制KILL。远端UID10000进程0、daemon21/start7980921/FD4及四服务/config/auth/known/network/volume/资源前后相同，49source/5fixture/15bundle未变。

harness和主管不读、摘要或打印私钥/口令；App stdout/stderr仅stat确认空，不读取其内容。主管独立核原19checks/typedmetadata、两请求和出生身份/严格gen变化/分阶段读取及唯一submit、40摘要（排除秘密leaf；空stdout仅stat）、当前四PID/端口/store及冻结源签名，证据：`DerivedData/Verification/primary-app-authui-pass-4026bb77-57a0-4cf7-887d-c3f98c616d4b/`。

**有限真实认证UI取消/恢复分项通过。** 不宣称无限期无额外挑战/秘密副本完全清除、保存凭据/未知MFA分类、企业或正式macOS26通过。原报告通用taskID保留，以phase/runID/authenticationUI/命令准确绑定。
