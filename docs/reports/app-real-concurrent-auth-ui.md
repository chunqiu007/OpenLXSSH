# 双加密私钥请求：真实原生认证 UI 归属

日期2026-10-28，Task `APP-REAL-CONCURRENT-AUTH-UI-PREP-A` / `LIVE-A`。

**唯一fresh案经主管独立通过：两真实masked请求同tick pending，原生取消A后B原请求/进程不变；仅向B原生提交一次并取得shell ACK，A不复活，双会话与资源清理通过。** 同一managed encrypted key/同一测试口令，只证明两个独立原生请求的UI归属和取消隔离，不外推不同秘密所有串用排列、多轮MFA UI或正式macOS26。

## 窄实现与安全

只App四测试接线文件新增closedphase `concurrent-auth-ui`、独立133行helper及typedmetadata Gate。复用已审加密导入、公有材料、固定phrase读取，只将closed allowlist扩到两个authphase；其他phase仍plain/noauth门。生产packages、控件、fixture/MFA cap、依赖和schema不改，旧finitehelpers逐字保留。

同MainActor同步块核两份真实request/token/session/PID出生身份/state/零manual-submit计数共存；原生选择A并打开空NSSecureTextField sheet后取消。A实际断开/PIDgone/pendingnil/canReconnect全过程只读核B原请求仍pending；再原生选择B，安全field target/action同步submit一次，无await持秘密在field、不回读秘密值。B原身份/代次outerconnected＋fresh AS1 ACK，A仍gen1/noPID/disconnected，再原生关闭B/A和通用窗口重开/store清理。

App导入验证读phrase1，Amanual0/submit0，Bmanual1/submit1；只App进程读秘密，harness和主管不读/摘要/打印私钥/phrase及长度，无UI dump/terminal快照/截图或clipboard/Keychain。可变buffer尽力清，Swift/UI副本不承诺完全零化。

## 静态与签名

4个新增聚焦测试，原156passed names全部实跑保留、51旧Contract主体不改，总160tests/0failure。唯一 `python3 -B Scripts/verify-app-real-integration.py diagnostic` exit0：`diagnostic-376de058-dddb-4d4c-9006-5e4bc3dcb303`，49inputs/native160/14cmd（12logs+2私有sign）符合expected，inert0-0-64。

main `c5582ea6919cb49db19308aaa70d2ef7be3b8a349a70ac5f9737e27cb252db14`，helper `b0f8254700be0230a486be24f25f1815b7eccd91af02d66e12dd810ab6bac315`；result SHA `39ffa6d5569825bb1f619b8705dd35e3f5b3b6d8eeabd8db29fd0487f9ccac46`。

主管完整源审Gate/barrier/两sheet/action/取消后不变与secret出口，并独立160/原156保留/49currenthash/Development同Team/Runtime/空权限/strict/inert，证据：`DerivedData/Verification/primary-app-concurrent-auth-static-62b82b03-e9f1-429d-a3fb-2f2dd2d4e91d/`。

## 唯一真实结果

runID `d252b333-a418-4371-8667-5139700c60a6`，collect/relay/App各1，未失败重试或追加答案。App6533自然exit0/29.7263秒，21checks全部通过；testscan15，production scan5/connect10不改。

- A PID6559/出生1793161349.715735，sessionD0C7CE0B-A368-4FA3-84DB-DE21B551884C，requestDE196AC2-8D18-428A-A808-C9306B7D8D99。
- B PID6594/出生1793161362.364900，session8D521BD9-8C16-4A12-99C0-FB5324FAB135，request8F570BB1-9048-428F-9D0D-3FEEB655FE0A。
- 两gen1/父PID6533/stateauthenticating/unknownMasked，barrier时两requestMatchesToken、零manual-submit。
- A原生empty sheet取消后实际disconnectedNil/pending与PID清/可重连，B request/token/birth完全同barrier仍pending。
- B仅一次原生target/action-submit、原gen1/PIDouterconnected+freshACK；A仍原gen1/disconnected/noPID/pendingnil。
- import1/Amanual0-Asubmit0/Bmanual1-Bsubmit1，SFTP/credential/handles0、双driverclosed/关闭重开不恢复/store清理。

relay6438由既有runner对自有PID发送TERM后exit0，未KILL，8accepted8finished0rejected0cleanupfailed；**不是自然退出**。App无TERM/KILL。原报告：`DerivedData/AppRealIntegration/Inputs/run-d252b333-a418-4371-8667-5139700c60a6/app-result.json`，SHA `50106f0e496901ed78bb27d46c6be882e649f8fd408b5c2954380a2cc38368c0`。

命令/资源/39公开证据：`DerivedData/AppRealIntegration/concurrent-auth-live-bf5ded21-fc56-4523-bd1d-2905c75ed15c/`，manifest SHA `79395f2d4357c5556ffb5c616201ccdfbc597d0694fababad78e0a7ca85bc2e5`。

## 资源与结论

6533/6438/6559/6594均不存在、逐PID FD0，22221～22225无listener、准确storegone/app-tmp空；fixture四容器前后相同/daemon21-start7980921-FD4/caps0x200400eb/UID10000进程空、FP/config/auth/known一致。49source/5fixture/15bundle不变。App输出仅stat空，不读日志内容。

主管独立读取原21checks/三阶段typedmetadata/identity关系/实际counts、全部39hash（秘密leaf拒绝、空日志仅stat）和当前四PID/端口/store/源签名，证据：`DerivedData/Verification/primary-app-concurrent-auth-pass-4f158532-30d2-4a14-a7d6-66be62ca2c9c/`。

**有限真实并发认证UI归属通过。** 不改原双MFA API取消材料卫生整案PARTIAL，不拿本案补写旧自动清理；正式mac26、企业、不同秘密矩阵及全多轮UI仍按验收总表，整体Goal未完成。
