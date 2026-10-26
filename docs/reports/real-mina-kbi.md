# 真实生产客户端 KBI：双提示与零提示

Task AUTH-MINA-PRODUCTION-KBI-A / AUTH-MINA-THREE-LIVE-A。日期2026-10-26。**限定auth-only真实验证通过，不是SFTP/FILE、GUI或macOS26产品验收。**

## 真实后端与接口

MINA SSHD2.20.0固定官方输入与JAR许可，真实容器javac/库契约已通过。image`sha256:18c77956cd388408edd3141b6d96ace4fce188dd038bea0c8cbc2d4435e1d84a`、project`openlxssh-mina-4ef7485cc4e9`、CID`fd10360e492d22e69c06e5f99f71aca77b1942d7b7584bee26bb44028fe8e49e`、network`50a86aed2a1f635573211587088ae10c262ee501f4da130dc757e64f406476c7`。实际internal/no外部默认路由/nonrootUID10000/readonly/capdropALL/512MiB128pids/lognone/nohostmount有inspect与主管独立复核。

带外RSA3072主机公钥指纹 `SHA256:MMUeIg3KZTA9YYMozj0f/UICafQL12eq8shcvcoHSsU`，精确独立trustgeneration `Tests/IntegrationEnvironment/multiprompt/.runtime/trust-cdfb873cc9a1`。仅127.0.0.1:22225由共享有限opaque relay承载加密字节，实listener、公钥一致与活动bridge UID/PID/start/token/pidfd清理已有证据；不信任扫描结果来替代带外核验。

生产client调用公开 `LibSSH2FileService.connect` 与 `.keyboardInteractive` typedcallback。同一次回调传入所有prompt字节/echo，不自研SSH编码。固定fixture name/instruction精确envelope只用于24hex attempt correlation，不是通用prompt秘密分类；未知/重复/迟到拒绝。答案仅固定exactownedCID的nofollow UID10000/0600/singlelink/TTL读取→私有内存PIPE，不host答案文件、argv/env/log/Keychain。

后端故意没有SFTP subsystem。认证接受案不能凭错误退出推断：必须严格回调/回复一次＋production已认证后 `FileServiceError(transport, operation:sftp-init, code:-21)`＋服务器accepted精确+1/其他计数匹配。-21单独也可能是channel错误，**仅联合固定服务身份和服务器接受计数支持auth-only**，不宣称SFTP可用。拒绝案必须typedauthentication及服务器rejected精确+1。

## 静态与独立审查

新增test-onlyMinaConsumer/Management/Contract/Policy/Reader和7Swift测试，旧SSH/SFTP契约未扩大、产品/服务器未修改。15Swift（原8+7）/8Python（原5+3）/9CLI拒绝/纯解析通过；singleUUIDDevelopment签名build36commands、333输入快照匹配、严格helper/App固定不同identifier/同Team/Runtime/无entitlements/timestampnone通过。

精确App：`Tests/RealIntegration/.build/host-a3dedbb7-073d-46b5-95d2-d4d0e8d55322/OpenLXSSHRealIntegration.app`，主程序SHA256`d586a7e19910483f4ef244e598c98f769a5859ea019668b5b67bf6f0a3715bb8`。

主管完整读取reader/目标核验/callback锁/once budget/drain、错误三元组与status增量判定，并独立offline/333input+snapshot/实际hash和严格签名验证。证据 `DerivedData/Verification/primary-mina-consumer-9c7c8e4f-cf42-473d-8e6d-4ec9b4948c46/`。随后才放行三案各一次。

## 真实三案

| Case | 真实退出/耗时 | 客户端回调与回复 | 服务器证据 |
| --- | --- | --- | --- |
| two-correct | 0 / 21.795s | callback1，promptCounts[2]，echo[[false,true]]，reply1/responses2，管理读取1 | generated/response_callbacks各+1，accepted0→1 |
| zero-accept | 0 / 15.528s | callback1，promptCounts[0]，echo[[]]，reply1/responses0 | accepted1→2，zero_response_callbacks0→1 |
| zero-reject | 0 / 15.538s | 同真实0prompt回调/回复 | rejected0→1，zero_response_callbacks1→2 |

均lateReplyCount0、statusDeltaVerified/closeCompleted/managementChildrenReaped=true。每case实际before/after sessions/pending/schedulerqueue为0，结果明确authOnly=true/sftpSuccess=false/fileAcceptance=false/productAcceptance=false。语言字段不在生产typedAPI中，不宣称核验该字段。

实际管理命令为 `managed.sh scenario --authorized-run --relay-mode --scenario <two|zero-accept|zero-reject>`；唯一childrelay `relay --authorized-run --allow-start --relay-mode --max-duration900`，消费者 `--auth-only --live --authorized-local-fixture --engine-ready --contract <独立mina-case12hex/auth-only.json>`。没有重试、修改server、source或答案。

证据 `Tests/RealIntegration/.build/mina-three-live-115c4f82-ac96-47e3-b84e-8d38b9541851/` 含3报告/精确argv/cwd/exit/公共契约、初末status和cleanup。有限relayPID90410精确TERM/awaitexit0，accepted3/finished3/cleanup_failed0，三个exacttokenowner/目录无残留、自有Docker/relayPID消失、22225释放；child仍原CIDHealthy。

## 主管独立真实抽验

主管用新独立0700case/0600contract，精确同App/source/trust，对two-correct实际执行一次：exit0/21.770s，callback1/prompt[2]/echo[[false,true]]/reply1/responses2，管理读1，accepted2→3/generated3→4/response3→4，状态idle0，backend严格认证后SFTP不可用联合判定。未显示一次性答案。有限180srelay结束精确TERM/awaitexit0。

证据 `DerivedData/Verification/primary-mina-two-live-9873f26d-57eb-49de-aa7a-49588c74ea27/`，主管未机械重复全部三案，但实际复现关键单wire两提示行为。lateReplyCount0只是本案计数，不冒称迟到竞态压力已过。

## 真实异步审批、拒绝与等待取消

后续最小扩展只修改Mina测试消费者/策略，服务器和产品不变。固定provider delay8s，独立19Swift/9Python/原9CLI、333input/snapshot与新UUID严格签名构建主管复核通过；新App `Tests/RealIntegration/.build/host-076649ce-e3bc-4b32-b9e3-e7ed8317a02e/OpenLXSSHRealIntegration.app`，主程序SHA256`58ebe0aafccbcb994be2b7768f9972c4caf285bdc136648036e8dd990beda258`。case30/operation20不改，额外管理/归零时限另计。

三案各一次、无重试：

| 场景 | 进程耗时 | 真实结果 |
| --- | --- | --- |
| approval | 26.741s，exit0 | reply→backend8.009328s，精确认证后sftp-init/-21与approved0→1 |
| reject | 26.648s，exit0 | reply→backend8.004148s，typedauthentication与rejected1→2 |
| cancel-wait | 29.740s，exit0 | 精确pending.responded后，reply+3.119852s本地取消（>=1且<8），cancelled/authenticate/-10001，session-closed0→1 |

均callback1/prompt[0]/echo[[]]/reply1/responses0、秘密读取0、close/drain/status精确delta通过。取消后0.012425s返回，pending观测后11.101638s再次status证明跨原decisiondue且无approved增量、sessions/pending/queue为0；这不是强制迟到回调竞态。

证据 `Tests/RealIntegration/.build/mina-async-three-live-7aa0e5e0-b387-40d9-8160-cd9dc7a050ce/`。唯一600s上限relayPID94564精确TERM/awaitexit0、accepted3/finished3/cleanup_failed0，三个exacttokenowner/目录无残留、自有PID释放、childHealthy。策略按要求保留cancel8。

主管独立cancel-wait抽验另用新契约/同精确App：真实exit0、pending证明后reply+约3.108s取消、postdecisionstatusVerified=true、服务器session-closed1→2且无批准，自己的180s有限relayTERM/await0。证据 `DerivedData/Verification/primary-mina-cancel-live-ef695c18-f888-448e-84c4-ea0e83321ad7/`，未重复全部审批三案。

## 未完成

受控MINA真实双prompt/zero/8s审批接受拒绝/等待取消已有核心证据，但真正企业审批、并发/强制late-result竞态、TTL75s与系统OpenSSH侧多轮及四类组合认证仍须另验。macOS26/GUI/人工未因此通过；auth-only不可替代FILE或完整AUTH验收。
