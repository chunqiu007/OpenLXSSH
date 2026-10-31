# App Native MFA — two fixed real cases

日期：2026-10-31。**两类真实App MFA认证、终端与挑战清理成立；两案整体均failed cleanup，未UX_READY_FOR_USER。** 不是GUI点击/像素验收，默认仍为Direct。

## 实现与审查

- 独立闭合MFA Arguments/wrapper/material仅允许已批准key-kbd/22223与password-kbd/22224，固定完整CID/FP/base/image/project/network/context/endpoint。旧keyonly及M1 Contract 52,595字节、旧30测试方法前缀保持，不修改历史pins。
- 同run固定公开policy proof记录主管实际带外核验，digest/fresh/buildEpoch及身份精确校验；字段明确externalPolicyProofValidated，不冒consumer实时inspect。
- key路径为Security管理副本+标准requestSession；password路径为manualhost+本次intent prepare/commit。KI按exact tab/host/token/generation/request绑定，前三轮各读取一次8位一次性答案，最后明确Controller `.answers([])`，不扫描终端、不复用主密码。
- HOST_PROBE管理owner复用成熟ap_tool与固定root reader、typed response/session-state argv，私有有界PIPE、单次≤10秒且受原剩余期限限制，stderr丢弃；不打印/哈希/外传秘密。
- auth-only与挑战cleanup-only收据分别写入；挑战状态最多一次只读核验，不删除服务端文件、不等TTL消绿。weak/FD和自然退出仍按原硬门。

独立管理静态审查未见HIGH/MED问题。主管发现cleanup吞Task.sleep取消可能空转；准确红例1测试2断言失败、6097探测，最小修为取消观察返回false，同一测试字节绿1/0，不取消管理owner、不伪reap。

## 本地验证

证据`DerivedData/UXVerification/AppMFA-M2-Verify/`：Debug71/0、HostProbe76/0、Python14/0，26件Mach-O均arm64/min26；Debug新入口及混合参数早拒、Host/Python inert门通过。最大三份FD快照+宽MFA失败收据16,092B≤原16,384B，没有提高预算。主管独立MFA13+密码12+旧18=**43/0**。未运行受occlusion限制的R9/中键。

## 冻结候选

`DerivedData/UXVerification/AppMFA-M2-Live/OpenLXSSH.app`，mainSHA`7616d2297e7afd76039874d4e224cea2eb34c77e427f42d821365b0f8be317f7`，helperSHA`4083e7c28511ebc274d2afb26e679d6dc5c2c2d169ba213d81a51518083f9f57`。既有Development仅离线timestampnone，helper/main固定ID strict验证，无Apple请求。

## 两案真实结果

| 真实事实 | 私钥＋KI | 本次密码＋KI |
| --- | --- | --- |
| runID | 2ae509f0-840f-45d5-83d7-5084e247d54a | 66385b88-84e9-42ea-8f97-7766ec90ac9a |
| App PID | 6388 | 6826 |
| typed primary | publicKey一次，code−19，当时未authenticated | password一次，code−18，当时未authenticated |
| KI | start/result各1、code0、真实authenticated/shellReady各1 | 同左 |
| 四轮字段/echo | [1,1,1,0]／[[false],[false],[false],[]] | 同左 |
| OTP read／secret reply／zero reply／late | 3／3／1／0 | 3／3／1／0 |
| credential owner | 0 | 0 |
| 本次intent | 不适用 | prepare零tab/连接且未消费，commit1/tab1/消费一次 |
| terminal | ACK/PTy/DONE、远端37×113、exit7 | 同左 |
| 原生close | closed/canonicaldrain/Driver队列空/registry0 | 同左 |
| server challenge cleanup | 只读status1，removed | 同左 |
| management owner | calls4/returned4/successfullyReaped4/pending0 | 同左 |
| 整案失败阶段 | weakWait，tab/driver/view仍alive | descriptorWait，三weak已nil，FD19→22 |
| App退出 | 自然exit0、无signal，整案仍failed | 同左 |

不把−18/−19称为公开partial-success；EOF仍标不可直接观测。known-host终核未到不表示文件变化。相同功能分项通过不覆盖资源失败。

第二案首次尝试遇原180秒relay到期，启动前即拒绝，未collect/未启动App，记录保留为PasswordKI-1；独立新180秒relay、fresh材料后才执行PasswordKI-2。两个relay均自然exit0，分别204.723013/204.808953秒（含预检），各accepted1/finished1/rejected0/cleanup_failed0，无signals；主管核批准端口free。

公开收据位于`AppMFA-M2-Live/{KeyKI-1,PasswordKI-2}/public-receipts/`。每案只由消费者内存读取一次性秘密，主管仅核公开policy/provenance/known_hosts/公钥。

## 剩余

真实App weak/FD资源根因仍未解决；首次信任三按钮的真实用户行为、once/persistent跨连接、changed、并发取消、SFTP新双栏实网及像素/键鼠验收仍待。此次不宣布COMPLETE、不切默认、不推送、不Apple上传、不重长测。
