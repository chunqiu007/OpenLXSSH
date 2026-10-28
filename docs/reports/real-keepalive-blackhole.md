# SSH 保活：正常对照、原黑洞失败与 R2 实测

日期2026-10-28，Tasks `KEEPALIVE-BLACKHOLE-PREP-A`、`KEEPALIVE-CONSUMER-BUILD-A`、`KEEPALIVE-REAL-CAMPAIGN-A`、`KEEPALIVE-CLOCK-R2`、`KEEPALIVE-BLACKHOLE-R2-LIVE`。

**主管独立接受有限host15/ServerAliveInterval2、CountMax2的正常与黑洞分项：A安静12秒保持真实连接后fresh ACK/自然exit0；修复后的B在TCP仍建立、后端仍活着、代理不提前关闭的DROP条件下SSH自行exit255，消费者正常清理。** 原B控制时钟失败与SIGKILL -9始终保留，不追认；不代表macOS26、全部网络故障或长期稳定性通过。

## 独立测试边界

新增 `Tests/KeepaliveAcceptance/`，不改生产App/packages、旧IntegrationEnvironment relay、容器配置/hostkey或系统网络。

- Swift公开DirectSSHSession消费者使用系统OpenSSH/PTY/SwiftTerm，固定plain key、无SFTP/Keychain/回答API，配置2/2。可信outerauth后另需不由回显伪造的short shell ACK。
- A独立relay进程使用冻结旧pump；至少12秒无应用输入/输出，同token/PID，随后另一个确定不同nonce的fresh ACK和自然exit0。
- B独立relay所有accepted连接先小型bounded FORWARD，不依accept顺序。私有继承FIFO管理管道与SSH字节严格分离；supervisor验证owned SSH的UID/PPID/PID出生身份、lsof唯一ESTABLISHED loopback tuple/sourceport，精确匹配relay连接token后才能arm。
- 同一worker在arm边界核TCP/bridge、清空并计数实际最多64KiB/方向队列、原子切DROP；之后只read/discard，不写、不主动FIN/RST/half-close，不记录payload或解析加密SSH消息。
- 先行backend EOF、代理IO错误、cancel/deadline、仅exit255或残留成功字段都不能通过。消费者先报告真实自然结果再关闭；15秒上限从同supervisor时钟arm请求发送至自然结果收到，事后管理/清理另判。
- 读取精确远端bridge owner receipt/pidfd/start/UID证明同一后端活至结果；不读取私钥/口令或其摘要/长度。控制消息闭合、重复/错role/run/字段类型拒绝。

## 源审、离线和签名

主管全读11初始源关键路径，提出Python3.9注解、EOF/drain、arm真实时点、时钟来源、StopFlag、strict控制帧、source/App冻结等问题并复核；R1修自然结果终点不混事后清理、nonce必不同。13Python pure和完整Swift/C typecheck过，首次Swift .3/.2语法失败保留。新OfflineMain执行83项实际Swift decoder/nonce断言。

唯一增量构建复用89033精确9只读对象，仅own3 Swift compile及identity.c。39命令（38log+1私有App签名）符合expected，14输入快照、原helper完整复制不重签。App sameTeamDevelopment/Hardened Runtime/空权限/deep strict；identity工具仅独立本地只读元数据程序ad-hoc，不作为认证IPC身份fallback。

App：`Tests/KeepaliveAcceptance/.build/host-d1854c48-bba2-459b-957d-d92175a4ef77/OpenLXSSHKeepalive.app`。

- main `2aace47cbc993675c84799f923007cba6cc53a44e0c1359aefb8db22f9127348`
- helper `b7d48e6a209c256c54b603247f5ed406b536daacd6e9525d6f9d59330e426f4e`
- identity `4fedce929b9f4d5951c5efe5de85730a62f00ba11cc7e3bffa4421d8b245e1e2`
- signed-static freeze `5679da9bd0240797fd09fa79ace5335b074cbec052b8585c685fba45472ad9c1`

主管独立13pure及83Swift、source/object/snapshot/Appfile/signature复核：`DerivedData/Verification/primary-keepalive-r1-50cdcce7-7665-4da8-832f-7834140a8c8d/`、`primary-keepalive-signed-77fdc130-03f0-464d-9432-826951a5800b/`。

## 首campaign：A通过，B失败（不改写）

`Tests/KeepaliveAcceptance/.runtime/campaign-b43232dfb84c467da6528fdf8c168834/`；freshcollect1、A/B relay/consumer各1。前置复用旧guard的binary basename错误发生于collect/consumer0，只ignored前置修复与独立目录续行，原失败保留。

A：12.000103秒/225samples、无应用输出、same token/PID、freshACK、自然disconnected0、closed/PIDgone/FD回基线，consumer/relay自然exit0。原normal-result SHA256 `ff0542b43ec30a399b4f6ef3477ba181af1d89135ee2800c4d80d8ed1b08bd83`。

B：精确绑定及实际arm DROP成立，discard[1384,0]/TCP established/remote bridge pidfdalive，但consumer immediately control failure，未取得自然255。supervisor错误把自身Python monotonic填作relayNow；本机Python3.9跨进程origin不同，实际混差31.691524s，与consumer时钟一致性门冲突。arm请求→失败帧3.169458s不是保活超时。失败路径未给consumer result ACK，外层TERM后10秒太早KILL，consumer exit-9，不能声称自然PTY reaper通过。

原blackhole-result SHA256 `d884ac073d3c67fb2466f17cb35f0cfadbd12ac6d2ce110854e4e1945433ead6`；52文件清单SHA `752cc84ec7920bb88bb36c61e7010afd46bc620973dcf56ae485e6d35b501e27`。主管独立读原A/B/52hash、实际时钟算术与9个当前PID/端口后验，`DerivedData/Verification/primary-keepalive-first-partial-812bfdf2-6de2-4168-94aa-256a5dd271fe/`。

资源后验9本地PID均absent/FD0/端口空、远端UID10000进程0/fixture不变。A bridge目录gone，B仅cancelled tombstone无owner，保留不删。准确两run根按heldFD/inode/闭合节点清，A typedresult先保存。后验不存在不追认B自然清理。

## R2精确修复

只改relay_control.py、supervise.py、test_static.py：relay worker自己给出relayNow/Wall，supervisor原样转发，自己的发送/接收时刻单列；不放宽0.2秒一致性或15秒门。失败case-result也尽力ACK让consumer自有close/exit1，控制断裂再完整30秒gentle预算后KILL，失败仍失败。

B-only门绑定旧A精确SHA、2/2通过/无强杀、原52清理证明、Main/Core/LiveInput及已签consumer二进制不变，只接受新nonce/新collect/preflight/审批；不重A。

17Python pure（原13保留）/完整SwiftC typecheck通过，最初新fake wait序列少值的StopIteration仅修fake次数不降断言。freeze-r2 SHA `f9b2a98549f0c236896839f0ad789dd078d486e5fd2424253f2643c644cbf55a`。主管实际diff和17pure独立过：`DerivedData/Verification/primary-keepalive-clock-r2-897410b6-0a33-4b0a-a562-c5744bbbdab2/`。Swift consumer未变，未重构建或重签。

## 唯一R2 B-only成功案

run `f2dff116ffd048848b9a4eaec0e1776e`，目录 `Tests/KeepaliveAcceptance/.runtime/campaign-bd6bf5a7d5f5420a87f8c65865655d37/`。freshcollect/Brelay/Bconsumer/arm各1，A重跑0。新审批独立目录不覆盖旧receipt。

- 实际SSH3737自然exit255，公开Session映射failed(.launchFailed)，不是新造专用keepalive错误。
- DROP→exit2.568177s；保守arm请求→自然结果帧5.682587s≤15。relay自身时钟与consumer差值0.000010006s<0.2。
- arm真实discard[2176,0]，随后drop[52,0]。arm/结果forwarded均[4101,4511]，无继续转发；bufferpeak[2176,1532]。
- 9个TCP快照，firstEOF client25.078245875，晚于arm22.531416，backend EOF为空，halfClosed[false,false]；无IO/cancel/deadline先行。
- remoteBridge arm/result同PID33698/start13258422/pidfdalive，未提前断开后端来制造退出。
- consumer3709/relay3701自然exit0，无TERM/KILL；closed/PIDgone/FD回基线。

原B结果SHA `3de33b6f5e2e1f4bedc6ccecf6792f94957797d37b7637706cc70079ad874cf2`；50文件清单SHA `af1c768c4293d09a483608584c157a692681a8ea9b1da8bbd47d244af9f0a1c0`。

supervisor3700/relay3701/consumer3709/SSH3737/bridgeCLI3748均不存在、FD0，批准端口空。typedconsumer result先保存再精确清本轮run根/sessions空；远端bridge pidfd已不存在、token仅cancelled无owner/tombstone保留。四fixture完整前后相同/UID进程0，R2source13/9objects/App全文件/旧receipt/原52证据未变；stderr只stat空，无秘密读取。

主管独立读取A原通过+B原失败+R2原结果、全部50及原52摘要，逐核时间/计数/EOF/bridge因果门与当前5PID/端口/source/App：`DerivedData/Verification/primary-keepalive-r2-pass-bd65b34c-699e-404c-9b56-ba55a662eed5/`。

**有限host15正常保活/黑洞失联检测分项通过。** 不精确解析/计数加密ServerAlive消息，不把2.568秒当所有初始相位固定超时，不代表macOS26、所有网络、AppUI专用错误提示或24小时。原B控制失败/强杀仍PARTIAL历史，整体Goal未完成。
