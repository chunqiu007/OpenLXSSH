# 真实公钥嵌套 SSH：独立一次性密钥与精确管理恢复

日期2026-10-28，Task NEST-INTEGRATED-PREP-A / BUILD-A / LIVE-A / NEST-RELAY-READY-R1-LIVE-A。**新R1唯一案完成真实内层系统SSH、公钥认证、12帧交互/控制键/尺寸/Vim文档SHA及返回outer；原授权文件、信任、配置和daemon保持原baseline，临时key/source/receipt精确清理。仅NESTrealpublickeyonly，不覆盖人工内层密码/OTP或公司环境。**

## 边界与安全设计

keyonly UID10000原本不能读取root-owned客户端私钥，不能复制App/root密钥来凑嵌套成功。新增 `Tests/NestedSSHAcceptance/` 测试区域，remote UID10000用成熟 `/usr/bin/ssh-keygen` 生成distinct无口令一次性Ed25519 key；root管理进程只检查private元数据、不读取其值，仅导出和验证新public line。旧outerfreshcollect仍是已授权容器→本机私有fixturegeneration认证通道，没有将outer旧私钥复制给inner。

root持FD/flock、固定CID/currentFP及开始/结束global-idle强排他；只对root0644/nlink1的原4行public authorized_keys核完整bytes/dev/inode/UID/mode/mtime/ctime，exclusive0600 prepared receipt先file+dir fsync/readback，再原位append精确新public suffix并回读，之后才READY。hash/flock不是对任意外部写入的原子CAS，排他条件明确。恢复只能原FD/inode/完整expectedappendedbytes、receipt绑定与所有用户/sshd子进程已结束时，截去自己的已核suffix；未知修改拒绝保留。

嵌套wrapper约20482B，嵌入已过a21 inner probe，固定os.execv系统ssh argv：127.0.0.1:2222/fixture/noncekey、BatchMode/publickey-only、strict本实例homeknownhosts、禁agent/forwarding/ProxyJump。outer DirectSSHSession只负责原连接，普通终端不匹配Password或送App秘密。inner probe不发送returned；原outer shell在nested ssh退出后才发returned0，避免将inner退出ACK误作返回outer。

单stdio controller有限240s、host总360/cleanup30/consumer180，root source只临时public staging无hostbind/新服务端口。FINISHED恢复auth→keycleanup→ownerclose，host fsync导出public receipts后ACK才清已知staging/receipt目录；unsafe EOF保公开恢复线索、不宽kill/unlink。

## 离线与签名验收

主管逐阶段读pure规则/rootFD+proc/keyledger/manager/wrapper/build/host/bootstrap/recovery关键全部源码，独立8→31→50→61→75→87项离线回归通过，后新binding总88。测试覆盖nofollow/link/inode替换/foreign append/partialwrite/fsync失败/flock/exactreceipt/同runrestore、initial-empty不能ready、异常EOF与全局idle约束。测试不冒真实Linux行为。

- root31：`DerivedData/Verification/primary-nest-root-offline-962d640b-344b-4789-98c3-8ded9ae997f8/`
- keyledger50：`DerivedData/Verification/primary-nest-key-ledger-6e72b9e1-040a-4b27-a6ea-2e44a97aea1b/`
- 集成61：`DerivedData/Verification/primary-nest-integrated-offline-4ef9ea8a-6f49-4c6c-a51f-9c636ab7314b/`
- host75与R1/recovery87：`DerivedData/Verification/primary-nest-host-offline-d11110d0-4131-447f-941c-fe38d2b07972/`、`primary-nest-relay-r1-7c625403-0545-4f5f-aa90-960d0f251b7a/`

复用正式已审89033测试消费者Core+8依赖共9对象，只compile冻结Main/LiveInput+新BuildLocation，无dependency/fullbuild/解锁软件。54只读输入前后相同，21cmd全部0，strict Development/sameTeam/Runtime/emptyentitlements，actualwrapperBase64在签名binary。正式产品min26不变，测试min15。

## 首案失败与精确恢复（保留）

原d801 nonce d8bbe17ac7f749158014c2505bf0ba74/946c真实案exit2：管理keygen/publicappend/READY成功，relay30s未ready，App0/无nestedframes。EOF补偿实际恢复auth hash并删除新key/lock，无活动用户/SSH/端口；publicsource9文件与receipt5文件因无ACK按设计保留。原失败和未运行部分不补绿。

R1只修外层顺序：固定desktop-linux、先relay READY≤125s再准备授权，追加前至少余250s、relay有限360s、记录真实relayexit/闭合错误。context固定是防漂移，不宣称旧失败确因默认context；实际新案relay耗36.873s支持原30s不足。显式固定946c公开恢复脚本全14bytes/hash/inode/UIDmode/原auth-trust-config-master/globalidle核后，唯一一次删除14文件/2空目录，旧证据不动。

恢复证据 `Tests/NestedSSHAcceptance/.runtime/public-recovery-9becd6e25e9b48cc9c7455f90910ac4a/`。之后新UUID build/newkeynonce，不重用旧nonce。旧recovery脚本保持固定旧nonce并拒新bundle。

## 新R1唯一真实成功

- Case：`Tests/NestedSSHAcceptance/.runtime/live-f6394968bf8743af9ab4cb09e00666b8/`
- Key nonce：e6ef3df244f4448f81d810592f3b6e03；relay READY36.873s，追加前剩283.150s。
- 新App：`Tests/NestedSSHAcceptance/.build/host-a4e5f93e-87d3-4402-b270-036873a5a753/OpenLXSSHRemoteTerminal.app`。
- mainSHA256 `b133434ea67e8e26c924d813ae8689a976dea4699987a57af6ec1613f359024c`；helper `162e4125500b089d190a9e6ecce5c32e2fd5484198c0138aae1a5bc729d02baa`；plan `41ecda1b8d5955e67243b123712ef9673a403779cc8f196f75a0be8cc3f117f1`。
- 固定keyonly CID1253a295…/FP MHUel445…；actualinner probe PID11765。
- case exit0/live_passed=true，consumer strict12；shellACK/probePID/inputSHA/CtrlC/size/VimSHA/termios/remoteCleanup/done/returned0/returnedToOuter均过，connected1/auth0/postConnectedAuth0。
- nativeclosed/PIDnil/FDreturn；relayexit0/4accepted4finished/0rejected0cleanupfailed/无活动连接。

FINISHED恢复authorized_keys原SHA256 `e1446ceb1b05243bf40db4eab4eb482cef084f0fb170fb7d705087e170afe0ae`；knownhosts `a8a54b0d6e9968d9d788e9f023e2beb8dbacba83704e15bdba5b5476175cf9cc`、config `0e1b32cfda7e0f60ae521dbc66a5a9a9f1db6e003f5290db5f857ac710e98616`、daemon[21,7980921]精确同baseline。新key/source-stage/receipt-dir/lock均不存在，globalidle无UID10000/SSH/SFTP；本机native/helper/dockerCLI空，outer72631/relay72522已结束、内probe11765不存在、批准端口无listener，本次outergeneration eceaad609829已精确清。

主管独立读原case/consumer12/FINISHED与STAGING-CLEANED/baseline、readonlyaudit、实际PID不存在：`DerivedData/Verification/primary-nested-pubkey-pass-c6b11fd1-17dd-48d5-8b7b-612475ebb1ea/`。新bundle复核：`primary-nest-relay-r1-signed-35eab06c-8634-4a9c-843d-f24d8ec406b8/`。第一次全currentinput检查拒绝已明确记录的三个postbuild runner重绑定文件，随后原snapshots/全部LOCAL8/只此known三变化及实际编译输入再核通过，未接受未知变化。

## 覆盖限制

冻结consumer旧schema `nestedAuthenticationTested=false`保留，NEST身份由新App内wrapper、workplan、管理receipt和真实执行绑定，不改旧raw字段。此分项不等完整NEST01–04：人工内层密码/OTP/审批、公司策略、IME/像素/macOS26/全部TUI仍待。没有自动ProxyJump、多级跳板管理或经跳板图形SFTP实现。

整体Goal NOT COMPLETE。
