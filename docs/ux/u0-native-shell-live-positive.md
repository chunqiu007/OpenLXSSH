# U0 NativeShell 四个隔离正向场景：真实验证

日期：2026-10-30。结论：**成熟libssh2候选四组同连接shell/PTY/resize/退出正向分项通过**；不是新版App认证UI/完整后端替换验收，负例/TUI/保活与资源趋势仍待。

## 来源与授权

仅已有获批Docker隔离fixture，四服务在运行且healthy，未重建/重启/更改配置。入口为`fixture.sh inspect --authorized-run`，现有wrapper分别collect到四个新的ignored0700/0600一次性generation；主管没有打印/Read私钥、密码、phrase或OTP内容，只有精确消费者在内存使用。

构建：`Experiments/UXNativeShellProbe/.build/live-b4937147-96ff-4862-8350-42884897b210/artifacts/UXNativeShellProbe`，arm64/min26，SHA256 `702f7f55348b5149b5bcfe87c95d6d2ec54734e250a7f5b435b7a52691575654`。主管在执行前核222个原公开输入及不可变快照摘要与构建record一致。链接器正常adhoc平台签名，无helper/同Team gate或Apple操作。

新消费者源经主管实际Read审查：fixedfixture不可自定义endpoint，显式三flags+marked合同，先context/container/image/network/policy核验再noFollow/ACL/UID/mode/link及heldFD稳定读取selectedgeneration，固定test-onlychallenge预算复用成熟管理reader，不将固定shape当生产OTP分类。旧SFTPAuthContract仅严格材料schema，新result是U0-NATIVE-SHELL-LIVE-A，不复用旧SFTP green。

## 真实步骤与判定

- 主会话启动既有有限不解密回环relay：`fixture.sh relay --authorized-run --max-duration 1800`，仅22221～24，非产品转发。
- 每案串行一调用`UXNativeShellProbe --live --authorized-local-fixture --engine-ready --contract <exact marked own case>`，外层200秒，不扩原内部active45/drain12/full85，不改LoginGrace/OTP TTL/系统时钟。
- 同一个私有socket真实hostkey校验→typed primary一次→必要KI一次→真实session channel/PTy/shell返回。连接后才显式发有限公开测试命令，随机nonce拆分构造，命令回显不含完整ACK；`test -t 0`、实际resize后`stty size`、`exit 7`、EOF/exit与awaitclose均要求。

| 固定场景 | 实际时长 | 认证事实 | 新shell证据 |
| --- | ---: | --- | --- |
| keyonly:22221 | 12.553s | primary publickey1/code0/actualauthenticated1，KI0 | ACK/PTy/37×113/EOF/exit7/close全true |
| passwordonly:22222 | 12.724s | typed password1/code0/actualauthenticated1，KI0 | 同上全true |
| key-kbd:22223 | 24.994s | publickey1/code-19/当时未完整authenticated；KI1/code0后authenticated1；3 secret replies+1 empty通知 | 同上全true |
| password-kbd:22224 | 25.095s | password1/code-18/当时未完整authenticated；KI1/code0后authenticated1；3 secret replies+1 empty通知 | 同上全true |

四案均sessionAttempts=1、shellReady=1、lateReply=0，MFA管理response reads3且serverSessionFileRemoved=true、childrenReaped/closeCompleted=true；无保存OTP。-18/-19不被解释为公开可靠partial标记，最终shellReady+ACK才证明完成，不用零退出猜成功。

## 资源与原始证据

根：`DerivedData/UXVerification/U0-NativeShell/live/`。

- 每案`<service>-1-run.json`真实command/exit/duration，`<service>-1.log`仅结构化脱敏结果，无终端全文/secret；`positive-contracts.json`公开身份/路径引用，未含secret。
- 主管独立重算四JSON全部必要字段与MFA计数后写`primary-four-positive-review.json`，未把exit0当唯一判定。
- relay14355严格检查同UID、argv/所属路径后TERM；外层exit0，`relay.log`记录accepted4/finished4/rejected0/cleanup_failed0。主管另ps确认14355gone、22221～25无listener。未用广扫kill/删除fixture，健康container保留。

## 下一门与限制

1. wrong password、hostkey mismatch、unknown KI不回填长期密码、认证/ready后取消等有限负例尚待新probe合同与实测。
2. encryptedEd/RSA、真实Vim/tmux/htop、输出/背压、正式App owner代次/一次性editor intent、并发认证隔离仍需候选新版本验证；旧SystemOpenSSH分项不冒新候选证据。
3. candidate无ServerAliveCount等价策略，保活/liveness不能悄悄退化；需ADR与明确真实黑洞证据或其他成熟实现。未定案替换系统OpenSSH。
4. 三按钮首次信任与once模式尚未UI/本次真实握手覆盖；候选本轮使用自己临时测试store里已带外核的持久key，不修改用户/系统known_hosts。
5. ASan/TSan discovery环境未过维持记录，不冒零泄漏；本案只有有限明确awaitclose/relay清理，不全对象/FD趋势普查。

无生产、真实凭据、Keychain、Apple上传/时间戳、最终分发包、新环境或24h/2GiB重跑。继续U2～U6，不提交UX_READY_FOR_USER。
