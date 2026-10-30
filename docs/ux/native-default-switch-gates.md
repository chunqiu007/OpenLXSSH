# 后端候选：正式切换前仍需满足的门

日期：2026-10-30。**设计/验收清单，不是替换决定。** 当前默认仍为DirectSessionBuilder；Native只在显式本次密码路径作为internal候选。用户允许有实证和ADR的核心候选调整，不需要重新询问产品范围。

## 已有证据与不能外推的范围

- 固定成熟libssh2/OpenSSL，同socket实际hostkey与typedprimary，必要时distinct manual KI；四组合、加密Ed/RSA有限真实分项已有。
- 新Appadapter正式107/0、主管39/0，单pull/input准入/resize合并、保存后preparedcommit、三按钮/owner模型可用；不是App真实网络和全部终端。
- normal/MaxSessions/严格DROP有限门分别通过，DROP5.917秒且真实arm年龄最坏0.109秒；不是所有服务器或高输出下调度。
- 当前Native liveness=nil，没有把用户已有keepalive设置应用；默认Direct仍保持原OpenSSH策略。

## 必须按顺序解决的缺口

1. Package typed changed事实、sealed canonical drain handle；App有限close/retirement与同tab重连fence。不能以永久unavailableRegistryDrain阻塞全局退出，也不能以超时假称排空。
2. 新版本一次性密码、两主方式+manualKI、once/persistent/changed、取消/并发A/B与精确释放真实App消费门。
3. 保活迁移与范围：App/SSHSessionConfiguration当前interval0…3600、count1…10，NativeShellLivenessCandidate当前interval≤300且interval×count≤300。不得静默clamp、忽略旧值或遇旧合法设置才报模糊认证错；需要明确兼容实现/范围与测试。
4. 非等价语义记录：Native单pending辅助session open连续timeout窗口不是N个OpenSSH ServerAlive；会短占远端MaxSessions与产生审计/限流。interval0需真正关闭；有效输出只能推迟idleprobe，不能重置pendingdeadline。
5. 有限输入/resize/输出/TUI负载同时开启活性，保证唯一queue/outbound EAGAIN恢复、终端可取消、资源无无界增长。不是重跑24h/2GiB/1000文件。
6. 真终端短验：保历史、naturalexit/重连换代、复制/两次真实CmdV、UTF8/Bracketed、Ctrl键/resize、Vim/tmux/htop有限门。IME/实体布局/用户双机仍按人工边界。
7. 正式min26 Debug候选、必要Release本地构建与依赖许可证/签名打包边界；体验确认前不做新最终分发包/Apple公证或时间戳。

## 保活兼容的最小实现建议（只读调查，尚未实施）

`NATIVE-LIVENESS-COMPAT-READ-R1` 已完成，无修改/构建/网络：

- 原合法主机配置 interval0…3600/count1…10 必须原样映射；0明确为nil，正值不clamp。可保留候选API名称，将policy范围扩到interval3600、response window36000秒，同时保持现有小数interval/count≤100的源兼容；不扩大网络operation/authentication预算。
- 不能只改Swift参数校验：现packet watchdog公式可能得到36002秒，须一起核C setter和成熟libssh2公开API允许范围，确保长policy不会被更短packet timeout误截断。
- 当前pump先检查取消/deadline，有pendingOutbound只续原API；否则轮换起点遍历write/control/read/probe各一步，活跃5ms/空闲25ms。没有无限饥饿的静态证据，但也不能凭轮转外推真实高负载时延；control任意EAGAIN更保守锁住队列，不能通过交错另一个outbound“提高优先级”。
- 需要精确App options捕获覆盖0…3600/count1…10、虚拟时钟36000秒边界、pending输出不延期、实际pump的脚本化IN/OUT EAGAIN与稳定参数、饱和输入/输出/resize的取消和准入门。
- 有限真实门应区分长配置shellReady后立即关闭、混合负载活性、pending时仍有输出、MaxSessions拒绝和严格DROP。旧五真实认证门及旧R4不自动覆盖新版本；不等十小时、不重长测。

## ADR应写出的决定

- 证据支持为何旧Askpass不足以给未知KI安全自动主秘密，以及typedprimary为何更可靠。
- 对保活/错误/资源所有权/无childPID/任务退役/known_hosts唯一真源的变化、兼容与已知限制。
- 最终默认builder替换具体提交与候选来源；候选通过不自动等于已切换。
- 没通过的门、用户需真实体验的位置和仍待像素验收；不能因编译成功将116项批量改绿。

不扫描终端提示投秘密、不从内层SSH/sudo自动读取凭据，不忽略主机密钥变化、不新增环境、不连接生产、不push。
