# AUTH 真实单消息多提示测试后端：固定版源码依据

## 结论与边界

选定 **Apache MINA SSHD 2.20.0** 作为未来隔离认证 fixture 的成熟候选，只用于测试，不进入 App，不将 JVM 变成产品运行依赖。本轮为公开固定版源码/许可研究，未下载执行 JAR、编译 fixture、启动 SSH 服务、创建 VM/容器或建立 SSH 连接。

现有 `Tests/IntegrationEnvironment/` 的 OpenSSH/PAM 方案能用于四类有序方法与多轮人工认证，但 PAM 两提示不能据此声称是同一条 SSH KBI 消息的两提示。MINA 现有库可直接发送一条含多个提示或零提示的 `SSH_MSG_USERAUTH_INFO_REQUEST`，避免自研/修改 SSH 协议。**源码可行不等于 OpenLXSSH 已真实互通，AC-10 仍未通过。**

## 固定来源与供应链

- 官方发布页：<https://mina.apache.org/sshd-project/download_2.20.0.html>；Maven Central POM：<https://repo.maven.apache.org/maven2/org/apache/sshd/sshd-core/2.20.0/sshd-core-2.20.0.pom>。选正式 2.20.0，不选 3.0 milestone。
- annotated tag `sshd-2.20.0` 对象 `5b03bf38e50f29339fd3d211d921912c49bb9dc0`，指向固定源码 commit **`2221febd396cd3daafdfbf2ff982c6d0eb69a203`**：[tag API](https://api.github.com/repos/apache/mina-sshd/git/tags/5b03bf38e50f29339fd3d211d921912c49bb9dc0)。该 tag API 未显示有效签名，不当作发行包验签。
- [LICENSE.txt](https://github.com/apache/mina-sshd/blob/2221febd396cd3daafdfbf2ff982c6d0eb69a203/LICENSE.txt) 为 Apache-2.0；分发保留许可、适用 NOTICE，标明修改。另核 [NOTICE.txt](https://github.com/apache/mina-sshd/blob/2221febd396cd3daafdfbf2ff982c6d0eb69a203/NOTICE.txt) 及 [NOTICE-bin.txt](https://github.com/apache/mina-sshd/blob/2221febd396cd3daafdfbf2ff982c6d0eb69a203/NOTICE-bin.txt)，二进制声明包含 SLF4J，不能外推全部传递依赖同属 Apache-2.0。
- [固定 README](https://github.com/apache/mina-sshd/blob/2221febd396cd3daafdfbf2ff982c6d0eb69a203/README.md#L35-L51) 区分 Java8+ 运行与上游 Java17+ 构建；后续 fixture 可统一 Java21，仅在获批测试容器。
- 尚未下载/验证发行归档或 JAR 的 PGP/SHA512、最终依赖闭包及可用 Java/容器。获批后必须固定并核对；Git commit/POM 不代替归档验证。版本选择也考虑官方发布说明涉及异步 password/KBI 限制及认证检查安全修复，不能据此承诺后续无漏洞。

## 可直接覆盖的真实 wire 行为

1. [`KeyboardInteractiveAuthenticator`](https://github.com/apache/mina-sshd/blob/2221febd396cd3daafdfbf2ff982c6d0eb69a203/sshd-core/src/main/java/org/apache/sshd/server/auth/keyboard/KeyboardInteractiveAuthenticator.java#L57-L85) 以 `generateChallenge(...)` 返回 `InteractiveChallenge`，以 `authenticate(..., List<String>)` 返回 primitive boolean。
2. [`InteractiveChallenge`](https://github.com/apache/mina-sshd/blob/2221febd396cd3daafdfbf2ff982c6d0eb69a203/sshd-core/src/main/java/org/apache/sshd/server/auth/keyboard/InteractiveChallenge.java#L35-L108) 默认空提示列表；`addPrompt(String, boolean)` 添加提示；`append` 先写数量，再把全部提示写进同一 buffer。[`PromptEntry.append`](https://github.com/apache/mina-sshd/blob/2221febd396cd3daafdfbf2ff982c6d0eb69a203/sshd-core/src/main/java/org/apache/sshd/server/auth/keyboard/PromptEntry.java#L61-L64) 保留 echo boolean。
3. [服务端 `UserAuthKeyboardInteractive`](https://github.com/apache/mina-sshd/blob/2221febd396cd3daafdfbf2ff982c6d0eb69a203/sshd-core/src/main/java/org/apache/sshd/server/auth/keyboard/UserAuthKeyboardInteractive.java#L60-L150) 创建 INFO_REQUEST、调用 `challenge.append` 后一次 `writePacket`；INFO_RESPONSE 数量不符失败，匹配时按顺序读取响应再调用认证器。

因此两个 `addPrompt` 是同一消息 `num-prompts=2`；非 null、空列表 challenge 是真实 `num-prompts=0`，对应空响应仍经过认证器。`generateChallenge` 返回 null 是拒绝，不是 zero-prompt。上游[真实连接多提示测试](https://github.com/apache/mina-sshd/blob/2221febd396cd3daafdfbf2ff982c6d0eb69a203/sshd-core/src/test/java/org/apache/sshd/common/auth/KeyboardInteractiveAuthenticationTest.java#L138-L236) 覆盖三提示和 echo，但本轮未执行；其名称 MultiChallenge 不代表同一次 KBI 多轮。

## 多轮限制：不编造高层 API

本版高层认证器的结果是 boolean，没有 `nextChallenge()`。一次响应后直接成功/失败，`AsyncAuthException` 的完成值也不是下一轮。因此不能仅实现高层 public authenticator 就宣称可运行 A+B→C→zero。

需要同一次 KBI 的2→1→0时，可研究通过 `setUserAuthFactories` 注册每次认证独立的 `UserAuthKeyboardInteractive` 子类：当前轮仍委托 `super.doValidateAuthResponse(...)` 完整解析/校验；当前轮成功且有下一轮时推进测试策略，再委托 `super.doInitialAuth(...)` 生成/发包，向认证服务返回 null（尚未完成）。最终轮才返回成功，错答立即失败。[`UserAuth` true/false/null 契约](https://github.com/apache/mina-sshd/blob/2221febd396cd3daafdfbf2ff982c6d0eb69a203/sshd-core/src/main/java/org/apache/sshd/server/auth/UserAuth.java#L33-L62) 是该判断依据。

这只是固定版 protected 扩展点的源码可行性，尚未编译/互通，不是开箱能力。最小可先用 MINA public API 验单消息多/零提示，以现有 OpenSSH fixture 验多轮；若采用薄适配，必须独立锁版审查、真实2→1→0互通，不自行编码 SSH 消息、修改上游或以失败后重试冒充多轮。

## 审批等待、拒绝与取消

可先发送带说明的 zero-prompt challenge；收到零响应后，在 `authenticate` 中安排有界异步审批并抛 `AsyncAuthException`，批准/拒绝调用 `setAuthed(true/false)`。不要在 `generateChallenge` 抛出后期待恢复生成下一提示。

证据：[AsyncAuthException](https://github.com/apache/mina-sshd/blob/2221febd396cd3daafdfbf2ff982c6d0eb69a203/sshd-core/src/main/java/org/apache/sshd/server/auth/AsyncAuthException.java#L41-L93)、[ServerUserAuthService](https://github.com/apache/mina-sshd/blob/2221febd396cd3daafdfbf2ff982c6d0eb69a203/sshd-core/src/main/java/org/apache/sshd/server/session/ServerUserAuthService.java#L159-L395)。服务核 pending身份、当前认证实例、连接关闭及是否已认证，旧结果不会被当作当前结果。异常类不替 fixture 取消任务或擦除挑战材料。

约束：

- 不在认证回调 sleep/等待 provider。默认 [NIO2读取回调](https://github.com/apache/mina-sshd/blob/2221febd396cd3daafdfbf2ff982c6d0eb69a203/sshd-core/src/main/java/org/apache/sshd/common/io/nio2/Nio2Session.java#L375-L422) 同步处理消息，认证服务 process 又持锁，阻塞会影响读取/取消。
- `setAuthed` 在调用线程直接通知，需有界调度器且不持 provider 锁，不逐请求无限开线程。
- 注册 [`SessionListener.sessionClosed`](https://github.com/apache/mina-sshd/blob/2221febd396cd3daafdfbf2ff982c6d0eb69a203/sshd-core/src/main/java/org/apache/sshd/common/session/SessionListener.java#L172-L205)，使用 attempt token、TTL、显式 AUTH_TIMEOUT 与幂等清理；不要依赖空的默认 `destroy()` 自动清理。
- 实际客户端关闭/替换认证才使迟到结果失效；还须验证等待期间取消、超时、迟到批准及并发隔离。说明确实在线传输不等于 App 必然及时显示。模拟审批不代表企业厂商兼容。

## 研究证据的保存边界

研究 Agent 以 `curl --fail` 在内存读取公开文本，返回成功退出码与源码行号，未保存完整 HTTP headers 或归档/JAR校验文件。主管将工具实际保留的五份源码摘录固化在 `DerivedData/Verification/auth-mina-source-research-a97b6b38-6772-4127-a2e4-4ab355d81190/`，`inventory.json` 记录逐文件SHA256；摘录中保留一次错误路径404，不作为成功来源。部分核心challenge/发布/许可文本只在研究返回中而非完整本地档案，永久链接仍固定到上述commit。不能把这些摘录当完整上游源归档、HTTP200逐项证明或发行包验签。上游回调失效测试部分使用mock，也不当真实连接结果。

## 最小环境增量与验收

沿用既提议的 Ubuntu24.04 ARM64、官方 digest、专用 internal 网络；增加一个仅 `127.0.0.1:22225`→容器2222 的非特权 MINA 服务，建议0.5CPU/512MiB/128PIDs，并优先与原四服务串行使用。Java21及MINA只限测试环境，不进入 App。只从 `sshd-core:2.20.0` 起步，核同版 `sshd-common`/最终运行依赖，无需增加LDAP/Git/SFTP模块。

必要真实场景：单消息双提示正确/错误、zero接受/拒绝、延时批准/拒绝、等待取消及迟到批准、并发挑战隔离；多轮薄适配若采用另验2→1→0。日志仅轮次、数量、非秘密attempt ID、结果，关闭TRACE/报文/响应dump；一次性秘密不入argv/env/报告。

**这份方案不授予新增环境、下载构建、启动或连接授权。** 与原方案一并待用户批准，不能因 Goal active 或脚本 `--authorized-run` 跳过。目标macOS26、产品真实互通和企业人工验收仍未完成。
