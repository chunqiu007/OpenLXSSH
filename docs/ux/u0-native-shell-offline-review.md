# 同连接认证与真实shell候选：离线审查检查点

日期：2026-10-30。状态：候选源码/离线边界可进入有限真实fixture探针准备，**不是已选定替代系统OpenSSH，也不是四类MFA已通过**。

## 为何需要候选

用户要求两主认证方法都响应真实附加挑战，并将未记住编辑器密码直接交给相同连接的初始密码方法。既有OpenSSH Askpass没有可靠KI/初始密码类型，不能扩大首masked白名单；详见`u0-auth-context-evidence.md`。候选使用现有固定libssh2/OpenSSL成熟协议实现与SwiftTerm呈现，不自写SSH/crypto，不按提示词判OTP。

## 已实现候选与主管源审

- `LibSSH2ShellSession`位于Files包的独立NativeShell类型/认证/owner文件，只复用静态成熟库，无新外部依赖。不是SFTP，更不会启动本地shell。public API只接受类型化SSHConnection、typed primary、manual KI与共享HostTrustStore，内部fd adoption仅测试可见。
- 同一私有socket：真实handshake hostkey→共享store exact rawkey核验→typed password或publicKey一次→必要时distinct KI一次→实际session channel、xterm-256color PTY、shell。none method发现只在primary之前一次，primary后绝不发none重置partial链；返回-18/-19只记notAuthenticated事实，不称初始已接受。服务器不提供主方法时拒绝，不自动改别的保存凭据。
- KI复用原KeyboardContext，整个交易最多16轮/128prompt/1MiB展示字节，各字段/回复原有界；未知生产KI必须用户handler回答。测试消费者的固定fixture shape仅测试，不成为生产OTP分类器。
- 输入dispatch前准入<=256KiB/128请求，稳定独立写缓冲跨EAGAIN pointer/length不变、释放wipe。输出单pull consumer<=64KiB，无无界AsyncStream。串行queue唯一native owner，outbound EAGAIN继续原API，inbound-only窗口等待让reader推进，有限每tick双向处理。
- EOF与channel close/exit分离；使用公开wait_closed而非将libssh2_poll当无副作用metadata。reported status0也可能没exit-status，不能单独证明成功。close撤销continuations并await本地socket/session真正释放。
- 主管已读Types/Session/Authentication/C bridge关键源及16项offline测试。测试覆盖非真实endpoint AF_UNIX socketpair超时/取消/并发close、noTrust拒绝、bounds/admission/mailbox/稳定buffer/预算；**不覆盖已认证后的真实双向EAGAIN、PTY resize/TUI/remote EOF和MFA互通**。

## 实际离线证据

工程师日志根：`DerivedData/UXVerification/U0-NativeShell/`。

- 固定native inputs/build script/archive与原manifest摘要一致；未重建libssh2/OpenSSL。
- C `clang -Wall -Wextra -Werror -fsyntax-only`：0；Files strict build：0。
- NativeShell Debug16/0、Release16/0，exit0；无TCP/DNS连接的Files回归119/0，exit0（明确排除4旧TCP/DNS测试，未改断言）。
- probe纯语法/流式matcher契约5/0，exit0；default/help/validate0，live参数64拒绝。首initializer访问级别编译失败保留`probe-test.log`，修后`probe-test-retest.log`通过。
- 主管独立 `swift test --package-path Packages/OpenLXSSHFiles --scratch-path DerivedData/UXVerification/U0-NativeShell/files-build --disable-automatic-resolution --filter NativeShellTests -Xswiftc -warnings-as-errors`：**16/0/exit0**，`primary/native-shell-tests.log`。
- TSan discovery helper SIGSEGV11，未进测试；ASan discovery挂起约3分钟后仅TERM本轮任务exit143；直接exec XCTest bundle为Exec format error。均未当通过，原日志保留，不以普通工具失败伪造内存安全结论。

## 依赖、许可与保活门

复用已有libssh2 1.11.1/OpenSSL3.5.9静态库和既有完整notice；新bridge无上游私有结构/协议解析。尚未作替换ADR定案，保留原System OpenSSH路径。

候选当前**没有与ServerAliveInterval/Count等价的liveness策略**：固定libssh2 keepalive实现会吞EAGAIN且无公开reply计数，不以静默输出判死。原用户保活需求不能悄悄删掉，后续需成熟可证策略（例如明确不同语义的TCP keepalive实测与ADR、或其他成熟库）及真实黑洞验证后再定案。仅发keepalive不等故障检测。

## 下一有限真实探针

新`Experiments/UXNativeShellProbe`仅固定获批fixture四端口22221～24，不用户可输入任意endpoint。准备复用现RealIntegration受控noFollow/privatePIPE/精确container-image-network-policy管理reader与SFTPAuth材料schema；schema只输入材料，结果taskID为新的NativeShell，不拿旧SFTP报告当shell证据。producer与消费者源/编译hash审完后由主管明确release，当前无新live。

有限成功必须同连接返回shellReady、随机token拆分构造以避免命令回显冒充ACK、test -t 0为true、真实resize后stty size37x113、显式exit7/EOF与awaitclose；输出<=1MiB。四正向串行后补wrong primary/hostkey mismatch/unknown KI manual/取消等负例。测试秘密只内存/fixture私有目录，不入源码/argv/env/log/截图，故障不改TTL/时钟或重复猜密码。无24h/2GiB重跑、无生产/Apple/Keychain操作。
