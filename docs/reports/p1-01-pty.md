# P1-01：本地无网络 OpenSSH/PTY 探针审查

日期：2026-10-25。执行者：software-engineer；独立审查：Primary Agent。

## 结论

P1-01 的本地进程/PTY 范围已通过主管独立审查。真实 SSH 连接、认证、MFA 和网络取消尚未验证，阶段 1 门槛仍未通过。

实现位于 `Experiments/P1-01-PTYProbe/`，无外部包依赖。实验最低 macOS 15 仅为了当前宿主可运行，不改变正式产品的 Apple Silicon/macOS 26 基线。测试 fixture 使用开发工具链已有的 `/usr/bin/python3`，Python 不是产品运行依赖。

## 实现审查

- `PTYProbeSession.swift`：单次会话 actor 持有 PID、PTY、输入队列、输出捕获和一个非阻塞 pump task。`waitpid(WNOHANG)` 回收直接子进程；TERM 后限时升级 KILL；幂等关闭和迟到输入不能触碰复用后的 FD。
- `ProbePOSIX.c`：父进程预先准备 argv/envp；子进程经 `openpty`、`setsid`、`TIOCSCTTY`、`dup2`、`execve` 启动，不运行 Swift/Foundation 回调，也不经 Shell 拼接用户字段。其他父进程 FD 不传入 child。
- `SSHArgumentVector.swift`：仅生成 `ssh -G -F /dev/null` 无网络配置展开参数，不是产品字段校验策略。
- I/O 有界；自然退出后排空尾部输出。输出超限明确终止实验，不能将这项策略直接用作正式终端的流式背压。
- 当前只对直接 child 发信号，后代进程树尚未覆盖；正式集成前必须增加对应验证。

## 已检查的验收覆盖

14 项 XCTest 覆盖：

1. 9 类 argv 原样回传（空格、换行、前导选项、引号、IPv6、空串、Shell 元字符、中文）。
2. 系统 OpenSSH 无网络配置展开及非法主机拒绝。
3. 256 字节输入顺序、128 KiB 二进制输出与尾部不截断。
4. 控制终端前台组、24×80 到 41×123 的尺寸变化和 SIGWINCH。
5. EOF、非零退出、exec 失败、配置错误和超时。
6. TERM/KILL、Swift waiter 取消、并发 cancel/close/wait 与关闭幂等。
7. 迟到输入/resize 不操作复用 FD、会话间取消隔离。
8. FD 继承隔离、20 次本地生命周期循环、对象弱引用释放。

这些断言不覆盖所有产品需求，不替代 200 次真实认证连接或 24 小时稳定性测试。

## 实际验证

工作目录：`/Users/liuwenshuo/Desktop/OpenLXSSH`。包路径：`Experiments/P1-01-PTYProbe`。

| 执行者 | 命令/场景 | 实际结果 |
| --- | --- | --- |
| 工程师 | Debug/Release `swift build`、`swift run`、`swift test` | 均退出 0；每套 14 项测试、0 失败 |
| 工程师 | `swift test --sanitize=thread`（独立 scratch） | 退出 0，14 项、0 失败，无 TSan 报告 |
| 工程师 | `swift test --skip-build` 重复 3 次 | 各退出 0，14 项、0 失败 |
| 工程师 | 显式 Swift/C macOS 26 target 构建和 `vtool -show-build` | 退出 0，minos 26.0、SDK 26.2；仅交叉编译 |
| 主管 | `swift test --package-path <包> -Xswiftc -warnings-as-errors -Xcc -Wall -Xcc -Wextra -Xcc -Werror` | 退出 0，14 项、0 失败 |
| 主管 | `swift run -c release --package-path <包> p1-pty-probe` | 退出 0；argv、PTY I/O、resize、无网络 OpenSSH 和取消实际行为通过 |
| 主管 | Release `--snapshot-hold` + `ps`/`lsof` | 父进程仍存活时 child 已消失，master FD 查询无行，tasks=0；CLI 最终退出 0 |

主管资源复核中，活动时 master FD 对应 `/dev/ptmx`，取消后 child 的 `ps` 返回 1；父进程仍存在，但其选定 master FD 的 `lsof` 没有输出行。FD 判定没有仅依赖 `lsof` 退出码，测试另以 `fcntl(...)=EBADF` 交叉验证。

工程师日志路径：`Experiments/P1-01-PTYProbe/.build/verification/`，包含 build/run/test、TSan、重复测试、目标元数据、资源快照和敏感扫描。主管读取了 `resources.log`、`test-tsan.log`、`target26-metadata.log` 并独立执行上述关键验证。构建日志和产物受既有 `.build/` 忽略规则保护。

## 限制与后续

- 宿主 macOS 15.8.1；macOS 26 只完成交叉编译，未运行。
- 没有隔离 SSH 服务，未连接服务器；SSH 只运行 `-G`，不宣称真实认证或网络取消通过。
- 未验证主机信任、Keychain、Askpass、正式 App/Sandbox、SwiftTerm、进程树或产品性能。
- 代码及本轮文本扫描未发现秘密；本轮未接触凭据。这不是对全部二进制产物的取证级证明。

下一阶段为 P1-02 受控配置与主机信任原型。阶段 1 仍需要隔离服务实测才能通过，不删除或弱化任何认证验收项。
