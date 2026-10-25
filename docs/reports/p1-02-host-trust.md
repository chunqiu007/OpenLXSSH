# P1-02：受控 SSH 配置与主机信任原型审查

日期：2026-10-25。执行者：software-engineer；独立审查：Primary Agent。

## 结论与范围

本地配置、信任状态机和文件一致性范围通过。未启动 sshd 或连接任何服务器；真实握手公钥获取与会话绑定、SSH/SFTP 集成仍未验证，产品 AC-12 不因此通过。

实现：`Experiments/P1-02-HostTrustProbe/`。无第三方依赖，实验最低 macOS 15 只为当前宿主运行；产品仍以 Apple Silicon/macOS 26 为目标。决策依据见 `docs/adr/p1-02-host-trust.md`。

## 独立代码审查

主管读取了 manifest、全部库/CLI 和四个测试文件，重点如下：

- `Identity.swift` 对地址、端口、用户、绝对路径分类型验证。拒绝控制字符、NUL/CR/LF、前导选项、通配符、配置注入与歧义数字 IPv4；规范化 DNS/IPv4/IPv6。
- `ControlledSSHConfiguration.swift` 仅用固定目标 alias、专属 `-F` 文件和固定环境；禁用 Agent、代理、转发、复用、任意本地命令与自动信任更新。配置路径/HostName 的百分号和引号按实际 OpenSSH 行为处理，命名 IPv6 scope 不存在时拒绝而非静默改变目标。
- `HostPublicKey.swift` 将公钥交由系统 ssh-keygen 解析，CryptoKit SHA256 与系统指纹对照；不自研协议或密码学，不读取用户私钥。
- `HostTrustStore.swift` 单一 known_hosts 为真源。首次/新算法显式确认，匹配通过，同算法变化拒绝。管理替换需核对旧、新指纹；令牌一次性、限时、绑定存储代次及摘要，取消/旧确认失效。
- `PrivateDirectory.swift` 保留目录 FD、openat/O_NOFOLLOW、owner/0700/0600/单链接检查；稳定 flock、fsync、原子 rename；损坏或缺失存储不静默清空。多个合作式进程共享同一锁。

## 验证证据

工作目录：`/Users/liuwenshuo/Desktop/OpenLXSSH`。包路径：`Experiments/P1-02-HostTrustProbe`。

| 执行者 | 实际检查 | 结果 |
| --- | --- | --- |
| 工程师 | Debug/Release build 与 test，`-Xswiftc -warnings-as-errors` | 均退出 0；Debug/Release 各22项、0失败 |
| 工程师 | `swift test --sanitize=thread -Xswiftc -warnings-as-errors` | 退出0，22项、0失败，无TSan报警；主管读取完整最终日志 |
| 工程师 | Release CLI `--self-test` | 退出0 |
| 主管 | `swift test --package-path <包> -Xswiftc -warnings-as-errors` | 退出0，22项、0失败 |
| 主管 | `swift run -c release --package-path <包> -Xswiftc -warnings-as-errors p1-host-trust-probe --self-test` | 退出0；显式信任、变化拒绝与无网络SSH配置对照通过 |
| 主管 | `git diff --check` | 退出0；新增文件在暂存前另核对 |

系统 `ssh -G/-vvG` 与 `ssh-keygen -F/-l` 在测试中真实执行，未发起网络连接。测试覆盖：DNS/IPv4/IPv6、非22端口、多算法、地址编辑；首次/取消/匹配/变化/管理替换；旧令牌/跨实例竞争；8个Store及4个独立CLI进程并发；旧FD读到完整旧文件；损坏/超限/重复/恶意记录，symlink/hardlink/FIFO、目录/锁替换和不安全权限。临时公私钥由ssh-keygen生成，仅读取公钥，自动清理。

日志：`Experiments/P1-02-HostTrustProbe/.build/verification/`，包括 debug/release build/tests、release-cli 和 thread-sanitizer-tests。主管已复核最终TSan日志，记录22项、0失败和退出0。

## 风险与未覆盖范围

- 当前宿主 macOS15.8.1，未运行macOS26；没有正式App/Sandbox验证。
- 尚未证明从真实SSH握手安全获取服务器公钥，并将接受结果与随后同一目标握手绑定。不能自动信任预扫描结果。
- 文件锁只保护合作式写入，不构成同UID恶意进程隔离；OpenSSH仍按路径打开文件，未完全消除相关TOCTOU风险。
- 未注入掉电/磁盘故障。rename成功后fsync失败属于提交状态不确定，调用者必须重读；崩溃残留临时文件不能晋升为信任。
- 严格App自有格式暂不支持CA、证书、通配符或hashed-host导入；V1不要求导入系统SSH配置。

下一步：继续P1-03凭据/私钥、P1-04认证桥接，以及获得隔离服务后真实主机信任/认证复验。阶段1门槛仍未通过。
