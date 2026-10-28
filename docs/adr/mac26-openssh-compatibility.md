# macOS 26.7.1：系统 OpenSSH 的精确兼容范围

日期：2026-10-28。Task `TAKEOVER-MAC26-AUTH-GATE-R1`。

## 决策与范围

保留既有 `24H32` / `OpenSSH_9.9p2, LibreSSL 3.3.6` 条目，并为本机新增精确组合 `25G241` / `OpenSSH_10.3p1, LibreSSL 3.3.6`。比较包括版本输出的结尾换行；不接受其他系统构建、交叉组合、宽泛的 26.x 或 10.x 范围。两个组合都必须通过既有 `/usr/bin/ssh` 的 Apple 签名校验；校验失败、工具失败或未知组合继续人工输入。

此次只修改兼容判断及其测试，不改变严格 `passwordOnly` 配置、一次提供额度、hint 消耗、会话和代次校验、迟到结果丢弃、取消、改密后续人工处理或 MFA 禁止自动提供长期密码的边界。纯匹配函数只供内部策略与测试使用，不能供调用者覆盖运行时系统、版本或签名。

系统升级后，旧测试硬断言宿主必须属于 `24H32`，会把新系统当成测试失败。本轮保留原 `ssh -G` 和一次额度断言，以兼容矩阵的正负案例与运行时独立事实对照替换该宿主假设，不删原场景或放宽未知系统。

## 来源与限制

- 已实际读取 [上游 OpenSSH 10.3p1 sshconnect2.c](https://raw.githubusercontent.com/openssh/openssh-portable/V_10_3_P1/sshconnect2.c)：`userauth_passwd` 967–998 行先取得初始密码、发送 change=0 请求，再注册 `PASSWD_CHANGEREQ`；1004–1072 行处理后续旧密码、新密码和重复确认。
- 已实际读取 [上游 OpenSSH 10.3p1 readpass.c](https://raw.githubusercontent.com/openssh/openssh-portable/V_10_3_P1/readpass.c)：45–101、113–173 行保留单 prompt 参数、`confirm` hint 及强制 Askpass 路径。Askpass 仍未提供通用的密码/OTP 类型信息，不能依赖提示词猜测。
- 以上原文 SHA256 分别为 `78e4b83a08df6a7371cff1201725ce488a566157a8b871c6a4a7d24e7ea425fa`、`657c8d5a0faffea365b678af8e8ef15ac4ac422ca6f44fd358196dc9ec64798f`。
- 本机 `/usr/bin/ssh` 的 SHA256 为 `e22a8f3069beddf378d24f6b747831491345ee2e7b4e7e4599c4ca61f6f38064`；本轮只读 `codesign --verify --strict -R '=anchor apple and identifier "com.apple.ssh"' /usr/bin/ssh` 退出 0。摘要是本次证据，不取代运行时签名与精确版本检查。
- 能读取的 [Apple 公开 main/version.h](https://raw.githubusercontent.com/apple-oss-distributions/OpenSSH/main/openssh/version.h) 仍显示 10.0p2，公开 tags 查询未成功。因此本轮**没有证明上游源码与当前 Apple 二进制逐项对应**，也不声称对应源码不存在。兼容范围限定到本机组合，并须联合真实行为验证。

## 验证状态

真实 passwordOnly 的公开 provider 一次/人工零次、无授权人工回退、后续改密不自动、MFA 不投递及默认 Keychain 生命周期由主管串行安排，**本轮尚未运行这些真实服务场景**。本决策不是 AUTH-02、整个认证矩阵或 V1.0 验收通过。

## 主机密钥扫描的有限时间预算

同轮经主管批准，将 `SystemHostKeyScanner` 默认扫描预算由 5 秒改为 10 秒，与连接配置默认 10 秒保持一致，为慢链路留有限余量。显式 1～15 秒仍受支持，`ssh-keyscan -T`、取消、输出上限、解析及信任处理不变；进程外层截止仍为扫描预算加 2 秒，因此默认最坏等待从 7 秒增至 12 秒，仍可取消。

主管在已就绪的获准本机隔离 relay 上得到 -T5 无密钥／5.008 秒、-T15 有一枚带外匹配公钥／6.2868 秒的对照。该路径包含隔离管理转发的开销，证明旧默认不足以覆盖此测试路径，不将其归因为真实远端或所有网络的缺陷。此次修改是有界产品容忍策略，不是放宽测试消费者来绕过正式 App 的默认路径。新默认真实对照及静默/取消边界由主管串行验证。

## 本轮实际离线验证

- 新 macOS 26.7.1 上，沿用现有离线缓存的 Release 构建、36 项 Transport 测试、真实系统 readpass 6 案、认证事件 4 案、28 项 Mach 对抗案及 38 个退出后服务撤销检查均通过；首轮测试二进制最低版本实际为 15，未将“在新系统运行”写成“最低部署版本26”。本轮只验证本机 PTY、控制面和策略，无服务器认证或 Keychain。
- 验证配方的额外目标参数复核发现 SwiftPM 的 `--triple` 不能覆盖 manifest 的最低平台，于是显式核 Swift/C 实际目标和 `vtool`。追加产物的 fixture、Transport 对象、测试可执行文件最低版本均为 26，Release 构建及相同36项和控制面验证通过。这次追加配方在缩限反馈/停止检查前已完成，也重复了未改变的对抗项；如实保留，不把重复项计为新的功能覆盖。
- 上述两轮各 53 份子命令日志退出均为0，既有 min26 正式 helper SHA256 `31d0ee0ee9d357d7edd0bfaf129a9ae4b38334fd8955184f6afc049d685a0590` 被复制并严格验证复用，未重新签 helper。新测试 App/对抗镜像仅使用既有 Development 身份及无时间戳本地签名，无证书、ACL 或系统设置修改。
- 默认扫描预算改动后仅执行4项定向 Release 测试：默认/显式/非法扫描预算、原工具 timeout/cancel/overflow、兼容矩阵、原真实 `ssh -G` 与一次额度/宿主策略，4项0失败。未再次运行完整控制面或远端 campaign。
- 首个搬迁配方因证据脚本 `__file__` 导致 ROOT 错误，在编译前退出127；原日志保留。这是验收脚本定位错误，不是产品编译失败。首轮 `vtool` 的 min15 记录也保留，没有回写成26。

证据根为 `Packages/OpenLXSSHTransport/.build/verification/mac26-auth-gate-54694349-aaa5-45c0-8101-edc6d186ba26/`：首轮 `resume-09836f35-8604-4893-a2c5-7714252e6cf5/`、显式目标 `explicit-target26-096be138-4f04-4d60-a4a2-622814e7d91c/` 各有配方、日志与 `verified-result.json`；最终定向 `scanner-directed-b5f0530d-6741-4270-a34c-e1938cb6ce7f/` 有精确 `command.json`、`tests.log` 和 `result.json`。正式 App/最终稳定性 driver 另按冻结后的生产源码构建与运行，不由这些测试产物代替。
