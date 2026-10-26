# 首轮真实 SSH/SFTP 互通及负向认证检查点

日期2026-10-26。范围：已授权Docker隔离服务＋host15独立生产API消费者；**不是macOS26正式App/GUI信任/MFA或整体验收通过**。普通终端输出、凭据或SSH wire未记录，真实公司/生产服务器未访问。

## 固定环境与测试入口

Docker Desktop4.97/Engine29.9.2，2CPU/4GiB/40GiB，自启关闭；用户已明确批准必要安装/下载构建及127.0.0.1:22221～22225运行。官方Ubuntu24.04ARM64base18b33f…与真实rootimage7f633d33…、四服务内部/noegress/权限资源有实证。纯internal不直接发布端口，按已审ADR采用有限前台127 opaque relay，不是产品端口转发功能。

测试consumer使用production公开DirectSSHSession.connect和LibSSH2FileService.connect、同握手/共享Trust、固定服务/用户/端口、单精确generation的带外known_hosts/fingerprint/provenance；不使用startProbe、不扫描终端提示注入、不autoacceptkeyscan。带外种trust仅自动测试准备，**不代替首次连接GUI接受**。

## 真实私钥 SSH

消费者host-f3d097c8（test-only scan15/connect20；正式min26不变）实际运行keyonly/22221 positive：

- exit0，12.847s。
- `.connected`可信outer-auth事件1，认证请求/回答0；不是spawn或shell提示推断。
- closeCompleted=true、ownedPIDReleased=true。
- 精确输入代次 `Tests/IntegrationEnvironment/.runtime/keyonly/credentials-fbbaa2ef27a3`，带外publickey指纹一致；秘密未写报告。

证据 `DerivedData/Verification/first-production-live-0f6984ea-03d1-4cad-80f1-c49eb80e3220/`。主会话亲自执行和读取结果，有限420s relay最终exit0，accepted5/finished5/rejected0/cleanup_failed0；包含预扫/认证及随后首次SFTP尝试。不把relay计数当SSH连接成功数。

## 首次 SFTP 失败与仅测试预算修正

同测试基础设施首次passwordSFTP实际5.108s失败`file-timeout`，connected0。这不是密码拒绝，也未删失败证据。生产Files的operationTimeout同时用于握手/信任/认证/SFTPinit；relay每次新鲜metadata约3s+dockerexec开销可在到server前耗掉5s。

只在Tests/RealIntegration将test-onlyoperation5→20，scan15/connect20/case30/drain12不变；产品Packages/门禁/默认超时和Stability未修改。原测试的“连接+操作串行相加≤case”假设不适用于per-operation语义，改为各阶段精确有界及outer30s/close12s边界仍断言；SFTP30s是取消watchdog而非close墙钟保证。原失败保留，修改后必须实际复验，不以offline绿替代。

新静态签名consumer：

`Tests/RealIntegration/.build/host-60254387-d91c-4f50-ab5e-b7793f09fc2f/OpenLXSSHRealIntegration.app`

主程序SHA256 `91963d3172a2b6aecb3ba77f478c84475885cec7ac6bb0371e692cdd68320ac4`；helper `d1add0ae957d1e0c1d70bc148def0da55ce7f1c4012fd662067114e29601e756`。328input/private snapshots、36commands、严格Development/Runtime/空entitlements均通过；主管核实际source/hash/封装签名。8Swift+5Python+5CLI基线通过，不重跑无关已验功能。

## 真实密码与私钥 SFTP 微型往返

新op20消费者，每例各一次：

| 用例 | 实际结果 | 清理/数据证据 |
| --- | --- | --- |
| passwordonly/22222 positive | exit0，6.531s，connected1 | 79bytes写/读一致、SHA匹配、list2/lstat5、remoteCleanupCompleted/closeCompleted=true |
| keyonly/22221 positive | exit0，6.401s，connected1 | 同上；唯一自有UUID小目录/payload被精确清理 |

证据 `DerivedData/Verification/sftp-production-live-a65f4851-0bdc-4f28-9257-a0b49d827dc3/`，含精确argv/cwd/contract/exit/报告。main亲自执行，结束精确TERM自身finite relay并awaitexit0，accepted2/finished2/cleanup_failed0。SFTP无sshPTY child，`ownedPIDReleased=false`是本报告字段不适用，未伪改true。

## 真实认证负例

独立执行工程师在新不可变generation使用同已核host6025consumer，各一次无重试：

| 用例 | 实际结果 | 分类依据 |
| --- | --- | --- |
| passwordonly bad-password | exit0，6.481s，expected-outcome/connected0/closeCompletedtrue | 唯一negative成功分支必须捕获typed FileServiceError.authentication |
| keyonly unregistered-key | exit0，6.280s，同上 | 自有一次性未注册key，不借另一代/服务key，不改authorized_keys |

timeout/transport/意外成功不算负例通过。报告未单列error kind，主管读取与hash一致的FileCase实现确认唯一成功分支，未仅凭exit0推断。请求/回答/读写/list/lstat均0，认证失败前未创建远端目录。

证据：

`Tests/RealIntegration/.build/sftp-negative-2958bc72-bee0-420f-bc9e-ad7e37837bb5/`

含两结果/精确contract路径、源码/二进制前后hash、真实有限300s relayPID87542、ready36.822s、exactTERM/await0、accepted2/finished2/rejected0/cleanup_failed0。两个精确token的owner/目录/tombstone均无残留、对应relay/Docker childPID消失、临时私钥/公钥副本不存在、端口监听释放，四原服务仍running/Healthy。主管已读实际结果与cleanup/sourcecheck。

## 有限转接实效与局限

启动初轮因63CLI冗余/四target16metadata共享8s实际失败130.68s，修后一次枚举/批inspect去重、并行新鲜checks、独立有界startup通过。正式端口仅127；独立root24/relay27与实际source读审通过，private tmpfs export从docker cp实失败改固定安全Python privatePIPE（28root/27relay及实际collect通过）。所有诊断/原始失败保留，未放宽internal/no-egress/身份/秘密策略换绿。

这些是基础认证与微型文件完整性证据，不覆盖有/无口令RSA/Ed25519全矩阵、保存Keychain真实流程、多轮/OTP/审批、变化hostkey/失败网络、完整2GiB/1000远端、GUI/Finder/IME、真实200/24h或macOS26发布安装。必要条目仍进行中；不把实现或少量正负互通标为整体COMPLETE。
