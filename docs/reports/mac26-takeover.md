# macOS 26 接手与剩余验收

日期：2026-10-28。接手基线 `0711b24`；当前整体仍未完成。

## 范围与复用

用户要求 Codex 接手剩余工程，不重复 ZCode 已完成且未受变化影响的工作。既有真实 2 GiB/1000 文件及异常 campaign、数据与引用规则、依赖来源和许可证据保留；不从历史“进行中”推定功能尚未实现，也不把历史失败回写成通过。

宿主实测为 Apple Silicon、macOS 26.7.1 / 25G241、OpenSSH 10.3p1 / LibreSSL 3.3.6、Xcode 26.3 / SDK 26.2。系统升级使原有认证兼容白名单和旧宿主测试假设不再适用，必须补相关验证。用户本轮已明确批准仅本轮新建的一次性默认 Keychain 测试条目的保存、读取、忘记/删除与失败回退；不枚举其他凭据，系统授权由用户处理。Developer ID 正由用户准备，没有 Apple 上传授权。

## 已审最小实现

- 保留旧系统组合，新增精确 `25G241` / `OpenSSH_10.3p1, LibreSSL 3.3.6`，保留 Apple 签名和未知系统人工回退；不修改密码一次额度、hint、会话/代次或 MFA 隔离。来源与限制见 `docs/adr/mac26-openssh-compatibility.md`。
- 主机候选扫描默认 5 秒改为 10 秒，显式 1～15 秒、全工具预算加 2 秒、取消和严格解析保持。扫描不写入信任记录。本次是允许慢链路的有限策略调整，不声称证明一般真实远端有缺陷：已 ready 的隔离 relay 上原 5 秒实际 exit1/无公钥，对照 15 秒实际 6.2868 秒取得一条公钥，且与管理通道导出一致。旧失败保留，正式默认 10 秒成功仍须真实验证。
- 同一固定镜像的 PTY 审计权限修复扩展到另外三种认证测试服务，只有原七项加 `AUDIT_WRITE`。保留 no-new-privileges、只读、内部网络、资源限制和严格身份校验；MINA 仍不加 capability。

## 独立审查和验证

主管读取实际差异；独立只读审查没有发现上述兼容门的新 P1 问题。工程师的新系统 Release 回归覆盖 36 tests、真实 readpass/event 与对抗/退出检查；首轮部署 min15 如实保留，追加明确目标的产物经 vtool 确认为 min26。后续扫描小改只执行四项定向验证。主管独立执行相同关键四项：0 失败；未重新执行远端大文件 campaign。

fixture 源码的 40 项静态、28 项 relay 和两项 MINA 定向检查通过；主管独立执行 40 项静态检查通过。应用后核实：keyonly 的容器 ID/启动时间不变，另外三服务重建为精确八项 capability，四服务 healthy，镜像、网络、数据卷、只读/非特权、日志与资源限制均保持。

原始证据：

- `DerivedData/Takeover/mac26-8834149cacad467585fd03a34f6379ec/`：环境、扫描对照、主管定向测试、fixture 应用前后与有限 relay 记录。
- `Packages/OpenLXSSHTransport/.build/verification/mac26-auth-gate-54694349-aaa5-45c0-8101-edc6d186ba26/`：工程师完整/明确目标/最终定向结果，包含原失败和真实部署元数据。
- `Tests/IntegrationEnvironment/.logs/mac26-mfa-cap-offline-b435436f-787c-48de-a837-790b29e26877/`：cap 回归、原 red、当前结果。

## 当前下一步

冻结生产 Transport 后只生成一次新正式 min26 稳定性驱动；原驱动可复用部分已通过只读来源验证，但源码变化后不冒用其旧摘要。新签名 API 消费者补真实默认 Keychain 生命周期和新系统自动密码行为；正式 App 的正常安装、界面、MFA/文件小数据集成、200 次与连续 24h、Release 资源测量及签名公证随后独立验收。

本报告不是上述未来场景已通过，也不将测试 wrapper、纯测试或编译成功等同于正式 App 验收。

## 真实凭据分项与候选产物

新已签名消费者 `Tests/RealIntegration/.build/host-65b125b1-29b8-4e99-954a-47bee61a254b/` 包含冻结的新兼容门。主管唯一真实Keychain案退出0：明确saved→精确provider读1/返1→外层认证事件1/人工0→关闭与provider任务drain→精确delete→再读missing→store.close恢复交互策略；只查询本次独占测试service的独立CLI后验exit44，未枚举其他凭据。无授权对照另一次退出0：provider调用/读取/返回均0、manual请求/读取/回答各1，连接与清理通过。只读独立review核367项源/快照和实际main/helper摘要匹配，未发现新P1/P2。

这仍是min15测试wrapper在mac26消费生产API，scanner显式15/connect20，不是正式AppUI、默认scanner10或真实Keychain锁定/拒绝的证明。原报告静态字段 `existing-production-gate-no-whitelist-expansion` 只表示消费者不覆盖gate；本次生产gate实际已扩精确25G241，不能照该旧字段声称没有改兼容范围。原结果保留，不回写历史。

候选版本元数据提交 `6124bbe`，1.0.0/build2；既有配方仅生成一个新的Development候选，来源dirty=false：`DerivedData/Distributions/1.0.0-2-6124bbeb4201/47f7c768-0a3c-4ecc-a46a-c284b84e991e/`。ZIP SHA256 `c23155d8ebe73610accbb9f638f74c17424cbf1fe3bfe6feb22aac3055360434`。正式arm64/min26、包内helper、严格同Team签名核验通过；Gatekeeper真实拒绝，尚未DeveloperID、公证或人工安装验收。该候选正常首次启动失败，见下方；不得称为可用交付物。

## 首轮200次失败与测试工具修复

原driver-5ae677f7真实运行2546.129182秒，200 authenticated/20 cancelled/220 closed均产生记录，但6个connected样本helper PTY指标未知，最终exit1/resourceUnavailable，原424行证据完整保留。closed/final cleanup FD5/PTY0完整不抵消坏点；旧记录没有errno，不能倒推它们一定是EBADF。

局部修复仅在Tests/StabilityAcceptance：0bytes+本次EBADF、身份UID/PPID/birth稳定、新完整无重复FD列表证明目标FD消失时，允许一次完整重采；短读、权限错误、未知、重复竞态及身份变化均拒绝。已精确匹配helper采样失败只允许独立strict GONE跳过，UNKNOWN不忽略，cleanup三态未放宽。工程师自有子进程实际关闭FD验证及23项回归通过，主管另23项通过、交叉源审通过。原proc_pidpath匹配前失败的观察边界保持，不声称覆盖所有短命helper。新driver-a215d18a构建/严验0、163输入匹配、main/helper min26，尚未真实200/24h。

## 正式App首次启动与父目录ACL修复

build2正常复制到~/Applications/OpenLXSSH.app并经CUA启动，遇storage.unsafeLocation；系统Application Support唯一标准非继承everyone deny delete ACL被旧parent blanket noACL误拒，尚未创建App目录。未清除系统ACL或修改其权限，旧失败保留。仅父目录验证允许无ACL或完整公有API构造的精确保护性ACL，保持当前UID/目录类型/禁止他人写及特殊位；App-owned目录/数据库/私钥等仍拒绝任何ACL。完整公开ACL字节比较拒绝其他主体/权限/继承/额外项。

旧源red真实复现；新源原15项通过、首green新增项有测试辅助快照失败并保留，修正辅助后相关4项通过。主管独立4项新增边界全部通过。build3将独立生成候选重验正式默认路径，不能用单测或旧HostProbe冒充GUI通过。

有限relay已正常结束868/868、cleanup_failed0。24h尚未启动；用户允许临时每30分钟回查，heartbeat openlxssh已建PAUSED，实际长测启动后才激活。
