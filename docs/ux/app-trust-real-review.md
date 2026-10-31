# 新版 App 信任消费者：M3 分项审查

当前结论：**三种真实信任/认证分项均成立，但三案整体都因 weak 对象未在12秒内释放而 failed。** 不是 GUI、完整资源或默认后端切换验收。默认产品连接仍为 Direct，HostProbe 显式注入 Native builder。

## 范围与证据

独立闭合的场景是 `keyonly-trust-once2`、`keyonly-trust-persist2`、`keyonly-trust-changed1`。复用既有批准的 keyonly 服务，不旋转服务器密钥，不读取用户凭据，不改系统 known_hosts。

- `once2` 需要两次全新的 tab、driver、session 和实际握手，两次分别提示并仅此次批准；App 自己的可信库记录数始终为零，初始化后的公开文件字节不变。
- `persist2` 需要两个新连接；只有首次提示并持久批准，第二次不提示，恰有一条记录且第二次公开文件字节不变。
- `changed1` 只向新的隔离 App 库预置固定错误公开 Ed25519 key；实际握手必须返回带精确 expected/presented 的 typed changed 错误。无普通接受路径、primary/KI/shell 调用均为零，不读取或导入客户端私钥、不读取密码、不创建一次性密码 intent。

每次允许批准前，锁内取得真实 primary/KI/shell/pending 计数和 prompt ID，必须为 `0/0/0/1` 并匹配当前 prompt；不是写入固定成功标志。callback changed 与 typed changed 分开保存；callback-only 或普通 untrusted 不能满足 changed 场景，两个来源若都有则必须一致。

每 attempt 的认证收据明确是 `trust-authentication-only-resources-unverified`。终端证据是实际 ACK、PTY 和 113×37，不请求 exit status，也不声称观测 EOF。全部 attempts 共用 active 45 秒，full 90 秒、cleanup 12 秒；每连接 close 最多 2 秒且不超过共享 active deadline。全案仍要求全部 weak 对象释放、canonical drain/队列/registry 真实回基线、FD 完整且成员身份与数量相等、存储清理、真实 Delegate quit 顺序及自然退出。任何分项成功不能覆盖资源失败。

## 本地验证与主管复审

冻结证据：`DerivedData/UXVerification/AppTrust-M3-Verify-R1/run.5s58EF/`。

- 工程师 HostProbe26 172/0、Debug 适用回归 147/0；其中 Contract 测试文件由原 75 个方法增加到 77，原 324 行断言保留。Trust 新消费者共 10 个方法，不等整个 App 全量回归。
- Python 公开 schema 136 项、inert CLI 58 项通过。Swift 实际两 attempt/三份 32-entry FD 宽报告为 9243 字节，未提高 16KiB 上限。
- 首 Host 构建 exit65 原因是依赖模块未开 testability；命令显式 `ENABLE_TESTABILITY=YES` 后通过，不改项目配置，保留首失败日志。
- 主管读取增量和关键完整实现，独立运行 Trust10 + 原 Contract18 = **28/0**；独立重放 Python136 项，并核十个实际 Mach-O 摘要及 minOS26。证据 `Primary/`。
- 本轮强化补丁 SHA256：`162333654687ce91a152547795ea52295d4ca55ffd18b041c7c32cf428b9e003`。M3 前 Contract 的 117436 字节前缀不变，成熟 TrustStore/Driver/Controller/Package 没有为测试改写。

## 真实连接前的独立候选

准确源为 `DerivedData/HostProbe26-AppTrustM3/Build/Products/HostProbe/OpenLXSSH.app`，unsigned main SHA256 `4dac8e47c4b82debb2297666c77f9a6a65c888dc8a9e62bd2f4805095a43df9b`。主管在新目录复制、补 helper/许可资源及有限 HostProbe plist，既有产物和失败结果不变。

`DerivedData/UXVerification/AppTrust-M3-Live-R1/candidate.json` 绑定：

- signed main：`ed2e0e2bd1d55ba479f597460431ec7b50b5efcddbc147c7cd7c7b005b55c50c`。
- helper：`d1cbddb65d27865dba824a3d41d761b0408e80772604e92dbd2c301a41003f36`。
- canonical supervisor：`92cde62c8f09cb3270f12f6f67fbaf3ac2826642c80daa31e4c64a4a7b912a9a`。

两个签名均固定 identifier、同批准 Team、Development、Runtime、空 entitlement、`timestamp=none`；没有 Apple 请求。签后 help、语法 validate 和 mixed-family 早拒通过，未启动 runtime。既有四服务只读完整 confinement、固定 keyonly ID/实际公开主机 fingerprint 核验通过；没有重建或修改 fixture。

## 三种 fresh 真实场景

同一冻结 signed main，三次分别 fresh collect、新 UUID/new App store、独立180秒 finite relay。主管没有打开一次性私钥；消费者沿成熟 reader 在内存读取自己的 fixture 材料。公开收据固定叶复制原字节，`primary-live-summary.json` 逐份重新调用 canonical validator 验证。

| 场景 | run / App PID | 实际信任与认证事实 | 全案结果 |
| --- | --- | --- | --- |
| once2 | `df65a962-73a4-4575-b68b-fa30f3c76300` / 30026 | 两 fresh owner，各 pending1/primary1/KI0/shell1；两次批准前真实0/0/0/1；records为0/0/0，初始化后63字节及SHA始终相同；两次ACK/PTy/113×37成立 | failed cleanup；首组三weak最终nil，第二组三weak仍alive；27.492秒自然exit0，无signal |
| persist2 | `1b05d107-de35-4a4b-bb5c-7fc5badcc323` / 30414 | 两 fresh owner，pending为1/0，各primary1/shell1；records为0/1/1，首次写入后第二次公开字节与SHA相同；两个真实113×37终端 | failed cleanup；首组三weak仍alive，第二组三weaknil；26.757秒自然exit0，无signal |
| changed1 | `007b1e65-dd07-458c-a980-1dba75831354` / 30888 | 真正`NativeShellError.changedHostKey`精确expected/presented；callback独立且一致；pending/primary/KI/shell均0，原错误pin162字节及SHA保持；不打开客户端私钥、不读密码 | failed cleanup；三weak仍alive；19.648秒自然exit0，无signal |

三案实际每连接 `closeDisposition=closed`、canonicalDrained/queueEmpty均为true，registry active/retired回原0；**不能据此推弱对象已释放**。baseline分别21/21/20，全stable/complete；三案均未通过先行weak门，因此没有cleanup FD快照，不称FD恢复，也不能把`fixtureKnownHostsUnchanged=false`误读为检测出变化：终核尚未执行。早期认证收据明确resources-unverified，没有清除overall失败。

三finite relay PID29794/30216/30609分别自然exit0，用时204.773/204.732/204.766秒；accepted/finished为2/2、2/2、1/1，rejected及cleanup_failed全0，无signal，批准端口22221～22225已核free、无本轮App。固定原始证据在`AppTrust-M3-Live-R1/{Once,Persistent,Changed}/public-receipts/`，两种成功认证各2份auth收据，changed只有1份。

启动工具的两个前置失败也保留：新副本三份公开许可证初始0664被strict mode022门拒绝，主管仅本轮创建副本规范为0644，字节/main/helper/candidate JSON和strict签名保持；adapter错误要求unsigned Info含签后epoch，隔离红例后修为原件两键缺失/签后exactepoch。没有改原件或放宽权限门。新16个纯测试及实际只读candidate预检经主管独立通过；这些只是安全启动工具验收，不冒实网结果。

## 尚未通过的范围

原 SSH App 间歇 weak 对象未释放或 FD 增加三项的失败保留，本轮不复跑这些无变化资源案。图形资源调查在准确可见绘制前置不足时保持 STOP。真实三按钮点击、像素、实体键鼠、全116项、普通产品入口一致性及最终体验候选仍未验收，不标 `UX_READY_FOR_USER`。
