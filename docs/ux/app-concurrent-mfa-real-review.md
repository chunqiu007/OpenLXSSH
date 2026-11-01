# 新版 App 并发 keyKI：取消 A、继续 B 的真实分项

状态：**并发归属与认证分项成立；逐 owner 服务端挑战清理失败，全案 failed。** 不是 GUI、终端、完整资源或默认后端切换验收。2026-11-01（Asia/Shanghai）。

## 范围与安全边界

同一个批准的 key-kbd 端点/主机，两个全新 App tab/driver/token。两个首 KI 同时 pending 后，选中 B 尝试用 A 的 prompt 回答 B 必须拒绝；选中 A 取消，再提交迟到 A 回答必须拒绝；B 保持原 prompt/token 完成 `[1,1,1,0]` 四轮。负例使用非秘密值，不进入 B 的管理读取或 budget consume。

`AppConcurrentBuilder` 在真正 `SessionBuilding.prepare(hostID:sessionID:)` 时分配专属 ticket，再委托原 `NativeSessionBuilder`。不按 connector 到达顺序或端点分 A/B，package session UUID 与 App session ID 分别记录。返回原 transport，生产 driver 仍是唯一 receive/write/resize owner。

A/B 各持一份管理实例和 KI 预算。A 不读取任何 OTP；B 每轮以精确 fixture session/index 读取，await 后重核 App owner/request/lease。fixture session 仅在内存绑定，不输出其字符串、提示、答案或秘密摘要。主 Agent 不打开一次性私钥/OTP。

## 本地验证与独立审查

源码与验证证据：`DerivedData/UXVerification/ConcurrentKeyKI-R1-{Source,Verify}/`，最终 `Verify/run.iy18Xt`。

- 独立安全审查发现观察回调在闭包中投影整个 `NativeSessionConnect`，使 manual KI/trust 路径重新可达 primary owner。主批准对新 concurrent 与同类 Trust 观察 wrapper 做极小拆函数值/显式 capture 修复；不改生产 Driver 或认证策略。静态旧/注入负例拒、新源码通过，**不是弱引用生命周期实证，也不证明历史资源失败根因**。
- Host111/0 = Contract84（旧77+新7）+ Native27；Debug86/0 = 适用Contract59 + Native27。双图严格 Swift6、完整并发、warnings-as-errors、显式 min26/testabilityYES 构建通过。未重跑全部 Files、visible-R9 或中键。
- 新 Python129项、旧 Trust136项分别通过；unsigned惰性入口64项通过。实际 Swift auth/cleanup/overall/所有 optional 失败报告分别3111/667/9918/10474字节，未提高16KiB门。
- 主管读关键实现及增量后独立并发7 + Trust10 = **17/0**，独立重放129项 schema，十件实际 Mach-O 摘要/min26通过。主另独立实网工具12/0与实际公开 candidate 只读预检通过。
- 累计补丁 SHA256 `cf7788e49164b65df70b66f13b5374c643ace1804bb8a7cb854d4cfa5d44af58`；旧77方法与断言前缀保持。成熟 Controller/Driver/Package、fixture/project、默认 builder 未改。

## 真实运行

冻结候选：`DerivedData/UXVerification/AppConcurrentKI-R1-Live/candidate.json`，源为 `HostProbe26-AppConcurrentKI-R1`，unsigned main `650a6b3d906ca3ccff1991c513924476dc16dbf8b9d0879fbdfe7edcf5713554`。

离线 Development/timestampnone 的 signed main：`bb3b51812288152aa505ccb681cf7cddd17eaac9018777f59b578da38b1222b4`；helper `ecef945627cb2a27c89912e016435cf506d3494c5e4a45e4525d16aacb45591b`。同固定标识/Team/Runtime/空 entitlement，未发 Apple 请求。只有精确 fixture flags/contract 模式隔离自退，不能双击作正常体验或空白测试。

唯一 fresh run：`779632c7-106d-4ae5-8023-46dbcb0dc495`，App PID37852。

- A/B 首 KI 同时 pending，App ticket/tab/session/request、package session 和 fixture session 均不同；两 token 未取消，管理读取均0。
- cross reply和late A reply实际返回拒绝；B 原 prompt在cross后不变，A取消后B原 owner/token保持。
- A typed publicKey调用1次、code -19，当时未authenticated，不能据该返回码认定主密钥已接受；KI首轮1、读取0、回复0。取消形成typed `cancelled/cancel`，keyboardResult为 -10001，shell0。
- B typed publicKey调用1次、code -19，当时未authenticated；随后KI4轮、3次OTP读取/secret回复和1次显式空回答、late0，keyboardResult0后才出现authenticated/shellReady各1。credential store调用0。
- 两个连接实际 closed/nativeClosed/canonicalDrained/queueEmpty均true。A三weak nil，B三weak仍alive；本案没有进行终端/TUI操作。

独立公开收据 canonical 复核位于 `Case/public-receipts` 和 `primary-live-summary.json`。

## 清理失败，不做消绿重试

共享12秒清理内分别只读一次服务端状态：

- A：status1，**present**；管理1调用/1返回/1实际reap、pending0。
- B：response3 + status1，**removed**；管理4调用/4返回/4实际reap、pending0。

五个管理调用全部收尾并不代表 A 的挑战材料被清除。`cleanupObservation=per-owner-not-complete`、`cleanupComplete=false`；整案 `failureCode=cleanup`、`passed=false`。没有等待TTL、再认证sweep、管理unlink或重启fixture来追认通过。现 PAM 源依赖 Python finally 删除，历史取消路径已有未执行 finally 的风险；本案是新的实际 present 证据，尚未定位服务端精确终止原因，不称产品把 OTP 持久保存（A从未读OTP）。

本案未进入 allweak/FD终核，不称描述符恢复。App实际24.168秒自然exit0/noSignal，仍failed。finite relay PID37598自然exit0/204.762秒，accepted2/finished2/rejected0/cleanup_failed0，端口22221～22225已核free。

补充只读机制调查：原C bridge本地socket shutdown/libssh2 free/close不构成服务器PAM清理确认；当前fixture仅监督sshd master，没有独立逐认证清理owner。公开上游PAM取消路径可用SIGTERM终止worker，Python finally不保证执行，但本案真实worker/信号未观察，仍不能断言根因。最小本地公开哑数据模型正常返回/异常执行finally，阻塞子进程的默认SIGTERM留下同inode文件；父在记录metadata后精确清理。工程师3/0及主管独立3/0（0.375秒）均全child reap/自建目录清理，证据`DerivedData/UXVerification/PAMCancelFinallyLocal-R1/`。此模型未访问或修复真实A残留，不代原硬门。

## 后续边界

认证归属分项不代逐owner服务端挑战清理、App弱对象/FD或实体GUI。现有fixture不得靠修改TTL、重建健康服务或新认证sweep掩盖失败；服务端卫生问题需单独调查和明确影响边界。普通 Direct/本次密码 Native 入口尚未统一，有限transport混合负载已过而正常可见绘制资源门仍待，未 `UX_READY_FOR_USER`。
# Codex后续修复：fixture认证生命周期（2026-11-01）

**源码与离线门已审，旧真实A残留仍failed；现有容器尚未更新。** 取消A后B继续的原始认证/资源收据不改写。

`pam_fixture.py`原来只依靠Python `finally`删除挑战；默认信号终止可以跳过finally，但旧实网案没有具体worker信号证据，不能倒推其精确根因。原`server.py`还存在读取session后另写export的竞争，可能在取消清理后重新建立导出。

本次新增仅fixture使用的`challenge_owner.py`：现有supervisor内单个selector线程，私有Unix socket、peer UID校验、32 owner/64 client/4096B边界；PAM注册获ACK后才显示挑战，所属worker socket EOF或显式close串行清理对应session与export。创建/导出/删除同owner，未知inode/内容替换保留且health失败；不使用TTL/sweep消除取消残留。过期仍拒绝认证和导出，生命周期清理与时间有效性分开。

改动仅server/PAM/新模块/Dockerfile COPY和离线测试。原40个StaticTests方法AST未改，新增12项包括精确子进程SIGTERM/SIGKILL、A/B隔离、注册ACK前取消、export竞争、容量/权限/未知替换拒绝、重复关闭及实际PAM/server函数消费者。工程师52/0；主管读完整关键实现、精确diff与新增测试，并独立执行`python3 Tests/IntegrationEnvironment/test_static.py`：52/0、exit0。首次APFS目录linkcount误判失败保留；修后目录核dev/inode/UID/type/mode，普通文件仍严格单硬链及内容。

证据：`DerivedData/CodexTakeover/FixtureLease-02/`，含before、`source-increment.patch`、`source-review.json`、工程师原失败/最终日志及主管`primary-offline-tests.json/log`。本机Unix IPC不等Linux SO_PEERCRED/PAM/sshd实网验证。

真实复验仍需对既有获批环境执行受审刷新并记录新image/container/generation/pin，不热改健康容器。当前共用镜像的既有build guard不允许所属容器运行时重建，未绕过；后续优先使用现有受控停机/构建/恢复配方，明确所需四服务停机范围后集中确认。没有新增环境、连接生产、读取旧挑战/凭据或删除原失败材料。
