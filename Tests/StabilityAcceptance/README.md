# OpenLXSSH 有限稳定性验收驱动准备

## 五会话长测准备顺序（2026-10-29）

正式 App 的快速新建案例留下四次认证成功、第五次扫描失败及 relay 一次拒绝；旧计数没有拒绝原因，不能确证它是并发上限。既有测试 relay 每端口限八流，单次 keyscan 同时尝试三类密钥，长测不应额外要求五次并发扫描突发。

`connectFiveSequentially` 依次创建会话，每次都要求真实认证、有效 owner 和此前会话仍连接，再创建下一项；每项至多600次真实50ms等待，取消/睡眠/失败/此前断开立即拒绝。所有已创建会话仍由 Runner 统一清理，不重试、不接受新的主机密钥。五项均满足后才开始原有至少86400秒的共同连续计时，计时与资源判定不变。此工具改动不代表长测或并发突发场景已通过。

## macOS 26 接手：有界 FD 采样竞态修复

原真实 200 次运行完成了 200 次认证及 20 次另计取消，但因 6 个短命 helper 的 PTY 指标不完整而最终 `resourceUnavailable`，仍是 **failed**，原 JSONL 不改写。旧行未保存 errno，不能追认为下面已确认的 EBADF 情况；后续必须使用修复后的新驱动重新执行必要验收。

同一进程的 FD 可以在列表查询与 vnode 查询之间关闭。本机自有临时子进程实测：关闭后的 `proc_pidfdinfo` 返回零字节/EBADF，完整新列表不再含该 FD。新分类器仅在该精确错误、前后完整稳定的 PID/UID/PPID/birth、新列表完整有界且无重复并明确不含旧 FD 时，允许一次完整 FD/PTY 重采；不会把未知指标改为零。重采仍失败、权限错误、短读、未设置 errno、旧 errno、FD 仍在或身份变化均保持 incomplete。成功调用遗留的 errno 不作为失败依据。

`fdListResamples` 为正值时记录一次重采；`confirmedGoneHelpers` 为正值时记录精确路径匹配 helper 的独立严格身份读取确认消失。二者是可选附加字段，旧 schema 1 行仍可解码。精确匹配 helper 的指标读取失败不再静默忽略：只有独立严格身份读取明确 GONE 才跳过，UNKNOWN、仍在、父进程不匹配均拒绝。原 cleanup 三态规则保持不变。

`SamplingRaceRegressionTests.swift` 的 13 个新测试通过 C callback 注入覆盖上述正负分支；现有身份与清理 10 项回归继续保留。此修复仅影响验收工具，不修改生产 App/Transport，不代表 200 次或 24 小时验收已经通过。下文旧阶段的宿主、授权与执行记录作为历史保留。

## P7-STABILITY-DRIVER-BUILD-B：离线真实链接与 Development 签名

状态仍为 **PARTIAL：真实 driver 产物准备，不是稳定性验收通过**。本任务允许使用已有 Apple Development 身份做本地离线签名；不创建证书/profile、不改 Keychain ACL/search list、不代答系统授权、不请求 Apple 时间戳、不上传公证。宿主仍是 macOS 15.8.1，**不运行 min26 driver 或 helper**，不 connect，不读官方 fixture `.runtime`、私钥/密码/Keychain 凭据，不启动服务、VM、长测或输出压力测试。

### 配方与最小使用方式

- `build_driver.py`：默认/help 只打印帮助；`validate` 只读检查现成 cache、固定 pins/plugin 门禁及源文件元数据；`build` 才创建独占 `Tests/StabilityAcceptance/.build/driver-<UUID>/`。没有新增依赖 manifest，不调用 SwiftPM resolve/build、根 `build-app.sh` 或 Xcode 项目，不写产品包/checkouts/DerivedData。缺缓存、pin/plugin/源码变化、符号链接或无效路径明确失败，不下载补齐。
- 每次都从完整源码重编 runtime：正式 `OpenLXSSHTrust`、固定 SwiftTerm、正式 Askpass/Transport、`StabilityCore`/`StabilityPOSIX`、真正 `SignedDriver/Main.swift`、官方 `OpenLXSSHAskpassHelper/main.swift`。所有 **11 个 runtime 链接对象均为 arm64 / MH_OBJECT / minos26**；不混入离线 SwiftPM min15 对象或缓存低部署版本对象。依赖库支持低部署版本并不意味着正式 App 部署有错；这里是本任务额外的严格输入约束。
- 只读调用 `Scripts/verify-build-plugin.py --helper` 的原有固定图门禁，并独立固定该门禁脚本 SHA。SwiftTerm 官方 generator 三份源码、plugin、manifest、terminfo 均先校验、记录哈希。generator 单独作为 **host-only 构建工具**编译并运行，生成官方 `SwiftTermBuildInfo.swift` / `SwiftTermTerminfo.swift`，不手造常量、不链接入 driver/helper，不是 Transport HostProbe，不降低任何 runtime 部署版本。
- 编译输入在 UUID 下快照并哈希；构建前后复核原源码和快照、源集/pins/plugin；记录真实 Git commit/dirty/status、编译器/SDK/Xcode、全量源文件/生成输入/输出哈希、对象哈希和 load commands、完整 compile/link 命令、link map、符号与系统 runtime 依赖。不接受调用者传 revision 充当二进制来源。SwiftTerm 上游警告保留原输出，不修改/压制源码或警告来过关。
- 直接链接带 `-Xlinker -no_adhoc_codesign`，先验证无隐式签名且 unsigned strict 校验必须拒绝；链接产物为 arm64 / **MH_EXECUTE / minos26**。实际 link map 必须恰好包含所记录的 min26 对象与所选系统 SDK `.tbd`，拒绝额外对象/兼容性 archive；允许 Apple 的同 SDK 版本别名规范化。只允许 `/usr/lib` 与系统 framework 的直接 dylib 依赖，无工具链或用户 dylib/rpath。此为静态闭包检查，不冒充目标 macOS 26 dyld/runtime 测试。
- `prepare_wrapper.py prepare` 不再接受任意 driver/helper/revision 包装：只接受该 UUID 内完整的 `linked-build.json`，复核来源、对象、链接命令/产物哈希后创建唯一 `wrapper/OpenLXSSHStability.app`，绝不覆盖旧 wrapper。旧 `validate --driver/--helper/--revision` 为兼容原离线测试仍保留，**仅表示输入元数据有效，不验证可执行代码或来源，也不能包装**。
- `--sign-development` 在完整链接之后才查询一次现有身份，结果仅内存解析，不打印/记录证书名或 identity hash，不导出私钥；无身份退出 3，保留编译产物但不签名。先签并严格校验 helper，后签并 `--verify --deep --strict` 校验 App；要求 `anchor apple generic`、正式 identifiers、有效且相同 Team、Hardened Runtime、无任何 entitlements、`--timestamp=none`。签名诊断不落日志，仅保存脱敏结果。保留正式 `org.openlxssh.OpenLXSSH` / `org.openlxssh.askpass` 身份要求，未修改产品校验策略。
- 签名后只有 `vtool` / `otool` / `nm` / `codesign` 等静态检查，不执行 driver/helper。不要安装这个验收 wrapper 或与正式 App 同时启动。

```sh
# 默认只读 help；不编译/签名/查询身份/联网
PYTHONDONTWRITEBYTECODE=1 python3 /Users/liuwenshuo/Desktop/OpenLXSSH/Tests/StabilityAcceptance/build_driver.py
# 只读：缺固定 cache 明确失败
PYTHONDONTWRITEBYTECODE=1 python3 /Users/liuwenshuo/Desktop/OpenLXSSH/Tests/StabilityAcceptance/build_driver.py validate
# 真正 min26 离线编译、链接和独占包装；不查询签名身份
PYTHONDONTWRITEBYTECODE=1 python3 /Users/liuwenshuo/Desktop/OpenLXSSH/Tests/StabilityAcceptance/build_driver.py build
# 本任务明确允许的现有 Development 签名；不运行 min26 产物
PYTHONDONTWRITEBYTECODE=1 python3 /Users/liuwenshuo/Desktop/OpenLXSSH/Tests/StabilityAcceptance/build_driver.py build --sign-development
# 已签名 UUID 的只读复核，不签名、不运行
PYTHONDONTWRITEBYTECODE=1 python3 /Users/liuwenshuo/Desktop/OpenLXSSH/Tests/StabilityAcceptance/build_driver.py verify --record /absolute/path/to/Tests/StabilityAcceptance/.build/driver-<UUID>/result.json
```

配方 `result.json` 是可复核的本地来源记录，不是来自敌对同 UID 进程的密码学证明；原源码变化后只读复核必须失败，应按新输入重新构建，不能改写 revision/hash 来沿用旧产物。失败 UUID 及其日志保留，不自动清理；本轮早期失败分别为 Swift WMO 输出参数不兼容、`codesign -R` 文本前缀遗漏、link map 的 Apple SDK 版本别名尚未规范化，均已定位修复，不能记作通过。

### 离线回归入口

原 **34 XCTest + 6 Python** 检查和原 API typecheck 保留；新增 `test_build_driver.py` 检查 help 不启动工具、cache/path/symlink/pins/plugin/source/snapshot 变化、禁止记录指向任意秘密路径、min15/min11/x86/非 MH_OBJECT、非系统 runtime/rpath、unsigned/无身份/错误签名/entitlements，以及旧 revision 不能包装。身份失败单测只注入本地进程输出，不查询真实 Keychain，也不将合成输入冒充真实 driver。

```sh
PYTHONDONTWRITEBYTECODE=1 python3 /Users/liuwenshuo/Desktop/OpenLXSSH/Tests/StabilityAcceptance/verify_offline.py
```

新版总入口把 scratch/cache/log/typecheck 输出集中在新的 `.build/offline-<UUID>/`，不覆盖历史 `.build/offline`。先保留 `--disable-get-task-allow-entitlement` 的 SwiftPM 构建图并检查无 codesign/debug entitlements，再执行原 34+6、新配方测试、严格 C syntax；没有真实 driver 的执行入口。下面 prep/R1 阶段的命令、停止点与签名偏差是历史记录，不是本任务对新配方权限/已执行事项的描述。

## 历史记录：PREP-A / PREP-R1（原文保留）

Task `P7-STABILITY-DRIVER-PREP-A` / `P7-STABILITY-DRIVER-PREP-R1`，状态 **PARTIAL：驱动准备，不是稳定性验收通过**。

本目录只新增验收工具，不改变 App、Transport、Trust、安全策略或产品依赖。当前宿主为 macOS 15.8.1；没有获授权的隔离 runtime/server。**本轮没有真实 SSH 连接、镜像下载、安装/启动 VM、真实签名身份查询、正式 App/helper 签名、驱动链接/运行、200 次真实循环、24 小时运行、睡眠设置修改、服务/调度或上传。**

实际约束偏差：早期离线 `swift test` 未关闭 SwiftPM 默认 debug entitlement 步骤，工具链曾对本目录的离线 `stability-preflight` 自动执行 `codesign --force --sign - --entitlements ...`（ad-hoc debug 签名，没有查询或使用真实签名身份）。这仍偏离本轮“不执行签名”的限制，已向主管报告；不能写成绝无签名执行。发现后改用 `--disable-get-task-allow-entitlement`，先只生成构建图并检查没有 codesign/entitlement 应用步骤，再执行离线复验。真实 driver/正式 App/helper 始终未构建、签名或运行。

## 文件与边界

- `Package.swift` / `Sources/StabilityCore/`：无任何远程或本地产品包依赖的离线选项、安全启用检查、有限生命周期、连续时长判定、有界证据。
- `Sources/StabilityPOSIX/`：macOS 只读权限/ACL与已知 PID 资源采样；唯一写入口为显式运行后的独占 JSONL 文件创建，不实现 SSH，不杀进程。
- `Sources/StabilityPreflight/`：可运行离线 CLI，默认 help；validate 无写入/网络；即使带授权 flag，run 仍拒绝，因其没有 Transport 实现。
- `SignedDriver/Main.swift`：真正公开 `DirectSSHSession` API 的 AppKit consumer。**不在上述 SwiftPM targets 中**，没有本地/合成会话替代真实驱动，没有调用系统 ssh CLI 来代替产品 API。真实连接路径保留 `SystemHostKeyScanner`、正式 `HostTrustStore`、正式内嵌 helper、outer-auth broker 和 PTY owner/reaper。
- `prepare_wrapper.py`：未来将显式提供的本地 driver/helper 二进制复制到一个固定 `.build/wrapper/OpenLXSSHStability.app` 的准备源码；默认 help/validate 只读，不编译、不签名、不查询身份、不执行、不覆盖已有 bundle。本轮未执行 prepare。
- `Tests/StabilityCoreTests/` / `test_offline.py`：离线 unit、黑盒拒绝、静态检查、现成模块 typecheck。合成会话只测试驱动循环合同，不是正式 Transport 测试，更不是实际 200 次 SSH。
- `verify_offline.py`：有限离线总入口，默认显式禁用 SwiftPM debug entitlement，先生成并检查无 codesign 构建计划，再跑本目录小型 tests/typecheck/C syntax；没有真实驱动构建/执行入口。

## 本轮可执行的离线验证

所有 build/cache/test 临时数据限于本目录 `.build/`；SwiftPM 图没有 `.package` 声明，不解析产品远程依赖。测试以 `0700` UUID 临时子目录及非秘密 public/metadata sentinel 做文件边界验证，不读取真实 IntegrationEnvironment `.runtime`。ACL 测试只对自己临时创建的文件增加/移除测试 ACL。

推荐总入口（结果日志写入本目录 `.build/verification/`，先检查构建计划无签名步骤）：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 /Users/liuwenshuo/Desktop/OpenLXSSH/Tests/StabilityAcceptance/verify_offline.py
```

等效的单项命令：

```sh
swift test --package-path /Users/liuwenshuo/Desktop/OpenLXSSH/Tests/StabilityAcceptance \
  --scratch-path /Users/liuwenshuo/Desktop/OpenLXSSH/Tests/StabilityAcceptance/.build/offline --jobs 2 \
  --disable-get-task-allow-entitlement
PYTHONDONTWRITEBYTECODE=1 python3 /Users/liuwenshuo/Desktop/OpenLXSSH/Tests/StabilityAcceptance/test_offline.py
```

`test_offline.py` 只消费现成的 `OpenLXSSHTransport/.build/macos26/.../Modules` 和离线核心模块，使用 `swiftc -typecheck -warnings-as-errors -target arm64-apple-macosx26.0`。没有链接/构建真实 driver，没有重建 native 或产品包；模块缺失则明确失败，不补建、不下载。typecheck 不能证明签名、Mach IPC、真实网络或目标系统运行正确。

离线 CLI 可直接执行，避免 `swift run` 带来的构建写入：

```sh
/Users/liuwenshuo/Desktop/OpenLXSSH/Tests/StabilityAcceptance/.build/offline/debug/stability-preflight
/Users/liuwenshuo/Desktop/OpenLXSSH/Tests/StabilityAcceptance/.build/offline/debug/stability-preflight validate
```

不提供文件时，validate 只验证有限计划，明确不检查 fixture。本轮不运行真实材料 validate。未来材料验证只读 `known_hosts`、`fingerprint.txt`、`id_ed25519.pub`、`provenance.json`；`id_ed25519` 仅以 `O_EVTONLY` 检查元数据；不打开 `password.txt` / `key-passphrase.txt`，不读私钥内容、不访问 agent/默认 `~/.ssh` / Keychain。

## 真实运行前必须单独满足的条件

1. 用户已经明确批准隔离 runtime、Linux/容器下载和官方 fixture 的构建/运行，以及本次连接/稳定性测试。**`--authorized-isolated-run` 只是防误操作开关，不是用户授权。**本轮未得到或使用该授权。
2. 正式 Apple Silicon / **macOS 26 runtime**。驱动 run 在其他主版本直接拒绝。没有降低产品部署版本，也没有把 HostProbe 当作正式证据。
3. 使用 `Tests/IntegrationEnvironment/README.md` 的受控 fixture 及其正式 `collect`，首版只接受 `127.0.0.1:22221` / `fixture` / `keyonly`。拒绝所有 DNS、IPv6、其他 127 地址、简写/整数表示、非该端口、非 keyonly；不查询 DNS、不支持生产 endpoint。该限制是有意比一般 loopback 更窄。
4. collect 通过本地管理通道导出的独立 `known_hosts`、host fingerprint 与 client public key。使用者已核对来源并显式传入 `--verified-host-fingerprint SHA256:...`。`provenance.json` 是可审阅记录，不是密码学来源认证；必须另外审查官方 fixture 和隔离 runtime。不能用 keyscan 直接批准、不能在运行时接受未知/变化的主机密钥。
5. 材料目录必须为 `.../Tests/IntegrationEnvironment/.runtime/keyonly/credentials-<12 lowercase hex>`。`.runtime`、service、generation 目录当前 UID/`0700`、无扩展 ACL；读取的公钥/元数据和私钥当前 UID/`0600`、无 ACL、普通单硬链接文件。逐级 `openat(O_NOFOLLOW)` 拒绝父路径及最终路径符号链接，不自动 chmod 或剥离 ACL。文件路径与权限在启动时检查，正式 Transport 启动前再次检查私钥；与产品相同，不能作为对抗相同 UID 恶意进程后续 pathname 替换的完整安全边界。
6. 使用 fixture **无口令**的一次性 `id_ed25519`。不把秘密放到配置/argv/env/log。首版没有 passphrase 输入；任何认证请求（包括加密 key、密码、OTP、未知 MFA）都明确 `unsupportedAuthentication` 并取消，不猜测、不自动回答。**这只覆盖稳定性驱动 keyonly 子集，不声称四类认证/MFA验收。**
7. 主管另行审查、构建真实 `SignedDriver/Main.swift`，静态链接/嵌入正式 release Transport 及其固定依赖；不能链接离线 `OfflineSession` 或 HostProbe backdoor。本目录刻意没有会自动构建产品依赖图或下载依赖的 manifest/脚本。**本轮尚无真实 driver 链接产物；完整构建配方和二进制来源/哈希验收为下一独立步骤。**
8. 将真实 driver 与正式 `openlxssh-askpass` 放入 wrapper。保持产品要求的 App bundle/signing identifier `org.openlxssh.OpenLXSSH`，helper identifier `org.openlxssh.askpass`，同一已批准团队、Hardened Runtime、无调试/绕过 entitlements，使用现有严格 Development 签名流程，不使用 ad hoc、关闭校验或修改 broker 固定信任身份。必须先验证 helper，再严格验证整个 `.app`。没有证书时停止，不另查/导出私钥或更改 Keychain。wrapper 的显示名称区分验收工具，不能替换/安装成正式用户 App；不要与正式 App 同时启动。
9. `Info.plist` 内 `StabilitySourceRevision` 为被审查源码的实际 40 位 Git revision。另保存编译器/SDK、源/包/二进制及 helper 摘要、机器/服务器配置、签名验证证据和干净/有改动状态；不能把传入 revision 当作二进制来源证明。
10. 选择自己创建的无 ACL/无链接 `0700` 输出目录并显式传入。工具只创建唯一 `stability-<UUID>` 子目录，保留 JSONL、public trust；运行前显示 endpoint、模式、循环/会话/时长、host fingerprint、实际签名 `.app` 路径，不上传。用户显式前台启动，不能自动排程、后台续跑或拼接。

`prepare_wrapper.py` 未来提供 `validate` / `prepare`，具体参数见 help。prepare 只做源文件复制及 plist 生成，不证明输入是正式 helper 或真实 driver，不签名也不使产物自动可运行；后续正式签名检查和产品 helper/broker 会继续拒绝错误身份。**本轮不要执行 prepare、签名或任何真实 run。**

## 有限运行合同与证据

### 200 cycles

- 固定要求 **200 个真实 outer-auth 成功**，不是 200 次 spawn、连接尝试、shell 文本或取消数。
- 默认每第 10 个 cycle 前增加一次 preparation 中取消，20 次取消**另计**，不从 200 成功数中扣除。`--cancel-every 0` 可关闭穿插；只有真实 backend 仍为 `.preparing` / `.connectionPending`、抽象 phase 为 pending、没有认证事件且没有失败闩锁时才允许主动取消。closing、failed、closed、认证挑战/未知信任和 pending＋failure 均拒绝并仍等待 owned cleanup，不计 cancelledAttempts。该时机不保证覆盖“网络握手中取消”，实际事件阶段需真实运行审查。
- 每次只创建一个 session；成功等真实 `.connected` 且 owner PID 非 nil。关闭后必须 `.closed` **且** `ownedProcessID == nil` 才计成功并创建下一次。
- 连接等待最多 600 次 50 ms，清理最多 240 次 50 ms；失败/用户 SIGINT/SIGTERM 先 cancel/close 当前所属 session，再有限等清理。没有全机 SSH 进程发现/kill。

### 5 sessions × real 24 hours

- 固定 5 个独立 `DirectSSHSession`、普通远端登录 shell，不注入远程命令/终端输入。五者均收到真实认证事件后才开始连续时钟。
- 最少 86400 秒，最多 7 天；没有时间倍率、可注入生产时钟、resume/重连/合并、改系统时钟、caffeinate/power assertion、sleep 设置、Cron/daemon/开机服务。
- 实际 wall UNIX、Darwin `CLOCK_UPTIME_RAW`（monotonic awake；`CLOCK_MONOTONIC_RAW` 在 Darwin 含睡眠，故不用于 awake 计时）、`mach_continuous_time`（含睡眠）起止及三类 elapsed 全部记录。每 50 ms 检查状态和时钟；采样间隔默认 30 秒，可 5..60 秒。
- 任意会话退出/认证失败、系统睡眠/唤醒通知、总 continuous−awake 差异超过 2 秒、wall−monotonic 差异超过 5 秒，或超过 `sampleSeconds+5` 的观测缺口 => fail/incomplete，绝不补短时段。微小睡眠未发通知且不足容差仍是尚需目标系统实测的边界。
- 合成时钟 unit 只证明判定逻辑，完全不写真实验收记录；不能用测试运行时间称作 24h。

### 资源、日志与清理

- JSONL 每行最大 16 KiB，总最多 25000 行/128 MiB，超限失败；参数拒绝必然超过行数预算的组合。每次写后 fsync。无终端输出、提示文本、私钥/口令字节、密码/OTP、完整 argv/environment/session transcript。
- 采样 self 与从公开 `session.ownedProcessID` 取到的 SSH PID；验证 UID、直属 parent、kernel start time。helper 仅从这些已知 SSH parent 的直属子进程中按精确 bundle 内 helper 路径取样，再检查 parent 身份。已观测 helper 即使被 reparent，也按 PID+UID+start time 检查存活；回收后的同 PID 新进程不是所属资源。不会遍历全机名称、猜 PID 或发 kill。
- RSS 为每个进程 point RSS 字节直接相加，**共享页重复计量**；FD 为描述符数量；PTY 为 FD vnode `/dev/ttys*`、`/dev/pty*`、`/dev/ptmx` 描述符计数，**不是唯一 PTY 设备数**；threads 是 kernel thread，不是假装 Swift task 数。
- helper 短于采样间隔可能不可见；非 vnode PTY/master、Swift tasks、Mach rights、精确终端弱对象数没有完整探针。未知/无法读取指标明确不完整并阻止 completedDriverScope，不能以 0 冒充。Swift task/唯一 PTY/完整 helper 后代及 ARC 对象验收仍须额外工具支持。
- 清理只调用本次保留的 sessions 的 `cancel/closeTab`，等待 closed+nil，再对已观测 SSH/helper 做 **alive / confirmed gone-or-recycled / unknown** 三态身份检查。C 层用两次完整一致 identity 读取，不把 EACCES、部分 stat、读取间身份变化、zombie/in-exit 或缺失资源指标当退出；仅初次读取明确零字节＋ESRCH，或完整稳定身份的 kernel birth 不同才能忽略。相同 birth 仅 UID 不匹配为 unknown，helper 被 reparent 仍是 owned。unknown 直接 `resourceUnavailable`、标记 `metricsIncomplete` 并阻止完成，不返回空资源集合；alive 阻止 cleanup。正式 Transport 是唯一进程/PTY owner/reaper，本驱动不自行杀 PID。
- 仅 `rmdir` 本次准确 UUID 根下的空 `sessions/`，非空/链接/权限异常即拒绝；不递归删除，不触碰真实 fixture `.runtime`、其凭据、容器/服务、App 数据或其他目录。保留 public trust 和 JSONL 便于独立审查。

## R1 离线修复证据

- 原源码与 SHA-256 保留在本目录 `.build/verification/r1-before/`，没有重置产品或并行改动。
- 修复前新增 9 项纯离线查询/会话注入回归，执行退出 1、8 个断言失败；日志 `.build/verification/r1-before/regression.log`。只添加查询注入 seam，未提前改变原失败判定，证明未知清理和失败取消计数缺陷可复现。
- `R1RegressionTests.swift` 另含真正 C 身份分类器的 callback 注入，覆盖 EACCES/未指明错误/部分 stat/第二次失败或 identity 不稳定/UID 与 birth 分类，不实际查询虚构 PID。原 20 项 XCTest 与 6 项 Python 检查保留；真实驱动仍仅现成模块 typecheck。

## 不可由本工具替代的验收

- AC-28/29：仍未执行；必须未来实际 200 次网络认证/关闭与 5 会话连续 24h 才能提供必要证据。驱动结果名称 `completedDriverScope` 不是产品 AC 通过。
- AC-30：大量输出、快速标签切换、UI响应/渲染没有实现为本轮负载，不能通过此 CLI 宣称满足。
- AC-32：这里只检查驱动关闭；正式主窗口/退出、App 文件连接、终端对象、MFA/SFTP 生命周期与完整 helper 资源仍需真实 App 验收。
- PERF-R：只准备 Transport fixture self+所属 SSH/helper 的同口径采样；不是完整正式 App Release 内存，也没有 Instruments Allocations/Leaks/Time Profiler 证据，不能将努力目标记为达到。

停止点：离线测试、静态检查、真实公开 API typecheck 和源码审查；外部授权、macOS 26、真实二进制构建/签名/验证以及真实运行都留待主管协调后的独立任务。
