# P8 候选打包入口：实现与独立审查

## 本轮结论

候选打包脚本及其101项独立fixture测试已完成主管复验；真实P6A未签名候选及后续B1干净源Development内部候选均已生成并核验。不是安装、Gatekeeper、Developer ID、公证或双机验收通过。本轮Transport安全修复未进入既有候选，最终仍需源码稳定后的新UUID产物。历史83项是R1时点，不是当前总测试数。

文件：`Scripts/package-release-candidate.py`、`Tests/ReleasePackaging/`、`docs/release/README-candidate.md`。默认unsigned，只显式选择已有Development/Developer ID身份才签名；不创建证书、不修改Keychain访问设置。Developer ID时间戳请求有独立显式开关，本轮未执行。脚本没有公证上传入口。

## 真实边界

构建前核源提交与dirty状态、固定构建输出/缓存/插件路径和祖先链接；只创建本轮UUID输出，不覆盖已有候选。校验正式名称、arm64、min26、App/helper布局、真实Mach-O MH_EXECUTE/LC_MAIN、可重定位依赖闭包和许可来源。当前V1只批准第一方主程序和固定helper，任何新增内嵌dylib/framework默认拒绝，须先审查来源与许可。

签名按内层代码到App顺序，不使用deep签名；严格验证identifier、Team、Runtime与权限。manifest记录实际commit/dirty、构建工具链、App目录摘要/清单、ZIP摘要、逐代码来源、实际链接依赖与许可；始终notarized=false/uploaded=false。不完整/失败marker不能视为完成候选。spctl结果独立记录，失败或超时不能冒充安装通过。

## 独立审查与修复

首轮71fixture通过后，只读审查发现4项真实缺陷：构建路径symlink检查晚于写入、拒绝真实helper裸@loader_path、未审查dylib可逃过许可覆盖、chmod后的MH_DYLIB可充当入口。作者在原5文件范围内修复，修前78项矩阵退出1的失败证据保留，原71项未删，新增12项后83项通过。

主管读取关键路径/二进制检查/来源/manifest实现，并独立执行：

`python3 -B -m unittest discover -s /Users/liuwenshuo/Desktop/OpenLXSSH/Tests/ReleasePackaging -p 'test_*.py' -v`

退出0，83tests/OK；日志 `DerivedData/Verification/primary-packaging83.log`。独立只读审查者定向重放原4问题，全部resolved：五类预存输出/插件symlink在任何tool调用前拒绝且外部不变、裸token接受但越界拒绝、未知dylib无完成manifest、真实header异常入口拒绝。只读现有Release主程序/helper字节与运行路径通过；这不是实际候选打包。

作者修前/修后证据：`DerivedData/Verification/ReleasePackaging-R1-d40d2ec7-fefc-48d1-adc8-004cf883ba56/`。隔离假App的系统ditto归档真实执行，签名/时间戳/build等为fixture模拟。

## 实际候选与 R2 hidden-native 证据

主管在P6A稳定停写时执行真实 `--allow-dirty` unsigned候选。首轮UUID `adc54006-a05b-4247-a2e2-ec6624820090` 在licenses阶段dependency-evidence失败，保留完整失败目录/marker，没有宣称候选完成。实际libssh2/OpenSSL以-fvisibility=hidden编译，Mach-O含defined local/private-external text，不是strip；原nm-g只看external缺证。

R2保留Swift外部定义路径，native改nm-U-m真实__TEXT,__text函数与已核lock/实际构建脚本/三archive摘要的唯一member精确符号映射，每库三个关键API需在同一代码路径共存；undefined/abs/data/const/unknownbinding/错误归属/单API/全strip拒。manifest记录binding/section、签名前codehash、witness/archive/member/provenance，libssl仅verified input不假称贡献代码，不宣称字节/bitcode等价或完整二进制SBOM。新增18项负正测，原83AST对照不删；主管读差异/测试、独立101tests退出0，并核真实失败产物只读适配109libssh2/908OpenSSL匹配、inventory不变。

随后主管真实重跑unsigned候选退出0：`DerivedData/Distributions/0.1.0-1-90084e491e2a/996cff64-e5cc-4efe-b4b3-80b3b0a3e4e5/`，manifest源commit90084e4且dirty显式，notarized=false/uploaded=false。App+helper arm64/min26、系统runtime闭包、静态原生依赖来源与完整许可、ZIP逐项摘要通过。主管另独立verify-manifest退出0。

此为**P6A时点未签名内部候选**，上传下载/任务UI尚未集成。spctl exit1/Gatekeeper false，strict封装签名与Runtime验证false，未安装/运行min26，不能正式分发或当最终Release。没有读取签名身份或执行codesign签名、没有时间戳/公证/上传；编译器既有adhoc不等发布签名。后续B1完整源码需新候选，不覆盖此产物。

日志 `DerivedData/Verification/primary-p6a-unsigned-candidate.log`、`primary-p6a-unsigned-candidate-r2.log`、`primary-packaging101.log`；R2只读诊断/证明见 `P8-ACTUAL-CANDIDATE-EVIDENCE-R2-3ae64fdb-2025-4e35-9b55-e8d95d7a8c8d/`。

## B1 干净源码 Development 内部候选（历史产物，未含本轮 Transport 修复）

主管在源码/构建停写并提交9fed318后串行生成：

`DerivedData/Distributions/0.1.0-1-9fed3180a60a/0608cf64-e5ba-4ad6-953b-a726167f4b0f/`

- version0.1.0/build1，来源 `9fed3180a60ab1725d876223033b9a715d8bf13a`、dirty=false，包含B1/R1完整本地功能；arm64/min26。
- 使用既有Apple Development身份，helper先/App后、Hardened Runtime、无entitlements、timestampnone，strict/deep封装验证通过。不是Developer ID；`spctl` exit3、Gatekeeper false。
- 实际包含GRDB7.11.1、SwiftTerm1.99.1 preview、libssh2 1.11.1、OpenSSL3.5.9；ArgumentParser/SwiftPNG/H虽然resolved，但未链接，不假称包含。没有Homebrew运行库。
- ZIP 7,417,890 bytes，SHA256 `dbab8a17f3945ccb7d9a2e72b5b3bc576762f1e7ba83604971247d4d7cb7f3bd`；App规范树摘要 `20301c50838c3616ef35b31b10dbe143e8852ee9093aa68e0e6eee8cfbf8edf9`；manifest SHA256 `0005ae8c6878c774fb466878dff1690489ea144839f9655ab8c5b587428bff63`。
- 主管独立 `--verify-manifest` 通过，并复核真实HEAD/摘要。首次额外比对误猜40位commit导致组合命令exit1，验证器本身已成功；随后从git取得准确revision重核通过，未修改manifest掩盖错误。

该产物未上传、公证、安装或在macOS26运行。后续对抗回归又发现voucher接收策略及发送超时ownership问题，旧候选不能用于证明新源码安全；最终需要新UUID候选，保留此历史产物不覆盖。

## 后续约束

实际打包需App/helper/Files集成结束、全部工程写入与构建暂停后串行进行；构建前预检不防御恶意同UID并发抢改。新增代码布局、剥离符号或依赖需要明确适配，不静默放宽。当前macOS15宿主不能运行正式min26产物，不以HostProbe冒充。必要Developer ID、公证具体产物授权、目标系统及双机/企业实测仍待外部条件。
