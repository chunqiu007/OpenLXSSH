# P1-03：凭据与私钥原型审查（进行中）

日期：2026-10-25。执行者：software-engineer；独立审查：Primary Agent。

## 当前结论

PARTIAL。本地私钥/授权策略/共享引用最小状态机已通过独立复核；真实 Data Protection Keychain CRUD 在原始SwiftPM进程及正确开发签名的App探针中均失败。签名探针已完成，官方文档确认还需合法provisioning profile授权；不降低存储安全策略，也不把40项独立测试的通过当作整个任务通过。

实现：`Experiments/P1-03-CredentialKeyProbe/`；无外部依赖，实验最低macOS15不改变产品macOS26目标。

## 代码审查

主管已读取全部核心Swift/C文件及3个测试文件：

- CredentialStore只按自己的service+account精确查询，未获记住授权时不调用存储；Data Protection Keychain、Synchronizable=false、WhenUnlockedThisDeviceOnly、禁止交互授权。读取失败返回人工输入路径，不落盘、不无限重试。
- SecretBytes不Codable且显示/反射遮蔽；测试秘密运行时随机。Swift/Data不保证彻底擦除所有副本。
- KeyStore用系统ssh-keygen验证与生成标准OpenSSH；口令经受控stdin管道、不进argv/env。最小C glue直接execve，无Shell，子进程无控制终端，超时/取消回收。
- 私钥导入建立管理副本、不改源文件。0700/0600、逐组件O_NOFOLLOW、大小上限、读取前后元数据、独占提交、路径与链接校验；公钥只返回algorithm+base64，不带私钥注释。
- ReferenceLedger为内存状态机，不是正式数据库。共享引用存在时不删资源；跨Keychain/元数据补偿及失败ticket明确，显式有限重试，不声称崩溃一致性已完成。

## 实际验证

命令工作目录/包为 `Experiments/P1-03-CredentialKeyProbe`。

| 执行者 | 命令/场景 | 结果 |
| --- | --- | --- |
| 工程师 | Debug/Release build，Swift warnings-as-errors与C -Wall/-Wextra/-Werror | 各退出0 |
| 工程师 | Debug/Release完整 `swift test` | 各退出1；34项，33通过、1真实Keychain失败 |
| 工程师 | 明确独立的CredentialStoreTests、KeyStoreTests、ReferenceLedgerTests集合 | Debug/Release各33项通过；不包含另行保留失败的真实Keychain |
| 工程师 | 独立集合ThreadSanitizer | 退出0，33项通过 |
| 工程师 | Debug/Release CLI --local-keys / --keychain | 本地key退出0；真实Keychain退出3、saveSucceeded=false |
| 工程师 | 显式Swift/C arm64-macos26交叉构建 | 退出0，minos26.0、SDK26.2；未运行 |
| 主管 | 全量 `swift test --package-path <包> -Xswiftc -warnings-as-errors -Xcc -Wall -Xcc -Wextra -Xcc -Werror` | 退出1；34项，33通过、1真实Keychain失败；与工程师结果一致 |

真实密钥测试覆盖Ed25519/RSA各有口令与无口令四种；源内容/权限/mtime不变，管理副本权限、错误/缺失口令、损坏/不支持算法、特殊文件名、取消、删除不跟随链接、共享引用与补偿通过。

完整失败：授权保存返回 `errSecMissingEntitlement(-34018)`；defer精确删除也被拒；`saveSucceeded=false`。未成功新增测试条目，不能把清理请求执行写成清理成功。未扫描其他条目，未降级到登录Keychain或明文文件，未改ACL或账号安全设置。

日志：实验 `.build/verification/`，重点 `debug-test.log`、`release-test.log`、`thread-sanitizer.log`、`debug-run--keychain.log`、`security-scope-check.log`。主管读取了真实Keychain失败、安全范围和target26元数据记录；独立全量测试结果直接与上述证据对照。

## P1-03-R1 签名探针复验

新增 `Scripts/verify_signed_keychain.py`、自身 `LiveSigningDiagnostics`、`LiveKeychainHandoff` 及7项测试；复用原CredentialStore/LiveKeychainProbe，原失败断言未改。只用现有Apple Development身份，无证书/profile创建、无Apple登录或上传；签名 `--timestamp=none`，无网络timestamp请求、无ACL修改或代答授权。

- 工程师签名脚本退出1：build/codesign/严格验证各0；真实Keychain CLI退出3，saveSucceeded=false、精确defer删除仍拒绝。
- 同脚本 `--diagnostics-only` 退出0，运行时appID存在且匹配实际证书Team+fixture identifier、动态签名有效、embedded profile=false；只证明值存在，不证明profile授权。
- Debug/Release完整测试各41项=40通过+1原真实Keychain失败；新增7项TSan通过。
- 主管读取5处R1实际代码、签名/CRUD失败日志与运行时诊断日志，并独立复跑完整41项：退出1、40通过+1相同失败；独立对已签名fixture严格验证和执行无Keychain诊断均退出0。

主管独立读取 [Apple TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains) 确认：Data Protection Keychain的访问组entitlements必须由provisioning profile授权，app-like bundle需嵌入profile；签名有效与SecTask返回值不能替代这一条件。当前没有profile，停止继续试新entitlements，不伪造授权。

日志：`.build/verification/signed-keychain-68ba5b22-a4af-4449-901d-4fe633b9c628.log`（签名/真实CRUD失败）；`signed-keychain-bfc109a9-95b6-4df8-a85c-e07bea80f411.log`（运行时诊断）。跨启动/同身份版本替换基础代码与替身测试已准备，但真实保存失败，未进入真实重启/版本替换读取；不能写成通过。无成功新增测试条目、pending ticket=0。

## P1-03-R2：显式file-based候选

独立候选没有修改DP原实现/失败断言，也没有自动fallback。主管读取候选全部Swift/C、真实fixture、签名脚本与6项测试，独立运行 `verify_file_keychain_candidate.py` 退出0（run cd8b4339-2b96-40fb-bb3c-0bb0a3384478），另独立6项候选策略测试退出0。

真实CRUD/未授权不写/重复不覆盖/精确namespace、默认creator ACL、跨启动、同DR版本替换读取成功；同Team不同identifier和同identifier ad-hoc读取均denied，不将missing假装成权限拒绝。自己的条目精确删除后确认不存在、ticket0。ACL只读检查decrypt1、trustedApp1、creator匹配、unrestricted0；无自定义allow-all ACL。同步属性系统未返回，不能假称读到false；明确选择同步false/DPfalse且itemRef归属file Keychain，语义不等价ThisDeviceOnly。

进程级禁UI guard仅fixture内读取/设置/恢复，不改用户全局Keychain配置/ACL，不答授权提示。生产必须一次串行拥有/lease，不能照搬并发per-call恢复。真实锁定仍未验（不锁用户库），正式包将用自己临时Keychain做独立分支验证。

基于实际证据与Apple TN3137，主管ADR `docs/adr/p1-03-file-keychain-selection.md` 批准V1显式file-based生产集成；旧DP实验仍失败并保留。正式 `Packages/OpenLXSSHSecurity/` 正在独立实现，不把候选成功算产品AUTH验收。

## 未覆盖与后续

DP路线若恢复需合法profile；当前V1选择显式file-based，避免把profile缺口当全产品不可推进。传统Keychain弃用风险、锁定与不可复制语义差异准确披露，未来迁移需显式授权。

真实锁定、用户取消等目前仅替身分支；正式数据库崩溃恢复、升级/重装/双机、App Sandbox、macOS26与真实SSH/SFTP认证未验证。私钥来源路径严格拒绝符号链接（包括系统别名）；仅系统临时父目录作realpath解析。管道口令限1023字节且拒绝NUL/CR/LF，此限制需在最终产品说明。

产品AC-05～AC-11及AC-27仍未通过；P1-03整体尚未验收。
