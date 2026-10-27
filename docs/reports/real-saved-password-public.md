# 真实公开密码授权：生产 gate 与无授权人工回退

日期2026-10-27，Task SAVED-PASSWORD-PUBLIC-PREP-A / LIVE-A。**host15/24H32下，两项生产public授权/人工回退实测通过。不是Keychain保存/忘记、App完整AUTH02或macOS26 gate验收。**

## 严格边界与实现

`Tests/RealIntegration/` 独立 `--saved-password-public` 两case，fixedpasswordonly@127.0.0.1:22222/newexactgeneration/CID/image/network/带外trust，默认/help/validate无I/O、双runtime门。产品Packages/OSbuild白名单/PasswordAutomationGate、原正向/负向认证实现不改。

授权案只调用公开 `DirectSSHSession.connect(configuration,savedPassword:SavedPasswordAuthorization(provider:...))`，真实productiongate自行决定资格，没有configureProbe/强制eligible。provider核当前session/generation且调用、读额度、返回各一次，读取前后取消/当前代次检查。provider公开API只有SessionToken，没有prompt参数，**不声称provider内做prompt SHA分类**。

授权案若到手动回调，立即gateNotCovered拒读/取消，不能自动手动补救凑成功。无授权案确实不传authorization，独立精确38bytes公开系统模板SHA/kind=unknownMasked/nohint只允许一次manualpassword。两者秘密只来自fixture privateinput到内存，无Keychain、argv/env/报告秘密或答案摘要。

报告keychainAccess=false/persistenceVerified=false，provider计数是测试预算控制流，不是OS全文件读取遥测。

## 主管源码与独立离线验收

主管完整读Contract/Policy/Owner/Consumer/tests，核token/once/取消/旧代次、原gate不覆盖、人工提示约束、close/drain与不虚构持久化。独立50Swift/16Python/25CLI、352input及快照/36命令、strictDevelopment签名通过：

`DerivedData/Verification/primary-saved-password-static-4c023ad5-52a0-463f-be9e-5544e041a89f/`

精确测试App：`Tests/RealIntegration/.build/host-11dceab6-5e20-4c07-b5f8-44a9ad9113dc/OpenLXSSHRealIntegration.app`

- 主程序SHA256 `e13ed4cbf0974708fd799d597834db1e7e2da60f9c7761dd0ae8e00827dacaf8`
- helperSHA256 `4a09932737cf4586ba115f26cb3608c27a15ebf0506dbbc3ff357563891b733c`
- host15仅测试，正式min26保持。

## 公开系统前提与实际两案

宿主build24H32；ssh版本精确 `OpenSSH_9.9p2, LibreSSL 3.3.6`；Apple系统ssh签名要求 `anchor apple and identifier "com.apple.ssh"` strict验证exit0。首次只读codesign命令-R内联requirement缺“=”而exit1，已缩证为语法错误并保留，不是gate拒绝，也未重跑认证。

freshpasswordonly generation `credentials-21f4f5eeb816`、带外trust/provenance/权限与App/snapshot核后，每case各一次，一个300s上限rootrelay：

| case | 退出/耗时 | 必须实际计数 |
| --- | --- | --- |
| positive-public-authorization | 0 / 19.029s | trusted outerconnected1，providerCall/read/return各1，manualRequest/read/reply各0，productionGateExercised=true |
| no-authorization-manual-fallback | 0 / 19.131s | outerconnected1，provider各0，manual各1，productionGateExercised=false |

手动提示由公开系统格式+精确HostKeyAlias独立计算，不复制观测hash：38bytes/SHA256 `7ae56f86343d23625f49ed78e8fb2429423a023fb6e64967263ff07e8113d1b3`。

两案closed/nilownedPID/providerAndManualTasksDrained/managementChildrenReaped=true，gateNotCovered=false。没有Keychain操作或持久化声明，未扩正式mac26资格。

## 资源与主管独立结果核验

relay29856精确TERM/waitexit0、accepted8/finished8/rejected0/cleanup_failed0（每case含扫描，不能当8次认证成功）。8个精确token目录/owner/tombstone均无，所属Docker/relay PID消失、root端口交接前无listener、五服务Healthy。203受检task/Packages/root源与App/契约hash未变，源码和runtime已停止。

真实argv/cwd/exit、原两报告、publicsystemprovenance和cleanup：

`Tests/RealIntegration/.build/saved-password-public-live-050684ee-0cc3-419d-8396-fbb9054db1c3/`

主管重新读取两原consumer result并核publiccase的provider1/manual0和无授权manual1/provider0、真实可信事件与close/drain、persistencefalse/Keychainfalse、源码无gate覆盖和最终资源元数据，不只信exit0：

`DerivedData/Verification/primary-saved-password-results-b67963cc-c1e6-4dc8-a4cb-77112af96792/`

未机械重复已完成两案。

## 尚未完成

真正保存到本机Keychain、App凭据元数据授权/读取/忘记、不可用人工回退与升级读取须另验；命名空间仅隔离service/account，不等独立物理Keychain。正式mac26 gate仍不在已测allowlist，不能根据本结果盲加。并发provider/强制late-result/取消等待真实压力等必要边界不能靠本两正向case补齐。整体Goal NOT COMPLETE。
