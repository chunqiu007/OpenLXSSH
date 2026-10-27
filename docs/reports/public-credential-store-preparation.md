# Public CredentialStore 生命周期消费者：离线准备与 R1 审查

日期2026-10-27，Task PUBLIC-CREDENTIAL-REVIEW-R1。**源码、纯测试与增量签名审点已通过主管审查；真实默认 file-based Keychain 生命周期未执行、未放行。不是 AUTH-02、App 凭据 UI 或 macOS26 验收通过。**

## 限定入口及真实动作边界

`Tests/RealIntegration/` 增加独立 `--credential-store-public` 测试入口。默认/help/validate仅解析，不打开store、读取fixture、调用SecItem或连接；future live需原本地fixture/engine门和独立`--authorized-test-keychain`事故门。该开关不代替用户授权或主管放行。本轮没有运行带完整live门的命令。

未来唯一场景固定passwordonly@127.0.0.1:22222、精确隔离代次与带外hostkey，内部fresh run/namespace/reference UUID，public `CredentialStore(testNamespace:)` 选择**当前默认file-based Keychain**；namespace只隔离service/account，不是独立物理Keychain。不同步、不设自定义ACL、不更改default/searchlist、不自动答系统授权，不进行枚举/未知重复项的read/replace/delete。

流程为非秘密prepared receipt持久化→public save(.granted)一次→仅明确.saved(exactReference)建立ownership→public SavedPasswordAuthorization provider只read该reference一次→原生产gate/once/token/关闭drain→deleteExact一次→read必须missing→store.close恢复进程交互策略。provider无fixture fallback/人工补答/gate覆盖，报告不存密码或答案摘要。失败保持精确恢复记录，prepared本身永不授权收养或删除未知条目。

## 原三项发现与修复

- **P1停止窗口**：原provider await后未直接核stop，connected可能先于stop被处理；fixture await之后也可能继续save。R1不可变MainActor stop guard同时核停止/Task取消，await前后、保存前、秘密返回前与成功前检查，停止优先。保存期间停止时，先登记明确.saved ownership，再响应停止，仍精确补偿，不以清理成功算业务成功。
- **P2父目录持久性**：原仅fsync receipt/run，未同步新run在父目录中的目录项。R1持有parent/run FD并核dev/inode/路径链接/UID/mode/noFollow/noACL，顺序identity→file write/fsync→identity→run fsync→parent fsync→identity；任一步失败拒后续正常admission。不是实际断电测试，也不声称完整掉电保证。
- **P2错误映射**：SavedPasswordPublicBudget typed error原被泛化。R1白名单逐项映射stale/extra/gate/取消等，未知仍fail closed，不导出raw Error。

主管读Consumer/Owner/Recovery/Guards/Contract/State/Status/两组测试和入口/build差异；原只读reviewer定向复审五文件，三项resolved且未发现新增P1。生产Packages、旧SavedPasswordPublicOwner和OSbuild白名单未变。

## 实际验证与精确构建

- 修前3项source边界回归exit1保留；新增8项行为纯测试为修后绿色验证，不冒称修前行为红证据。
- 8项pure测试含fake fixture/store await停止、save边界、connected同tick停止、saved后ownership补偿、durability六步失败注入、完整typed map及正常路径；主管独立exit0：`DerivedData/Verification/primary-credential-r1-pure-52bbbe08-d489-48f8-bf79-61f9929b2d60/`。
- 工程师完整离线一次、主管独立再跑均65 Swift/17 Python/29 CLI通过，主管日志：`DerivedData/Verification/primary-credential-r1-full-5140868d-a8f4-42ae-831d-e0eb6903ba8f/`。
- 增量仅编译RealIntegrationCore与Consumer，复用12依赖对象；18条命令均0、368输入及快照逐项核一致，无重新构建依赖/网络/原生库。父manifest SHA256 `30953428ec4f561585049f6ff40332b176d342656899b9de172a775939c94bbc`。
- 新App：`Tests/RealIntegration/.build/host-f20119c1-8514-4545-b4d0-eb9562da4d0d/OpenLXSSHRealIntegration.app`。
- 主程序SHA256 `3526b30837530e436b7e8278af695ffc8426bca01670429144e25afb1646cd1e`；helper `842ed0925afa5b36a4800bc68887c3abcc39881e965c675d92c8431c2e04a44d`。host15测试wrapper，非正式产品平台调整。
- 主管独立deep strict签名、主/helper摘要、368快照和inert signed help/validate/缺额外门，预期exit0/0/2；`DerivedData/Verification/primary-credential-r1-signed-d57f1a91-975d-4924-bcc5-417ee78b0d50/`。
- 完整工程师命令/父对象/来源：`Tests/RealIntegration/.build/credential-store-review-r1-8cce36ab-1ad6-41a1-98e6-2abe2d6bfc9c/verification.json` 与新UUID `commands.json`。205受检依赖源码不变。

## 未覆盖与风险

本轮未实例化真实CredentialStore、未执行凭据SecItem/save/read/delete、无Docker/连接；已有Development签名使用不冒充凭据测试。纯失败注入不等实际Keychain阻塞/系统授权/跨进程访问或掉电验证。

future live的SecItem调用本身不可取消/设独立deadline，外层结束可能留下prepared/owned记录，必须按精确namespace/reference处理，不能自动枚举删除。锁定/权限/交互恢复失败须保持失败且保留回执。当前gate仅host15/24H32/OpenSSH9.9p2，不扩称macOS26可自动使用。正式App保存/忘记UI、不可用人工回退、升级/重新安装/双机/目标系统仍待。

整体Goal NOT COMPLETE。
