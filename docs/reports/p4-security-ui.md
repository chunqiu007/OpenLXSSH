# P4-SECURITY-UI/R1：正式App凭据和密钥管理审查

更新2026-10-26。工程师实现；Primary Agent独立审查。本地范围通过，完整产品/目标系统/真实SSH仍未通过。

## 交付与安全边界

真实接入OpenLXSSHSecurity与Core：密钥列表、Ed25519加密/无口令生成、RSA/Ed25519副本导入、公钥查看/复制、共享引用拒删、显式remember默认false、host密码忘记、私钥口令解除、精确跨存储补偿/恢复。OTP无保存入口。秘密只短期SecureField/SecretBytes，日志与journal无秘密，Swift副本不承诺彻底擦除。

主管已读取SecurityCoordinator/Journal/ViewModel/Views和原生控件、相关集成与签名脚本。创建先外部成功再Core注册；Core失败只补偿本次created UUID，失败精确ticket保留。Core先检查共享引用并持久化删除ticket，再外部幂等删除/完成，不通过删主机误删其他引用。

R1三个关键修正：

- 忘记私钥口令只解除当前key引用；旧口令仅无其他key/host引用才删除，私钥文件字节不改。Core受检API保持用途/授权/FK与单事务。
- 未确认prepared intent不证明外部资源存在/所有权。用户可核对kind/UUID/状态后仅丢journal，绝不删文件/Keychain/配置；注册metadata、pending/完成墓碑、非prepared均拒绝。完整record+随机revision绑定，旧确认/ABA/重新打开失效。
- key创建Core已经提交后journal清理失败返回committed+cleanupPending，不能throw误导用户再次创建或补偿已登记资源；注入故障测试保留文件/metadata并可重启恢复。

## 实际界面缺陷与修复

恢复会话确实复现32项中1个断言失败和多轮签名GUI失败，没有依赖旧通过记录放行。核心缺陷为嵌套SwiftUI sheet在模型reload/编辑后owner失效，保存已commit却弹窗未关闭。

生产界面现使用明确AppKit sheet owner（NativeSheetPresenter）：只持有/结束自己呈现的NSWindow，保留同item ID的NSHosting root与State；单一item调度主界面和安全子编辑器。确认/公钥/删除内容用独立ObservedObject及时更新错误。测试仍真实控件target/action与attachedSheet=nil断言，未用测试代码强关窗口。短复现最终连续3轮每轮7项通过。

## 主管独立验证

工作区 `/Users/liuwenshuo/Desktop/OpenLXSSH`：

```sh
/bin/bash Scripts/verify-app.sh all
/bin/bash Scripts/verify-app.sh signed-security
```

两条均退出0。正式Debug/Release arm64/min26编译与依赖元数据检查通过；HostProbe32测试（13基础+19安全）0失败；原生GUI15+8+7检查通过。

真实现有Development/runtime/timestampnone签名App：保存8、跨启动读取管理15、精确清理5项均通过，严格签名校验通过。测试UUIDnamespace、Keychain项删除后确认missing、Core registry/hosts为0、pending ticket0、恢复journal空。无证书/profile创建/ACL修改/系统授权代答/Apple上传。

主管本次证据：DerivedData/Verification及隔离GUI路径OpenLXSSH-AppSmoke-k7ap9her、签名OpenLXSSH-AppSmoke-tza739_i；工程师保留resume-r1-delivery-evidence及初始失败日志。AppKit owner、prepared确认与postcommit分支已逐项代码复核。

## 未完成

macOS26仅编译，HostProbe15不替代正式运行；人工IME/视觉、NSOpenPanel实际选择GUI、DeveloperID/公证/双机/真实用户企业策略与SSH/MFA/SFTP未验。安全包自建锁库真实验证与App签名真实CRUD分别记录，故障注入凭据替身不冒充系统Keychain错误。

下一任务为SSH/终端/信任/认证UI整合，随后文件面板/独立任务入口与传输关闭保护。整体Goal未完成。
