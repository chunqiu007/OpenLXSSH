# P4-CREDENTIAL-A：正式安全包审查

日期2026-10-26。工程师实现；主管独立审查。

## 结论

`Packages/OpenLXSSHSecurity/` 本机包范围通过，批准App集成。完整AUTH/KEY、正式macOS26/签名升级/双机验收仍未完成。

显式file-based Keychain按ADR选择，不是DP错误fallback。生产service `org.openlxssh.credentials`，类型+UUID account、同步false、默认creator ACL，不声明ThisDeviceOnly/屏幕锁等价语义。

## 审查与实现边界

主管读取CredentialStore/共享进程coordinator、Credentials、持久KeyStore/KeyFiles、ssh-keygen工具以及全部3个测试文件。

- CredentialStore actor，所有SecItem/lease在单一serial coordinator；首owner禁进程交互、最后owner恢复，close失败可重试、closing状态拒绝继续使用；多owner不提前恢复。
- SecretBytes内存不可Codable、description/debug/reflection遮蔽；未授权不保存、重复不覆盖，读取拒绝/锁定/不可用人工回退，删除只精确一次。
- KeyStore持久App自有leaf0700、UUID.openssh0600；独占目录锁、逐组件NOFOLLOW、原子不覆盖提交、同UUID重开，不扫描未知文件。源文件不改，公钥只显示algorithm/base64。
- 取消/超时与提交失败只补偿本操作拥有文件，非秘密ticket仅受控UUID/pending名；Core必须先判定共享引用再deleteExact。安全包不自行决定共享资源可删。
- 成熟系统ssh-keygen经固定execve与管道输入，口令不进argv/env；局部deprecated shim隔离fileKeychain交互API，不改变用户全局设置/ACL。

## 主管独立验证

```sh
swift test --package-path /Users/liuwenshuo/Desktop/OpenLXSSH/Packages/OpenLXSSHSecurity -Xswiftc -warnings-as-errors -Xcc -Wall -Xcc -Wextra -Xcc -Werror
python3 /Users/liuwenshuo/Desktop/OpenLXSSH/Packages/OpenLXSSHSecurity/Scripts/verify_signed_fixture.py
```

均退出0，20项0失败。真实签名fixture（run ca59d68d-73ef-4feb-924d-12d7e8c95f45）现有Development/runtime严格检查、真实CRUD/多owner/更新/缺失与精确cleanup=true。

自建临时Keychain测试只锁/解锁自己库，真实锁时manual回退、解锁恢复同secret、精确删项/删库/临时目录清理；创建前/期间/删除后用户default/searchlist相等。删除后结果实为missing，没有冒充unavailable实测；其他不可用错误为mock映射。

Ed25519/RSA有/无口令四组合、复制/源不变、重开、公钥、拒链接/冲突/取消/超时/补偿ticket与多owner恢复失败都有断言。工程师Debug/Release/TSan各20项通过，显式min26交叉构建元数据通过，日志在包 `.build/verification/`。macOS26产物未运行。

## 限制

file-based相关legacyAPI弃用风险需升级回归；App其他代码不得独立切进程非交互标志。KeyStore只释放资源不删长期文件，父目录须存在且规范无symlink。口令1023字节/NUL-CR-LF限制、Swift副本不能完全擦除如实保留。

测试/签名脚本复用实验身份发现工具，仅验证脚本依赖，生产library不依赖实验；测试fixture/自建Keychain API不进入library依赖图。正式App集成、跨存储清理worker、DeveloperID、重装/双机与真实SSH认证仍需验收。
