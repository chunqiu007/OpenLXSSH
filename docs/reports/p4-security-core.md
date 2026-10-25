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

## P7 ACL 修复复验

后续独立审查发现原mode-only策略接受危险继承ACL（修前生成/导入仍成功），已在 `P7-SECURITY-ACL-R1` 修正。采用保守拒绝任何扩展文件系统ACL，包括deny-only/empty；不清除用户目录、导入源或生成leaf的ACL。新leaf在创建锁或产生私钥前核对，root/lock/source/stage/final均有对应检查，I/O与系统ssh-keygen路径调用前后及提交后复验。

Darwin `acl_get_fd_np` 在无ACL时也返回NULL/ENOENT，不能把NULL统一解释为无ACL。生产C shim用公开filesec/fstatx_np，成功且MODE已填、ACL property不存在才接受，查询失败保存errno并单独systemCall，释放filesec内部资源；不把旧errno误用于成功路径。此实现不依赖Linux acl_get_entry语义。

修前10项真实ACL回归退出1、25断言失败，日志 `.build/verification/acl-r1-before-fix-confirmed.log` 保留。工程师最终Debug/Release各31项退出0。主管读取7个实际修改文件与11新tests，在独立scratch运行Release完整31项退出0，日志 `.build/verification/acl-r1-primary-release.log`。本轮真实自有临时Keychain锁/解锁/清理再次通过，用户default/searchlist不变；无真实用户私钥操作、无签名脚本并发、无上游native重建。

拒绝ACL时需要用户检查App专属leaf/lock/key或导入源，单纯chmod不足；App不自动改ACL。前后检查不是ACL与I/O的原子绑定，恶意同UID进程及瞬时竞态不在完整防护承诺内。当前只宿主macOS15包级证据，正式签名App与macOS26仍须后续回归。

## P6 认证专用私钥内存接口

SFTP frommemory 接口需要受检内存材料，正式KeyStore新增 `privateKeyForAuthentication(id:) -> SecretBytes`，三行实现只精确UUID读取并核OpenSSHEnvelope，复用既有root/lock/noFollow/mode/ACL/owner/link/1MiB界限。不提供任意URL读取或私钥文件导出，不改源文件；加密密钥仍返回原密文。调用方必须核Core关联与显式认证授权、限期保留，Swift/Data副本不保证完全擦除。

工程师Debug/Release各39项（原31+新8）通过。主管读新API/8tests与离线probe，独立Release新8项、verify_authentication_material.py退出0。四种真实Ed25519/RSA有/无口令返回原字节，经固定libssh2内存解析/签名/验签匹配公钥，source不变、自有UUID清理；日志 `.build/verification/auth-material-primary-release8.log`、`auth-material-primary-probe.log`。probe使用已有固定libssh2内部ABI，仅测试路径；正式Security无native新依赖，未重建上游或联网，不算远端认证通过。

## 限制

file-based相关legacyAPI弃用风险需升级回归；App其他代码不得独立切进程非交互标志。KeyStore只释放资源不删长期文件，父目录须存在且规范无symlink。口令1023字节/NUL-CR-LF限制、Swift副本不能完全擦除如实保留。

测试/签名脚本复用实验身份发现工具，仅验证脚本依赖，生产library不依赖实验；测试fixture/自建Keychain API不进入library依赖图。正式App集成、跨存储清理worker、DeveloperID、重装/双机与真实SSH认证仍需验收。
