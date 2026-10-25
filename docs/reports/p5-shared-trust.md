# P5-TRUST-A：正式共享主机信任库审查

日期2026-10-26。工程师实现；主管独立审查。

## 结论

`Packages/OpenLXSSHTrust/` 本地范围通过，供SSH/SFTP共用一个App信任目录和政策，不再各自复制HostTrustStore。真实握手/目标macOS26仍未验收。

## 差异与审查

原P1-02的Identity/PrivateDirectory逐字一致；Store/config仅新增worker-only/同UID边界说明。HostPublicKey公开API和验证政策不变，内部固定ssh-keygen执行由Foundation.Process改为有界posix_spawn/单一waitpid owner。主管读取新runner、8项测试、manifest、HostPublicKey和同源比较证据，并核对原政策未漂移。

runner非阻塞并发泵stdin/stdout、输出/时间有界、TERM→KILL，PID在waitpid回收时立即清除；外部全局waitpid(-1)/自动reap不得抢夺所属child。极端内核阻塞转交不再发信号的后台sole reaper，不无限阻塞调用者。新增测试验证128KiB双向泵、EPIPE无SIGPIPE、输出超限、忽略TERM超时、非零退出、并发公钥解析与重复超时FD回收。

同步公钥构造、Store初始化和配置写入是worker-only，不应在MainActor同步执行。生产App仅依赖library product；SwiftPM为测试executable target自动合成fixture产品，但fixture不在library依赖图中，不能打包。

## 实际验证

- 工程师Debug/Release各30项、0失败；TSan30项、0失败；fresh library-only scratch构建无fixture二进制。
- 主管独立 `swift test --package-path /Users/liuwenshuo/Desktop/OpenLXSSH/Packages/OpenLXSSHTrust -Xswiftc -warnings-as-errors` 退出0，30项、0失败。
- 主管读取 `.build/verification/source-parity.log`，原22项断言仅module/fixture名称变化，同源政策一致；新8项单独通过。

同UID恶意改写、OpenSSH后来按路径读取的TOCTOU仍不是已解决安全边界。没有连接服务器，也没有把共享库通过算AC-12产品验收。

## P7 ACL 加固与独立复验

后续只读审查真实复现：继承everyone ACL的0700根/0600known_hosts被原实现接受，合法版本头不变、同inode公钥A换B后evaluate(B)直接trusted。新增测试保留修前2项3失败及实际trusted输出，未将ACL已授权的其他UID归入sameUID排除项。

PrivateDirectory改用FD的fstatx/filesec属性查询，成功且MODE已填/ACL不存在才接受；空/deny-only/任意ACL或查询错误失败关闭。新目录在lock/known_hosts创建前检查；稳定flock前后、读前后、commit前与返回前复验root/lock/已访问文件。原子temp写前/commit前/rename后核权限/ACL/inode，cleanup只删原temp inode。构造器校验完成后才转交FD所有权，避免初始化失败双close。用户ACL不清除，known_hosts真源、token/expiry与公共API不变。

工程师最终Debug/Release各46项（原30+新16）与min26消费者编译通过。主管阅读2文件完整差异、16新tests及资源/查询注入，独立Release46项退出0，日志 `.build/verification/acl-r1-primary-release46.log`。包含运行期篡改不能trusted、flock等待期追加ACE、读后/提交前拒绝、任何query错误与未填MODE、chmod不清ACL、临时文件替换不误删、重复失败FD不涨且锁可重新获取。

所有真实ACL操作限自有临时UUID，未切换UID实读、未网络/Keychain。macOS26仅编译，不宣传为真实握手或目标系统验收通过。
