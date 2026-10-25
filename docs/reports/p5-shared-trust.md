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
