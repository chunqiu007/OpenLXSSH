# ADR-P3：直接文件服务与安全提交策略

状态：P3-LOCAL-A/R1本地实现及主管完整验证通过；真实SSH/SFTP与正式App仍待验收。更新2026-10-26。

## 结构与信任

- 结构化RemoteFileService列目录/lstat/块读写/mkdir/rename/remove/cancel/close，不经Shell/不解析ls。名字与路径保留原始字节，不做Unicode归一化；拒空分量、`.`/`..`、NUL及名字内`/`。本机APFS不能落盘的非UTF8名明确invalidPath/EILSEQ，不替换名字后假成功。
- 类型化SSHConnection→后台DNS/非阻塞TCP→同会话libssh2 hostkey→正式OpenLXSSHTrust→认证。首次准确指纹显式确认，变化默认拒绝，不通过预扫描自动信任。只共享一个store/目录。
- DNS caller可截止/取消且迟到结果不建连接；系统getaddrinfo不可强制中止，最多4个未完成worker，超量拒绝，不无限排队。
- 认证只经内存C API，kbd保留name/instruction/prompts/echo，多轮未知挑战人工；显式至多3个互异方法，不按prompt猜密码/OTP或无限重试。无真实服务，不声称组合MFA已过。

## 传输与链接

- 每host串行、全局默认同时2个chunk，默认64KiB、有界等待/目录/深度/项数。先0600独占同目录唯一临时文件，流式完成/长度核查/finish/关闭后提交，不先删原目标。
- 本地根目录FD+openat/O_NOFOLLOW遍历，下载提交RENAME_EXCL，目标竞争出现原子拒绝；本地根防逃逸不因远端风险确认而削弱。
- 远端SFTP v3无内核O_NOFOLLOW，逐component lstat拒绝已知链接，但已认证服务器可随后改变自身树。这个剩余风险必须明示确认，不能把缺O_NOFOLLOW扩大为所有远端传输永远不可用，也不能隐瞒成强保护。
- 新远端目标使用独占temp；非覆盖rename需与当前服务实例绑定的能力证据，没有证据返回needsCapabilityConfirmation。不得由UI因“想成功”自动伪造确认；未来隔离服务实测后形成能力矩阵。
- 覆盖先完整temp，再复核已选择目标size/mtime/身份与流式SHA256（不用远端Shell）。已知变化raceDetected；最终检查仍非CAS，必须显式确认非CAS风险。远端只尝试posix-rename@openssh.com，不支持就失败，不删目标、不回退普通rename。libssh2正数FX_OP_UNSUPPORTED已在桥接归一为失败。
- fsync扩展不支持时需要明确风险/确认，不吞错。逐项结果记录已确认风险；提交后取消不能逆转已完成项。取消/失败只清理记录的自有temp，失败返回retainedTemporary，不扫描删未知文件。
- 递归copy合并目录但不具整体事务；链接/未知/特殊文件逐项失败，明确剩余项与深度/数量/取消。不跟随链接。正式包将增加确认计划后的安全递归删除，不能沿用单项remove假称目录功能已全。

## 依赖与验证

初始OpenSSL3.6.5临近维护截止，R1已改3.5.9 LTS（官方维护至2030-04-08），Apache-2.0；libssh2仍1.11.1。tag object/peeled/archiveSHA/官方checksum/许可与工具链固定于native-inputs.json，产物不依赖Homebrew。同机干净重复三个静态档案hash相同，不外推跨机逐位一致。

主管读完整原27测试/适配代码与R1连接/信任/TransferPolicy/engine，独立运行Scripts/verify.py退出0：Debug/Release/ASan/TSan各46项通过、真实native smoke/系统链接、minos26.0/SDK26.2编译。socketpair与loopback仅无协议peer测试EAGAIN/取消/EOF，不是SSH server或互通。

ASan/TSan未插桩上游静态库，上游测试未执行；macOS26只编译未运行。真实认证/SFTP、POSIXrename/fsync/非覆盖能力、网络异常/实际释放与大文件仍待获授权隔离服务验收。

## 正式化

当前实验位于Experiments/P3-RemoteFileProbe，正式唯一实现迁移至Packages/OpenLXSSHFiles中；不维持两套生产政策。构建脚本/固定源码/完整许可证与NOTICE必须自包含随发行打包，不能依赖实验/tmp或用户Homebrew。未关闭任何系统保护、未向Apple上传。
