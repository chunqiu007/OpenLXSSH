# P7 正式核心独立审查

## 状态与范围

基于本地提交 `a65bfa2` 的正式 Security / Files 实现。只读审查工程师以已有 Debug 对象在自有 `/private/tmp` 目录运行最小复现，运行后删除复现脚本、二进制和测试文件；没有网络连接、Keychain 访问或服务启动。主管随后读取对应正式实现确认逻辑缺口，按包独占范围派修。以下为修前事实，不是修复验收。

## 已确认问题

### P1：私钥危险继承 ACL 未被 mode 检查发现

`Packages/OpenLXSSHSecurity/Sources/OpenLXSSHSecurity/KeyFiles.swift` 的目录初始化/复验与私钥读取只检查 UID、POSIX mode、常规文件/链接数。`chmod` 不会移除 macOS 扩展 ACL。

复现：在自有可遍历测试目录内，对 `shared` 增加 `everyone allow list,search,read,write,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit` ACL；通过正式 KeyStore 创建 `shared/Keys` 并生成无口令 Ed25519。生成与重读成功，目录 `0700`、私钥 `0600`，但 `ls -le` 仍显示私钥 `group:everyone inherited allow read,write,execute,append`。未切换 UID 实读；证据是内核 ACL 授权及库接受结果，不是声称完成另一用户攻击测试。

处置：P7-SECURITY-ACL-R1。新建目录必须在产生秘密前清除仅本轮自有的继承 ACL 或拒绝；用户已有目录/导入源不得擅自改 ACL。现有目录、锁、源、stage、最终私钥查询 ACL，失败关闭，覆盖运行期新增 ACL 与资源释放。

### P1：根目录重复列举共享目录偏移

`LocalFileService.directory` 使用 `F_DUPFD_CLOEXEC` 复制 rootFD，`list(.root)` 将副本交给 `fdopendir/readdir`。副本和 rootFD 共享 open-file description，故目录偏移被消耗。

复现：源根目录只有 `file=payload`。同一服务连续三次列根目录结果为 `[file]`、`[]`、`[]`。先列根再 `copyTree(sourcePath: .root, destinationPath: /out)`，报告 `allSucceeded=true`、一项目录成功，但 `/out` 无子文件。

处置：P7-FILES-INTEGRITY-R2。供目录枚举使用的 FD 以 `openat(rootFD, ".", ...)` 独立打开；精确验证重复/并发根列举与预览后整根拷贝的数量和内容，不仅检查 allSucceeded。

### P2：源同 inode 等长修改形成混合内容

`SafeTransferEngine.copyFile` 原实现只对比初始 size 与累计读取量，没有提交前源属性或内容复核。

复现：`source/file=AAAABBBB`，块大小 4，目标预置 `original-target`。第一块进度回调使用 `pwrite` 原地将同 inode 源改为 `CCCCDDDD`；选择显式风险确认覆盖。最终源为 `CCCCDDDD`、目标为 `AAAADDDD`，报告仍全部成功。此变化在后续块读取前，不能用已披露的目标最终检查/rename 非 CAS 窗口解释。

处置：同一 R2。比较源 path 与已打开 handle 的前后属性（本地纳秒时间/identity），提交前复核；弱远端属性采用有界流式摘要复核。不一致报 raceDetected，清理自己 temp，保留原目标。不把这些检查宣传为原子快照或 CAS。

## 复现构建来源

使用 `/usr/bin/swiftc -parse-as-library -target arm64-apple-macosx15.0`，模块来自各包 `.build/arm64-apple-macosx/debug/Modules`，链接已有包 Swift/C 对象；Security 链接 Security.framework，Files 链接正式 Trust/C 桥及 `.build/native/install/lib` 下 libssh2/libssl/libcrypto。未重新构建上游静态依赖。复现临时文件已清理，后续回归测试应成为保留的可复核证据。

## 同类 ACL 扩展审查

限定读取 Core/Trust/Transport 与 App 边界后，进一步以自有可遍历临时目录和相同继承 ACL 确认：

- Core 的 Data / SQLite 虽为0700/0600仍被授权 everyone 原位读写；库初始化与复验接受。关闭后用系统 sqlite3 修改 fixture 地址，再由 Core 重开，读到替换地址。修复必须保留“不额外 open/close 已有 SQLite inode”的 POSIX 锁约束。
- Trust 的 known_hosts 同样继承写权限；正常确认 A 后，保留合法版本头原位替换为有效公钥 B，evaluate(B) 返回 trusted，未要求 replacement。目录、稳定锁、读写文件及原子 temp 均需 ACL 检查。
- Transport 的 Sessions/UUID/ssh_config 继承写权限；原位修改配置后只运行无网络 ssh -G，退出0且输出修改后的目标、StrictHostKeyChecking false、ProxyCommand /usr/bin/true。没有实际网络或执行代理命令。必须在写配置前建立无 ACL 的私有目录，而非只事后检查。
- AppParent/SessionEnvironment 目前也未处理 ACL，不能假设包外已防护。SecurityJournal 确认接受同类 ACL 及原位 prepared→created 修改；本次未追读清理执行器，不宣称已复现误删。

复现均未切换 UID。证据是实际 ACL 授权、库接受和篡改后行为，不等于默认私有 Home 可被其他 UID 遍历。六个新增临时目录已清理；没有触碰真实 App 数据、Keychain 或网络。P7-CORE-ACL-R1、P7-TRUST-ACL-R1、P7-TRANSPORT-ACL-R1 与 App ACL 修复按不重叠文件所有权处理，统一采用保守拒绝任何扩展 ACE、错误失败关闭、不修改用户 ACL 的策略。

## 验收边界

修复后须主管审查实际 diff、读取测试输出并独立复验。Files R2两项已完成主管审查和独立Release57复验并提交25f802d，详见 `p6-files-core.md`，AC-19恢复进行中（非真实SFTP通过）。Security ACL已完成主管7文件/11新测试审查与独立Release31复验并提交8fffea4，AC-05恢复进行中。Core/Trust/Transport ACL随后完成主管独立Release48/46/35与严格签名离线IPC复验，提交1e275b1，AC-12恢复进行中；App父目录/恢复日志ACL、提交后失败分类、Journal FD ownership与并发关闭R2已主管审查及68tests/GUI/signed复验，提交7ed142e，详见 `p5-native-session-ui.md`。R3同service根自拷边界已主管Release16通过并提交ff00e7d。历史测试事实保留，真实 SSH/SFTP、macOS 26 runtime、长测及 Release 全体验收仍未通过。

本轮后续正式Transport对抗又发现voucher接收策略与发送超时ownership缺陷，当前状态不能由上述ACL验收外推。修复/回归进度见 `ENGINEERING_STATE.md`，闭环后在专项报告记录，不删历史失败。
