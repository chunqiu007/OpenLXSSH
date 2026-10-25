# P1-02 — App 独立主机信任文件与受控 SSH 配置

状态：本地原型决策已通过主管代码审查与独立22项测试/Release CLI复核；不表示产品或真实 SSH/SFTP 互通通过。

## 决策与替代方案

采用单一 App 专属 OpenSSH `known_hosts` 文件作为信任真源；不读取、合并或修改 `~/.ssh`。首行为 OpenSSH 可忽略的版本/随机代次注释，其余为排序后的精确 `host algorithm base64`。端口 22 使用地址，其他端口使用 `[address]:port`；同一地址/端口/公钥算法最多一条记录，用户名不改变服务器身份。RSA 公钥类型为 `ssh-rsa`，不将 RSA 签名算法名称误作不同服务器公钥。

不采用结构化数据库加可变 snapshot：两份真源会增加 SSH/SFTP 并发更新、崩溃恢复与过期 snapshot 风险。未来后端须复用同一 store/lock，或另行定义迁移，不能直接覆盖文件。原型只接受自身格式的严格子集；不导入通配符、hashed host、CA、证书、revoked 或任意手工记录。损坏/缺失/不安全文件拒绝访问，不静默修复为空记录。

## 决策流程

- `evaluate` 返回匹配、待确认或密钥变化拒绝；只读，不自动保存。
- 首次及未知新算法均返回 host、算法、SHA256 指纹和一次性令牌，必须显式 `confirm`。令牌绑定 store 实例、精确身份/公钥、文件内容摘要与随机代次，5 分钟到期；取消、错误指纹、重复使用和陈旧确认失败。暂存请求有界。
- 已知同算法变化永远默认拒绝。管理入口另行要求当前旧指纹，显示新指纹，再显式确认；期间任何存储更新都使令牌失效。调用者须重新展示并取得新确认，不能自动重放用户旧回答。
- 地址编辑不迁移信任记录；会话关闭/地址编辑调用取消接口。另一地址/端口必须重新评估。没有自动将 `ssh-keyscan` 结果当作可信来源的路径。
- 公钥解析交给 `/usr/bin/ssh-keygen -l -f - -E sha256`；公钥仅经 stdin，不读取用户私钥。CryptoKit SHA256 计算同一标准公钥 blob 指纹，并与系统输出对照，不实现 SSH 协议或密码学。

## 持久化与权限

私有目录须属于当前 UID 且为 0700，普通单链接文件须为 0600；权限不符时拒绝，不悄悄改现有文件。保留目录 FD，经 `openat(O_NOFOLLOW)`/`fstat` 验证文件，拒绝 symlink、hardlink、FIFO。目录规范化后再核对 inode；运行期间验证目录及稳定 lock inode，禁止删除锁文件来“释放”锁。

actor 串行单实例操作；稳定 `trust.lock` 的 `flock` 协调多实例/多进程，最多等待 10 秒。读－校验代次－修改－写均在锁内。写入同目录独占临时文件、fsync、原子 rename、fsync 目录；读者看到旧或新完整文件，不会看到半写入。临时文件常规错误路径清理；文件上限 1 MiB，超过时拒绝。首次初始化只在新建稳定锁时创建空文件；之后丢失 `known_hosts` 不能当作首次使用。

文件锁是合作式协议，不是隔离同 UID 恶意进程的边界；OpenSSH 仍会按路径打开文件，不能以此声称完全消除同 UID 攻击或所有 TOCTOU。目录父路径须由 App 生命周期管理。掉电/磁盘故障未注入验证；rename 已成功但后续 fsync 报错时，调用者必须重新读取，不可假设未提交。崩溃遗留临时文件不自动晋升为可信记录。

## SSH 配置边界

固定目标 alias，只有类型化地址/端口/用户名及 App 路径能进入配置。配置写入产生不可由任意 `-F` 路径构造的 prepared 类型，参数数组直接传给 `/usr/bin/ssh`，无 Shell。`-F` 专属配置、独立 known_hosts、`StrictHostKeyChecking yes`、全局 known_hosts `/dev/null`，禁用 DNS 自动信任、UpdateHostKeys、KnownHostsCommand、Agent/转发、ProxyCommand/Jump、复用及 LocalCommand；有限连接超时与保活。禁用默认私钥/agent，认证凭据接入不属于本任务。环境只有固定 PATH/LC_ALL/TERM，无秘密输入接口。

本机 `ssh -G` 证明引号/空格/反斜杠及 `%` 必须分别处理：路径和 HostName 的 `%` 双写，拒绝路径 `$` 以避免 `${...}` 展开。地址仅接受规范 DNS/IPv4/IPv6，拒绝控制字符、配置语法、前导选项和歧义数字地址。IPv6 scope 只接受小写合法标识或规范正整数；配置写入前检查命名接口存在，因为本机 OpenSSH 会悄悄删除不存在的 scope。尚未创建的接口仍可存在信任记录，连接配置则必须失败而非改用无 scope 地址。

`HostKeyAlias` 使用完整 known_hosts 名称（包括非默认端口）；OpenSSH 对该选项直接使用 alias，而非再次附加端口。已用 `ssh -G` 与 `ssh-keygen -F` 对照 DNS、IPv4/IPv6、22/非 22、多算法。源码依据为 OpenSSH 9.9p2 `sshconnect.c` 的 `get_hostfile_hostname_ipaddr`，本机手册同样说明其替代数据库查找名。

## 验证与剩余边界

macOS 15.8.1 / Swift 6.2.4 / Xcode 26.3 / OpenSSH 9.9p2；本实验最低 macOS 15 仅用于宿主，不改变产品 macOS 26 目标。Debug/Release 严格警告构建与各 22 项 XCTest、Thread Sanitizer 22 项、Release 本地 CLI 均退出 0。测试覆盖临时 ssh-keygen 公钥、私钥 0600/目录 0700 与清理、注入、首次/取消/匹配/变化、新算法、人工替换、旧请求、8 store 并发与 4 独立进程更新、原子读取、损坏/恶意存储、权限/链接/稳定锁替换。日志在实验 `.build/verification/`，正式报告由主管维护。

未启动 sshd、未连接任何 SSH 服务；从真实握手安全获取并绑定服务器公钥、SSH/SFTP 共用 UI/会话集成、系统工具的正式 App/Sandbox 签名运行、macOS 26 runtime、真实掉电恢复尚未验证。该原型不能自动信任某个预扫描公钥，也不能把本地工具对照写成产品 AC-12 通过。
