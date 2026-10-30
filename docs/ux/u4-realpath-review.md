# U4 登录目录能力：主管独立离线审查

日期：2026-10-30。结论：新 `initialDirectory(token:)` 接口、成熟 SFTP realpath 调用与离线边界门已审；真实服务器互通和新版双栏显示仍待，DX-F04 不标通过。

## 实现

- RemoteFileService 新增 source-compatible 能力。未实现的方法先检查取消再明确抛 unsupported，不伪造 `/` 或猜用户名的 home。
- LibSSH2FileService 使用既有 serial owner 和有界操作，调用公开 `libssh2_sftp_realpath`（固定 1.11.1 展开至 `symlink_ex` 的 REALPATH），输入仅 `.`；不执行 shell、不读取终端 cwd、不解析私有协议结构。
- C bridge 固定最大32769字节接收区，保留终止字节空间；EAGAIN 等待继续同一API，既有取消/timeout/deadline 路径生效。真实返回长度为准，负值映射错误，BUFFER_TOO_SMALL 不静默截断。
- Swift 按长度构造 Data 后由 RemotePath 校验；不经过 String(cString:)/UTF8修复。拒非绝对、NUL、点/重复分隔、过长 component/path；保非法UTF8、控制字节和组合字符的身份。
- LocalFileService 返回它自己的 confined namespace `.root`，不是宿主根目录，也不是远端登录目录证据。
- FilesController 默认 initialPath 调真实服务能力，不再硬编码根；现有请求/generation 检查拒迟到，解析/列目录失败不落到根。
- 生产 AppRealObservedFiles 和 HostProbe LocalFilesProbeService 仅 forwarding；旧本地测试包装器显式 forwarding，协议默认不改为伪成功。

## 独立审查与验证

主管读取 RemoteFileService/LocalFileService 差异、LibSSH2FileService 新实现、C bridge 以及15项 InitialDirectoryTests和5项App consumer新测试。无原生归档/依赖pin/库重建，也不改现有NativeShell认证实现。

工程师严格包 Debug/Release 编译exit0、离线回归各112/0，证据 `DerivedData/UXVerification/U4-Realpath/R1/`。主管独立复跑 `swift test --package-path Packages/OpenLXSSHFiles --scratch-path DerivedData/UXVerification/U4-Realpath/R1/PackageBuild --skip-build --filter InitialDirectoryTests`：**15/0 / exit0**；`DerivedData/UXVerification/U4-Realpath/Primary/initial-directory-tests-1.log`。

新增5项App默认入口/失败保留/cancel/stale测试已随RELIABILITY-R1最终正式Debug/min26执行并通过（App119/0），主管独立DualPaneFilesTests19/0也实际包含这5项，见`reliability-app-review.md`。这解除原先“consumer尚待构建”的缺口，不把本地替身消费者当真实服务器realpath或GUI显示通过。包层先前结果仍仅各自来源范围。

离线套件只使用临时文件/本地替身，以及一次无TCP/DNS的AF_UNIX socketpair证明未就绪owner不发数据；没有SSH/SFTP真实握手。因此必须另以既有批准隔离服务验证实际 `realpath(".")`、不同于根的真实返回/列目录、取消清理和新版显示，不用合成成功补足此门。

## 后续独立UI缺口

首个本地列表失败后的 Refresh 重试需修：activate先置activated，失败path仍nil；refresh再activate会被guard吞掉。保留页切换不一定触发onDisappear，初始SFTP密码应在route离开时明确清空。两项不在本次包能力写域中。

无生产、用户凭据、fixture重建、Keychain、Apple、公证/时间戳或最终出包。
