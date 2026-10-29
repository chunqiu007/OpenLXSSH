# OpenLXSSH V1.0 必要验收与外部条件

本表本身不是用户批准，也不会自动启动服务或上传。整体Goal仍未完成；具体AC状态以 `docs/acceptance.md` 为准。

**Codex 接手更新（2026-10-29）：** 宿主macOS26.7.1已实际运行正式build3；一次性默认Keychain公开API生命周期/正式UI保存忘记回退、四类SSH正向接线及独立密码MFA SFTP目录已补，有限五会话/输出/关闭资源已审。新200+20于11:11真实启动，24h尚未启动；原失败保留。DeveloperID Application已核为可用1，用户明确允许当前build3的DeveloperID签名与Apple时间戳请求，不包含公证上传；最终具体App/ZIP/摘要仍按下方单独确认。用户允许未来长测真实开始后建立独立Terra/medium每30分钟回查，正常安静、结束停用。下方旧平台/待授权状态只作历史，当前以工程状态顶部为准。

**当前授权已更新：** 用户本人已明确同意按本方案从官方来源安装Docker Desktop、下载构建必要Ubuntu ARM64镜像/测试依赖，并运行四认证及必要多提示服务。限OpenLXSSH测试、127.0.0.1:22221～22225，不LAN、不真实凭据/生产数据挂载、不宿主远程登录、不生产服务器、不Apple公证上传；安装前重核磁盘、按方案控制资源，许可/系统授权由用户本人处理。这一真实答复取代此前“等待环境授权”，不等于许可已接受或环境已验证可用。

## 隔离运行环境

当前已获用户本人授权；官方Docker4.97已安装并核验签名，外部GUI后的实际settings记录许可版本2、2CPU/4GiB/40GiB，Engine资源实物一致。本机context/builder、固定Ubuntu24.04 ARM64镜像/PAMABI及四OpenSSH服务和MINA服务均已真实核验；有限127 opaque relay保留internal/no-egress边界。生产API基础SSH/SFTP、MINA双提示/零提示/8s审批拒绝取消和远端2GiB/1000文件核心campaign已有实际证据，见验收表引用报告。没有开启macOS远程登录，也没有连接公司/生产服务器；这些宿主15分项不代表完整AUTH/FILE或目标macOS26产品通过。

建议统一使用一种获用户批准的本地Apple Silicon Linux容器运行时（例如官方Docker Desktop），Ubuntu24.04 ARM64官方digest固定后构建。起步2vCPU/4GiB，磁盘需预留40GiB以上用于四服务及2GiB往返；开发机当前磁盘数字会变化，实施前重新检查。服务只绑定127.0.0.1:22221–22224，独立内部网络、不桥接LAN、不挂载host路径或Docker socket，不privileged。构建镜像/软件包下载需要联网，运行期禁外部出口；具体权限与清理见fixture README。

只有用户明确批准新增环境、必要下载与运行范围后才能执行。脚本的 `--authorized-run` 或长测驱动开关只是防误操作，不能充当授权；不能因为发了“继续”或收到子Agent消息推定已批准。也不能用临时开启宿主sshd、生产主机或mock SSH替代缺口。

## 真实互通矩阵

使用一次性账号/密钥/密码，测试报告不保存秘密或完整终端内容。首次指纹从本地服务管理通道取得，在产品UI人工核对；不能自动信任keyscan。

- 直接私钥：Ed25519/RSA，有口令/无口令，错误口令、取消、timeout与关闭释放。
- 直接密码：记住/未记住、Keychain不可用人工回退、错误密码有界；目标macOS26自动使用条件另核系统ssh版本/签名/认证前提，不按prompt投递。
- 私钥/密码后接OTP：长期凭据与unknown挑战隔离，错误/过期OTP、多轮并发不串用；关闭后迟到答案无效。
- 等待审批、拒绝、取消及零输入通知：受控模拟只证明交互状态机，不宣称兼容所有企业厂商。
- fixture OpenSSH PAM会串行化多提示，不能用多轮替代**同一wire消息中多个提示**。固定 Apache MINA SSHD2.20.0/commit2221febd396cd3daafdfbf2ff982c6d0eb69a203 的成熟后端已构建/运行，单消息双提示、零提示及8s审批接受/拒绝/等待取消已通过生产libssh2核心验证；来源/许可见 `docs/reports/auth-multiprompt-backend-evidence.md`，实际证据见 `docs/reports/real-mina-kbi.md`。非特权服务入口仅127.0.0.1:22225、Java只在测试容器；不代表真实企业MFA或完整AUTH验收。
- 首次/再次主机信任、非22端口、已知hostkey轮换阻止新握手，精确人工替换后恢复；不静默删库。
- 正式App远端TUI、中文/Unicode/Emoji/组合字符、控制键、缩放、Bracketed Paste。嵌套SSH在远程终端手动执行，内层认证不接收本机保存秘密。
- SFTP密码/私钥/适用交互认证、同握手信任、按需连接；目录/创建/重命名/精确删除计划、Finder拖入、整目录/特殊原名/链接策略。
- 真实2GiB与1000文件往返、双向25%取消、权限与当前服务提交能力已完成核心campaign；主管R1新16MiB真实断连/精确receipt/显式新SFTP原目标无损与清理闭环已过；既有/dev/shm64MiB上的真实ENOSPC联合证据/先释放后清理也已核。首断连案PARTIAL保留；其他能力边界及正式App/mac26仍需补齐。结果见 `docs/reports/real-sftp-file-acceptance.md`、`docs/reports/real-sftp-disconnect.md`、`docs/reports/real-sftp-disk-full.md`，不以本地压力或微型往返替代缺项。

## 长测与资源

- 200次真实创建/认证/关闭，穿插连接中取消；每轮等待自身child/PTY/FD/任务回收，并记录趋势，不统计synthetic成功。
- 5个独立真实会话连续24小时，记录wall/monotonic起止、采样负载/构建与错误；睡眠、掉线或中断按实际结果标记，不拼短时段、不改时钟。
- 长测为显式启动的有限测试进程，可保存证据，不创建未请求Cron/常驻服务，不改电源设置。若无法保持运行条件，记录具体原因而非声称完成。
- Release App及所属子进程内存、CPU、Swap/FD/PTY、输出与快速切标签；200/500MB为努力目标，超出实测分析。Instruments可用性需实测，不把未运行写通过。

## 目标系统与签名发布

正式最低macOS26。开发宿主macOS15的HostProbe用于本地验证，正式min26 load commands编译通过不能证明该系统运行、IME或安装成功。需要Apple Silicon/macOS26实际设备与第二台Mac。

已验证的Apple Development离线签名不等Developer ID或Gatekeeper发布资格。Developer ID证书可用性、访问与登录由用户安全准备；Agent不创建证书/profile、不代答系统授权、不改Keychain ACL。App/helper身份和Runtime必须保持一致与严格校验。

公证上传前需提供**具体构建App/ZIP、版本、提交、SHA256、Apple目的地与用途**，获得针对该产物的明确批准后才调用Apple公证服务。当前无上传批准，也未执行。不能关闭Gatekeeper、清除隔离标记、改SIP等绕过安装。

第二台Mac及公司允许环境由用户操作或提供明确授权测试条件，不索要公司密码、OTP、私钥或终端录屏。记录日期、构建、覆盖场景与结果；账号拥有、第一台重复运行或模拟审批均不能代替人工验收。

## 当前集中交付前提（2026-10-28检查点）

已授权隔离环境无需再次等待安装或Docker许可。基础真实四认证/SFTP、多提示审批、2GiB/1000及异常、App上传/关窗/Quit/文件操作/批skip-rename-overwrite/正字节切标签、外层Vim/tmux/htop、公钥nested、原生加密key认证取消恢复/信任管理，以及有限正常保活与R2黑洞分项已有主管独立证据；不得为消除历史失败而重复campaign。原并发MFA fixture取消材料卫生整案PARTIAL、原黑洞control/-9失败均保留，不因精确恢复或后来成功追认为原案成功。

仍必须满足且不能由host15短测或构建替代的条件：

1. **目标设备与正式长测**：可运行正式min26产物的Apple Silicon/macOS26设备；正式driver200次创建关闭和五会话实际连续24小时，真实Release输出/快速切标签压力及App＋子进程资源趋势/内存努力目标报告。Agent不升级宿主、不改电源设置或创建定时/常驻保活。
2. **默认Keychain真实动作的明确放行**：公开CredentialStore消费者目前source/offline-only。需要仅一次性测试命名空间的save/read/forget/delete/不可用回退实跑及系统交互条件；testNamespace不是独立物理Keychain。历史隔离CRUD、内存provider及当前只读签名证据不能替代该动作授权。目标mac26自动密码白名单及升级/重新安装访问另需验证。
3. **发布身份、具体产物与Apple上传**：准备可用Developer ID及正常系统访问，Agent不创建/读取签名私钥或代答登录授权。最终Release含版本/commit/依赖/摘要后，展示具体App/ZIP及Apple公证目的地/用途再集中申请上传批准；未批准不上传。现内部候选不是已完成正式验收的Release，旧manifest不自动代表后续源码。
4. **双机与人工/企业场景**：第二台Apple Silicon/macOS26安装、正常启动/升级/卸载说明；人工IME/组合输入、Finder/NSOpenPanel、真实剪贴板copy/paste与像素交互；公司允许环境四类适用认证/手机审批、内层密码/OTP。用户自行操作秘密，不提供给AI；记录构建/日期/覆盖范围，不采敏感终端录像。
5. **剩余工具合法运行条件**：Docker日志需非秘密日志源和受限读取方案，不能挂宿主Docker socket/特权或开启认证日志；Claude Code需要合法账号/条款/网络条件，OpenCode无账号离线TUI仍未实测，不擅自补装、读取宿主配置或连provider。执行计划允许缺合法条件时记录限制，但不等help/version通过，见 `docs/reports/terminal-tool-runtime-prerequisites.md`。

App并发提示归属已在现有keyonly/cap8上用两真实加密私钥请求完成有限原生接线验证，不扩称不同秘密全排列或多轮MFA UI；不为此重建MFA服务。若后续要补App密码/OTP整条shell可用链，另三旧root服务仅cap7，应先审定目标服务最小AUDIT_WRITE方案/精确单服务重建及fresh CID/指纹绑定，而不是拿outer-auth事件冒shell-ready。

本轮最后的原生并发归属分项与当前源码正式Debug/Release静态隔离均已主管独立验收，全部执行者停止，当前没有需模型持续占用或自动续建的任务。等待上述必要条件不意味着V1.0已完成；现有内部候选未经过正式发布/目标运行验收。

本清单是必要条件记录，不是新增授权、范围删减或产品完成声明；当前实际已完成项与最新源码审点仍以 `ENGINEERING_STATE.md` / `docs/acceptance.md` 为准。
