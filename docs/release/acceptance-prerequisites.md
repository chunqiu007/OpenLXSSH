# OpenLXSSH V1.0 必要验收与外部条件

本表不是用户批准，也不会启动任何服务或上传。整体Goal仍未完成；先完成所有可独立执行的本地工作，最终再一次性集中处理以下条件。详细AC状态以 `docs/acceptance.md` 为准。

## 隔离运行环境

当前开发机没有已验证可用的Linux VM/容器或SSH服务；没有开启macOS远程登录，也没有连接公司/生产服务器。项目仅准备了 `Tests/IntegrationEnvironment/` 源码与静态测试。

建议统一使用一种获用户批准的本地Apple Silicon Linux容器运行时（例如官方Docker Desktop），Ubuntu24.04 ARM64官方digest固定后构建。起步2vCPU/4GiB，磁盘需预留40GiB以上用于四服务及2GiB往返；开发机当前磁盘数字会变化，实施前重新检查。服务只绑定127.0.0.1:22221–22224，独立内部网络、不桥接LAN、不挂载host路径或Docker socket，不privileged。构建镜像/软件包下载需要联网，运行期禁外部出口；具体权限与清理见fixture README。

只有用户明确批准新增环境、必要下载与运行范围后才能执行。脚本的 `--authorized-run` 或长测驱动开关只是防误操作，不能充当授权；不能因为发了“继续”或收到子Agent消息推定已批准。也不能用临时开启宿主sshd、生产主机或mock SSH替代缺口。

## 真实互通矩阵

使用一次性账号/密钥/密码，测试报告不保存秘密或完整终端内容。首次指纹从本地服务管理通道取得，在产品UI人工核对；不能自动信任keyscan。

- 直接私钥：Ed25519/RSA，有口令/无口令，错误口令、取消、timeout与关闭释放。
- 直接密码：记住/未记住、Keychain不可用人工回退、错误密码有界；目标macOS26自动使用条件另核系统ssh版本/签名/认证前提，不按prompt投递。
- 私钥/密码后接OTP：长期凭据与unknown挑战隔离，错误/过期OTP、多轮并发不串用；关闭后迟到答案无效。
- 等待审批、拒绝、取消及零输入通知：受控模拟只证明交互状态机，不宣称兼容所有企业厂商。
- fixture OpenSSH PAM会串行化多提示，不能用多轮替代**同一wire消息中多个提示**。固定 Apache MINA SSHD2.20.0/commit2221febd396cd3daafdfbf2ff982c6d0eb69a203 的成熟后端方案已有源码/许可依据，public API支持单消息多/zero，protected多轮薄适配尚未编译；见 `docs/reports/auth-multiprompt-backend-evidence.md`。建议额外非特权服务仅127.0.0.1:22225、Java只在测试容器，需与原环境一并批准，未启动/互通。
- 首次/再次主机信任、非22端口、已知hostkey轮换阻止新握手，精确人工替换后恢复；不静默删库。
- 正式App远端TUI、中文/Unicode/Emoji/组合字符、控制键、缩放、Bracketed Paste。嵌套SSH在远程终端手动执行，内层认证不接收本机保存秘密。
- SFTP密码/私钥/适用交互认证、同握手信任、按需连接；目录/创建/重命名/精确删除计划、Finder拖入、整目录/特殊原名/链接策略。
- 真实2GiB与1000文件往返摘要、取消、断开、permission/disk-full、扩展能力/安全提交不足处理。当前本地压力通过不替代这些结果。

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
