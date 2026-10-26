# 已授权 Docker 隔离环境：安装与首次许可检查点

## 当前结论与安装时序

官方Docker Desktop4.97.0/build244584已安装验签，外部GUI后的持久许可记录和2CPU/4GiB/40GiB资源实物已观察就绪；五个隔离服务现已真实运行，基础SSH/SFTP、MINA多提示/审批取消及完整远端文件campaign见对应实测报告。Agent未代接受协议或输入系统凭据。本报告以下保留首次安装、暂停和后续解除等待的时序，不将当时“0容器/尚未连接”误读为当前状态。

## 本轮授权与当前结果

用户本人已明确批准按 `docs/release/acceptance-prerequisites.md` 安装官方Docker Desktop、必要Ubuntu ARM64镜像/测试依赖下载构建，运行四类认证和必要单消息多提示测试服务；只用于OpenLXSSH，端口仅127.0.0.1:22221～22225，不向LAN开放、不挂载真实凭据/生产数据、不宿主远程登录/生产连接、不Apple公证上传。需本人处理许可或系统授权时必须明确指出。

本轮已实际安装官方Docker Desktop4.97.0/build244584，**未代接受订阅许可，也未建立测试容器/真实SSH/SFTP连接**。首次启动官方日志显示 `new-license` 页面；后台Engine虽已响应，也不把它当作用户接受法律协议的证据。确认containers=0后已正常停止该新引擎，未强制杀其他进程、未删除任何Docker资源。

## 实际核验

- 宿主macOS15.8.1/24H32、arm64；初始工作树干净、HEAD0bff262、无remote。正式产品仍min26，不能以本机HostProbe替代目标系统验收。
- 安装前可用磁盘73,277,263,872bytes（68.24GiB），高于方案40GiB以上；安装后约65.44GiB，瞬时值不当永久保证。新环境未占有既有Docker资源。
- 安装前 `/Applications/Docker.app`、用户Applications同名App、Docker CLI和settings不存在，22221～22225无监听；检查lsof无匹配exit1，不误报为工具故障。
- 官方URL `https://desktop.docker.com/mac/main/arm64/Docker.dmg`，实际下载571,487,013bytes，SHA256 `94e4ccec4a035b7dcdf67cfff0520d4b46ee873ae04b155abc0d22b333cc90ad`。这是本次下载摘要，不假称官方发布checksum。
- `hdiutil verify`、只读挂载、App与installer签名验证exit0。严格Apple generic anchor+Docker固定identifier `com.docker.docker`/Team`9BNSXJN65R`通过；证书主体Docker Inc、Hardened Runtime、ARM64、LSMinimumSystemVersion14.0。
- 使用官方 `Contents/MacOS/install` 默认模式实际安装exit0，目标`/Applications/Docker.app`原不存在；**无sudo、无--accept-license、无--user、无config/vmnetd/socket-symlink子命令**，没有改系统SSH或安全保护。安装后再严格签名通过，安装卷已正常detach。
- CLI29.9.2、Engine29.9.2/linuxarm64曾只读响应；当前context`desktop-linux`，Unix endpoint`~/.docker/run/docker.sock`。默认context仍`/var/run/docker.sock`，不为适配旧fixture建立特权全局socket链接。
- 第一次启动实物settings只有AutoStart=false等默认项；Engine默认8CPU、约8GiB内存，不符合本方案起步2CPU/4GiB。没有盲写未经核对的私有JSON键。
- 后台日志明确打开`app://dd/new-license`，不自动点击/使用--accept-license。先查询containers0，再执行官方Desktop CLI graceful stop exit0；后续engine query exit1，证实停止。登录自启AutoStart=false。

安装证据目录：

`DerivedData/Environment/docker-install-a8f77d1b-176f-4329-a672-2e3d5e9a04dd/`

含download结果与摘要、签名/Appleanchor、安装help/实际exit、首次启动/停止与许可资源hold记录。日志仅本机保留，不外发。

## 官方Ubuntu ARM64固定输入

通过Docker官方token与registry HTTPS只读取得官方`library/ubuntu:24.04`的index、ARM64 manifest和config，逐层校验返回文本SHA256，config确认linux/arm64、版本label24.04；尚未下载或执行image layers。

- index：`sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac`
- ARM64/v8 manifest：`sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d`
- config：`sha256:f3ff6f5009cb3b8de09d949f24109461606f626fae231a81f66ba3226c8302a6`
- 固定ref：`docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d`

证据 `DerivedData/Environment/ubuntu-official-digest-a7d614c8-120b-4f9c-87b9-15248d5aaf7d/`。这不是容器ABI/PAM/网络能力已通过，尚需真实构建后验证。

## 必须由用户本人处理的具体步骤

1. 打开 `/Applications/Docker.app`。首次Docker Subscription Service Agreement需要用户自行阅读，并仅在同意且符合适用订阅条件时点击接受；Agent不会代点、代选订阅或假称许可已获接受。若要求登录/付费/组织许可，由用户本人处理，不提供凭据给模型。
2. 进入Docker Desktop **Settings → Resources → Advanced**：CPU limit设2，Memory limit设4GiB，Disk usage limit按测试方案设约40GiB；保留宿主足够空闲空间，关闭不必要的Kubernetes/扩展等功能，不新增生产/个人目录的容器挂载。点Apply & Restart。若该版本标签稍有差异，以CPU/Memory/Disk对应实际项为准，不猜私有配置键。
3. Settings → General 的“Start Docker Desktop when you sign in”保持关闭；当前已核AutoStart=false。无需为了fixture创建`/var/run/docker.sock`或安装特权端口helper，测试使用高端口和已核本地desktop-linux context。
4. 若macOS出现管理员密码/系统扩展/安全许可提示，由用户本人核实用途后完成；不关闭Gatekeeper/SIP/TCC、不向Agent提供密码。

这些是首次许可和具体系统操作，不是再次请求已给出的隔离环境范围授权。处理后才能继续获批镜像构建/服务运行；不因Engine API在许可页后台可访问而绕过这一步。

## 后续实际状态更新：许可/资源条件已满足

本轮在等待fixture源码审查期间，最后只读检查观察到外部GUI交互后settings已含 `LicenseTermsVersion=2`、Cpus2、MemoryMiB4096、DiskSizeMiB40960、AutoStartfalse；Engine实际报告2CPU、4,107,407,360bytes内存，且0images/0containers。Agent没有写这些键或点击协议，不虚构新的人类文字确认；以真实持久许可记录和资源实物为依据，解除先前first-run等待，继续已经明确获批的本机测试，不再要求重复批准。

首次真实Buildx预检发现v0.38.1 `buildx inspect` **不支持--format**，此前mock测试未覆盖实际CLI差异；无format的selected inspect实际成功、driver=docker、唯一node/endpoint=desktop-linux。已派根工程师最小兼容修复，保留原测试语义；不采用会探测所有builders的全局ls作为runner路径。记录 `DerivedData/Environment/engine-ready-8adcdc7d-05e1-4564-9a29-342de4503849/` 保留未知flag失败及真实help/inspect输出，不把第一次readiness错误写全过。

本节取代上方“仍待本人”的当时状态；前文保留安装时序。镜像构建、PAM ABI和实际服务/互通仍要后续真实验证。

## 不依赖许可的并行工作

既有四服务fixture本地context/builder边界检查与必要最小修复、多提示MINA2.20.0子树源码/锁定输入/许可/静态检查继续进行；文件所有权不重叠，根compose只有一位工程师写。运行前再次核本地context/资源/loopback/internal网络、无hostmount与日志/一次性秘密边界；容器内先核Ubuntu包和PAM Python ABI再启动认证服务。任何静态结果不当真实互通通过。
