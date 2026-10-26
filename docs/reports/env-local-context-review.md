# 已授权隔离夹具：本机 context 与 builder 预检修复

Task：ENV-AUTHORIZED-PREFLIGHT-A / FIXTURE-LOCAL-CONTEXT-R1。当前只完成离线预检与最小runner修复；没有调用真实Docker CLI、构建镜像、生成凭据或SSH/SFTP连接。环境安装授权已具备，但Docker首次协议需本人处理、资源2CPU/4GiB需实物核定，不能把后台API响应视为Engine-ready。

## 缺陷与最小改动

仅修改 `Tests/IntegrationEnvironment/fixture.py`、`test_static.py`、`README.md`，不改原四服务compose/Dockerfile/PAM/bootstrap，也不写独立multiprompt子树。

1. 旧runner同时强制default context和`/var/run/docker.sock`。官方Docker4.97用户模式实物为`desktop-linux`、`unix:///Users/liuwenshuo/.docker/run/docker.sock`，因此即使本地引擎正确也无法使用。不能用创建全局特权socket链接补救。
2. 旧子进程环境继承BUILDX_BUILDER等，可能绕过本机daemon检查选择远端builder。环境授权不含远程构建服务。

新runner先读取当前context，只允许default/desktop-linux，并inspect该context的规范化绝对Unixendpoint，拒绝tcp/ssh/custom、authority、..、query/fragment、percent/重复斜线等。验证结果只在当前进程冻结，后续每条Docker命令显式同一--context；拒DOCKER_HOST/TLS等覆盖，清除继承Docker/Buildx/BuildKit/Compose路由开关。

构建固定到所选context的同名builtin builder，而非含糊的显式default别名；在写state前执行不带bootstrap的buildx inspect，要求driver=docker、恰一node、endpoint与已核context名或精确Unixendpoint一致，缺失/不匹配直接拒绝，无fallback。CLI路径由主会话使用已验签Docker App目录加入本次shell PATH，不改系统全局路径。

这是本地路由边界，不声称能防恶意同UID同时修改context或Docker本身；真实Compose/Buildx实物兼容还需许可/资源条件到位后验证。

## 工程师与主管验证

工程师原有13项静态测试和bash syntax先通过；所有12种wrapper action及server/data入口共14种不带授权flag时exit2、stdout空、runtime未创建。新7项测试保留原13项，最终20项通过；这些都不调用真实Docker。

主管读取实际3文件diff、关键helper/状态前置与新增测试，独立执行：

- `/bin/bash -n fixture.sh`：exit0。
- `PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 test_static.py`（根环境目录）：20tests/OK、exit0。
- 独立multiprompt子树static8与固定输入cache17亦exit0，分别属于源准备，不以此验收Java/wire。

证据 `DerivedData/Verification/primary-env-static-9a6c0dbd-f454-4dec-a3e7-f4f8a01ccda4/`，记录命令/cwd/exit及日志。静态测试检查remote/context/TLS/异常URL拒绝在命令/构建state前、后续context冻结、远端builder拒绝；不因单测绿宣称实际运行通过。

## Buildx v0.38.1 实装兼容 R2

首次真实Engine-ready预检实际失败：`buildx inspect ... --format` 返回125/unknown flag。原20个mock测试只证明检查政策，未覆盖CLI是否支持该选项；错误日志保留，不写成初次全过。

R2仅根同3文件：`buildx inspect <verified-context> --timeout 10s`，不带format/bootstrap，不用会探测其他builders的全局ls作runner路径。C locale/NO_COLOR，按实装native stdout有界解析（64KiB/512行/单行4096字符），精确header/Nodes/唯一builder与nodeName/driverdocker/endpoint匹配，拒重复/缺失/错误/控制序列/多node。实际Devices缩进Name不误当node。新2项回归保留原20安全语义，旧实现红测exit1，最终22tests/OK。

主管读取R2diff，独立22tests，再真实调用当前Docker的`require_local_engine`/`require_local_builder`均通过；实际Compose展开四服务127.0.0.1/internal/namedvolume-only/read-only/cap白名单/0.5CPU384MiB128PIDs/lognone正确。外部解析脚本先因Compose省略false字段、将mem_limit序列化decimalstring而失败，修正解析为默认false/严格int比较384MiB后通过，没有改低产品配置；之前失败发生在build/state前。

实物与最终readiness证据：`DerivedData/Environment/ready-final-307c9ef8-4dc6-456a-8a77-00a71cd4284b/`。外部GUI后的LicenseTermsVersion2、2CPU4096MiB/40GiB/autostartfalse与Engine2CPU/约4GiB一致；不是Agent代接受协议。此时0images/0containers、未建runtime，才明确放行镜像构建和无网络ABI短探针，不等真实SSH/SFTP通过。

## 真实运行前下一关

用户本人处理Docker法律许可和必要系统权限，Resources设2CPU/4GiB/约40GiB后，主管独立核本机context/resource/builtin builder。使用已核官方Ubuntu24.04 ARM64 digest，先compose配置检查、build；对产物用无网络/端口/hostmount且capdropALL的短探针核包与PAM Python ABI，成功后再up并inspect实际限制，最后collect/真实四认证/SFTP。不能以python3已安装或sshd -t代替PAM模块ABI与认证运行；OpenSSH/PAM多轮也不能替代单wire多提示。
