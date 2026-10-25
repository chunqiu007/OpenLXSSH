# ENV-FIXTURE-A：待授权隔离验收夹具审查

日期2026-10-26。状态PARTIAL，仅源码/config准备通过，未运行Linux/容器/sshd。

实现位于Tests/IntegrationEnvironment，官方Ubuntu24.04 ARM64基础镜像要求明确digest；四实例仅127.0.0.1:22221～22224，内部网络、无privileged/宿主目录/docker socket挂载、资源限制。源码含运行时随机一次性凭据/密钥、4种AuthenticationMethods、PAM多轮/信息/模拟审批、hostkey轮换、严格信任、2GiB+1000文件和hash校验、归属label停止移除。

主管读取Dockerfile、compose、driver和PAM策略并独立执行：

`PYTHONDONTWRITEBYTECODE=1 python3 Tests/IntegrationEnvironment/test_static.py`

13项通过、退出0；bash -n也退出0。无授权参数/远程Docker context/未归属label/不规范digest/路径逃逸/秘密目录边界均在Docker或写入前拒绝；只临时非秘密元数据测试。没有安装或下载镜像，没有运行build/up、没有生成凭据或连接服务器。

未验：Ubuntu ARM64 package/ABI/PAM路径、sshd -t、权限capabilities、网络隔离实际语义、认证/MFA/SFTP/数据往返。OpenSSH会将PAM双提示串行为单prompt多轮，不能覆盖单个SSH消息多prompt；信息/zero/审批显示和取消后worker回收也未验证。apt版本未完全锁、named volume无磁盘配额、网络黑洞/磁盘满等仍未覆。

用户确认新增运行时和资源网络范围后才可build/run；脚本--authorized-run只是防误操作参数，不代替用户授权。该夹具不改变AC-06～AC-13/17～25/31状态。
