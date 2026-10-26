# 已授权隔离镜像：真实构建与 PAM ABI 检查

Task ENV-AUTHORIZED-BUILD-ABI-A。用户已明确授权官方Docker/UbuntuARM64及测试依赖下载构建、仅本机回环服务；当前Docker许可记录和2CPU/4GiB/40GiB资源已经实物核定，不再是授权或许可等待。本报告只验镜像构建/受限ABI，**不等PAM认证、SSH/SFTP或产品验收通过**。

## 实际构建与兼容修复

固定base：`docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d`。本机context/Unixendpoint、同名builtin docker-driver builder已先主管独立核验。

首次 `fixture.sh build --authorized-run` 经Compose5.6.1路径exit1，实际错误为要求切换desktop-linux上下文。独立selected builder inspect成功、Compose dry-run亦成功，但不执行真实child，不能当修复证明。具体Compose子环境丢失点未最终确证，不编造根因。

主管批准wrapper内部直接调用已核本机Buildx：精确`buildx build --builder <verified-context> --platform linux/arm64 --pull --load --build-arg UBUNTU_IMAGE=<state> --tag <固定fixturetag> --file <ROOT/Dockerfile> <ROOT>`。仍经过原授权/上下文/builder/现有资源归属/固定base与构建后镜像架构标签检查；Compose后续生命周期保持no-build/pullnever。不取消builder pin、不建特权socket、不加privileged/额外网络挂载或build entitlement。

新增红测先捕获旧Compose分支exit1，原22测试保留，新23项通过。根.gitignore/.dockerignore新增.logs排除，防raw日志进入后续build context；只本轮私有logs目录0700、文件0600。

修后同一wrapper命令exit0：built image **`sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363`**，linux/arm64、size235,068,339bytes，base label与已核ref完全一致。没有修改原Dockerfile、compose或PAM策略来换绿。apt版本记录而非声称跨时完全锁定；BuildKit固定platform/baseARG lint warning保留。

## 精确ID受限探针

只对上述image ID启动随机自有短probe，`--rm --pull never --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --pids-limit128 --memory384m --memory-swap384m --cpus0.5 --log-driver none`；无port/nohostmount、entrypoint仅Python检查，不启动sshd或调用PAM认证。host inspect核全部约束、自动删除成功。

实际事实：

- Ubuntu24.04.5/aarch64，Python3.12.3。
- libpam-python `1.1.0~git20220701.1d4e111-0.4ubuntu3`，实际ldd链接`libpython3.12.so.1.0`，无missing；不是先验猜测的Python2问题。
- 模块ELF64/AArch64、dlopen、pam_sm_authenticate/pam_sm_setcred符号、Python3策略模块import成功；**没有调用认证函数/完成conversation**。
- OpenSSH server/client/SFTP `1:9.6p1-3ubuntu13.20`；sshd/SFTP/pam_permit路径存在；build hostkeys已移除、runtime秘密目录不存在。
- CapEff/CapPrm/CapBnd等全0、NoNewPrivs1；memory402653184bytes、swap0、cpu50000/100000、pids128；无IPv4路由。
- probe已删除，自有project容器/网络/卷0/0/0，runtime只有state.json。认证服务尚未启动（报告时点）。

## 证据与主管独立验收

失败目录 `.logs/build-abi-20261026T141357Z-7394f093/`；成功目录：

`Tests/IntegrationEnvironment/.logs/build-abi-20261026T142531Z-60fc8160/`

含build命令/cwd/开始结束/exit/sourcehash、image inspect/provenance、probe源码/精确参数/实际constraints inspect、结果与artifactSHA清单。build raw SHA256`02ad0fc9a5adf71d90062855aaa70ce5c4b65be0c5cb6e93a1a1c79c3bb1bdf6`；probe raw`c0c88dcc6743284e62ac2a38cdfd2b0012e333bdfe674105cb1d682bae485517`。

主管读取代码与实际raw输出，独立逐文件artifactSHA匹配、image当前ID/base/arch inspect、probe实际限制与结果核对，通过；再独立23tests/OK、exit0，没有机械重建整个image或重复probe。证据 `DerivedData/Verification/primary-build-abi-19e685f2-70c9-4e6e-add7-f3730f65544b/`。

## 下一真实关卡

主管已放行ENV-AUTHORIZED-UP-COLLECT-A：仅四服务wrapperup、实际回环绑定/internal网络/资源/权限/namedvolumes检查、精确generation私有collect，尚不自动连接认证。启动失败属于普通工程问题继续定位，不扩大权限或用hostsshd替代；成功后单独分案运行production consumer。PAM嵌入conversation、认证顺序/加密key/PTY/chroot、zero审批与SFTP仍须实际验证。
