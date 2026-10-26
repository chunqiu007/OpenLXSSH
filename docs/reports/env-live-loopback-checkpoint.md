# 四认证服务实物隔离与回环入口检查点

日期2026-10-26。用户已明确授权，官方镜像build/ABI已通过独立核验。当前四服务已真实Healthy，但**尚无SSH/SFTP认证成功**，入口转接首轮仍失败待修，不将service health、YAML ports或离线测试当互通。

## 已观察事实

`fixture.sh up --authorized-run`首次exit0，project `openlxssh-fixture-61ed25328c13`：

- keyonly CID `2db5bbb3cb75a3253d9b02af5ca52cbdc8095230464f82c18d37eca9ac1fc837`，host请求22221。
- passwordonly `bbee0c65e6e3fab33f7693fb7d20be568f4ced27959faef43b149c6361f813fe`，22222。
- key-kbd `43c0c4401c99851d8f2c7d78543b104aef1e4ef9ac0033c2be85112afe45bbf6`，22223。
- password-kbd `b2ed801a870aeabdd7965d48033e105f5726f101713eb5a061bfa36a251ce29c`，22224。

各自exact image `sha256:7f633d33bf5af2fbee137385eba3e036ef7bbbcf18fe423d99b25be12d12a363`、Healthy、只读/no-new-privileges、精确7cap、0.5CPU384MiB/noswap/128pids、none日志，唯一自身project internal桥及各自named volume，未hostbind/Docker socket。Engine可能以CAP_前缀表示cap及在HostConfig.Binds写named-volume串，实际Mounts.Type和精确标签核对避免误报。

容器内部2222 LISTEN，IPv4无默认路由，TEST-NET-1保留IP192.0.2.1:443有限0.5s连接返回ENETUNREACH101（未接触真实外网）。HostConfig.PortBindings虽127，但NetworkSettings.Ports是`2222/tcp:[]`、宿主22221～24无LISTEN且socketECONNREFUSED61。这是Docker29 pureinternal实际不发布入口，不可normalize成通过。

证据 `Tests/IntegrationEnvironment/.logs/up-collect-20261026T144215Z-b5ccc915/`：raw inspect/network/no-routes/socketchecks、checkpointVerification与26文件artifactSHA，主管独立逐一匹配。源码解释仅Moby旧版对照，不假称实际Engine同版已审。

## 保留隔离的入口决定

见 `docs/adr/test-internal-loopback-relay.md`：仅测试固定127有限前台字节转接→exactowned dockerexec UID10000→容器127:2222，协议/认证仍真实SSH。绝不改为external或双网、NET_ADMIN/privileged/hostSSH，不记录wire/凭据，也不是产品端口转发功能。

rootrelay source/offline初轮通过：24root静态（含官方LastActivity误拒红转绿）、22relay真实socketpair/ownchild字节完整性、背压/EOF/drain/half-close/取消/限额/端口碰撞、fakeLinuxpidfd路径；主会话独立全部通过。Linux真实pidfd/exec仍未验。

## 首次 live 入口失败及收缩复现

主管唯一执行 `fixture.sh relay --authorized-run --max-duration480`，前台有限测试，未launchd/cron/自启。证据 `DerivedData/Verification/relay-live-af9b7d87-5448-45cb-b9b0-614073cb4500/`。

结果exit1、130.68s，无ready/listener/auth/collect，countersaccepted0/cleanup_failed0。外部readiness读取过早的assert错误保留；实际failure最终由进程exit1确认，不把readiness脚本先失败当产品结论。

实测单exactCID `docker --host <frozenUnix> inspect`3.02s；当前rootpreflight重复约63CLI，之后四target16metadata共享8s启动预算不可达。root只读分析提出保持全部ownership核验但单次枚举/批inspect去重复；admission身份校验不能用启动缓存替代。主管已派ENV-RELAY-LIVE-STARTUP-R1，有限只读测同frozenUnix Docker公开HTTP GET metadata，若确实快则保留相同精确id/label/image/health/internal校验改同本机API读取、exec仍DockerCLI；有界deadline/pathallowlist/1MiB，不实现Docker或SSH协议栈，不扩大远程服务。

修复后必须新有限入口实跑、核hostlisteners127、实际带外hostkey与exec清理，再collect/liveconsumer；未完成前不记可达或AUTH/FILE通过。四既有容器仍不重启/重建，不必要重复产生秘密。
