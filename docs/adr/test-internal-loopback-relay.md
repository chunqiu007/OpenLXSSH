# ADR：纯 internal 隔离服务的有限本机测试转接

状态：依据真实运行问题批准实现；源码/运行验收分别记录，当前不等于已可用或产品通过。

## 实测问题

获用户明确授权的四类认证服务已在Docker Desktop/Engine29.9.2中Healthy。HostConfig.PortBindings请求127.0.0.1:22221～22224，但NetworkSettings.Ports实际为空，宿主socket返回ECONNREFUSED；容器内2222正常LISTEN、专用internal桥无默认路由，TEST-NET-1保留地址有限连接返回ENETUNREACH。故YAML静态端口配置不是实际可达证明。

证据 `Tests/IntegrationEnvironment/.logs/up-collect-20261026T144215Z-b5ccc915/`；主管复核26份证据hash及实际记录。公开Moby旧版源仅供解释对照，未取得实际Engine同版源码，不声称同版源码审计。没有因未发布而改为external网络、双网络、NET_ADMIN或主机防火墙。

## 决定与边界

保持现有测试容器专用internal/no-egress/精确cap与资源/无hostbind；增加**仅测试基础设施**的有限前台本机TCP字节转接。绑定固定127.0.0.1:22221～22224，MINA独立入口可复用同库固定22225；每个连接仅通过已核同一本机Docker context的exact-owned container `exec -i --user10000:10000` 固定Python桥连其容器内127.0.0.1:2222。

- 用户授权覆盖本机隔离环境必要测试运行和这些端口，普通可恢复技术选择由主管判断；没有新增外部网络/生产权限或法律同意。
- SSH协议、主机密钥、密码学和认证全部仍由真实系统OpenSSH或成熟MINA/客户端生产代码处理。桥只搬运不透明字节，不解析或匹配提示，不记录/落盘payload，不导出凭据。没有把mock或假server当互通。
- 明确这不是OpenLXSSH产品端口转发功能，不进入App/Packages，不改变V1排除范围；不称为Docker原生端口发布。
- 固定服务/端口/容器ID/image/project/fixture双label与internal网络绑定；每admission复验，stale/foreign拒绝，无任意host/CID CLI。限16总/每port8 active、有界每方向64KiB、半关闭/排空、连接/空闲/整体期限。
- 以显式启动的有限前台测试进程运行，不launchd/cron/login自启/无期限常驻；结束须关闭listener和自有exec/pipe并回收。只清理精确PID/token/身份资源，不能按名扫杀Docker/SSH进程。
- host监听碰撞拒绝，不SO_REUSEPORT或换端口；容器依然没有默认外部路由，也不挂载Docker socket。

## 验收门槛

先离线真实socketpair/公开二进制payload测试背压、partialwrite、EOF双向排空、取消/超时、限额、监听碰撞和ownedchild回收；主管审diff和独立回归。随后仅在已授权四服务实物上启动有限桥，检查所有listeners严格127.0.0.1、实际可达、带外主机指纹一致、外部路由仍拒绝，停止/取消无自己的exec遗留。真实SSH/SFTP由生产consumer另验，未通过不计AC。

转接引入Dockerexec进程开销和测试网络特征，真实负载/性能报告须计入并披露，不冒称原生TCP路由或最终Release性能。目标macOS26、长测、企业环境仍需各自证据。
