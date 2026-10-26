# 多提示隔离服务：源码准备与导出清理 R1

Task：AUTH-MINA-FIXTURE-A / AUTH-MINA-EXPORT-CLEANUP-R1。只新增 `Tests/IntegrationEnvironment/multiprompt/`；不是App依赖，不修改上游或自研SSH。当前仅源准备、固定输入与离线验证；**Java尚未编译，容器未构建/启动，SSH wire未验证，不把AC10记通过。**

## 范围与固定输入

MINA SSHD2.20.0，public `KeyboardInteractiveAuthenticator` / `InteractiveChallenge` / `AsyncAuthException`；单次two两提示（echo false/true）、非null零提示接受/拒绝、异步批准/拒绝/等待取消/超时，不声称同一次KBI2→1→0多轮。每次attempt随机ID与独立答案、75s TTL、session/attempt精确绑定、8 sessions/8 pending/3 attempts、2线程调度器/至多2timer每attempt；completion在provider lock外调用，关闭/替换/过期撤销状态。

固定17公开输入URL/SHA512在子树`inputs.lock.json`。官方source/binary归档分别核官方SHA512，4个运行JAR与已校验官方binary archive逐字节一致；第五slf4j-nop从Maven固定SHA512。源码/JAR只读取/校验，未宿主执行Java。未PGP验签，不编造发行签名认证；MINA/JCL Apache-2.0、SLF4J API/NOP MIT，原notice保留；Ubuntu/OpenJDK包许可及实际apt版本仍须容器build记录。

主管独立cache17和4JAR逐字节对照通过；源审确认zero返回非null空列表、public API调用，而不是null拒绝冒充zero。协议发包仍由成熟MINA执行，未编译/运行前不声称实物可用。

## 隔离契约

单独compose contract尚未接父runner：127.0.0.1:22225、专用internal桥、nonrootUID10000、read-only、cap-dropALL、no-new-privileges、0.5CPU/512MiB/128PIDs、日志none、专有tmpfs、无hostbind/socket/hostnamespace。Ubuntu两stage固定主管从官方registry核对的24.04ARM64digest。Java只在容器；无SFTP/转发/任意shell，认证后仅固定成功marker。

控制为容器内固定文件API，status无答案，公钥trust经管理通道获取；挑战答案只存在0700目录/0600短生命周期文件。父runner集成仍需本机context/builtin builder及双ownership label、实际resource/port/network inspect；contract本身不是可绕过父runner的启动入口。

## 独立审查发现与 R1

聚焦只读审查确证P2：旧`private_export.retain_challenge`在创建答案文件后于try/finally外输出路径，stdout BrokenPipe/中断或期限计算异常可绕过TTL清理；写入中途也可能留下partial。旧TTL清理按路径删，还可能误删已替换的常规文件。这不是SIGKILL/断电的已声明限制。

作者先红测：强化后的旧实现16tests/13failures/0errors、exit1。最小修复为受保护`created_file`：open O_EXCL|NOFOLLOW0600、保留原fd；创建/写入/输出/期限计算/等待都位于保护域，普通错误/KeyboardInterrupt均清理本轮对象并关fd；清理以仍打开的dev/inode和当前UID常规文件核归属，不删OEXCL已有目标或已观察到的替换inode/symlink。schema/权限/原8测试函数逐字节不变。

工程师最终16tests/OK、cache17通过并停写。主管读取实现/新增8测试与红绿JSON，独立16/cache17exit0；原审查者另定向新增8清理测试和4条FD生命周期复核通过，原P2 resolved。未承诺lstat/unlink原子防同UID持续竞态；SIGKILL/断电/文件系统拒删仍可阻止清理，父生命周期仍须精确清理宿主复制件。

证据：

- 初独立static8/cache17及官方JAR对照：`DerivedData/Verification/primary-env-static-9a6c0dbd-f454-4dec-a3e7-f4f8a01ccda4/`。
- 最终主管static16/cache17：`DerivedData/Verification/primary-mina-export-r1-8db75ea7-7b4d-4d8c-a87e-d2ce1795c1f9/`。
- 修前/修后/精确patch：子树`.cache/export-cleanup-r1-red-strengthened.json`、`export-cleanup-r1-green-final.json`、`export-cleanup-r1.patch`。只有公开合成metadata，没有真实挑战/用户秘密。

## 剩余必要工作

Docker官方first-run订阅协议需用户本人处理，资源2CPU/4GiB核定前Engine未放行；当前Docker正常停止，不能因为API曾响应就启动服务。之后父runner生命周期接入、真正javac/FixtureContractTest、wire两提示/zero/异步/取消/超时/并发、客户端次数与材料/资源归零均须实跑；任何源码或静态检查不代替它们。MINA response-count mismatch可能在高层回调前拒绝，材料由关闭/替换/TTL兜底，此public API局限已明示。目标macOS26与App人工展示/MFA厂商兼容另验。
