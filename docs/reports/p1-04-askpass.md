# P1-04：Askpass 认证控制面阶段审查

更新：2026-10-26。工程师实现；Primary Agent独立审查。

## 当前结论

P1-04C的本地跨进程控制面迁移通过；P1-04整体仍未完成。真实系统OpenSSH+PTY+Askpass force、实际认证/多轮MFA/审批、正式UI/Sandbox/macOS26和Release仍未验证。没有把未知挑战自动当密码/OTP，也没有向Keychain请求或投递长期秘密。

实现：`Experiments/P1-04-AskpassProbe/`。活跃认证请求/随机回答全部走带内核audit trailer的Mach消息，已移除Unix socket/LOCAL_PEERTOKEN回答路径。

## 分步证据

### A：行为原型，身份证明不足

原始Unix socket fixture经主管代码审查、独立Debug/Release各14单测+20跨进程场景通过，验证有界状态、并发隔离、取消和回收。但LOCAL_PEERTOKEN可能按last_pid重新查询，不是冻结消息身份；原A不获生产安全通过。其不足促成B/C，不被绿测试掩盖。

### B：冻结身份可行性

主管读取 `Probes/MachRendezvous/` 两C文件及 `scripts/verify-mach-feasibility.py`，独立运行脚本退出0。公开临时bootstrap注册与Mach audit trailer可用；5个真实进程场景验证：正常不同镜像双向签名、同签名错误parent、同Team错误identifier、假broker和排队后exec旧token拒绝。旧token未重新解释为新镜像，拒绝回复。

`bootstrap_register`公开但deprecated。`bootstrap_register(name,NULL)`返回1101，不能当注销成功；释放自己receive/send rights后短暂dead right过渡再lookup1102，独立进程post-exit确认名称移除。没有安装launchd job或常驻服务。

### C：将有界状态机迁到Mach

主管读取新 `AskpassMach.c`、更新的协议/权利包装、broker/helper及现有签名脚本，独立运行：

```sh
/bin/bash /Users/liuwenshuo/Desktop/OpenLXSSH/Experiments/P1-04-AskpassProbe/scripts/verify.sh
```

退出0：Debug/Release各16个XCTest、28组真实本机跨进程场景、不同identifier的现有Development runtime签名/严格verify及退出后独立lookup均通过。日志在实验 `.build/verification/`，包括双配置build/test/signatures/self-test/post-exit。

## 审查重点

- broker与helper从自身有效Apple-anchor签名派生真实Team和对方固定identifier策略，不接受环境/IPC传入requirement。仅使用本机已有身份，无创建证书/改ACL/登录上传。
- 每条请求/响应由内核Mach audit trailer取sender身份，UID与动态SecCode核验；消息体自报PID不授权。broker自己登记spawn parent、检查PPID/出生时间/存活，消息处理期间保持直属child未reap。
- 仅有界inline frame12288字节；拒complex/OOL/额外descriptor/voucher/非法头，异常message destroy。一次性reply right被Swift owner消费或释放；实测helper死亡后的send失败、port count与FD基线恢复。
- helper单prompt argv、不读stdin，响应只写stdout给parent。未知hint为unknownMasked人工模型；confirm/none为明确确认/通知。回答1023字节，拒NUL/CR/LF/超限；不截断、不按文字或顺序猜秘密类型。
- nonce/会话/代次/请求ID、8请求预算、限时、取消与迟到回答失效。TERM后有限KILL，waitid(WNOWAIT)保留PID直到组清理后waitpid；取消只影响自己的会话。

28场景包含错误signer/identifier/parent、真实跨会话grant重放、queued-exec、complex/OOL拒绝、随机响应边界、helper异常/失联、超时迟到回答、send-once失败和6轮FD/Mach port计数稳定。决定输入是合成fixture，不是用户操作或真实SSH。

## 未验证与下一步

临时Mach注册在当前macOS15.8.1可行，尚无macOS26/Sandbox证据。正式helper需要不同镜像签名/运行时路径与版本关联；当前已验证Development fixture，不是Developer ID/公证产物。

当前parent为受控fixture；实际`/usr/bin/ssh`签名/父进程接入、PTY并存、认证UI、取消空密码竞态、企业挑战说明/分组、Keychain自动使用前提仍需真实原型与隔离服务测试。必须保留AUTH-02自动使用需求，同时上下文不可靠时人工回退，不能凭prompt或测试通过直接启用。

## P1-06A：真实App/系统readpass共存

主管已读取 `AskpassKeygen.c`、`BundleReadpass.swift`、App入口、打包脚本与系统parent签名策略，并独立运行 `python3 .../scripts/verify-app.py release` 退出0。

- 实际Development runtime签名AppKit `.app` 直接启动，从Bundle.main/Contents/Helpers发现helper并严格核验，不依赖开发机外部helper路径。
- 固定 `/usr/bin/ssh-keygen -y -f`，受控fork建立session/控制PTY后SIGSTOP，登记PID/birth/PPID，再只执行字面系统程序。exec后核对实际路径、Apple anchor及`com.apple.ssh-keygen`，不任意adoptPID。
- 一次性Ed25519加密key/随机口令由P1-03成熟工具管道生成；0700/0600、无DISPLAY、SSH_ASKPASS_REQUIRE=force。真实readpass调包内helper后答案只经认证Mach返回，输出公钥精确匹配。
- 成功/取消/超时三场景均退出0，取消/超时终止系统parent/helper、迟到回答拒绝；FD/Mach port回基线，服务名由独立进程lookup确认unknown；临时密钥根目录和App清理。
- 工程师Debug/Release三场景都通过，原全量回归各16单测+29真实Mach场景通过。主管Release证据在 `.build/verification/release-app-readpass.log`、app-post-exit日志。

仅证明系统OpenSSH readpass而非真正ssh网络认证。实际启动方式为直接执行AppKit bundle可执行文件，不是Finder/LaunchServices；runtime非Sandbox、宿主macOS15，macOS26/DeveloperID/公证/真实MFA均未验收。随机答案是显式合成探针，不启用产品自动密码。

下一项是正式App会话、真实SSH/PTY、信任与认证UI整合；隔离服务与合法Keychain profile条件具备后分别实测，不削弱身份策略或恢复旧socket回答路径。整体阶段1及产品AUTH/SEC AC未通过。
