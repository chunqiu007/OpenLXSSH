# P7 正式 Transport 对抗回归及 Mach 所有权修复

## 结论与范围

本轮正式 Transport 有限本地安全补证通过主管独立审查、聚焦只读复核和独立 Release 验证；两处实际生产 C 缺陷已修。最终 `AskpassMach.c` SHA256：

`34ee7ffbad3c2f75e60a08c308ae1e7021ae82293826b84bd327c3caa20fbb32`

此结论限宿主 macOS15.8.1/24H32、arm64 的签名认证控制面与本地资源所有权，不代表真实 SSH 服务器认证/MFA、目标 macOS26运行、Sandbox、Developer ID、公证或整体 Goal 完成。正式产品仍 min26。

## 实际差异与隔离

- `Sources/COpenLXSSHAskpass/AskpassMach.c` 仅两处最小生产修复及必要约束注释，身份、JSON/header拒绝、授权代次、普通终端/认证隔离政策未放宽。
- 新 `Sources/CTransportAdversary/`、`TransportFixture/AdversarialClient.swift`、`AdversarialVerification.swift` 与 fixture入口，只位于 `OPENLXSSH_TRANSPORT_HOST_PROBE=1` 条件图，不进入默认shipping图。
- `Scripts/verify.py` 保留原35测试/readpass/event，新增不同签名镜像、完整矩阵与28个独立post-exit lookup。签名镜像和数据位于独占UUID临时树，结束仅清理本轮树，不覆盖旧路径或删除别人的资源。签名身份只在内存查询，离线timestampnone；未创建证书或修改ACL/search list。
- `Package.resolved`、上游源码、其他包/App业务代码未改。

## 缺陷1：voucher拒绝检查不可达

原 `ap_mach_receive` 未设置 `MACH_RCV_VOUCHER`，内核先剥离消息voucher，因此既有 `msgh_voucher_port != MACH_PORT_NULL` 的inline-only政策检查无法发现它。

强红测不是仅用非法JSON：真实有效编码 `Request` 携真实 `host_create_mach_voucher(USER_DATA)`，修前正式Broker `accepted=1 rejected=0`。证据 `.build/verification/debug-voucher-valid-request-before-fix.log`。

修复：接收options加入 `MACH_RCV_VOUCHER`，再沿既有header判断拒绝并 `mach_msg_destroy` 释放voucher/其他已接收权利。Debug、Release与主管独立Release均变为 `accepted=0 rejected=1`；C层各类拒绝与rights/VM回收亦独立检查，不以JSON失败替代voucher政策。

## 缺陷2：请求发送超时遗留LOCAL send-once权利

受限复现仅 listener qlimit=1、一条公开marker及一条正式请求，250ms发送超时；不是大量填队列/攻击。修前 `ap_mach_send_request` 返回 `MACH_SEND_TIMED_OUT`，port count +1，精确新增类型为DEAD_NAME。

Host-only包装生产调用的诊断证明：

1. 发送前 LOCAL是 `MAKE_SEND_ONCE(21)`，借用原caller receive；REMOTE是COPY_SEND。
2. 超时pseudo-receive后，LOCAL变为 `MOVE_SEND_ONCE(18)`，返回一个新的、当前调用方拥有的send-once name；REMOTE也返回owned引用。
3. `mach_msg_destroy` 释放REMOTE引用3→2，但有意保留LOCAL（正常接收中的LOCAL是借用receive name）；原caller receive关闭后，这个新name变为dead-name。

修复仅失败分支：当返回LOCAL disposition精确为MOVE_SEND_ONCE且port有效时，deallocate **返回的LOCAL权利**，置NULL并清LOCAL bits，再让既有destroy处理REMOTE/voucher。不猜原receive name，不扩大为任意端口清理，不删除未copyin时的MAKE_SEND_ONCE receive。

证据位于包 `.build/verification/`：

- `debug-send-timeout-before-fix.log`：timeout、+1dead-name。
- `send-timeout-ownership-diagnostic.log`：修前LOCAL/REMOTE类型和ref变化。
- `send-timeout-ownership-proposed.log`：host-only最小候选delta0。
- `send-timeout-ownership-after-fix.log`：最终生产实现delta0，原caller receive仅drop一次。
- `send-precopyin-after-fix.log`：INVALID_DEST、LOCAL仍MAKE_SEND_ONCE，原receive保留至caller唯一drop，delta0。

send-once发往已死目标在本机可能静默消费且绕过qlimit，不能坚持“必返回失败/必队列超时”的错误假设。fixture保留success/dead/invalid-length三种精确归零检查，真正发送错误销毁分支使用同一生产 `send_message` 的request timeout。

## 最终矩阵

每个Debug/Release配置保留并通过：

- 35 unit tests，原断言未删。
- 6次真实系统 `ssh-keygen` readpass场景和4次签名parent/authenticated-event场景；不是远端SSH登录。原10个Mach service退出后独立lookup unknown。
- 28个正式Broker进程场景：同Team错误identifier、正确identifier的adHoc signer、错误parent/session/generation/nonce、重放；三种queued exec（wrong→helper/helper→broker/helper→helper），明确等exec完成才泵Broker，不能靠处理时序碰巧成功；取消/parent退出/关闭后迟到答案不送出。
- 14类原始消息：complex-empty、port descriptor、OOL memory、OOL ports、voucher、错误id、缺reply、send非sendonce、短header、inline超限、zero/high count、size mismatch、receive-too-large。每类3条有限消息，另检查精确rights/VM回收。
- send-once success/dead/invalid-length及request发送超时错误清理；28个新增service退出后独立lookup unknown。

不把adHoc镜像冒称第二Apple Team；没有第二Team身份，真实different-Apple-Team仍未测。子进程只使用自有PID/parent/reaper，捕获输出为零，未打印随机迟到回答或认证秘密。

资源口径：工程师Debug FD45→45、ports96→99；Release FD45→45、ports96→100。主管Release FD45→45、ports95→98；总port有框架初始化差异，逐场景采用已声明有界稳态余量2，不声称总port精确零增长。14种原始C消息的rights/VM则精确归零，二者不是同一统计。

## 执行与主管复核

工程师实际执行（包目录）：

```sh
python3 Scripts/verify.py debug
python3 Scripts/verify.py release
python3 Scripts/compile-macos26.py
```

全部exit0；strict Clang `-fsyntax-only -Wall -Wextra -Werror`、Python syntax与diff-check通过。默认mac26双配置只编译，实际改动对象 `.build/macos26/arm64-apple-macosx/{debug,release}/COpenLXSSHAskpass.build/AskpassMach.c.o` 主管另以vtool确认minos26.0/sdk26.2，helper/DirectSSHSession对象同样有脚本metadata证据。

主管完整读取生产diff、host-only C/Swift fixture及验证入口；独立只读聚焦审查未发现可操作的新问题，初审指出的动态缺口随后由最终日志补齐。工程师停写后，主管独立执行完整 `python3 .../Scripts/verify.py release`，exit0，C hash前后不变，35/6/4/10/28/28及raw/rights均通过。固化日志：

`Packages/OpenLXSSHTransport/.build/verification/primary-adversarial-aa62e529-e374-4372-9e9f-ff2501a2dfb1/`

含command/cwd/exit/sourcehash、release-test/ipc/adversarial/dependencies及主验证日志。

## App对应回归

voucher单修复时点的18ab8f…App回归已成功但不是最终证据；第二修复后，工程师在新目录执行一次最终HostProbe105/0失败、Release build-for-testing、signed12/8/15/5、sessions-exit17与files-transfer-exit17，均exit0，不重复无关历史GUI/压力。

`DerivedData/Verification/p7-voucher-final-9803826c-31d1-4a9c-9bde-45a313b37a08/`

主管核九项App/helper/C对象hash、四份依赖文件、Releasearm64/min26、HostProbe min15明确隔离、两份真实退出cleanup/admission报告；输入前后无变化。主管另直接对最终已构建App独立执行 `Scripts/verify-signed-app.py`，12/8/15/5及精确隔离Keychain清理exit0：

`DerivedData/Verification/p7-primary-final-signed-82124dfc-3ea9-40d2-96d3-f535fd737eee/`

没有把签名验证当作真实网络认证。旧候选/driver未含本轮C，必须另以新UUID生成并核验，结果在对应打包/driver报告继续记录。
