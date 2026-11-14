# NativeReadiness-R1 新版本有限真实门

日期：2026-10-30。结论：**新冻结候选10个真实分项通过，KI取消案失败且待补报告复验；不替代正式App/活性门。**

## 版本与授权

主管审源码后运行冻结min26 `live-6a50390d-93df-4e21-9824-61f13d76fe61/artifacts/UXNativeShellProbe`，SHA256 `1808b3bd411e30384be31fbd5d645967981bb8aa951b152ed2c251000a392818`。228不可变公开输入snapshot摘要逐项一致；当前实验源码已由R2继续编辑，不能用当前路径摘要冒该二进制来源。

仅已有批准Docker四服务及有限127.0.0.1:22221～24中继。主管collect新的ignored0700/0600一次性generation，读取的仅公开provenance/fingerprint作合同，秘密由受审消费者私有FD/PIPE在内存使用，没有打印/Read密码、私钥、phrase、OTP。未重建服务器/改TTL或时钟。

证据根：`DerivedData/UXVerification/NativeReadiness-R1/Primary/`；每案独立`*-1-run.json`有完整argv/cwd/exit/时长，`*-1.log`仅脱敏结构化结果。材料schema沿旧SFTPAuth仅输入，不拿旧SFTP绿；结果taskID为本轮NativeReadiness。

## 实际结果

| 分项 | 实际结果 |
| --- | --- |
| passwordonly positive | 同socket typed primary1/code0，真实shell ACK/PTY/resize37×113/EOF/exit7/awaitclose；exit0 |
| wrong-primary | 一次内存变更仅fixture密码，provider1/primary1/code-18、KI0/shell0/input0、typed authentication、close/task0；exit0 |
| hostkey-mismatch | 合成wrong key仅临时test store，实际hostkey changed拒，provider0/primary0/KI0/shell0，typed untrusted；exit0 |
| cancel-after-ready | 真实shellReady1后才cancel，provider1/primary1、无输入/回调，close/task0；exit0 |
| keyonly Ed plain | 12.661s，真实ACK/PTY/37×113/EOF/exit7/close；exit0 |
| keyonly Ed encrypted | 12.770s，同上；exit0 |
| keyonly RSA plain | 12.641s，同上；exit0 |
| keyonly RSA encrypted | 12.802s，同上；exit0 |
| key-kbd | 25.010s，publickey primary1/code-19未完整auth后KI1，三秘密人工handler读答+一次零通知，真实ACK/PTY/37×113/EOF/exit7、server session file移除、close/task0；exit0 |
| password-kbd | 25.052s，password primary1/code-18后KI1，其余同上；exit0 |
| password-kbd cancel-ki | **15.758s/exit1**，仅固定“fixture refused”无结构化结果。不能断言取消正确、server file已清或哪项证据缺失，保持失败 |

positive报告的`primaryProviderCalls`字段旧consumer没有累计，默认0不是provider实际读取计数；仅依据已审typed调用路径与primary stage/实际shell，不能扩称该字段已证明调用数。负例另有专用provider计数。

## 清理与未覆盖

有限relay PID36177设900秒，结束日志accepted11/finished11/rejected0/cleanup_failed0，外层实际exit0。主管stop前精确ps已gone，没有发signal；再核22221～25无listener、无consumer进程。`relay-final-review-1.json`与原relay.log保留。

KI取消的final guard抛出后外层吞掉已有脱敏report，主管审窄修后另运行新冻结b41dc75a…同契约（`password-kbd-cancel-2.log/run.json`）：firstChallengeValidated=true、callback1/reply0、provider1、typedcancelled/keyboardcode-10001、primary-18、精确order、shell0/input0、pendingtask0、close与managementreaped均true；**仅serverSessionFileRemoved=false触negative-preconditions，exit1保持。** 因此客户端取消分项有真实证据，但整案因fixture服务端challenge残留未通过，不能改绿或称自动清理。两次失败均保留，未改server/TTL/时钟/断言/等待或手删材料。

第二次有限180秒relay PID38269实际自然exit0，原日志记录完整停止，未留consumer/监听。PAM `_interactive` 的 finally删除依赖服务端conversation收尾，已有历史同类取消卫生缺口；后续应在精确身份下复核自然清理/实证等待，不能猜测或删文件冒自动通过。

本轮不含真实once、活性正常/MaxSessions/DROP、并发不同秘密、TUI/资源趋势及正式App接线。Native候选仍未替换默认Direct后端。无生产/真实用户凭据/Keychain/Apple/最终出包/24h或大文件重测。
