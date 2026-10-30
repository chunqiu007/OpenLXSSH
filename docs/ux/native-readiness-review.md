# NativeReadiness-R1：离线实现与主审检查点

日期：2026-10-30。状态：**候选包与测试consumer离线门已通过；必要真实门/正式App接线未完成**。不切默认App后端，不用旧四正向覆盖新版本。

## 新候选接口与边界

- 源兼容保留`connect(primary:)`，新增预选method/异步typed primary provider，在真实握手信任与method discovery后仅调用一次；token/lifetime/方法返回一致性前后复核，primary后无none重置/长期秘密fallback。
- 网络、单次交互、总体认证预算分离；默认overall=operationTimeout比旧逐步骤累计行为更严格，**只源兼容，不全时序兼容**。新fixture显式15s交互/45s总体，旧原始green不追认。
- Native KI owner不持primary/saved reader，支持多prompt/echo/zero，取消token并撤销reply，不能将空数组冒取消。
- `ChallengeReply.cancel`仅新增接口，SharedHostTrust增加confirmOnce仍核实际endpoint/rawkey、changed拒绝，单pending cancel不伤B。
- 一个辅助session-channel的可选SSH round-trip候选，默认关闭；同queue轮转且原outbound EAGAIN续原API，open confirmation或固定上游实际OPEN_FAILURE才证明回复；成功close/free有界。固定libssh2 archive/source/error-origin gate已绑定，不自写SSH包。
- 该活性策略是单pending连续interval×periods时间窗，**不是N次OpenSSH ServerAliveCountMax**，会短暂占MaxSessions槽/产生审计或限流；需真实正常/拒绝/黑洞/不饿死/资源门及ADR。
- provider/mailbox任务有显式registry与0.5s有界drain；不合作外部provider无法被Swift强杀，snapshot/error记录未排空，不以cancel或close返回冒零任务。后续App provider必须合作、可取消、有owner排空。

主管已读取新Types/Session/Authentication、C callback/公开probe桥接、SharedHostTrust/ChallengeReply及关键readiness/once回归，核39源码冻结changed0及consumer摘要一致；真实positive/fault consumer亦已读，不将其编译等同实际运行。

## 已执行工程师验证

日志根：`DerivedData/UXVerification/NativeReadiness-R1/`。完整cwd/argv/exit在每个`*-run.json`。

| 验证 | 实际结果 |
| --- | --- |
| C bridge clang Wall/Wextra/Werror语法 | exit0 |
| Files严格定向 | 55/0，exit0：NativeShell16、Readiness15、SharedOnce5、InitialDirectory15、旧KI4 |
| 实验probe严格Swift测试 | 15/0，exit0 |
| 固定source-origin gate与unittest | gate0、2/0 |
| NativeSupport独立relay判定合同 | 4/0 |
| min26 consumer build | 第二次exit0，首次FaultCase闭包推断失败保留 |
| FixtureOfflineChecks | 46项，exit0 |

前两次包编译（闭包类型/async semaphore）、consumer首编译失败均保留，没有降低断言。以上无TCP/DNS真实服务、Docker/Keychain/GUI动作；本地socketpair只证明无真实SSH的取消/边界。

冻结consumer：`Experiments/UXNativeShellProbe/.build/live-6a50390d-93df-4e21-9824-61f13d76fe61/artifacts/UXNativeShellProbe`，SHA256 `1808b3bd411e30384be31fbd5d645967981bb8aa951b152ed2c251000a392818`。228公开构建输入末次变化0，主管复核39源码ledger变化0。该consumer尚未live。

## 当前缺口与具体后续

1. 当前CLI只positive/fault，活性LivenessCase未接受审私有PIPE监督器；现NativeSupport只合成verdict，不是黑洞结果。
2. 已恢复NATIVE-LIVENESS-SUPERVISOR-R2，仅实验/NativeSupport写域补anonymousPIPE、准确PID birth/UID/source-port tuple、freshACK与独立relay arm、backend alive/noFIN/自然timeout+FD/task闭环；正式runtime冻结。
3. 批准一个明确test-only MaxSessions instrumented对象：只实验Cshim，对冻结Bridge测试副本编译define wrapper，同行程同连接先占7个无startup channel（fixture MaxSessions8），helper第9次真实OPEN_FAILURE；normal/DROP绝不插桩，不改服务器/vendor/runtime。尚source准备/无live。
4. 新本次provider/once及四正向、wrong primary/changed/KI cancel/ready cancel、encryptedEd/RSA需主管审冻结输入并release后有限真实场景。当前旧四positive不能当本版本通过。
5. 等必要真实门与ADR定案后才正式App adapter（单receive/input/resize owner、两主方式KI/多字段/自动三按钮/一次性intent）；再短TUI/键盘/输出/资源验证。

无新环境/生产/真实用户凭据/Apple/最终出包/长测。源码准备和离线通过不构成UX_READY_FOR_USER。
