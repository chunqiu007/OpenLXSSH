# ADR-UX-SSH：统一主认证入口与 Native 候选的切换条件

状态：**入口一致性缺口已确认；采用方向为成熟 typed primary + manual Keyboard-Interactive，正式默认切换尚未批准或实施。** 本记录不宣布候选通过。2026-10-31。

## 问题及当前事实

新版 UI 只提供密码或 SSH 密钥两个主认证选择；两者都必须处理实际的附加挑战，编辑器未记住的本次密码不能丢失。长期授权仍按 host/credential/key identity 精确限制，内层 SSH/sudo 必须人工处理。

当前代码并不具备统一产品入口：

- `AppModel` 普通 `sessionBuilder` 默认为 `DirectSessionBuilder`，内部 `nativeCandidateBuilder` 独立存在。
- `VaultHostEditor.save` 在“保存并连接”且确有本次密码时准备 Native intent；没有新输入时，dismiss 后调用普通 `requestSession`。之后从主机列表双击或开新会话也走普通 builder。
- `SessionEnvironment.configuration` 仍按旧四个持久枚举决定 OpenSSH password-only 或是否启用 Keyboard-Interactive。因此不能从本次输入密码的候选成功，推导保存后列表打开、密钥入口及旧数据具备相同的两主方法自动挑战行为。
- “普通Direct”只指默认**新建**连接；reuse依据有效连接快照选择最近会话，可能复用已存在的Native候选标签；手动重连保留原driver和tab.builder，不自动转到另一个后端。四项实际模型入口契约及主管独立4/0见 `../ux/entry-routing-contract-review.md`，只固定当前差异，不代表已统一。

不通过新增用户可见“测试后端”开关或把某一入口悄悄退回未知秘密自动投递来掩盖差异。旧四枚举、ID、引用和保存授权继续保持，不能批量迁移成错误授权。

## 已比较的实际方案

1. **继续使用系统 OpenSSH + Askpass 作为所有入口。** 系统协议和进程/PTY 路径已有历史证据，仍是当前默认；但 Askpass 没有完整可靠的主密码与 KI 分组/echo 类型。受限 password-only 首请求的证据不能扩展到未知 KI。按提示文字或首个 masked 请求投递长期秘密不可接受。研究及受限策略见 `p1-04-askpass-authentication-context.md`、`../ux/u0-auth-context-evidence.md`。
2. **固定成熟 libssh2/OpenSSL，App 适配 typed primary 与独立 manual KI。** 现有实现复用同一真实 socket 的 hostkey、method discovery、一次主方法、必要 KI、PTY/shell；SwiftTerm 不变，无新的密码学或协议实现。分项实网证据最强，选择它作为统一入口的候选方向，但资源/并发/兼容与正常 App 体验仍必须先过。
3. **另换成熟 SSH 库。** 当前没有同等本地比较、许可证与互通证据；不能凭名称或上游说明声称已经满足。仅当现候选暴露无法合理修复的必要缺陷时再评估，不因此削减功能或放宽信任。

## 不可省略的语义差异

Native 活性策略不是 OpenSSH ServerAliveCountMax 的逐次等价实现。它在同连接保持一个辅助 session-channel-open，等真实确认或拒绝，再 close/free；不申请 PTY/shell/exec/subsystem。拒绝仍表示收到真实远端答复。它可能短暂占用 MaxSessions，并产生审计或限流影响。

旧 interval/count 的合法数值已原样映射，interval0关闭，最大连续响应窗口36000秒；这不赋予其 OpenSSH 的 N 次独立请求语义。将来切换时界面/帮助必须明确连续响应窗口的实际含义，不能只保旧字段名称而隐瞒差异。不能以 TCP ACK、普通输出或 libssh2 keepalive-send 返回成功替代服务端 SSH 响应证明。

Native 不再拥有本地 ssh PID/PTY 进程；socket/libssh2 owner 为单串行队列，App 单 receive consumer。关闭 `closed` / `retired` / `incomplete` 的事实、只读 canonical drain ticket、有限 registry 与同 tab 重连 fence 必须继续准确，不能因没有 child PID 就称资源已清。

## 已有证据与仍未满足的门

- typed primary、两类 manual KI、changed 精确事实及 once/persistent 信任均有固定隔离服务的真实分项；App 本次密码、两类四轮 KI、三类信任也成立。分别见 `../ux/app-password-transient-review.md`、`../ux/app-mfa-real-review.md`、`../ux/app-trust-real-review.md`。
- 数值兼容、原 pump 的 EAGAIN/稳定参数/有限调度与饱和取消已有本地门，固定 vendor、archive 和许可证未换。
- 历史 normal、MaxSessions 和严格 DROP 各有有限实网门；它们不自动覆盖新的 mixed-load 或 App 入口。
- **旧 SSH/App 整体资源门仍失败。** 一些运行卡 weak 对象，另一些三 weak nil 但 FD 多三项；仅一个只读项已识别为 QuartzCore metallib，另两项未知。三类信任新案也均 weak cleanup 失败。不能按数量白名单、强 nil 或延预算。
- 新版并发 A 取消/B 原 owner 继续及 cross/late 拒绝已真实成立，但 A 服务端挑战 present、B removed，逐owner清理整案失败，见 `../ux/app-concurrent-mfa-real-review.md`。
- 有限真实输入/输出/resize/活性及同连接 tmux 门已通过，逐leg native drain/socket关闭/FD计数4→4成立；见 `../ux/native-finite-mixedload-review.md`。这不是 App 图形资源、长期pending deadline或全部TUI验收。
- 原生输入、真正 CmdV、中文 IME、Finder、三尺寸/全屏实际截图及像素门未过。图形调查恢复需准确自有窗口真实可见绘制与 ACK 后 frame 推进，而不是 `isVisible` 或 AX 树。当前不以不可见的截图替代人工体验。

## 后续正式切换的准确范围

只有上述必要门满足后，才修改普通 builder 与相关路由，使新建/编辑保存连接、列表双击、新会话、旧四枚举和手动重连一致使用已选策略；保持本次秘密优先、保存授权与 KI 永不自动接收长期材料。届时需定向覆盖所有入口、错误/取消/重连代次和无授权回退，记录具体源码差异、依赖/签名/许可影响及候选来源。

**本次不执行默认切换。** Native 分项成功或该 ADR 草案存在，都不满足 `UX_READY_FOR_USER`。体验确认前不请求 Apple 公证/时间戳或新最终发行出包。
