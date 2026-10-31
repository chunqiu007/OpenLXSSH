# Native liveness configuration compatibility — reviewed local gate

日期：2026-10-31。范围仅为候选数值兼容及App options映射，**不是默认后端替换、真实活性或完整UX验收**。默认仍为DirectSessionBuilder。

## 变更与约束

- `NativeShellLivenessCandidate`保留0.05秒小数下限及count1…100，interval上限扩至3600秒，responseTimeout乘积上限36000秒。
- App从实际传入的`SSHSessionConfiguration`映射，interval0明确为nil，正值原样使用，不clamp、不忽略已保存合法值。原App合法interval0…3600/count1…10共36010种组合均已覆盖。
- bridge packet read timeout上限为36002秒，保留真实auth guard与公开readback。固定libssh2 1.11.1的公开set/get可保存该正值；未修改vendor、归档、pins或原生依赖产物。
- 网络operation10秒、interaction120秒、authentication300秒不变；其合法上限仍分别300/120/300秒。长保活窗口不能扩大认证或网络操作预算。
- Native是单个辅助session-channel-open的连续响应窗口，不是OpenSSH的N次独立ServerAlive请求；会短占MaxSessions并可能产生审计/限流。没有请求PTY、shell、command或subsystem，不自动重连。

## 验证与独立审查

证据根：`DerivedData/UXVerification/NativeLivenessCompat-R1/`。

| 已执行验证 | 结果 |
| --- | --- |
| 新policy/虚拟时钟/预算/public readback | 4项通过 |
| 包相关回归 | 61项通过 |
| 包完整严格min26回归 | 203项通过，原199方法正文全部保留并执行 |
| Debug及显式HostProbe26构建 | 均exit0 |
| App两图mapping、retirement、精确旧断言回归 | 每图17项通过；不是全部60项App方法 |
| 实际Mach-O最低系统检查 | 21件均minOS26 |
| 主管源审后独立复验 | policy4及App17共21项通过 |

主审确认实际connector边界0×10、默认30×3、3600×10均正确，取消与资源账本回归保留。虚拟状态时钟覆盖t3600开始probe、t39600截止，pending期间普通applicationRead不延期。独立无socket libssh2 session set/get确认36002；未信任bridge调用仍拒绝且不发包。

首轮新测试字面量编译失败与vtool检查器数量误判保留，修复后按最终摘要复验，没有修改断言来伪造通过。精确增量SHA256：`905a2010d3d3d2c5b0c40f2531c657ce0c4d0e0c7219894c1967d5bf5575e5c4`。权威来源与执行名单见`final-freeze.json`、`final-audit.json`、`Primary/`。

## 未覆盖

原pump出站EAGAIN恢复、混合输入/输出/resize调度和饱和取消测试为后续独立任务；本次没有更改pump。未执行新live、GUI、collect、签名或历史长测。旧normal/MaxSessions/DROP只覆盖其各自冻结来源，不自动覆盖本次接线。

真实App间歇weak对象持有与描述符20→23仍未过；其中新增只读项已精确匹配QuartzCore default.metallib，另两个读写文件仍未知。没有改count门、添加数量豁免或宣布UX_READY_FOR_USER。详见`app-native-live-design.md`。
