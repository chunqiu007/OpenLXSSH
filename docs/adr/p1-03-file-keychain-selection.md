# ADR-P1-03：V1显式采用macOS file-based Keychain

状态：本机原型安全链路已独立复验，批准进入正式集成；最终macOS26/签名/锁定/双机验收仍待完成。日期2026-10-26。

## 问题与证据

Data Protection Keychain在原始及现有Development签名fixture中均返回-34018。appID值/签名有效不等于授权；Apple TN3137要求profile授权。没有创建/伪造profile，也没有改失败测试。相关证据见 `docs/reports/p1-03-credential-key.md`。

系统file-based Keychain仍是受系统加密与应用ACL保护的秘密存储，不是普通明文配置。它是macOS SecItem默认实现；Apple建议DP且称file-based处于走向弃用过程，但目前未正式弃用整个实现。V1仅两位用户独立本机使用，不需iCloud、Secure Enclave或跨App共享，允许选择该成熟系统实现。

独立候选代码在P1-03实验目录；主管读取全部候选Swift/C/脚本/测试并运行 `verify_file_keychain_candidate.py` 退出0（run cd8b4339-2b96-40fb-bb3c-0bb0a3384478）：真实CRUD、未授权不写、重复不覆盖、精确引用、默认creator ACL、跨启动和同DR版本替换读取成功；同Team不同identifier及同identifier ad-hoc读取均非交互拒绝。全部自己UUID条目删除并确认缺失，ticket0。

## 对比与决定

| 维度 | Data Protection | file-based显式策略 |
| --- | --- | --- |
| 当前可用性 | 缺合法profile，真实CRUD未过 | 正确签名本机CRUD/升级/身份拒绝已过 |
| 保护 | 访问组+accessibility class | 系统Keychain+creator ACL/designated requirement |
| 同步 | false/ThisDeviceOnly可声明 | false+绑定file Keychain；不等于ThisDeviceOnly或不可复制 |
| 锁定 | WhenUnlocked类别 | 实际Keychain锁/ACL；屏幕锁不等于Keychain锁 |
| 维护 | Apple推荐 | 相关legacy ACL/UI API已deprecated，未来需迁移 |

V1显式选择file-based，稳定App service namespace+UUID account，绑定当前默认file Keychain，不跨搜索列表枚举；无DP错误fallback。只有用户同意记住才保存；OTP不得保存。默认creator ACL，不放宽受信应用或全App访问。读取拒绝/锁定/不可用返回人工输入，不无限重试或降级磁盘。

生产调用必须通过单一串行拥有者；非交互策略在该进程一次建立/有界关闭，不复制实验中并发不安全的per-call恢复。不得改用户全局Keychain设置或ACL；最小deprecated shim局部隔离并记录，未来SDK变更重验。

## 范围与迁移

当前没有DP产品秘密，选择成本低。旧DP实验和失败证据保留，不能把选择新实现写成旧DP已通过。未来已有数据迁移必须显式用户授权、逐引用读取/写入/验证/删除，失败可恢复，不悄悄搬用户Keychain或生产秘密。

## 未完成验收

真实锁定/不可用未通过；不为测试锁用户Keychain。正式App的签名身份、并发策略、macOS26、DeveloperID、升级重装与双机仍需验收。不会承诺屏幕锁自动让file Keychain不可读；产品说明/会话授权应准确反映。若公司策略不允许访问必须人工回退。

依据：[TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)、[TN2206](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)。本决定不削减AUTH需求或允许未知挑战自动投递。
