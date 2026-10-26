# ADR：V1 当前非 Sandbox 构建与发布权限

状态：当前本地集成决定，目标系统与发行运行验收仍待。不是声称Sandbox技术上永远不可行。

## 当前证据

正式App/Core/Trust/Security/Transport/Files和Development内部候选已集成，主App/helper开启Hardened Runtime，当前entitlements为空。原生进程使用系统OpenSSH、PTY与包内Askpass/Mach认证控制面；SFTP静态libssh2；文件选择为本地明确选择并FD/noFollow锚定。当前Store/代码身份政策不接受额外entitlement。已有本地readpass、严格签名、Keychain隔离CRUD与GUI/生命周期回归在此权限配置完成。

Sandbox与Hardened Runtime、公证是不同机制。普通签名成功和空entitlements不证明Sandbox兼容；当前没有受配置profile授权的Data Protection Keychain访问组，本机DP实验保留-34018，已显式选file-based Keychain而非运行期隐式fallback。不能通过给无授权entitlement、改变用户KeychainACL或关闭系统保护解决。

## 决定

V1当前直接分发构建不启用App Sandbox，不申请沙盒继承/文件bookmark/JIT/library validation例外，不为证明可用临时扩大权限。保持Hardened Runtime及主App/helper固定身份/同Team严格检查。优先交付当前已验证本地安全路径，再在目标macOS26、真实认证与发行签名中复验。

这不是用户产品范围变化，既有架构允许评估后选择非Sandbox；没有因此获得修改Gatekeeper/SIP/TCC/系统SSH、签名证书或服务器的授权。DeveloperID/公证仍须对应外部条件与具体产物授权，非Sandbox不免除它们。

## 风险与补偿边界

非Sandbox进程拥有启动用户的一般文件/网络权限，路径校验与签名不是同UID恶意进程隔离。通过用户选择、精确UUID/FD归属、目录/文件mode+ACL拒绝、参数与配置边界、主机身份、按代认证、无Agent转发/代理/任意本地命令、禁OSC剪贴板/URL/本地媒体及有界资源降低风险，不承诺同UID或root完整防护。

后续若启用Sandbox，应是独立验证变更：沙盒继承/系统OpenSSH/PTY、Machrendezvous、文件访问、Keychain、签名profile、目标系统与同一真实互通回归，不可只翻一个build flag后宣称安全提升完成。
