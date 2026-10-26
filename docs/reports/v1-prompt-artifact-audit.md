# V1.0 需求到产物检查点审计

日期：2026-10-26。结论：**NOT COMPLETE；剩余必要验收受外部条件阻塞。** 本报告记录截至最终修复、内部候选及限定差量审计的事实，不代替 `docs/acceptance.md`，不将已完成子任务替代整体Goal。

## 原目标与本轮闭环

原目标是 Apple Silicon/macOS26 可安装正式 Release，四类直连认证/MFA、多终端与手动嵌套SSH、直连SFTP、安全管理和独立传输/生命周期，完成真实200次、五会话连续24h、文件/网络异常及发布双机企业验收。没有把目标缩减成本地演示或打包器成功，排除功能亦未偷偷增加。

主会话按需求/架构/计划/验收表及实际工作树复核，主要业务与测试由software-engineer实现。每次DONE均再查实际差异、关键实现/所有权、验证输出和受影响行为；修前失败不删除。默认一个业务writer，本轮Transport/App/只读研究分别限定范围，最后打包前全部停写/停build。仅相关文件本地提交，无remote/push。

本轮关键闭环：

- `ba4a2ec`：五真实终端view/逻辑driver有限渲染输入压力，主管独立105tests及76原生检查/22轮、每view814108 bytes、关闭/disposed/weak验证；不冒充真实SSH/PTY或Release PERF。
- `d331188`：正式Transport对抗矩阵迁入及两处生产C修复（voucher显式接收后拒绝、发送超时pseudo-return LOCAL send-once精确释放）。主管独立Release35、readpass6/event4/原postexit10、进程场景28/新增postexit28、raw14×3与rights/VM核验通过；聚焦只读审查未见可操作新问题。
- 最终C对应App105tests/Release、signed12/8/15/5、退出17+17通过；主管匹配九项二进制/对象hash与依赖、读取真实退出清理，并独立签名安全复验。
- `driver-71e5e2da`：最终C的新UUID真实min26全对象/链接/Development严格静态签名与主管record核验完成；**未运行、未200/24h**。
- 固定MINA2.20.0/commit2221febd…源码与许可方案：public API支持真实单wire多/zero prompt；protected多轮适配未编译，服务未启动/互通，不作AC10通过。
- `8b63961`：打包前干净文档检查点；新Development内部候选fdb05b4d包含已审修复，不上传/不公证/不安装。

## 需求覆盖与仍未满足的验收

| 原需求/验收 | 已有产物与证据 | 不可外推的必要缺口 |
| --- | --- | --- |
| HOST / AC01～04 | Core/原生主机管理、配置边界、持久化、session定位/显式多会话；App本地tests/GUI | macOS26正式运行、真实连接与整体回归 |
| KEY、AUTH / AC05～11 | 标准密钥管理、隔离Keychain CRUD/锁回退、授权撤销、多轮/代次状态、严格Mach控制面 | 真实四类认证/MFA/审批/单wire多prompt；目标系统自动密码gate不可盲扩 |
| SEC主机身份 / AC12 | SSH/SFTP共享Trust、首次/变化策略、ACL安全、同握手SFTP路线 | 真实SSH/SFTP握手、hostkey轮换与产品确认流程 |
| NEST、TERM / AC13～16 | SwiftTerm固定preview、本地PTY/输入输出/历史主题、五view有限压力 | 真实手动嵌套、远端TUI、人工IME/像素与严格ZWJ未通过问题、目标系统回归 |
| FILE、LIFE / AC17～24 | 正式libssh2后端、原生Local操作/传输/冲突/风险/取消、独立Manager、窗口/退出保护 | 真SFTP四认证适用子集、网络/权限/磁盘满/服务能力、人工Finder/选择器 |
| SEC/DATA / AC25～27 | 固定依赖/许可/实际链接来源、非Sandbox ADR、ACL/引用/日志/恢复审查与有限秘密检查 | 目标系统/真实运行出口、升级/认证整合；静态无命中非完整泄漏证明 |
| PERF / AC28～32 | 本地2GiB/1000往返SHA/取消、有限Instruments、压力view与新稳定性driver准备 | 真200次/5会话连续24h、Release App+子进程资源趋势、远端数据/网络异常 |
| DIST / AC33～38 | arm64/min26 App/helper、Development内部ZIP/manifest、101打包边界测试、使用说明/本地提交 | DeveloperID/指定产物公证授权、正常安装升级、第二Mac/企业人工验收 |

具体失败和局限必须继续保留：SwiftTerm稳定1.20尾部丢失后选1.99.1 preview，不称稳定2.x；本地Vim严格ZWJ历史失败不删除；DP Keychain -34018路线已显式改file-based，不等ThisDeviceOnly；Allocations一次exit20无trace、Leaks空表不作零泄漏；五view关闭RSS未回冷启动值，不据短测证明长期无增长。

## 最新内部候选与对应性

`DerivedData/Distributions/0.1.0-1-8b6396199db2/fdb05b4d-a035-4040-8ded-5d549ffadb57/`

- OpenLXSSH0.1.0/build1，来源`8b6396199db273493a438679df0020fa6ef7c3a4`、dirty=false；ba4a2ec/d331188均其祖先。git中C SHA与已审最终`34ee7ffbad3c2f75e60a08c308ae1e7021ae82293826b84bd327c3caa20fbb32`一致。
- arm64/min26，主App/helper严格签名与Hardened Runtime通过，实际included GRDB/SwiftTerm/libssh2/OpenSSL，系统运行闭包/完整许可已核。压力/adversary专用符号匹配0。
- ZIP7,418,092bytes、SHA256`fc927f568d50f67e8bd17a4c90f94fd666f41a3c1ba41a6d4317153755b7052e`。App规范树与manifest摘要见打包报告。
- **Development内部用途；spctl3/Gatekeeper false、未公证/上传/安装/运行macOS26、functionalAcceptance NOT PERFORMED。** 不能通过去隔离标记或关闭系统保护补缺。
- 主管独立verify-manifest/归档/严格签名/源提交/hash通过。旧0608cf64/P6A产物保留历史，不再冒称覆盖新源码。后续文档提交不改变该候选的源commit，也不为改文档重打相同代码。

## 差量审计和剩余条件

独立只读差量审计核本轮delta闭环、原需求与新候选来源，未确证仍可脱离外部条件独立完成的必要业务实现/测试遗漏；这不是全产品无缺陷证明。审计指出STATE历史摘要过期，主管已修为最终验收/newdriver及当前候选，不列作未修业务问题。

**AUTH02仍是必要实现/验证欠账**：saved-password gate当前仅已核24H32，不能把macOS26人工回退当功能完成。必须取得目标系统/实际服务后核版本/签名/上下文、补适用实现和真实回归，不降低要求。

最后内容delta检查仅覆盖新增压力/Transport15文件变更/1062新增行与本候选路径/文本：App32文件、ZIP32文件/19目录、29文本，未发现可确认的新增真实秘密、lateanswer日志出口或敏感运行材料误入，命令全部exit0。构建工具notice中的build命名已分类为许可而非误判产物。未覆盖全部Git历史、任意编码秘密、二进制内部、全部日志或运行内存，不将AC25整体改通过，详见 `docs/reports/p7-secret-artifact-check.md`。

在当前授权和设备条件下无法自行补齐：

1. 新增隔离环境安装、官方镜像/必要包下载构建及运行的批准；现无已验证可用runtime，不能启宿主sshd/连生产替代。
2. macOS26 Apple Silicon设备，真实四认证/多prompt/审批、SSH/SFTP/嵌套/TUI、网络/文件异常及目标系统自动凭据门禁；现宿主15.8.1仅HostProbe运行。
3. 真200次与五会话连续24h、Release自身与子进程性能；不改时钟、不拼短测、不改电源、不创建未请求Cron/常驻服务。
4. DeveloperID Application身份当前0；证书/登录/账号安全由用户处理。公证必须先形成对应DeveloperID最终产物，再获该具体产物Apple上传批准，现不上传Development候选。
5. 第二台Mac、中文IME/Finder/安装升级与公司允许环境人工记录。模型不索要/记录公司秘密，实际操作不能由本机重复测试替代。

完整前提与资源/网络提议见 `docs/release/acceptance-prerequisites.md`。未取得这些条件，不宣布完成、不擅自新增环境或发布。
