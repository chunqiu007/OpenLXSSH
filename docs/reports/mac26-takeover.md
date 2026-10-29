# macOS 26 接手与剩余验收

日期：2026-10-28。接手基线 `0711b24`；当前整体仍未完成。

## 范围与复用

用户要求 Codex 接手剩余工程，不重复 ZCode 已完成且未受变化影响的工作。既有真实 2 GiB/1000 文件及异常 campaign、数据与引用规则、依赖来源和许可证据保留；不从历史“进行中”推定功能尚未实现，也不把历史失败回写成通过。

宿主实测为 Apple Silicon、macOS 26.7.1 / 25G241、OpenSSH 10.3p1 / LibreSSL 3.3.6、Xcode 26.3 / SDK 26.2。系统升级使原有认证兼容白名单和旧宿主测试假设不再适用，必须补相关验证。用户本轮已明确批准仅本轮新建的一次性默认 Keychain 测试条目的保存、读取、忘记/删除与失败回退；不枚举其他凭据，系统授权由用户处理。Developer ID 正由用户准备，没有 Apple 上传授权。

## 已审最小实现

- 保留旧系统组合，新增精确 `25G241` / `OpenSSH_10.3p1, LibreSSL 3.3.6`，保留 Apple 签名和未知系统人工回退；不修改密码一次额度、hint、会话/代次或 MFA 隔离。来源与限制见 `docs/adr/mac26-openssh-compatibility.md`。
- 主机候选扫描默认 5 秒改为 10 秒，显式 1～15 秒、全工具预算加 2 秒、取消和严格解析保持。扫描不写入信任记录。本次是允许慢链路的有限策略调整，不声称证明一般真实远端有缺陷：已 ready 的隔离 relay 上原 5 秒实际 exit1/无公钥，对照 15 秒实际 6.2868 秒取得一条公钥，且与管理通道导出一致。旧失败保留，正式默认 10 秒成功仍须真实验证。
- 同一固定镜像的 PTY 审计权限修复扩展到另外三种认证测试服务，只有原七项加 `AUDIT_WRITE`。保留 no-new-privileges、只读、内部网络、资源限制和严格身份校验；MINA 仍不加 capability。

## 独立审查和验证

主管读取实际差异；独立只读审查没有发现上述兼容门的新 P1 问题。工程师的新系统 Release 回归覆盖 36 tests、真实 readpass/event 与对抗/退出检查；首轮部署 min15 如实保留，追加明确目标的产物经 vtool 确认为 min26。后续扫描小改只执行四项定向验证。主管独立执行相同关键四项：0 失败；未重新执行远端大文件 campaign。

fixture 源码的 40 项静态、28 项 relay 和两项 MINA 定向检查通过；主管独立执行 40 项静态检查通过。应用后核实：keyonly 的容器 ID/启动时间不变，另外三服务重建为精确八项 capability，四服务 healthy，镜像、网络、数据卷、只读/非特权、日志与资源限制均保持。

原始证据：

- `DerivedData/Takeover/mac26-8834149cacad467585fd03a34f6379ec/`：环境、扫描对照、主管定向测试、fixture 应用前后与有限 relay 记录。
- `Packages/OpenLXSSHTransport/.build/verification/mac26-auth-gate-54694349-aaa5-45c0-8101-edc6d186ba26/`：工程师完整/明确目标/最终定向结果，包含原失败和真实部署元数据。
- `Tests/IntegrationEnvironment/.logs/mac26-mfa-cap-offline-b435436f-787c-48de-a837-790b29e26877/`：cap 回归、原 red、当前结果。

## 当前下一步

冻结生产 Transport 后只生成一次新正式 min26 稳定性驱动；原驱动可复用部分已通过只读来源验证，但源码变化后不冒用其旧摘要。新签名 API 消费者补真实默认 Keychain 生命周期和新系统自动密码行为；正式 App 的正常安装、界面、MFA/文件小数据集成、200 次与连续 24h、Release 资源测量及签名公证随后独立验收。

本报告不是上述未来场景已通过，也不将测试 wrapper、纯测试或编译成功等同于正式 App 验收。

## 真实凭据分项与候选产物

新已签名消费者 `Tests/RealIntegration/.build/host-65b125b1-29b8-4e99-954a-47bee61a254b/` 包含冻结的新兼容门。主管唯一真实Keychain案退出0：明确saved→精确provider读1/返1→外层认证事件1/人工0→关闭与provider任务drain→精确delete→再读missing→store.close恢复交互策略；只查询本次独占测试service的独立CLI后验exit44，未枚举其他凭据。无授权对照另一次退出0：provider调用/读取/返回均0、manual请求/读取/回答各1，连接与清理通过。只读独立review核367项源/快照和实际main/helper摘要匹配，未发现新P1/P2。

这仍是min15测试wrapper在mac26消费生产API，scanner显式15/connect20，不是正式AppUI、默认scanner10或真实Keychain锁定/拒绝的证明。原报告静态字段 `existing-production-gate-no-whitelist-expansion` 只表示消费者不覆盖gate；本次生产gate实际已扩精确25G241，不能照该旧字段声称没有改兼容范围。原结果保留，不回写历史。

候选版本元数据提交 `6124bbe`，1.0.0/build2；既有配方仅生成一个新的Development候选，来源dirty=false：`DerivedData/Distributions/1.0.0-2-6124bbeb4201/47f7c768-0a3c-4ecc-a46a-c284b84e991e/`。ZIP SHA256 `c23155d8ebe73610accbb9f638f74c17424cbf1fe3bfe6feb22aac3055360434`。正式arm64/min26、包内helper、严格同Team签名核验通过；Gatekeeper真实拒绝，尚未DeveloperID、公证或人工安装验收。该候选正常首次启动失败，见下方；不得称为可用交付物。

## 首轮200次失败与测试工具修复

原driver-5ae677f7真实运行2546.129182秒，200 authenticated/20 cancelled/220 closed均产生记录，但6个connected样本helper PTY指标未知，最终exit1/resourceUnavailable，原424行证据完整保留。closed/final cleanup FD5/PTY0完整不抵消坏点；旧记录没有errno，不能倒推它们一定是EBADF。

局部修复仅在Tests/StabilityAcceptance：0bytes+本次EBADF、身份UID/PPID/birth稳定、新完整无重复FD列表证明目标FD消失时，允许一次完整重采；短读、权限错误、未知、重复竞态及身份变化均拒绝。已精确匹配helper采样失败只允许独立strict GONE跳过，UNKNOWN不忽略，cleanup三态未放宽。工程师自有子进程实际关闭FD验证及23项回归通过，主管另23项通过、交叉源审通过。原proc_pidpath匹配前失败的观察边界保持，不声称覆盖所有短命helper。新driver-a215d18a构建/严验0、163输入匹配、main/helper min26，尚未真实200/24h。

## 正式App首次启动与父目录ACL修复

build2正常复制到~/Applications/OpenLXSSH.app并经CUA启动，遇storage.unsafeLocation；系统Application Support唯一标准非继承everyone deny delete ACL被旧parent blanket noACL误拒，尚未创建App目录。未清除系统ACL或修改其权限，旧失败保留。仅父目录验证允许无ACL或完整公有API构造的精确保护性ACL，保持当前UID/目录类型/禁止他人写及特殊位；App-owned目录/数据库/私钥等仍拒绝任何ACL。完整公开ACL字节比较拒绝其他主体/权限/继承/额外项。

旧源red真实复现；新源原15项通过、首green新增项有测试辅助快照失败并保留，修正辅助后相关4项通过。主管独立4项新增边界全部通过。build3将独立生成候选重验正式默认路径，不能用单测或旧HostProbe冒充GUI通过。

有限relay已正常结束868/868、cleanup_failed0。24h尚未启动；用户允许临时每30分钟回查，heartbeat openlxssh已建PAUSED，实际长测启动后才激活。

## build3正式GUI桥接与性能测量启动

修复提交3ee3a68对应1.0.0/build3新Development候选独占生成并验证。正常安装到~/Applications/OpenLXSSH.app并经CUA启动成功，系统父目录mode/UID/GID/dev/inode/flags及ACL前后不变。主机编辑UI仅保存已授权的一次性fixture密码，核对管理通道导出22222公钥指纹后无需人工prompt真实outer-auth及shell；原生粘贴公开中文printf有正确输出。键盘自动化typeText曾丢失部分字符，改原生粘贴验证，不把这当IME组合输入通过。

独立SFTP连接，能力探测通过且自有临时探测目录自然清理；上传及下载各独立风险确认，36B源/远端/下载SHA256均d8a2acd4e33ab472ae5fddecb102dcaeb62372fba964bf9043fe619c2e802cdd。后验只清本轮专用远端ui-mac26-20261028-2d18e43a及其中唯一样本。UI忘记后关联消失，下一次重连进入真实人工认证窗口、输入成功。退出重启只恢复配置、0会话。GUI声明仅以上实际动作，不扩大为四类MFA/IME/Finder拖放/所有边界。

精确PID24956串行TimeProfiler20s、Allocations20s、Leaks30s attach均exit0，无签名权限放宽；Leaks表不可导出不能猜扫描结果。正常重启后新PID25406另执行一次实际leaks -nocontext -nostacks，exit0/106811 malloc nodes/14853KB/0 leaked bytes，仅空闲时点。性能原始trace含工具自身采集元数据，保留本地ignored证据，不上传或提交。

未插桩正式App阶段采样已启动960秒/5秒，只观察准确PID/UID/birth/路径及所属已观察SSH/helper。独立脚本和C辅助经主管及交叉源审，修正子列表errno与有限时钟/独立截止，未知拒绝；CPU为ps报告值、非5秒区间CPU，RSS相加重复共享页，线程不是Swift任务。不因工具正常收口就判产品性能通过。

## 2026-10-29 自动回查纠正

只读核对所有当前稳定性evidence：只有首轮cycles原failed，修复后driver未运行、24h尚未启动。原正式App有限采样960.010223秒正常结束、192样本，但全程只观察到App，最大SSH数0；fiveSessions阶段marker未对应实际会话，不能算五会话/输出测试。空闲App RSS范围106.515625～111.03125 MiB、FD11，仅保留该窄范围结果，不改原始记录。App25406仍在，有限relay24420已退出。

实际heartbeat提前ACTIVE，已通过工具删除openlxssh无效回查，避免继续检查不存在的24h测试；原用户自动回查授权保留，真实长测启动后再建。没有启动新测试、修改时钟/电源、读取生产凭据、推送或Apple上传。下一步与未完成状态已写ENGINEERING_STATE顶部。

## 2026-10-29 正式App有限五会话与工具准备收口

用户要求按成本分工执行，常规检查/GUI资源/定向测试实际派gpt-6.1-terra/medium，主管处理诊断与关键小修。原快速新建5案仅4认证、第5扫描失败，relay18accepted/1rejected/18finished/cleanup_failed0；没有拒绝原因，不能确证是并发上限。原案保留PARTIAL，所有5标签正常关闭，观察到4SSH全部confirmedGone。初次相对输出路径参数错误exit1及旧observer受控exit143均保留，不当产品失败或成功。

新案逐个确认outer-auth与shell后再建下一项，同一正式build3/同一签名/原中继限额：5会话持续319.865781秒、64完整样本，RSS App+SSH均125.139/峰125.516 MiB；FD96/PTY vnode35。输出/切换132.954083秒、27样本、5SSH完整，RSS均131.601/峰135.438 MiB；120批×100行×65B为命令定义780000B，非独立实收证明。屏幕末尾SERIAL_LOAD_DONE_748fbfed及随后RECOVERY_OK_748fbfed真实出现；中途AX编号失效刷新后继续，原工具错误保留，不算产品错误。

recovery至closed包含最后关闭过渡，不把全168秒当5会话；closed至finite-end204.853927秒40样本，只有App，RSS均118.351/峰119.016 MiB、FD16/PTY0、五SSH全部退役。采样自然exit0、1000.004542秒、200样本/remainingObservedChildren0。原始JSONL/phase UUID748fbfed-3011-4e53-a4f7-672aa340a941，主管primary-review-748fbfed.json独立重算；CPU为ps调度报告值，RSS共享页/PTY描述符重复计，短于采样间隔的helper和Swift任务不作完整覆盖声明。

长测驱动原来同时发起5次三算法keyscan。主管只调整测试工具为逐项真实认证的有限准备，避免把并发突发当24h前提；检查此前项持续连接，错误/缺auth或PID/取消/睡眠/断开拒绝。原有86400秒从全部5项就绪后才开始，计时与cleanup门不变。新增5项加原采样/身份/清理共28项XCTest，由Terra在资源关闭后2分钟一次执行全过，主管读取实际日志/命令/cwd/exit并源审。准备新driver，不将旧a215静态校验沿用为改后来源，不在此声称200/24h通过。

## 泄漏扫描归属对照（未改产品代码）

正式App post-close单次leaks exit1/274项/9232B，原图为244个NSArray根和30个AXObserverCookie，未列产品会话或终端类。主管以独占ignored ax-control-d7c7a25e-2138-43d0-b432-73c279d036b2创建标准SwiftUI公共文字/按钮/五行展开控件，无产品导入、SSH、文件或用户数据访问；arm64/min26编译0。CUA启动原PID45520，baseline leaks288项/14400B（NSXPC及标准容器）；12次展开/收起后317项/15728B，新增AXObserverCookie13及NSArray16。原始0600扫描/类摘要和源码均保留，正常Cmd-Q后该PID不存在。

该对照证明相同类别可在完全不含SSH/终端代码的UI/观察路径出现，不等于证明原App没有任何泄漏、普通人工无辅助工具条件下的影响或精确OS责任。正式有限RSS预算/PID退役证据按原范围保留，不将此扫描改为0，不无依据修改产品来消除系统报告。

新driver-c12524dc按cdf47ac干净源唯一构建/verify0、主管静态复核通过，未live。MFA首个原生正向案因安全读取完成时75秒TTL已过期，零OTP提交/取消/精确临时材料清理，原PARTIAL保留；后续仅改善测试动作批处理速度，不延长TTL或放宽session/secret检查。

## 正式App MFA桥接与新200启动

私钥MFA公开session5b8c882e14c32009763d0aaa三轮实际提交、外层认证/shell/MFA_KEY_UI_OK_5b8c；密码MFA session3221a8c000611fea7847fc13三轮提交/真实shell/MFA_PASSWORD_UI_OK_3221。原过期ac4ef…零提交案、499049…缺C案均保持PARTIAL，精确本地材料清理，旧服务端过期残留由下一次认证原有sweep自然清除，不追认为原cleanup成功。

独立SFTP原1c4a…三轮后C外额外等待10秒才确认空通知，最终files.timeout，保留PARTIAL。源审fixture LoginGraceTime90、OTP75、App KBI预算120；缺原总时序不能确证根因，不修改产品延长预算。新案把已核为空的最终通知及时确认，session b552fc09c6fff1467f984650实际ready并列根目录21项，全部精确挑战与App资源已清理。connect/首次A/C/zero确认分别1793243113395/3129355/3187087/3189371ms；ready明确观测1793243258734ms仅上界，不能声称首次ready要145秒。证明正向接线，不代表所有企业提供方或无需人工响应。

新唯一driver-c12524dc已于11:11:28+0800开始200+20，PID47157/UID501/birth1793243488.663325，stability-6FE08664-AE01-4700-B38F-095D47829596/evidence.jsonl，尚未结束不先标通过；relay42333原7200s预算在启动时尚余57m52s，四服务/FP/材料身份经当前核对。24h尚未启动；用户明确选择未来独立Terra/medium每30分钟监测，须在真实长测启动后创建。

用户另明确批准当前同产品源码build3候选DeveloperID签名/Apple时间戳请求，不含公证上传；下一步骤仅现有配方生成与静态验证，不运行App干扰200，也不上传Apple公证。

## DeveloperID候选（仍未公证）

用户批准的签名/时间戳动作由Terra唯一运行既有配方完成，source4616677 dirty=false，产品源相较3ee3a68无差异；1.0.0/build3、arm64/min26、严格DeveloperID/同Team/Runtime/无权限，时间戳字段存在。新89cfceaa目录ZIP e91a18d2d75b2cef32f82b1ea1cfe9356ac3f31a24577565b07ac43ed9ccb7a8、7318818B，App canonical-tree46904aed06a5f02942add8cf510c4229c8a528e0c3c8c02a1c6ce919cca12cd0。主d13a3629c8c0c07b420828e598b6d4b4af829fd332ccafe045e016bc9d47553a、helperffc38c2a198057769677d383e697789cae9faf67fad0480bcccfeed88415d554。配方及只读manifest核验各exit0，主管独立代码身份/锚/同Team/Runtime/时间戳检查0；原主管内联requirement缺等号的语法失败保留，不是签名失败。

spctl实际exit3/Gatekeeper拒绝，未notary或上传，未安装/运行该新签名候选。200正在另一冻结driver进行，不把此静态包核验当整体通过。具体App/ZIP的公证批准与登录条件仍须最后处理。

## 新200次验收收口（2026-10-29）

唯一driver-c12524dc/cdf47ac于11:11:28启动，11:53:47实际结束。6FE08664原始证据424行，200次outer-auth、20次额外取消、220次关闭，最终completedDriverScope；wall2538.540682秒、awake/continuous2538.529963秒。主管独立读取全部行，695资源样本完整，所有closed及cleanup仅driver、FD5/PTY0，末20次closed RSS均36481434B低于前20次37573427B；PID47157已不在，精确sessions目录消失。独立报告`DerivedData/Takeover/mac26-8834149cacad467585fd03a34f6379ec/primary-200-review-4d820158-588c-49eb-a310-2abb34fe0c8b.json`，原JSONL SHA256 `9a479fc431a2f249978b4f9a5c28a4d5055238dc2b3646f8b1aa7af050c782fd`。这是正式Transport驱动范围通过，不是完整App/Swift任务计数、MFA或24h通过。旧failed200原样保留。

## 唯一五会话24h启动与回查（2026-10-29）

200审查后旧relay42333正常TERM/exit0，898accepted/0rejected/898finished/cleanup_failed0，端口释放；没有重跑旧测试。新relay55592为90000秒有限进程，严格身份及日志见新6F5F0F5C目录handoff-30b90068-42f6-41dd-9de2-1bc9fc9b4905.json。driver55678/UID501/birth1793246237.956792复用cdf47ac冻结来源，10-29 11:58:21.102844+0800五会话认证后计时。主管通过既有严格identity C库另核driver/五直属SSH/relay，后续多个完整样本确认五SSH；记录primary-start-review.json。最早预计10-30 11:58:21以后，最终仍需86400实际awake/continuous及wall/连续性/资源/cleanup证据。没有改时钟、电源或建立保活。

用户明确选择独立定时任务后，实际创建`openlxssh-24h-terra`：ACTIVE/local原工作区/gpt-6.1-terra/medium/每30分钟，工具及保存配置均核对。只监测本轮身份与原证据；正常安静，不重复启动或测试，新异常/结束才通知，完成该用途后停用。新DeveloperID候选的实际helper挑战及公证/双机人工验收留待长测后，不在24h期间启动同bundle正式App。整体仍未完成。
