# App Files manifest — real SFTP round-trip review

日期：2026-10-31。**单一logical App real SFTP清单往返、精确清理及严格资源/自然退出门通过。** 不代表双栏像素、Finder、SSH终端资源、所有冲突取消重试或整体UX候选通过。

## 实现和独立审查

- 新闭合Files入口仅使用批准keyonly/127.0.0.1:22221/fixture与当前完整CID/FP；旧1253 pin/decoder、历史认证合同及ledger不改。consumer内存读取一次性key，主管只读取公开材料。
- 共享App bootstrap、Repository/Security、生产FilesController/TransferManager及原Delegate结束顺序，不创建SSH标签，不拿shell canonical drain当SFTP close证明。
- 每次上传/下载独立immutable manifest与原planID；确认前分别核累计计数差值，必须read-open/read/write-open/write/mutations/bytes全0、jobs0，准确counts与rawnames冻结，确认只调用一次。
- 透明service observer仅在生产调用已读写字节时计数/哈希，无第二内容读取器；远端mutation仅新nonce根及精确批准能力探针目录/三直属叶，拒绝任意深后代。
- 独立scope审查发现probe祖先深路径绕过、第二本地FD获取失败漏关两MED；共用实际guard/withPair修复后复审fixed，同源实际FD失败测试通过。
- 完整宽报告原24,944B、首次紧凑19,523B两失败保留；Files专属lossless wire v1保完整2plans/2jobs/streams及三份各32FD，最终15,851B≤原16,384B。严格版本/列顺序/整数或null/unknown/计数/顺序/完整性校验，原shell schema与资源门不变。

## 本地验证

`AppFilesManifest-Verify-R3-0tdbf6w_`：Debug/Host26构建0，Host契约53/0、Debug契约+factory49/0、Files77/0、退役22/0；Python闭schema21与fullreceipt/compact26均过，实际10件min26。主管独立契约53+Files77=130/0。

首次实网候选误取旧DesktopUnified产物，flagsreturn64、未连接SFTP，保留`AppFilesManifest-Live-R3`失败。准确来源为`DerivedData/HostProbe26-AppFilesManifestR3/Build/Products/HostProbe/OpenLXSSH.app`；重冻结前实际help/validate语法门均exit0。

准确R4实网已完成往返与清理，但FD20→21。新增DIR与baseline Trust目录同dev/ino，源审证实consumer预热了AppModel的presentation environment，而实际connector持有另一个bootstrap environment；首次连接晚创建第二常驻Trust目录FD。没有将+1白名单；只将helper显式接实际connector owner并构造identity guard，原count/identity相等要求保持。

R4修后Host55/0（新真实本地owner两项）及Files77/0；主管独立55/0。两个actor访问同目录精确DIRFD1→2、同actualconnector env复用store及FDset不新增。私有helper guard为源码审，非直接注入运行。

## 真实通过案

候选`DerivedData/UXVerification/AppFilesManifest-Live-R5/OpenLXSSH.app`，mainSHA`c6d62de363b5442271c9db7f81f872d31b0c638d1dc0314ce0a8b087c0ba54bf`。既有Development仅timestampnone离线签名、固定helper/main ID strict验证；无Apple请求。

run `3e746d44-7685-4bef-b81e-d4fbbb66b836`，App14245，supervisor **passed=true**，9.104775秒、natural exit0、无signals：

- 单一真实SFTP连接/固定binding，首次实际hostkey与带外FP匹配，credential owner0，SSH sessions0。
- capability probe明确风险确认并passed，retained paths0。
- 两个manifest计划，分别item4/file2/directory2/bytes12288，确认各1次；两个prepare阶段本地/远端内容I/O全部Δ0，jobs0。
- 上下行两个真实job，各成功12,288B、2files/2dirs。中文、空格、隐藏项、组合字符与标点文件名保持；source/remote/download实际stream SHA/bytes一致。
- 审核精确payload删除，再重新捕获空nonce根当前属性/binding并单目录审核删除；远端root不存在，本地payload和App专属store清理完成，不shell rescue/不重连。
- remote service1、local2全部实际close；live handles0、rescued0、close failures0、observation failed=false。manager closed/drained、operations0。
- **FD baseline20→cleanup20，全部entry身份精确相等**，不是只比数量，不截断、不豁免。
- ready、before/after stores、willTerminate与外部自然exit0完整，源key与fixture known_hosts未变。

relay14060自然exit0（204.777540秒含预检）、accepted1/finished1/rejected0/cleanup_failed0，无signals；主管核批准端口free。公开收据`AppFilesManifest-Live-R5/public-receipts/`完整保留。

## 边界

SFTP attributes/manifest/delete仍非CAS，同属性ABA及最终check-use窗口保留。此小数据回归不重2GiB/1000文件或长测。后续冲突/取消/重试、GUI/Finder、可见绘制上下文、信任/并发及SSH终端weak/FD门仍待；不宣布UX_READY_FOR_USER。
