# 递归传输清单包：审查检查点

日期：2026-10-31。**包层本地门已审查通过：严格min26全包199/0，主管独立新增19/0。不是DX-F09或App审核完成证明。** 当前仅包层3生产源和新TransferManifestTests，App递归审核还未接；旧App目录仍直接入队，不把包门冒用户已见计划。

## 当前设计与主审

- prepare/confirm/discard以准确planID消费，不接UI改写后的requests；清单内部构造，service对象/ID、rawroots/host及immutable attrs/childsets绑定。confirm全量只读复核后一次atomic入队。
- 枚举只lstat/list，不读内容/写目标，depth32/items10000、单计划8MiB/全Manager20000entries及16MiB，上限包括准备、未确认和持有清单的历史。未知大小nil，链接/特殊项/重复rawname/超界明确issue，不可确认；原非manifest包tree兼容。
- engine有manifest时只走已审name集合，live list只复核不供新遍历；文件读取/目标创建/提交前及风险/冲突等待后再核源事实。复用原流式、SourceIntegrityCheck、风险、冲突、原件保全/partial/临时清理，不宣称CAS或目录事务。
- 全部准备/确认阶段I/O和scheduler使用同一准确token；cancel/discard不关闭共享service，实际operation返回和drain才释放。关闭仍等真实任务，不把Task.cancel当排空。
- 主审发现anchors最初先构造全prefix再预算，深路径可出现二次方元数据；已要求单prefix、append前预算及独立32祖先界限，超界明确resourceLimit，global RemotePath规范不改。
- 准备前先满额预留，ready按完整保守actual计量收缩，history保到最后job记录移除。不得把任意两次很小目录后就满额的限制作为默认UX，也不能扩大总预算绕过；需tinyhistory连续3+及容量准确归还门。

## 已保留的测试事实

- 首严格min26编译成功，新增17方法16通过1失败：容量竞争夹具预期resourceLimit、实际因blocker/filler写同目标父目录而raceDetected。安全检查正确触发，不是atomicqueue产品失败证明。
- 只将审核目标改为真实独立根FD namespace，隔离不相关父mtime变化，保exact resourceLimit/零部分入队/原件断言；第二17/0、exit0。原失败保在`FilesTransferManifest-R1-Package/targeted-17-attempt1.{json,log}`。
- 实际计量收口后18项首跑有1个unexpected typedresourceLimit：极小metadata连完整issue/plan开销都不能容纳，prepare直接failclosed。不是产品应吞掉错误或造半个计划的依据；只拆测试为items/depth返回unconfirmable issue、极小metadata精确抛resourceLimit并零job/read/mutation/预算归零，第二18/0已保。随后仍补长ancestor可容纳基础计划的issue场景、destination按source扫描后的真实余额先限再构造，最新源受影响/全包与主管独立复验尚待；不能报最终通过。

## 最终包层验证与主管复验

- 新增最终19/0、先前受影响95/0（当时18新增）、最终全包199/0均exit0，原180方法保留且包内其他生产/测试源无违规变化。19已包含在最终199，不重复累计。
- Swift6 complete/warnings-as-errors，Swift及C目标明确26；`actual-min26-final.json`实核xctest和三生产对象minos26.0，不仅命令含triple。
- 主管读取实际before-relative增量、prepare/confirm/discard/lease/预算、engine来源锁定和全部19测试后，独立`--skip-build --filter TransferManifestTests` **19/0、exit0**，全过程四源hash未变。证据`Primary/independent-manifest-19-1.{json,log}`。
- 最终19新增：实际首子项已commit后新增来源项，真实report保首项成功/后项raceDetected、原已提交内容不回删、新项不传、ownedtemp清理；并发confirm在真实inflight gate时二次拒绝。默认四次小目录连续成功且配额精确归还。
- 最终四源/增量收据：`final-freeze.json`、`final-hashes.json`、`final-source-increment.patch`（SHA256 `695330c402d9a2d0fff8cf647a63456d2564d3e2e74238bf49f6952653e94ae7`）。原两类失败均留，未skip/删测试或放宽资源断言。

证据根：`DerivedData/UXVerification/FilesTransferManifest-R1-Package/`；初before和source-ready保存。所有测试临时本地IO或明确logicalrawnamespace，不是真实SFTP。非法UTF8本机EILSEQ事实保持，不偷换普通名字称rawFS通过。工程师freeze/STOP，后续App接线另派，不自动把Package来源实测覆盖新版App。

## 后续与明确限制

- 精确App审核owner需另接所有上传/下载/跨栏/Finder/旧picker入口及manifest目录重试；取消/隐藏只撤未提交计划，已入队仍App级owner。App需冻结lifetime/generation/host连接身份/方向/原source和destination/reviewUUID，迟到picker和旧confirm不能误投。
- 任务总数/bytes从清单显示，子项按真实report，不编每文件速度或精确剩余时间；风险等待独立。
- 逐文件多次ancestor childset核验可能O(n²)目录行返回，metadata有界不等总体耗时有界。有限本地门不能外推真实远端大目录性能，不重历史1000/2GiB campaign；后续基于有限实测调整而不删安全门。
- attrs非CAS、相同attrs ABA及最终check/use竞态仍存在；不承诺文件系统锁或内容快照。
- 真实SFTP有限目录、GUI计划呈现、三尺寸/焦点与像素仍待。无生产、真凭据、环境新增、Apple或push。
