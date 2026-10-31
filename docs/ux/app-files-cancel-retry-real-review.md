# App Files controlled cancellation and manifest retry

日期：2026-10-31。结论：**受控local-read节奏下，真实SFTP正字节取消、partial保全、显式新清单重试、清理和严格资源门通过。** 不证明自然网速下抢中取消或native阻塞I/O中断。

## 测试范围与约束

独立闭scenario `keyonly-direct-sftp-manifest-cancel-retry`复用原helper。两文件4096+262144=266240字节，首项真实commit，第二文件第一64KiB实际SFTP写入且生产progress发布后，在第二次local source read进入底层前由consumer-owned gate等待，随后经实际FilesController取消。

gate精确绑定path/phase、原job token不替换；取消在wrapper本地检查并抛错，不拦截/改写remote返回，不向已取消token开启新的remote传输操作。原引擎独立cleanup token负责handle关闭和临时文件清理，首commit不回滚。无重连、purge或rescue。

取消终结后保留原job并同步App快照，经`retryTransfer`→`prepareRetry`→新review→confirm一次；新plan/job/generation/batch/retryOf，原local service借用，不另登记。重试明确skip已完成4KiB，第二从零完整传256KiB，准确结果completedWithSkips。

原passedroundtrip/conflict类型、schema与方法前缀保持。新mode stream上限256KiB，旧32KiB不动；报告仅summary、实际partial items、gate事实、phase与digest，无chunk内容。最大完整报告14,097B≤原16KiB。

## 审查和本地验证

R6 Host145/0、Debug131/0、退役22/0、Python29，首unused Set.insert严格编译失败保留并最小修复。独立gate/facts/scope审未见HIGH/MED，但主与独立审交叉发现risk分支误用jobs.first、会取到保留的旧cancelled job。

R7只按exact jobID定位，再核generation、活动/取消状态与完整pending decision。共用实际guard测试先旧first红1/1，再修后同源green，新cancel6+guard1=7/0，完整Host146/0、Debug适用契约53/0。主管独立7/0，未以本地测试冒真实consumer。

## 一次真实通过

准确来源`DerivedData/HostProbe26-AppFilesCancelRetryR6/Build/Products/HostProbe/OpenLXSSH.app`。候选`DerivedData/UXVerification/AppFilesCancelRetry-Live-R7/OpenLXSSH.app`，mainSHA`b01b6bd1acf91a3ea1bfb11bc12812328e95edc0902a1954d3b42a38a165e4db`，helperSHA`30d9dd2fcc220ccb6616efc888116f4ac530a9b900eb7cc763656e60af467146`。固定ID离线Development/timestampnone严格签名，无Apple请求。

run `7f43da17-4398-4fee-bdf9-8f37e767eda7`，App22023，supervisor **passed=true**、9.194727秒、natural exit0、无signals：

- 第一次取消点真实job running，transferredBytes **69,632**；第二远端temp实际写 **65,536**，首4KiB已commit。gate readCalls2/forwarded1/localCancellationObservedtrue/waitingfalse/abortedfalse。
- 原job cancelled、准确cancelled error；首文件succeeded4096，第二failed(cancelled)，retained paths0。独立读核首SHA未变，第二最终目标不存在且临时文件已清。
- retry保旧job1，prepare内容I/O增量0、全新manifest、显式confirm1；新job/generation/batch/plan及retryOf准确。首项skipped，第二实际完整262144，completedWithSkips，不假称resume或整树重新全成功。
- 最终独立SFTP读取两项共266240B，bytes/SHA同source；remote1/local1同服务复用并实际close，handles0/rescue0/closefailures0。
- nonce树、本地payload和App专属store精确清理；**FD20→20，全部entry身份完全相等**，ready/stores/willTerminate完整。
- `naturalCatchVerified=false`、`nativeBlockedIOVerified=false`明确保留。

relay21853自然exit0（204.795046秒含预检），accepted1/finished1/rejected0/cleanup_failed0、无signals，主管核批准端口free。公开收据完整归档`AppFilesCancelRetry-Live-R7/public-receipts/`。

## 保留边界

metadata prepare-cancel、真实native socket中断/重连恢复、其他策略传播与GUI交互仍是独立门。manifest/attrs/delete非CAS。旧SSH weak/FD及正常可见绘制上下文未解决，不能据SFTP三案通过宣布整体UX_READY_FOR_USER。
