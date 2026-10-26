# P7 有限本地 Instruments 与泄漏采样

## 范围与结论

对当前unsigned HostProbe隔离真实Local传输场景执行有限采样，非正式macOS26/真实SSH/SFTP/5会话Release/PERF验收。每模板仅一次，未改变App源码、签名策略、系统权限、电源或设置，未安装工具；所有自有目标/trace进程已结束。源码与原HostProbe整包hash前后相同。

实际调查xctrace record/export help与模板，模板存在Allocations、Leaks、TimeProfiler。日志/trace只在私有忽略UUID目录 `DerivedData/Verification/p7-profile-33ecc012-41d8-4733-98f8-3311642b13dc/`。trace可能含进程环境/路径元数据，仅本地保留不上传或直接外发。

## 实际结果

- Allocations：20秒上限的一次launch在1.174秒exit20，工具将复制bundle内二进制识别为ambiguous（同标识HostProbe/SignedHostProbe已有注册），没有有效trace，未重试/改BundleID或系统权限。
- Time Profiler：先启动唯一自有copy并按精确PID attach，一次exit0；实际record6.362秒，Local测试正常exit0使其提前结束，1208个本进程样本可读，目标18checks通过。不能以短时采样外推长期/正式服务器。
- Leaks：精确自有PID attach一次exit0，实际record14.142秒、保存过程共30.46秒，目标18checks通过。Leaks detail为0行但没有扫描次数证据，**不能据此宣布Instruments零泄漏**。附带Allocations统计含attach前free造成negative persistent，不能当绝对存活堆。
- 独立替代一次 `/usr/bin/leaks --noContent --atExit -- <隔离copy Localphase>` exit0：83605nodes/17719KB、0leaks/0bytes，footprint110.7MB/peak111.7MB。这是单独工具短时结果，不等同Instruments完整Leaks通过。

短时ps采样自身最大RSS约123.0MiB（TimeProfiler）/151.1MiB（Leaks），CPU峰21.4%/100.6%。测量包含调试/采样开销与本地fixture；不是正式空闲<200MB/5真实会话<500MB的目标测量，不据此写PERF达标。没有优化变更，无前后优化对比声明。

## 证据核对

Primary Agent读取readable-summary/final-boundaries/leaks-at-exit-result及命令/退出索引，区分失败模板、实际trace及不可推断结论；没有机械重跑相同采样。有限采样不要求修改系统授权，遇歧义保留失败。原生完整103测试与签名回归证据另见p6b1报告。

未覆盖：正式macOS26/Release真实会话/长测、完整Allocations、完整Leaks扫描/Swift任务/ARC对象、真实网络异常、性能趋势。需要外部运行条件后复验，不把工具存在、exit0或detail空表当全部通过。
