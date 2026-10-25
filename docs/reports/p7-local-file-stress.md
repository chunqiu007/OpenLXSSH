# P7 有限本地大文件/多文件压力验证

## 结论与边界

正式 `LocalFileService + TransferManager/SafeTransferEngine` 的2 GiB单文件、1000小文件往返、真实进度取消、竞争目标保留与资源释放在有限本地Release夹具通过。主管读取5个新文件及修正后的证据，并独立重跑完整模式退出0。不是远程SFTP、网络断线、macOS26 App、Instruments、24小时或产品PERF验收。

夹具位于 `Tests/LocalFileStress/`，独立SwiftPM消费者，64KiB块、chunk/job并发上限2，不伪造文件服务数据。测试observer显式转发真实fstat。运行前检查>=12GiB可用空间；非稀疏、非clone，流式生成并fsync；源/去程/回程逐项SHA256与原始名字manifest比较。中文、空格、引号、换行、组合Unicode均覆盖。

## 主管独立实跑

命令：`python3 -B /Users/liuwenshuo/Desktop/OpenLXSSH/Tests/LocalFileStress/verify.py --mode full`，退出0。HEAD为 `1e275b1`，依赖源码hash构建与运行前后相同；只读核对既有160个native输出，没有重建上游静态库。首次消费端build误用内部初始化器失败已在工程师阶段修，不降低逐项断言。

主管证据：

- `Tests/LocalFileStress/.build/primary-full.log`
- `.build/evidence/20261026T072447-b2db6a266cf24a53ac9e1131a901f709/{verification,full}.json`
- full.json SHA256：`8c66e4b1ca76647f5e86c38d641df6a886d56d69835f7fea80906a5f11a8109c`

实际完整过程18.073560秒，自身峰RSS13,697,024bytes。2GiB去程2.060127秒、回程2.105252秒；1000小文件25,298,524bytes，去程0.422018秒、回程0.422757秒。这是本地文件系统/缓存速度；有并行Xcode开发负载，不能宣传为网络或产品性能。

2GiB内容SHA256：`9797456a54cb6a9e0b92eb68cb0cd0f7b2323e9a021b57cac0c6bc8b736513c9`。主管以JSON重新比对全部1000项manifest、源与两次结果相同、拥有根已不存在；未只相信passed字段。

## 失败与生命周期

- 两个真实大文件任务各到536,870,912bytes（25%）后取消；cancelAllAndWait实等0.014342秒，所有任务cancelled、原目标inode/metadata/SHA不变，新final不存在，retainedtemp空。取消测试仅在真实25%之后阻塞下一read控制时机，不伪造进度。
- 唯一循环symlink放在另树副本：单项明确失败，整体failed，其他文件摘要仍一致。
- 提交前真实新建竞争目标：no-replace冲突，竞争内容保留。
- 小型混合成功/skip报告completedWithSkips，不能误报succeeded。
- 总FD3/9/3（初/峰/终），owned-root FD0/活动3/峰6/关闭前0，API成功open/close各12025，API峰4/终0，没有依赖service.close强行收回未关句柄。
- 关闭前owned FD=0与删除后根不存在分开核验，只删除本轮0700 UUID目录、dev/inode/owner匹配；没有宽泛扫描/清理。

## 计量修正与历史证据

第一轮运行内容校验通过，但owned FD始终0，工程师自审定位Foundation `/var` 与Darwin `/private/var` 别名。旧JSON保留在 `.build/evidence/20261026T071245-6b9c4d765b5f45c0be5920fc51b26dd6/`，其资源数字不得引用为通过证据。metrics改为POSIX realpath规范root与vnode，新增活动>=3/取消>=6的断言；alias自测FD3→4→3、owned0→1→0通过。

修正后工程师small/full各退出0，完整15.320211秒、峰RSS15,007,744bytes；主管使用相同最终源码另跑上述完整模式通过。`.build/evidence/20261026T071613-0ec1cadf297b4ffea1be27388a566245/`为工程师最终证据。最终源码有一条String(cString:)弃用警告，未改上游或隐藏警告，非编译失败。

仍未覆盖真实远端、权限不足/磁盘满、网络异常、GUI任务生命周期、Instruments和24小时；AC-31只更新进行中。没有启动TCP/sshd/虚拟机、常驻服务或定时任务，没有改电源设置。
