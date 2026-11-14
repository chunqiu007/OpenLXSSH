# U4 双栏SFTP实施与验收边界

日期：2026-10-30。U1已提交60bd6d8，仅路由/交互门通过。以下为当前后端实物形成的下一实施接口，不是功能完成证明。U3正独占App公共入口/主题，U4待其写域释放后实施。

## 现有可复用资源与真实缺口

- `FilesController`/应用级`TransferManager`是真实独立owner，不依赖SSH标签，已验服务lease/安全传输/冲突/risk/取消/记录清理。`FilesTransferContext` immutable serviceID/hostID/path/confirmation将目标锁在入队时，切路径不重定向已入队任务。
- `LocalFileService`已用fd/openat/O_NOFOLLOW/lstat，不跟随links，list读取元数据而非内容；`FilesLocalPaths.openDirectory`可安全遍历选定绝对路径。适合作为本地pane后台，不自行用FileManager.contentsOfDirectory跟随链接或逐文件读取正文。
- 现FilesPanelView只是旧远程面板移到固定SFTP页。**当前无本地pane、导航前后历史、过滤隐藏/宽列/右键/跨栏拖放，不能称双栏完成。**
- `RemoteFileService`缺`realpath`/登录目录公开API；FilesController连接后写死`.root`。U4必须给成熟libssh2 realpath(".")的结构化接口/能力，再从真实登录目录开始；不能猜`/home`或把terminal cd当路径。LocalFileService可用根目录本地映射，但不要让远端“.”未经规范化流入RemotePath全局绝对路径校验。

## UI结构

统一顶部bar后约1:1分栏，左本地/右直连远端；标题+filter/actions，第二行后退/前进/up/refresh+breadcrumbs/editable path，下面可调宽/横滚NSTableView（name/date/size/kind/permissions）。窄窗保证两侧目标标题/路径和主动作可达；分隔拖动限定范围，队列底部可展开且高度有界。

远端无连接为选择主机空状态，本地仍可用；主机chooser复用完整Vault catalog（search/favorite/recent），不建第二真源。换host先列影响活动job，确认取消不改变原连接/认证；旧request/gen回答不能作用新host。固定页切换保留本地与远端独立路径/history/selection/filter/hidden状态。

## 本地pane owner

- 独立MainActor ObservableObject持有本地成功路径（raw bytes）、history index、entries/filter/sort/selection、loading/error/current operation UUID。实际FD/LocalFileService在actor/后台队列，不阻塞主线程。
- 初次仅在用户首次进入SFTP时列默认主目录元数据，或测试用明确注入marked临时目录；不能自动扫描真实目录做测试，也不读取文件内容。可选目录用NSOpenPanel，前后取消保旧状态。
- 从last success导航：输入绝对路径Enter尝试，失败保原成功路径/列表；Escape还原编辑文本；错误与empty/filter-empty区别。
- 本地rename/mkdir/delete/详情/复制path/Reveal in Finder必须精确目标；删除聚合计划/确认，取消无部分执行；沿用SafeFileOperations/no-follow。链接只显示不进入，删除link本身明确选择。

## 传输与菜单

- 左本地选中→上传到右成功当前目录；右选中→下载到左成功当前目录，可改本地目标picker。按钮/右键/跨栏drag/Finder drop最终都调用同一FilesController admission，锁定context，不在shell拼路径。
- 下载不可误把remote raw name转normalization string；FileName/RemotePath原字节为identity，display escape只作展示/tooltip。
- 上传目录先真实枚举计划/项数阶段（若总量未知显示计算中），不能编百分比；existing engine有界stream/unique temp/safe commit/explicit current probe保全不能删。低频capability/risk收Advanced/按需弹，短正文可展开技术详情。
- queue真实direction/path/name/state/bytes/known total/speed（按真实样本计算）/unknown ETA，batch-parent/item errors，cancel item/batch/from-zero retry，locate result，clear completed only records。切Vault/SSH有低干扰入口显式打开，不toggle关闭。
- 任何不支持pause/resume/remote-to-remote/Open with/remote edit不显示假按钮。files↔terminal路径/认证独立。

## 必要新实证

合成临时本地dir和既有批准fixture单独小批量：中文/空格/组合字符/特殊名字往返SHA、导航history/path error保持、hidden/filter-empty/permission、双多选/context、真实跨栏与Finder拖入、队列冲突skip/rename/overwrite/每job risk、取消/断连原件保全/从零retry/清记录不删文件、传输中切页与关SSH不取消、换host旧回答拒绝、无任务idle关闭/退出保护。

不重跑24h/2GiB/1000无关campaign，不重建健康fixture；新后端/协议变化需选择受影响有限实证。每入口状态拆matrix，不把表格截图/compile当整个FILE验收。
