# 下一里程碑边界：U2 数据与Vault实现包

日期：2026-10-30。仅为U1进行时的主管接口设计，不是已实现/已验收项；U1原生焦点与路由门通过后才实施本包。

## 当前实物

`OpenLXSSHCore/Models.swift`只有四值持久AuthenticationKind、单层HostFolder(id/name/sortOrder)、ManagedKeyReference(id/algorithm/passphraseCredentialRef)，没有tags/key label。`Schema.swift`仅v1/v2，明确拒绝未知迁移；`OpenLXSSHDatabase.hosts`搜索只含name/address/username，排序name/recent/favorite但没有UI升降序；folder筛选仅直接归属。现有DB引用/事务/WAL/权限与Keychain事务不能放宽。

完整spec已明确要求嵌套本地分组/移动/标签，取代旧单层组织限制；**不引入组凭据/协议继承**。本包是组织元数据，不引入新的秘密或终端/远端内容留存。

## U2A：最小兼容数据层

- 增量迁移新版本，保留已有hosts/folders/keys/credentials IDs和所有引用/保存授权；旧v1/v2数据通过原路径升级，失败事务完整回滚；不清表、不重建用户数据目录。
- `HostFolder.parentID`可空、外键及应用层循环验证，名称长度保持现有规范，同名可按路径区分；删除组仅解散组织，不删主机。选定规则：直接子组移动到被删组原父组，直接主机移动到原父组（若无则未分组）；向用户显示影响数量，不递归删除。需要与spec“默认保留主机到明确位置”一致，删除前确认。
- `HostTag`稳定ID/name，host-tag多对多；删除tag与移除host-tag关联为不同动作，删除tag须显示引用数量。搜索tag、group路径使用参数化查询，tags多选AND筛选，名称/地址/用户名仍本地即时搜索，不读秘密。
- key label为公开元数据。key指纹/公钥来自现有KeyStore公开材料，不将私钥内容写DB；重复导入以真实公钥指纹/字节为身份，不用文件名或label认重。
- 新enum/UI偏好需使用有向后兼容默认值的解码或增量schema；新增列不能因缺省Codable字段使旧fixture解码失败。
- 不在U2A把四持久auth枚举删成两值：旧值按主方法展示，真正迁移/策略统一与认证可靠上下文探针联动，不能仅改四个label就称MFA完成。

## U2B：列表/卡片与共享操作

- Vault三主入口icon+label、统一选中底；主机/收藏/嵌套分组与tags层级；新建当前有效组，drag move不得形成环。
- 同一数据catalog产生列表/卡片；核心信息与菜单相同：名称/端点/用户名/主认证/收藏/组/tag。选择只显示详情；双击/Enter明确连接，多个选中时连接只当前行。
- 排序name/recent升降序有稳定tie-break（id），未连接项确定位置。偏好非秘密持久，搜索/组/详情切页保持。
- 右键/更多共享动作：连接/独立会话；编辑/复制配置；收藏/移动/标签；复制端点；删除。多选批处理单SQLite事务，确认数目和目标；不复制未保存秘密/扩大凭据授权。
- 空数据/筛选空/加载失败分开；刷新失败保留前快照。主机删除不误删key/credential，旧tab标示配置已删除并保原快照。

## U2C：检查器与管理页

- 按`visual-reference-text.md`图三/六执行共享tokens；表单Address/General/SSH/Credentials/Advanced分区，默认折叠高级。窄窗overlay可收起且不点击穿透，底部动作可达。
- 稳定draft含非秘密状态，密码/口令在短期view state，切host/取消/失焦mask重置与release；保存/保存并连接语义独立。离开脏draft：保存/放弃/取消。
- 密钥选择器共享Vault同实体，search label/显示algorithm/fingerprint/ref count；就地导入/生成返回draft。管理页搜索/排序/label/edit/copy public/fingerprint/ref list/unlink/delete/forget；精确引用保护及journal语义保留。
- 已知主机精确remove、新的三动作信任在U5受信任API门处理，不能做只改变文字的假按钮。

## 验收依赖

数据层先在复制的合成v1/v2 DB上验迁移及失败/循环/删除/共享引用；然后UI最小新增/编辑/取消/搜索/卡片列表/多选/组tag/密钥/重启端到端。U1未过前不开始堆U2界面；通过本包也不意味着U3全页终端或U4双栏已完成。全部新写入由单一工程师接单，主管独立diff/测试/GUI检查。
