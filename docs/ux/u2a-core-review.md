# U2A Vault组织元数据：主管独立审查

日期：2026-10-30。结论：本地兼容数据层所列验收通过；Vault UI、编辑器和真实连接并未因此完成。

## 交付与兼容

Core增加v3增量迁移：folders.parentID、managedKeys.label、tags/hostTags表及外键/循环拒绝trigger；v1/v2不改写，旧host/key/credential IDs、保存授权、收藏/时间、settings、cleanup tombstones原样保留。GRDB事务包住DDL和迁移版本，未知或缺中间迁移拒绝，不清库。

HostFolder层级只做本地组织，无协议/秘密继承。删除组将直接host/child group移到最近存活祖先，无祖先移未分组；多组删除基于原层级，批次顺序确定，不递归删除主机。HostFolderPath保留UUID components/identityPath，displayName仅展示与搜索，不当路径身份。

HostTag稳定ID与host多对多；增/改/删实体和assign/unassign分离，删tag只去关联；批操作一个SQLite事务。搜索增加分组完整祖先展示路径与tag，仍参数化本地查询；多tag AND，原.folder(id)直接成员语义保留，新增.folderAndDescendants。名称/recent升降序稳定id tie-break，never-connected两方向最后。

ManagedKeyReference.label是公开元数据，空值兼容旧key；专用updateKeyLabel不改phrase授权。authenticationIdentity仅id/algorithm/passphraseCredentialRef，**App旧全行key比较仍须后续改用该identity**，不能因label编辑误拒/丢授权。注册仍完整Equatable严格校验，不把注册退化为任意upsert。

HostFolder/ManagedKeyReference及缺旧字段HostConfiguration的Codable安全默认不扩大保存授权；数据实体无secret/log/网络/Keychain路径。copyHost保持公开group/tag和既有共享引用与授权，独立新id/清lastConnectedAt，不新存秘密。

## 实际审查

主管已读Models/Schema/OpenLXSSHDatabase及20项新增VaultMetadataTests，核SQL参数/读写事务、cycle/FK、delete reparent/bulk、tag assignment、copy及key label；旧测试只将单层不存在parentID的需求冲突改为新parent FK/RESTRICT契约，保留root delete不删host断言。原schema-v1.sql SHA256未变：049ad4ccafc71014f725c0dc014d00f6cf0aac6f7e61d5bcedbae330d6cda13d。

新合成schema-v2.sql是测试用独立旧schema，真实v3失败夹具在ALTER之后制造tags碰撞，证明DDL/row/version回滚；未操作用户数据库。

## 验证

- 工程师基线Debug48/0；实施首轮48/1是原单层断言与新需求冲突，原log保留；按新契约修改后原48保留+20新tests。
- 工程师最终Debug **68/0/exit0**、Release **68/0/exit0**：`DerivedData/UXVerification/U2A/core-metadata-{debug,release}-final.log`。
- 主管独立`swift test --package-path Packages/OpenLXSSHCore --disable-automatic-resolution`：**68/0/exit0**，`DerivedData/UXVerification/U2A/primary/debug-tests.log`。
- scoped/global `git diff --check`：0；无manifest/pins变更。

覆盖：v1/v2逐列/四auth/ID/ref/settings/tombstone保留及重开；失败DDL回滚/修夹具重试不清数据；缺中间版本和坏FK拒绝；根/嵌套/批量/父子两删除顺序；cycles/missing-parent与beforeCommit rollback；同名路径identity/rename/move/restart；Unicode/literal搜索、tags AND、赋值与删除分离、wrongIDs原子拒绝；稳定sort；label与秘密identity分离；迁移后copy共享引用/授权保全；integrity_check/foreign_key_check。

## 后续接线

AppRepository需返回Vault结构化snapshot/tags/paths/all catalog，copyFolder要复用新tag/hierarchy语义，主机多选批处理仍单事务。FilesConnection/SecurityCoordinator对ManagedKeyReference整行contains要改authenticationIdentity且补label-only正例/phrase-ref撤销负例；不能放松host connectionIdentity或key material检查。然后按图三/六做Vault卡片/列表/分组tag/详情编辑/密钥页；完成前父DX-H/E/K均不VERIFIED。没有新的真实SSH/SFTP、Keychain、Apple或长测。
