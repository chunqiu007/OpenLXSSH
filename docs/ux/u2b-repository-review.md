# U2B App仓储桥接与原子递归复制：主管审查

日期：2026-10-30。结论：本轮结构化桥接、复制及label授权兼容门通过；Vault完整UI未完成。

## 实现与独立审查

- AppSnapshot保旧initializer/defaults，增加folderPaths/tags/filtered hostMetadata/full allHostMetadata，以及host-tag/key/credential公开引用计数。完整catalog不受当前搜索/组/tag筛选影响。
- AppRepository新增vaultMetadata/query、group/tag删除影响、updateKeyLabel，原有fake可依赖明确notFound默认，不伪造成功。主管检查协议新增方法的生产实现均显式async，保证any AppRepositoryProtocol实际派发到生产actor实现。
- Core新增atomic copyFolder(id:name:)。一个真实SQLite write事务内读取整个subtree、生成新group/host UUID、映射parent、复制tag/既有共享key-credential引用和授权、清连接时间；原root副本保原parent。避免read/apply两事务之间另一进程撤销授权而旧快照复活。App只在外层生成“副本”后缀，名称竞争最多采用稍旧公开名称，不影响授权事务。
- FilesConnection和SecurityCoordinator对key的授权比较改authenticationIdentity（id/algorithm/phraseRef），label不撤销认证；host connectionIdentity、取消/current request、phrase purpose/ref/授权、真实key材料和权限检查均保留。

主管已读AppRepository/新5项bridge tests、Core atomic copy与3项真实SQL rollback/并发撤销tests及label正负例差异。没有改Packages依赖、Keychain、秘密持久或网络。

## 实际验证与修复

- Core工程师Debug/Release各71/0/exit0（原68+3）。
- 主管独立 `swift test --package-path Packages/OpenLXSSHCore --disable-automatic-resolution --filter VaultMetadataTests`：23/0/exit0；`DerivedData/UXVerification/U2B/primary/core-copy-tests.log`。
- App首次合并186/4，四项notFound实际指向协议extension默认实现。生产新增同步actor方法与同名async默认重载导致派发歧义；改四个生产witness为显式async，并让bridge成功路径显式以any protocol调用，未将default改伪成功。
- 修后工程师正式min26 Debug完整186/0/exit0：`DerivedData/UXVerification/U3/debug-tests-2.log`；首次186/4保留`debug-tests-1.log`。
- 主管独立正式min26 `xcodebuild ... -only-testing:OpenLXSSHAppTests/VaultRepositoryBridgeTests -only-testing:OpenLXSSHAppTests/FilesAuthenticationTests test`：23/0/exit0（bridge5、FilesAuth18）；`DerivedData/UXVerification/U2B/primary/app-bridge-tests.log`。
- Xcode项目仅新增bridge测试fileRef/buildFile/group/testsource，plutil/diff-check0。

覆盖：filtered/full catalog及refcount、group/tag/query/impact、unsupported fake明确失败、recursivecopy/old source unchanged/shared refs/tags/history clear、lateSQL失败无部分副本、并发writer撤销授权后copy读取新值；label-only before/credential await/finalmetadata通过、phrase ref/algorithm/ID变化仍拒。

## 限制与下一项

App snapshot多次批量read可能在另一进程写入时跨相邻公开metadata版本，不作为secret授权依据；每次实际secret和连接仍独立精确重新验证。此限制不影响Core atomic copy事务。

未执行真实SSH/SFTP或默认Keychain；只临时DB/KeyStore与fakecredentials。新Vault/编辑器/密钥页U2C正实现，首次三按钮/一次信任和两类MFA仍需后续真实接线；父DX-H/E/K不因本桥接通过整体VERIFIED。
