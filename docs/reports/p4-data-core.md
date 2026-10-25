# P4-DATA-A：主机数据持久化核心审查

日期：2026-10-26。执行者software-engineer；主管独立审查Primary Agent。

## 结论

数据层任务通过，完整P4/App/产品验收未通过。实现位于 `Packages/OpenLXSSHCore/`，真实GRDB 7.11.1（b83108d10f42680d78f23fe4d4d80fc88dab3212）与系统SQLite，不是mock仓储。

## 主管代码审查

已读取全部4个核心Swift文件、manifest、29项完整XCTest、异常退出fixture与NOTICE。

- HostConfiguration仅元数据/UUID引用，四类认证、名称/地址/端口/用户名、分组/收藏/最近时间/保活；无秘密、终端输出、跳板或转发必填模型，不限制10台。
- 单层文件夹；删除解组不删主机，复制新UUID/共享引用/清空最近时间；收藏/搜索稳定排序。存储字段边界不是完整SSH参数验证。
- 凭据用途与授权触发器、外键、共享删除拒绝；资源注册行删除与清理ticket同事务，完成墓碑防UUID复活。跨Keychain/文件操作不在SQLite事务中，worker仍未实现。
- 明确v1→v2迁移与未来版本拒绝，迁移失败回滚；不eraseDatabaseOnSchemaChange。
- DatabaseQueue/WAL/FULL/5秒busy timeout；GRDB建立WAL后重新设置FULL，测试PRAGMA确认。初始化稳定flock；权限巡检不额外open/close现有SQLite文件，避免释放POSIX锁。
- App自有leaf0700、DB/sidecar0600、NOFOLLOW/owner/link/inode检查；只处理固定App文件，不改无关文件。同UID恶意路径竞争不宣称完全防御。

## 实际验证

工程师Debug/Release build/test均退出0，各29项0失败；另做重复Release与50轮首次双进程初始化，100进程均0、逐库20行及integrity_check=ok。修复权限/锁风险后重新跑过，不沿用修复前结果。

主管独立：

```sh
swift test --package-path /Users/liuwenshuo/Desktop/OpenLXSSH/Packages/OpenLXSSHCore --disable-automatic-resolution
```

退出0，29项0失败。本次完整重编译没有上游warning；没有禁用警告或修改上游。

关键真实DB场景：

- 重启持久化、125台主机、CRUD/复制/分组/收藏/Unicode字面搜索。
- 明确SQL v1 fixture迁移；ALTER后注入冲突，字段/回填/版本标记均回滚并可重试。
- 真实事务提交前注入失败、重复ID/外键/授权及资源删除票据一致。
- 两实例、多进程并写、首次初始化竞争；跨进程持有写锁后当前writer实际等待，确保权限检查没破坏锁。
- 自有child `_exit(71)` 保留已提交未checkpoint WAL并恢复。
- `_exit(72)` 未提交数据真实溢写WAL（12392→82432字节），重开仅baseline且integrity/foreign-key check正常。
- `_exit(73)` 删除/孤立清理票据持久化。

验证日志及summary：包 `.build/verification/` 中 build-and-test-summary.json、verification-summary.json、fresh-start-final.json、wal-metrics-final.json、static-scan.json。私有测试目录自动清理，不连接服务器、不读用户数据。

## 未覆盖

异常子进程退出不是机器掉电/磁盘损坏。真实资源worker、Keychain/私钥跨存储一致性、UI交互、macOS26运行、正式安装/升级/双机都未验证。核心min15为宿主可测，正式App必须min26。Core历史上限100000而当前终端50000；UI整合须统一有效上限，不能静默截断用户设置。

下一项：正式OpenLXSSH Xcode App接入数据层，数据库操作离开主线程；保留未集成SSH/SFTP的明确错误，不用假连接替代后续验收。
