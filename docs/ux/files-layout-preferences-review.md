# 双栏文件布局偏好：独立审查

日期：2026-10-31。**本地模型和自有 AppKit 控件门通过；实体分隔线拖拽、跨显示器恢复及新版像素仍待验证。** 不代表双栏 SFTP 或整个 UX 验收完成。

## 修改和持久化边界

- `DualPaneFilesView.swift` 使用实际 `FilesNativeSplitView`；左右两个 `NSHostingView` 实例保持，更新根值不重建宿主。文件页面原有状态、对话框和短期输入仍属于原根页面。
- `LocalBrowserModel.swift` 的布局 owner 只读写三个显式白名单偏好：分栏比例、本地列顺序和宽度、远端列顺序和宽度。固定列 ID 为 name/modified/size/kind/permissions，不保存文件名、路径、主机、搜索、选择、认证回答、排序对象或终端输出。
- 偏好注入 `UserDefaults?`；nil 不读写，也不隐式开启 AppKit 全局 autosave。坏类型、未知或重复列、缺列、非有限数及越界宽度只恢复对应布局键，不重置其他设置。
- 列宽范围 55…4096，并按可用显示宽度约束；两栏可用宽度至少 600 时各保留 300，窄于此值时对半。临时窄窗不改写已保存比例。
- 表格公共 move/resize 通知仅由准确 owner 消费，不改变行的原始字节身份、选择、排序或文件操作目标。布局恢复不浏览目录、不取消连接/传输、不复活已清短期输入。

## 证据和独立审查

增量基线：`DerivedData/UXVerification/FilesLayoutPreferences-R1/{before/,source-increment.patch,source-ready.json}`。

首统一构建因新增测试两个 weak 变量的 warnings-as-errors 失败。原 owner 仅在析构 `XCTAssertNil` 后显式置 nil，保留 weak/deallocation 断言和原 34 个测试方法；产品两源不变。准确新测试 SHA-256 为 `b11267642553d7b8773023605ac240ab63df8550be553ac25ba3ea6b48b235c8`，见 `compile-fix-1/source-ready.json`。旧失败未删除。

工程师统一正式 Debug build-for-testing 成功，文件布局相关组 78/0，其中布局新 10、审核归属 15、原 DualPane 19、FilesAuth 19、Transfer 15。App 和 xctest 实核 arm64/minOS26；编译设置为 Swift 6、complete concurrency、warnings-as-errors。

主管读取实际增量、关键布局实现和全部十项断言，再独立运行：

- 布局 10/0。
- 文件审核归属 15/0。
- 同批关闭关键新 15/0，合计 40/0，exit 0。

实际 argv、cwd、退出、耗时和结果包：`DerivedData/UXVerification/NativeAppRetirement-R1/UnifiedVerification/primary-retirement-layout-owner-1.{json,log,xcresult}`。本轮没有网络、真实 SFTP、用户数据或系统偏好修改。关闭源码后续 R2 独立修复不把该 40 项外推为最终关闭验收。

十个布局方法覆盖：独立 suite 持久化、坏键恢复、极窄/非有限几何、序列化白名单/nil 隔离、真实 NSTableView 列通知、选择/排序/横向滚动、真实 NSSplitView 尺寸/位置、稳定 SwiftUI State 和弱宿主释放、恢复不触发浏览及短期输入清理。

## 未覆盖

- 公共 `setPosition`、自有隐藏窗口渲染和表格通知不等于实体鼠标拖拽。
- 无新版截图或像素判断；全屏、三种主窗尺寸、跨显示器移动与实际焦点另验。
- 不据此升级完整 DX-V06、DX-F 或全 116 条父项，不称整体 UX_READY_FOR_USER。
