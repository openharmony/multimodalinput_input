# Spec

## 概述

| 属性 | 值 |
|------|-----|
| 特性名称 | HID 标准设备与显示组运行时绑定 |
| 特性编号 | draft-20260528-hid-display-binding |
| 优先级 | P0 |
| 复杂度 | 复杂 |
| 目标版本 | OpenHarmony-master |

## 用户故事或场景

### US-1: 系统服务绑定 HID 设备到指定屏幕组

**作为** 系统服务, **我想要** 通过 displayId 把蓝牙/USB HID 标准设备绑定到屏幕所属 display group, **以便** 该设备后续事件只影响指定屏幕组。

**验收标准：**
- **AC-1.1:** WHEN 系统应用持有输入设备配置权限，且 `deviceId` 对应 USB 或 BLUETOOTH HID 设备，且 `displayId` 存在于某个 `DisplayGroupInfo.displaysInfo` THEN `BindDeviceToDisplayGroupByDisplay(deviceId, displayId)` 返回 `RET_OK`，运行时绑定表记录 `deviceId -> displayId/groupId`。
- **AC-1.2:** WHEN 调用方不是系统应用或权限校验失败 THEN 接口返回 `ERROR_NO_PERMISSION`，运行时绑定表不新增、不覆盖、不清理任何绑定。
- **AC-1.3:** WHEN `deviceId` 不存在、不是 USB/BLUETOOTH HID 标准设备，或 `displayId` 无法解析到 display group THEN 接口返回 `RET_ERR`，`msg` 写入明确失败原因，运行时绑定表不变。
- **AC-1.4:** WHEN 同一 `deviceId` 已绑定 group A 后再次绑定到 group B 的 display THEN 接口返回 `RET_OK`，后续事件只使用 group B，上一次绑定上下文被替换并清理。
- **AC-1.5:** WHEN 系统应用持有输入设备配置权限且 `deviceId` 当前存在运行时绑定 THEN `UnbindDeviceFromDisplayGroup(deviceId)` 返回 `RET_OK`，运行时绑定表删除该 deviceId，关联绑定派生状态被清理；WHEN 调用方无权限 THEN 返回 `ERROR_NO_PERMISSION` 且绑定表不变。

### US-2: 绑定设备事件只在绑定组分发

**作为** 多屏用户, **我想要** 绑定 HID 设备只控制当前屏幕, **以便** 多屏之间输入焦点和窗口命中互不干扰。

**验收标准：**
- **AC-2.1:** WHEN 绑定鼠标产生 move/button/axis 事件 THEN 目标选择、鼠标位置、捕获状态、pointer item 更新和 UDS 分发均使用绑定 group 的窗口和焦点状态。
- **AC-2.2:** WHEN 绑定键盘产生 key 事件 THEN 焦点窗口解析使用绑定 group 的 `focusWindowId`，默认 group 焦点不接收该设备普通按键分发。
- **AC-2.3:** WHEN 绑定触控板产生 pointer/gesture 派生事件 THEN 事件 display/group 上下文来自绑定关系，不退回默认 group。
- **AC-2.4:** WHEN 设备未绑定 THEN 事件行为与当前默认实现一致，不创建非默认 group 绑定上下文。
- **AC-2.5:** WHEN A、B 两个鼠标均未绑定 THEN 两者继续共享当前默认实现中的 cursor position、pointer style、pointer color、pointer size、surface node、mouse location 等全局/默认组状态；WHEN A 绑定 group A 且 B 绑定 group B THEN A 的移动、样式、颜色、大小、surface node 和 mouse location 更新不覆盖 B 的对应状态。
- **AC-2.6:** WHEN A、B 两个键盘均未绑定 THEN 两者继续共享当前默认实现中的焦点、按键按下状态和修饰键状态；WHEN A 绑定 group A 且 B 绑定 group B THEN A 的焦点解析、pressed-key 状态和 modifier 状态不覆盖 B 的对应状态。
- **AC-2.7:** WHEN 设备在绑定前已经向默认 group/window 发送开始事件（例如 key down、mouse button down、pointer down 或 gesture begin）且该序列尚未闭环 THEN 绑定或重绑定后该序列的结束事件（例如 key up、mouse button up、pointer up/cancel 或 gesture end）必须继续发送到开始事件的原 group/window；只有新开始的事件序列使用新的绑定 group。

### US-3: 生命周期自动解除

**作为** 系统, **我想要** 在设备、显示或 SA 生命周期变化时自动清理绑定, **以便** 不使用悬空 device/display/group 状态。

**验收标准：**
- **AC-3.1:** WHEN 已绑定设备下线 THEN 运行时绑定表删除该 deviceId，关联的绑定派生状态被清理。
- **AC-3.2:** WHEN 已绑定 display 下线或 display group 不再包含该 display THEN 运行时绑定表删除所有指向该 display/group 的绑定。
- **AC-3.3:** WHEN 多模输入 SA 重启 THEN 运行时绑定表为空，connect manager 不重放 `BindDeviceToDisplayGroupByDisplay` 绑定。
- **AC-3.4:** WHEN 清理后同一设备再次上报事件 THEN 事件按未绑定路径处理或因设备不存在被丢弃，不访问已释放 group 状态。

### US-4: 光标渲染按绑定组隔离

**作为** 多屏鼠标用户, **我想要** 绑定鼠标的光标显示在绑定屏幕上, **以便** 视觉位置与事件命中一致。

**验收标准：**
- **AC-4.1:** WHEN 绑定鼠标走软光标 RS 渲染路径 THEN `CursorDrawingComponent`/RS 使用绑定 display 的 rsId 和 display info 更新光标。
- **AC-4.2:** WHEN 绑定鼠标走硬光标路径 THEN CPU 绘制、HWC buffer 设置和 RS buffer 通知均使用绑定 display 上下文。
- **AC-4.3:** WHEN group A 与 group B 均有鼠标状态 THEN group A 鼠标移动不覆盖 group B 的 cursor position、display id、capture mode 或 mouse display state。

### US-5: 兼容性与默认组行为

**作为** 既有调用方, **我想要** 不使用绑定时行为不变, **以便** 旧业务无需适配。

**验收标准：**
- **AC-5.1:** WHEN 调用窗口级 pointer style、custom cursor、capture 等 API THEN 行为继续按窗口所属 group 生效。
- **AC-5.2:** WHEN 调用全局 pointer size/color/speed/visible/location/capture 等遗留 API THEN 行为继续仅作用默认屏幕组。
- **AC-5.3:** WHEN 服务启动且未设置任何运行时绑定 THEN 不新增非默认 group 常驻状态，不新增持久配置项。
- **AC-5.4:** WHEN 实现触碰 `MAIN_GROUPID`、`DEFAULT_GROUP_ID`、`GetDefaultDisplayGroupInfo`、`GetConstMainDisplayGroupInfo`、`FindDisplayGroupInfo`、无参 `GetDisplayInfoVector`/`GetWindowInfoVector`/`GetFocusWindowId`、`GetDisplayId` 默认显示回退、capture/cursor reset 等默认组使用点 THEN 每个使用点必须有分类结论：启动/遗留全局 API 保持默认组语义，绑定事件链/光标链/分发缓存链改用 resolved group 或序列快照，并有多 group 回归验证。

### US-6: 真实服务与 hidumper 验证

**作为** 验证人员, **我想要** 使用真实 `mmi_service`、内核虚拟设备、监听器和 `hidumper` 检查多显示组状态, **以便** 证明单元测试之外的实际服务分发和渲染参数正确。

**验收标准：**
- **AC-6.1:** WHEN 板侧运行真实 `mmi_service`，并通过 `/dev/uinput` 创建 A/B 两个虚拟鼠标和 A/B 两个虚拟键盘，且通过调用 `InputManager::UpdateDisplayInfo` 构造两个 display group THEN 注册到 `mmi_service` 的 listener 能记录每个事件的 deviceId、action、target group/display/window。
- **AC-6.2:** WHEN A/B 鼠标和 A/B 键盘分别执行未绑定、绑定到不同 display group、解绑和生命周期清理场景 THEN listener 输出必须证明未绑定状态共享默认目标敏感状态，绑定后分发目标按 group 隔离，解绑或清理后回到未绑定路径。
- **AC-6.3:** WHEN 在上述场景执行 `hidumper -s 3101` THEN dump 必须包含运行时绑定表、display group 拓扑、per-group pointer 状态、per-group keyboard 状态、未闭环序列快照和 listener/last-dispatch 摘要，并且字段能区分每个 group。
- **AC-6.4:** WHEN 软光标和硬光标路径分别触发 THEN `hidumper` 必须输出 RS 软光标参数以及 HWC 硬光标 buffer/RS buffer 参数，字段至少包含 groupId、displayId/screenId、surface node 或 buffer id、位置、样式、大小、颜色/可见状态。
- **AC-6.5:** WHEN 对尚未创建非默认状态的未绑定场景执行 `hidumper` THEN dump 只能输出 absent/empty 状态，不得因为查询本身创建非默认 group 的绑定、分发或渲染上下文。

## 业务规则

| 规则 ID | 规则描述 | 约束条件 | 关联 AC |
|---------|----------|----------|---------|
| BR-1 | 运行时绑定优先于现有配置绑定用于事件路由 | 只在设备事件链路解析上下文时生效，不写配置 | AC-1.1, AC-2.1 |
| BR-2 | 绑定 API 只接受 USB/BLUETOOTH HID 标准设备 | 连接类型和能力校验都必须成功 | AC-1.1, AC-1.3 |
| BR-3 | displayId 是 API 输入，groupId 是内部解析结果 | displayId 必须存在于当前 display group 拓扑 | AC-1.1, AC-1.3 |
| BR-4 | 绑定上下文按 deviceId 唯一 | 重复绑定覆盖旧绑定 | AC-1.4 |
| BR-5 | 未绑定路径不得因本特性预分配非默认状态 | map/context 只在绑定成功或绑定事件命中时懒创建 | AC-2.4, AC-5.3 |
| BR-6 | 全局 API 继续默认组语义 | 除新增绑定 API 外，不扩大 legacy 全局 API 范围 | AC-5.2 |
| BR-7 | 显式解绑和生命周期清理等价清除运行时绑定 | 解绑接口同样受系统 API 权限管控，不写持久配置 | AC-1.5, AC-3.1 |
| BR-8 | 默认组 helper 使用点必须分类处理 | 绑定事件链不得通过无参 helper 隐式回主组 | AC-5.4 |
| BR-9 | 未闭环事件序列按开始事件上下文闭环 | 绑定、重绑定、解绑不得改变已开始序列的结束目标 | AC-2.7 |
| BR-10 | 多设备状态隔离只在绑定后生效 | 未绑定多设备保持现有共享默认状态，绑定后按 resolved group 隔离目标敏感状态 | AC-2.5, AC-2.6 |
| BR-11 | 真实服务验证必须包含 listener 与 hidumper 双证据 | 单元测试不能替代 `mmi_service`、`/dev/uinput`、listener 和 `hidumper` 的端到端证据 | AC-6.1 - AC-6.5 |
| BR-12 | hidumper 是只读诊断入口 | dump 不得改变绑定表或触发非默认 group 懒状态创建 | AC-6.3, AC-6.5 |

## 异常与边界规则

| 编号 | 场景 | 触发条件 | 系统行为 | 关联 AC |
|------|------|----------|----------|---------|
| ER-1 | 权限拒绝 | 非系统应用或缺少输入设备配置权限 | 返回 `ERROR_NO_PERMISSION`，绑定表不变 | AC-1.2 |
| ER-2 | 非法设备 | deviceId 不存在、连接类型不是 USB/BLUETOOTH、或能力不属于 HID 标准外设 | 返回 `RET_ERR`，msg 说明设备非法 | AC-1.3 |
| ER-3 | 非法显示 | displayId 不存在或当前不属于任何 display group | 返回 `RET_ERR`，msg 说明显示非法 | AC-1.3 |
| ER-4 | 绑定覆盖 | deviceId 已绑定其他 display group | 原子替换绑定；旧 group 绑定派生状态清理 | AC-1.4 |
| ER-5 | 生命周期清理 | 设备/显示/group 移除 | 删除绑定和派生状态，不触发持久化恢复 | AC-3.1, AC-3.2 |
| ER-6 | SA 重启 | 服务进程重新启动 | 运行时绑定为空，客户端缓存不重放 | AC-3.3 |
| ER-7 | 显式解绑 | 系统服务撤销 deviceId 运行时绑定 | 删除绑定和派生状态；无绑定时返回 `RET_OK` 且无副作用 | AC-1.5 |

## 错误码定义

| 错误码 ID | 错误码值 | 含义 | 关联 AC |
|-----------|----------|------|---------|
| EC-OK | `RET_OK` | 绑定成功、解绑成功或清理成功 | AC-1.1, AC-1.4, AC-1.5 |
| EC-PERM | `ERROR_NO_PERMISSION` | 调用方不满足系统 API 或权限要求 | AC-1.2, AC-1.5 |
| EC-ERR | `RET_ERR` | 参数非法、设备非法、显示非法或服务端绑定失败 | AC-1.3 |
| EC-SERVICE | `MMISERVICE_NOT_RUNNING` | 多模输入服务未运行 | AC-1.3 |

## 接口变更分析

### 新增接口

| 接口名称 | 开放级别 | 参数概要 | 返回值 | 错误码 | 关联 AC |
|----------|----------|----------|--------|--------|---------|
| `InputManager::BindDeviceToDisplayGroupByDisplay` | Inner API / System API | `int32_t deviceId`, `int32_t displayId`, `std::string &msg` | `int32_t`/`ErrCode` | `RET_OK`, `RET_ERR`, `ERROR_NO_PERMISSION`, `MMISERVICE_NOT_RUNNING` | AC-1.1 - AC-1.4 |
| `InputManager::UnbindDeviceFromDisplayGroup` | Inner API / System API | `int32_t deviceId`, `std::string &msg` | `int32_t`/`ErrCode` | `RET_OK`, `RET_ERR`, `ERROR_NO_PERMISSION`, `MMISERVICE_NOT_RUNNING` | AC-1.5 |
| `IInputWindowsManager::BindDeviceToDisplayGroupByDisplay` | service internal | `deviceId`, `displayId`, `msg` | `int32_t` | `RET_OK`, `RET_ERR` | AC-1.1, AC-1.3 |
| `IInputWindowsManager::UnbindDeviceFromDisplayGroup` | service internal | `deviceId`, `msg` | `int32_t` | `RET_OK`, `RET_ERR` | AC-1.5 |

### 变更/废弃接口

| 接口名称 | 变更类型 | 影响场景 | 迁移指引 | 关联 AC |
|----------|----------|----------|----------|---------|
| `SetDisplayBind` | 保持兼容 | 现有配置/历史绑定能力保持原行为 | 新运行时绑定场景使用 `BindDeviceToDisplayGroupByDisplay` | AC-3.3, AC-5.3 |
| 全局 pointer 设置 API | 行为声明 | 继续仅默认组生效 | 需要按窗口隔离时使用窗口级 API | AC-5.1, AC-5.2 |
| `hidumper -s 3101` dump 输出 | 扩展诊断字段 | 多 display group 下需要定位绑定、分发和光标状态 | 字段只增加诊断信息，不作为应用 API 兼容契约 | AC-6.3 - AC-6.5 |

## 兼容性声明

- **已有 API 行为变更:** 否。新增接口独立承载运行时绑定语义，旧接口保持兼容。
- **配置文件格式变更:** 否。运行时绑定不持久化。
- **数据存储格式变更:** 否。仅新增内存态绑定表和懒分配状态。

## 验证映射

| AC | 关联规则 | 验证方式 | 证据 |
|----|----------|----------|------|
| AC-1.1 | BR-1, BR-2, BR-3 | SA/WindowManager 单元测试绑定成功 | `MMIServiceTest`, `InputWindowsManagerTest` |
| AC-1.2 | ER-1 | 权限 mock 失败测试 | `MMIServiceTest` |
| AC-1.3 | ER-2, ER-3 | 非法设备/显示测试 | `InputDisplayBindHelperTest`, `InputWindowsManagerTest` |
| AC-1.4 | BR-4, ER-4 | 重复绑定覆盖测试 | `InputWindowsManagerTest` |
| AC-1.5 | BR-7, ER-7 | 显式解绑成功、无权限拒绝、无绑定无副作用测试 | `MMIServiceTest`, `InputDisplayBindHelperTest`, `InputWindowsManagerTest` |
| AC-2.1 | BR-1, BR-5 | 多 group 鼠标事件分发测试 | `InputWindowsManagerTest` |
| AC-2.2 | BR-1 | 多 group 键盘焦点测试 | `InputWindowsManagerTest` |
| AC-2.3 | BR-1 | 触控板/派生 pointer 事件 group 测试 | `TouchpadTransformProcessor`/window manager 测试 |
| AC-2.4 | BR-5 | 未绑定 map 不增长测试 | `InputWindowsManagerTest` |
| AC-2.5 | BR-10 | 双鼠标未绑定共享状态、绑定后位置/样式/颜色/大小/surface node 隔离测试 | `InputWindowsManagerTest`, cursor drawing tests |
| AC-2.6 | BR-10 | 双键盘未绑定共享焦点/pressed/modifier、绑定后隔离测试 | `InputWindowsManagerTest` |
| AC-2.7 | BR-9 | key/button/pointer/gesture begin-before-bind 与 end-after-bind 闭环测试 | `InputWindowsManagerTest`, dispatch cache tests |
| AC-3.1 | ER-5 | 设备移除清理测试 | `InputWindowsManagerTest` |
| AC-3.2 | ER-5 | 显示/group 移除清理测试 | `InputWindowsManagerTest` |
| AC-3.3 | ER-6 | connect manager 不重放测试 | `MultimodalInputConnectManagerTest` |
| AC-3.4 | ER-5 | 清理后事件不访问旧状态测试 | `InputWindowsManagerTest` |
| AC-4.1 | BR-1 | 软光标绑定 display 测试 | `CursorDrawingComponentTest` |
| AC-4.2 | BR-1 | 硬光标 buffer display 测试 | `PointerDrawingManagerTest`/板侧 |
| AC-4.3 | BR-5 | 多 group 光标状态互不覆盖测试 | `InputWindowsManagerTest` |
| AC-5.1 | BR-6 | 窗口级 API 回归测试 | 现有 pointer style/capture 测试 |
| AC-5.2 | BR-6 | 全局 API 默认组测试 | `InputWindowsManagerTest` |
| AC-5.3 | BR-5 | 启动/未绑定路径状态测试 | `InputWindowsManagerTest` |
| AC-5.4 | BR-8 | 默认组使用点分类清单与多 group 回归测试 | `InputWindowsManagerTest`, 代码审查清单 |
| AC-6.1 | BR-11 | 真实 `mmi_service` + `/dev/uinput` 虚拟鼠标/键盘 + 两个 display group + listener 分发记录 | 板侧测试日志 |
| AC-6.2 | BR-11 | 双鼠标/双键盘未绑定、绑定、解绑、生命周期清理端到端场景 | listener 输出与断言日志 |
| AC-6.3 | BR-11, BR-12 | `hidumper -s 3101` 多组绑定/事件状态 dump | hidumper 输出 |
| AC-6.4 | BR-11 | 软光标 RS 与硬光标 HWC/RS buffer 参数 dump | hidumper 输出和必要的板侧渲染日志 |
| AC-6.5 | BR-12 | dump 前后检查非默认懒状态未被创建 | hidumper 输出和状态计数断言 |

## 代码映射

| AC 编号 | 预期实现模块/文件 | 实际实现文件 | 关联 Task | 验证状态（Pass/Fail/Blocked） |
|---------|------------------|-------------|-----------|---------|
| AC-1.1 | `interfaces/native/innerkits/proxy/include/input_manager.h`, `frameworks/proxy/**`, `service/connect_manager/**`, `service/module_loader/**`, `service/window_manager/**` | | TASK-1, TASK-2, TASK-3 | Blocked |
| AC-1.2 | `service/module_loader/include/mmi_service.h`, `service/module_loader/src/mmi_service.cpp` | | TASK-2 | Blocked |
| AC-1.3 | `service/module_loader/src/mmi_service.cpp`, `service/window_manager/src/input_windows_manager.cpp`, `service/window_manager/src/input_display_bind_helper.cpp` | | TASK-2, TASK-3 | Blocked |
| AC-1.4 | `service/window_manager/src/input_display_bind_helper.cpp`, `service/window_manager/src/input_windows_manager.cpp` | | TASK-3 | Blocked |
| AC-1.5 | `interfaces/native/innerkits/proxy/include/input_manager.h`, `frameworks/proxy/**`, `service/connect_manager/**`, `service/module_loader/**`, `service/window_manager/**` | | TASK-1, TASK-2, TASK-3, TASK-8 | Blocked |
| AC-2.1 | `service/window_manager/src/input_windows_manager.cpp`, pointer dispatch/cache helpers | | TASK-5, TASK-7 | Blocked |
| AC-2.2 | `service/window_manager/src/input_windows_manager.cpp` | | TASK-4 | Blocked |
| AC-2.3 | `service/window_manager/src/input_windows_manager.cpp`, touchpad transform path if required | | TASK-6 | Blocked |
| AC-2.4 | `service/window_manager/include/input_windows_manager.h`, `service/window_manager/src/input_windows_manager.cpp` | | TASK-7, TASK-11 | Blocked |
| AC-2.5 | cursor/pointer state maps, pointer style/color/size/surface node paths, `input_windows_manager.*`, cursor rendering files | | TASK-7, TASK-9, TASK-10, TASK-12 | Blocked |
| AC-2.6 | key focus/pressed-key/modifier state paths, `input_windows_manager.*`, key dispatch cache if touched | | TASK-4, TASK-7, TASK-12 | Blocked |
| AC-2.7 | pointer/key sequence snapshot and dispatch cache paths, `input_windows_manager.*` | | TASK-7, TASK-12 | Blocked |
| AC-3.1 | `service/window_manager/src/input_display_bind_helper.cpp`, `service/window_manager/src/input_windows_manager.cpp` | | TASK-8 | Blocked |
| AC-3.2 | `service/window_manager/src/input_display_bind_helper.cpp`, `service/window_manager/src/input_windows_manager.cpp` | | TASK-8 | Blocked |
| AC-3.3 | `service/connect_manager/src/multimodal_input_connect_manager.cpp` | | TASK-8 | Blocked |
| AC-3.4 | `service/window_manager/src/input_windows_manager.cpp` | | TASK-8 | Blocked |
| AC-4.1 | `cursor_drawing_component.*`, `service/window_manager/src/input_windows_manager.cpp` | | TASK-9 | Blocked |
| AC-4.2 | `pointer_drawing_manager.*`, `screen_pointer.*`, `service/window_manager/src/input_windows_manager.cpp` | | TASK-10 | Blocked |
| AC-4.3 | `service/window_manager/include/input_windows_manager.h`, `service/window_manager/src/input_windows_manager.cpp`, cursor rendering files | | TASK-7, TASK-9, TASK-10 | Blocked |
| AC-5.1 | `service/window_manager/test/input_windows_manager_test.cpp` | `Compat_WindowScopedPointerStyle_ByGroup_001`, `Compat_WindowScopedCapture_ByGroup_001`, `Compat_WindowScopedPointerStyle_GlobalOverride_001` | TASK-11 | Done |
| AC-5.2 | `service/window_manager/test/input_windows_manager_test.cpp` | `Compat_GlobalAPI_MouseInfo_DefaultGroupOnly_001`, `Compat_GlobalAPI_CursorPos_DefaultGroupOnly_001`, `Compat_GlobalAPI_CaptureMode_DefaultGroupOnly_001`, `Compat_GlobalAPI_DisplayGroupInfo_DefaultGroupOnly_001` | TASK-11 | Done |
| AC-5.3 | `service/window_manager/test/input_windows_manager_test.cpp` | `Compat_Startup_NoNonDefaultBindingState_001`, `Compat_Startup_NoNonDefaultRenderContext_001`, `Compat_UnboundEvent_NoNonDefaultState_001` | TASK-7, TASK-11 | Done |
| AC-5.4 | `service/window_manager/test/input_windows_manager_test.cpp`, `service/window_manager/include/input_windows_manager.h`, `service/window_manager/src/input_windows_manager.cpp` | `Compat_DefaultGroupAudit_TopologyFallback_001`, `Compat_DefaultGroupAudit_ResolvedGroupRequired_KeyboardRoute_001`, `Compat_DefaultGroupAudit_ResolvedGroupRequired_MouseLocation_001`, `Compat_DefaultGroupAudit_ResolvedGroupRequired_CaptureMode_001`, `Compat_DefaultGroupAudit_ResolvedGroupRequired_CursorPos_001`, `Compat_DefaultGroupAudit_LegacyDefaultOnly_CameraCheck_001`, `Compat_DefaultGroupAudit_EnsureGroupState_LazyAllocation_001` | TASK-0, TASK-4, TASK-5, TASK-6, TASK-7, TASK-11 | Done |
| AC-6.1 | `/dev/uinput` integration harness, `mmi_service` listener path, display group setup | | TASK-13 | Blocked |
| AC-6.2 | listener assertions for dual mouse/keyboard binding, unbinding and cleanup | | TASK-13 | Blocked |
| AC-6.3 | `service/event_dump/*`, `InputWindowsManager::Dump`, event dispatch state dump | | TASK-13 | Blocked |
| AC-6.4 | `PointerDrawingManager::Dump`, `ScreenPointer`, `CursorDrawingComponent`, RS/HWC parameter dump | | TASK-13 | Blocked |
| AC-6.5 | dump-only no-allocation checks for lazy group state | | TASK-13 | Blocked |
