# 输入设备作用域知识

本文记录分析输入设备和输入事件作用域时使用的稳定背景知识。

## 作用域解析

输入事件在读取或更新目标敏感状态前，应先关联到明确的运行时作用域。根据特性不同，作用域可以包含用户、显示组、显示、窗口组、设备能力或序列状态。

除非周边子系统明确把某个 API 参数、传输标识或兼容字段定义为运行时作用域，否则不要把它当作权威依据。应先解析，再把已解析上下文沿事件链传递下去。

## 作用域输入和权威来源

Device id、display id、group id、window id、API token、transport fd 和兼容 dump 字段都可以作为有用输入。但除非周边子系统明确把该标识定义为已解析运行时作用域，否则它们都不应成为路由权威。

新增路由或缓存决策时，优先使用记录了已解析用户、显示组、显示、设备分类和窗口作用域的上下文对象或序列快照。避免使用一组并行的原始键，因为它们可能在生命周期事件中彼此漂移。

## 设备分类

不同设备分类可以拥有不同的归属和目标选择规则。修改分发或状态缓存前，代码应先识别当前路径处理的是指针类、键盘类、触摸、手写板、摇杆、遥控还是虚拟输入。

共享 helper 不应假设所有输入设备都使用相同的显示、焦点、光标或序列状态。

## 分类指南

- 指针类设备通常依赖显示组边界、坐标范围、光标状态、捕获状态和指针序列快照。
- 键盘类设备通常依赖已解析目标作用域的焦点状态，以及 subscriber/interceptor 顺序。
- 触摸和触控板路径可以共享指针容器，但在手势、悬停、手写板和坐标转换规则上不同。
- 手写板和手写笔路径可能增加工具类型、接近状态、按键、压力和绘制行为，不应在未检查归属的情况下折叠进通用鼠标路由。
- 摇杆、crown、遥控、虚拟和注入输入可能带有传输或 API 标识，需要在目标选择前显式解析。

新增共享 helper 时，需要记录它支持哪些分类，以及需要哪些作用域字段。

## 分类作用域表

| 分类 | 需要检查的作用域字段 | 典型锚点 |
| --- | --- | --- |
| 指针或鼠标 | Device id、显示组、显示、光标状态、序列 | `service/mouse_event_normalize/`、`service/window_manager/` |
| 键盘 | 相关时使用 device id、已解析焦点组、subscriber/interceptor 状态 | `service/key_event_normalize/`、`InputWindowsManager::UpdateTarget` |
| 触摸或触控板 | Device id、显示/组转换、手势状态、pointer items | `service/touch_event_normalize/` |
| 手写板或手写笔 | Device id、工具类型、接近状态、按键、压力、显示转换 | `TabletToolTransformTest`、触摸转换代码 |
| 摇杆、crown、遥控 | 设备能力、传输来源、焦点作用域或配置目标 | `service/joystick/`、`service/crown_transform_processor/`、遥控转换代码 |
| 虚拟或注入输入 | API 调用方、token/传输身份、已解析目标作用域 | `interfaces/`、`frameworks/`、分发/窗口管理器代码 |

## 生命周期

从设备、显示、用户或窗口状态派生出的运行时作用域，必须在这些状态变化时重新校验。设备移除、显示移除、用户空间变化和服务重启路径不应留下过期的事件作用域或状态缓存条目。

典型清理触发包括：

- 设备添加、移除、启用、禁用或能力变化。
- 显示添加、移除、折叠、旋转或组拓扑变化。
- 用户切换、前台组变化或服务重启。
- 窗口销毁、焦点转移、捕获释放、取消事件或序列结束。

清理应删除或使作用域缓存失效，不应为普通默认路径创建替代上下文状态。

## 禁止的捷径

- 除非子系统明确把 `deviceId`、`displayId`、fd 或 API token 定义为已解析运行时作用域，否则不要直接用它们路由新行为。
- 不要因为共用 `PointerEvent`，就把手写板、手写笔、触控板、遥控或虚拟输入的归属规则折叠进鼠标路由。
- 热插拔、显示拓扑变化、用户切换、服务重启、取消或序列结束后，不要保留过期的设备派生状态。
- 不要把 dump 或兼容结构作为新路由决策的事实来源。

## 兼容性

遗留查询或 dump 结构可以因兼容性保留，但不应成为新事件路由决策的权威来源。相比散落的全局状态或彼此独立的原始键，应优先使用已解析上下文对象。

## 代码锚点

- 设备发现、能力和生命周期：`service/device_manager/`。
- 设备状态和热插拔测试：`service/device_manager/test/` 和 `service/libinput_adapter/test/`。
- 鼠标/指针设备状态：`service/mouse_event_normalize/`。
- 触控板、手写板、手势和遥控转换：`service/touch_event_normalize/`。
- Native、NAPI、ETS 和兼容 API 表面：`interfaces/` 和 `frameworks/`。

## 测试映射

生命周期或能力变化使用 `DeviceManagerTest`、`DeviceManagerExTest`、`InputDeviceManagerTestWithMock`、`DeviceStateManagerTest` 和 `mmi-libadapter-hotplug-test`。分类专属转换和路由变化使用 `MouseEventNormalize*`、`Touch*Transform*`、`TabletToolTransformTest` 或 `RemoteControlTransformProcessorTestWithMock`。涉及 API 兼容字段时使用 `InputNativeTest`。
