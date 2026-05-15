# 输入设备作用域知识

本文只记录设备分类和设备生命周期相关知识。通用目标作用域规则见 `display-group-model.md`。

## 设备标识不是天然权威

`deviceId`、`displayId`、`groupId`、`windowId`、API token、transport fd 和兼容 dump 字段都可以作为解析输入，但不要在子系统未明确约定时把它们直接作为路由权威。新增路由或缓存决策时，优先传递已解析上下文或序列快照。

## 分类差异

| 分类 | 需要关注的作用域字段 | 典型锚点 |
| --- | --- | --- |
| 指针/鼠标 | device id、显示组、显示、光标状态、捕获、序列 | `service/mouse_event_normalize/`、`service/window_manager/` |
| 键盘 | device id、已解析焦点组、subscriber/interceptor 顺序 | `service/key_event_normalize/`、`InputWindowsManager::UpdateTarget` |
| 触摸/触控板 | device id、显示/组转换、手势状态、pointer items | `service/touch_event_normalize/` |
| 手写板/手写笔 | tool type、proximity、button、pressure、显示转换 | `TabletToolTransformTest`、触摸转换代码 |
| 摇杆/crown/遥控 | 设备能力、传输来源、焦点作用域或配置目标 | `service/joystick/`、`service/crown_transform_processor/` |
| 虚拟/注入输入 | 调用方、token/传输身份、已解析目标作用域 | `interfaces/`、`frameworks/`、分发/窗口管理代码 |

共享 helper 需要说明支持哪些设备分类，以及依赖哪些作用域字段。不要因为共用 `PointerEvent` 就把手写板、手写笔、触控板、远端或虚拟输入规则折叠进鼠标路径。

## 生命周期

从设备、显示、用户或窗口状态派生的作用域，在以下场景需要重新校验或清理：

- 设备添加、移除、启用、禁用或能力变化。
- 显示添加、移除、折叠、旋转或组拓扑变化。
- 用户切换、前台组变化或服务重启。
- 窗口销毁、焦点转移、捕获释放、取消事件或序列结束。

清理应删除或失效对应缓存，不要为了普通默认路径创建替代上下文状态。

## 测试指引

设备生命周期或能力变化使用 `DeviceManagerTest`、`DeviceManagerExTest`、`InputDeviceManagerTestWithMock`、`DeviceStateManagerTest` 或 `mmi-libadapter-hotplug-test`。分类转换和路由变化使用 `MouseEventNormalize*`、`Touch*Transform*`、`TabletToolTransformTest` 或 `RemoteControlTransformProcessorTestWithMock`。涉及 API 兼容字段时使用 `InputNativeTest`。
