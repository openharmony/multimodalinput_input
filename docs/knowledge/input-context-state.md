# 输入上下文状态知识

本文记录影响目标选择、分发或渲染的输入状态缓存稳定规则。

## 权威键

会影响目标、坐标、焦点、绘制或分发隔离的事件状态，应以已解析运行时上下文为键，而不是以前处理阶段中的偶然标识为键。

设备标识、显示标识和组标识可作为上下文解析或兼容投影的输入。权威缓存键应匹配被缓存行为的隔离模型。

## 键选择指南

选择仍能匹配隔离模型的最窄键：

- 焦点、目标、光标、捕获、显示范围和组隔离分发状态使用用户/显示组上下文。
- 状态同时依赖物理设备身份和目标作用域时，使用设备加已解析上下文。
- end、cancel、axis-end、redispatch、绘制或通知必须在原始事件相同作用域完成时，使用序列快照。
- 遗留默认键仅用于默认初始化、显式默认查询或已记录的兼容 helper。

不要把一个行为拆到无关键上，例如读使用 display id、写使用 group id。这种模式通常会造成跨组泄漏。

## 必须感知显示组的状态

当系统支持多用户、多显示组、多窗口、多设备或多活跃序列时，以下状态通常需要带作用域的缓存：

- 鼠标位置和鼠标坐标。
- 光标显示范围和当前显示。
- 光标可见性、样式、大小和颜色。
- 鼠标捕获模式。
- 指针序列快照。
- 轴事件和生成的结束事件状态。
- 焦点依赖作用域时的键盘焦点和重发状态。
- 受焦点或命中测试影响的 UDS 分发目标状态。

## 代码锚点

- 窗口、焦点、命中测试和捕获状态：`service/window_manager/` 中的 `InputWindowsManager`。
- 指针序列分发状态：`PointerDispatchEventCache`。
- 鼠标位置、光标样式、光标范围和绘制状态：`PointerDrawingManager`、`CursorDrawingComponent`、`PointerRenderer` 和 `ScreenPointer`。
- 显示绑定 helper：`InputDisplayBindHelper`。
- 设备派生状态：`service/device_manager/` 和 `service/mouse_event_normalize/`。

新增缓存或修改键时，需要更新最近的单元测试，覆盖两个拥有不同值的独立作用域。对于带作用域行为，单个默认作用域测试不够。

## 状态归属表

| 状态 | 推荐键 | 归属或锚点 | 清理触发 |
| --- | --- | --- | --- |
| 鼠标位置/坐标 | 已解析显示组；坐标是物理坐标时再加显示 | `InputWindowsManager`、`PointerDrawingManager` | 显示/组变化、序列结束、服务重启 |
| 光标显示范围/当前显示 | 已解析显示组和显示布局 | `PointerDrawingManager`、`ScreenPointer` | 显示拓扑变化、绑定变化 |
| 光标样式/大小/颜色/可见性 | 用户加已解析组/窗口，取决于行为作用域 | `PointerDrawingManager`、`CursorDrawingComponent` | 用户切换、窗口销毁、样式重置 |
| 鼠标捕获模式 | 已解析组/窗口 | `InputWindowsManager::SetMouseCaptureMode` | 捕获释放、窗口销毁、取消 |
| 指针序列快照 | sequence id 或 pointer id 加已解析上下文 | `PointerDispatchEventCache` | end/cancel 的分发、绘制和上报完成后 |
| 轴/生成的结束状态 | 原始序列快照 | `InputWindowsManager`、`PointerDispatchEventCache` | axis end 处理完成 |
| 键盘焦点/重发 | 已解析显示组 | `InputWindowsManager::UpdateTarget` | 焦点转移、组/窗口更新 |
| UDS 分发目标状态 | 已解析目标/窗口上下文 | `EventDispatchHandler`、`InputWindowsManager` | 分发完成、目标失效 |

## 懒分配

不要在服务构造或普通默认输入处理期间创建可选上下文状态。上下文状态只应在事件、显式上下文操作或测试设置需要时创建。

只读遗留查询不应隐式创建可选分发或渲染上下文。

优先使用能返回“not found”的查询 API 访问可选上下文状态。如果读取路径会以副作用创建状态，测试应证明该行为是有意的，且不会影响普通默认路径。

## 禁止的捷径

- 不要对同一行为使用 group id 写入、display id 读取。
- 不要为了简化后续查询，在服务构造中分配可选作用域状态。
- 不要在 end/cancel 分发、绘制和上报完成前清除指针序列上下文。
- 除非 API 明确记录该副作用，否则不要让只读 dump 或查询路径修改作用域缓存。
- 不要只用默认组测试证明作用域行为。

## 序列时序

指针序列状态应保留到结束事件完成必要的目标计算、pointer item 更新、绘制或状态刷新、UDS 分发尝试和 RS 通知。过早清理可能让结束事件混入错误上下文。

## 清理顺序

对于基于序列的指针行为，需要保留序列上下文直到所有目标敏感消费者完成：

1. 解析或恢复序列上下文。
2. 计算目标窗口和 pointer item 更新。
3. 必要时刷新绘制或光标状态。
4. 尝试 UDS 分发和相关事件投递。
5. 通知渲染或上报组件。
6. 清除序列快照和不再存活的可选作用域状态。

即使 cancel、axis-end、redispatch 和合成 end 事件是在原始输入事件之后生成，也应遵循同一归属规则。

## 测试映射

序列快照行为使用 `PointerDispatchEventCacheStandaloneTest`；焦点/目标/捕获状态使用 `InputWindowsManager*`；光标和绘制状态使用 `PointerDrawingManager*` 和 `CursorDrawingComponent*`；显示绑定缓存使用 `InputDisplayBindHelper*`。测试应覆盖懒分配、只读查询、清理，以及带作用域行为中的至少一个非默认或多作用域场景。
