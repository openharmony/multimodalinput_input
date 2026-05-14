# 输入事件流水线知识

本文记录多模输入事件流水线的稳定背景知识。任务专属 spec 和实现笔记仍保留在 `docs/superpowers/` 下。

## 流水线阶段

输入处理应保持以下阶段清晰可见：

1. 归一化原始设备事件。
2. 解析事件上下文和目标作用域。
3. 选择目标窗口、焦点窗口或分发接收者。
4. 分发给消费者。
5. 更新绘制、渲染或上报状态。

策略决策不应隐藏在底层解析或传输代码中。当特性改变目标选择、焦点、坐标、光标状态或分发作用域时，必须在读取或写入这些状态前完成上下文解析。

## 常见代码区域

以下路径可作为起点锚点，编辑前仍需沿本地调用链继续追踪：

- 原始设备和传输处理：`service/libinput_adapter/`、`service/message_handle/` 和 `frameworks/proxy/`。
- 事件归一化：`service/key_event_normalize/`、`service/mouse_event_normalize/` 和 `service/touch_event_normalize/`。
- 分发和 subscriber 投递：`service/event_dispatch/`、`service/event_handler/`、`service/interceptor/`、`service/monitor/` 和 `service/subscriber/`。
- 窗口目标选择和指针绘制：`service/window_manager/`。
- 公开 API 和兼容投影：`interfaces/`、`frameworks/native/`、`frameworks/napi/` 和 `frameworks/ets/`。

当补丁跨越这些区域时，需要说明它改变的是哪个边界。例如，“目标查找前归一化”和“目标查找后重分发”不同，测试也应覆盖精确边界。

## 典型调用链

这些调用链仅用于定位；编辑前需要确认当前分支，因为特性分支可能增加中间 handler。

| 流程 | 典型锚点 | 说明 |
| --- | --- | --- |
| 设备事件到归一化事件 | `service/libinput_adapter/` -> `service/*_event_normalize/` | 保持设备解析和策略决策分离。 |
| 归一化指针到目标 | `MouseEventNormalize` 或触摸转换 -> `InputWindowsManager::UpdateTargetPointer` | 命中测试或光标状态更新前解析显示/组上下文。 |
| 键盘到焦点目标 | key normalize/handler -> `InputWindowsManager::UpdateTarget` 或 `HandleKeyEventWindowId` | 使用已解析作用域的焦点，而非无关默认状态。 |
| 已定目标事件到客户端 | `EventDispatchHandler` -> monitor/interceptor/subscriber/window consumer | 在 UDS 投递过程中保留目标信息和分发顺序。 |
| 指针绘制更新 | 目标/坐标更新 -> `PointerDrawingManager` 或 `CursorDrawingComponent` | 避免每次移动都扫描和格式化重日志。 |
| 生成的 end 或 cancel | 序列快照 -> 目标更新 -> 分发/绘制/上报 -> 清理 | 保留上下文直到所有 end-event 消费者完成。 |

如果某个变更无法描述为上述流程之一，需要把新流程写到最近的 spec 或测试中，便于后续工作保持边界。

## 事件上下文

某些输入特性先收到 API 或传输标识，再需要把它解析成运行时事件上下文后才能查找目标。该上下文可能包含用户、显示组、显示、窗口组、设备能力或活跃序列信息。

解析完成后，事件链应使用同一上下文进行目标查找、焦点选择、光标状态、合成事件和分发状态处理。

不要在某个阶段解析上下文，却在后续阶段读取默认组或全局状态，除非该代码有意服务于遗留默认查询。如果事件从 display id、device id、window id、token 或传输连接开始，应把该值视为上下文解析输入，而不是目标敏感状态的最终权威。

## 事件类型说明

- 指针类事件通常影响坐标、显示范围、光标状态、捕获、命中测试、序列快照和绘制通知。
- 键盘类事件通常依赖已解析目标作用域的焦点状态，并可能需要重发或 subscriber 行为保持作用域正确。
- 触摸、手写板、手写笔、触控板、摇杆、遥控和虚拟输入路径可以共享事件容器，但仍可能拥有不同归属规则。把逻辑移动到通用 helper 前需要检查设备分类。
- 合成、取消、重分发和 axis-end 事件应复用原始事件链中的已解析上下文或已捕获序列状态。

## 禁止的捷径

- 不要让底层解析器选择窗口、焦点或分发策略。
- 不要让后续分发或绘制阶段用不同于目标选择阶段的标识重新恢复作用域。
- 不要在指针移动、光标绘制、重分发或生成 end 循环中增加 INFO 日志、字符串格式化或整表扫描。
- 不要为了简化读取路径而给未绑定/默认事件创建可选上下文状态。

## 高频路径规则

事件移动和光标绘制路径是高频路径。需要避免：

- 每次移动或绘制都完整扫描 map。
- 在热路径中进行字符串格式化。
- 每次移动或绘制都打 INFO 级日志。
- 为未绑定事件重复创建上下文。

默认事件路径应保持在既有快速路径上，除非显式上下文操作需要额外状态。

在移动、绘制或重分发循环中增加工作前，先检查所需上下文能否解析一次并向后传递。优先使用缓存的已解析上下文或序列快照，而不是重复遍历 map 或做格式化诊断。

## 测试映射

- 归一化变更通常需要 `service/*_event_normalize/test/` 中最接近的测试。
- 分发或事件处理变更通常需要 `EventDispatchTest`、`EventHandlerTest` 或最接近的 subscriber/interceptor/monitor 测试目标。
- 窗口目标、焦点、坐标、捕获、重分发和绘制变更通常需要 `InputWindowsManager*`、`PointerDrawingManager*`、`CursorDrawingComponent*` 或 `PointerDispatchEventCacheStandaloneTest`。
- 公开 API 形态变更通常需要 `InputNativeTest` 或匹配的 NAPI/ETS 覆盖。

当行为依赖真实显示、窗口、图形或设备状态时，按 `board-verification.md` 补充板侧证据。
