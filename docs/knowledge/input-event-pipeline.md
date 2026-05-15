# 输入事件流水线知识

本文只记录输入事件主链路中容易被改错的边界。显示组、设备分类、状态缓存和板侧验证细节分别见同目录其他知识文档。

## 主链路

输入处理应保持阶段清晰：

1. 归一化原始设备事件。
2. 解析运行时上下文和目标作用域。
3. 选择目标窗口、焦点窗口或分发接收者。
4. 分发给 monitor、interceptor、subscriber 或窗口消费者。
5. 更新绘制、渲染或上报状态。

策略决策不要下沉到底层解析或传输代码。改变目标选择、焦点、坐标、光标状态或分发作用域时，先解析上下文，再读写相关状态。

## 典型边界

| 流程 | 锚点 | 要点 |
| --- | --- | --- |
| 设备事件到归一化事件 | `service/libinput_adapter/` -> `service/*_event_normalize/` | 设备解析和策略决策分离。 |
| 指针到目标窗口 | `MouseEventNormalize`/触摸转换 -> `InputWindowsManager::UpdateTargetPointer` | 命中测试前解析显示组上下文。 |
| 键盘到焦点窗口 | key normalize/handler -> `InputWindowsManager::UpdateTarget` | 使用已解析作用域的焦点。 |
| 目标事件到客户端 | `EventDispatchHandler` -> monitor/interceptor/subscriber/window consumer | 保留目标信息和 UDS 分发顺序。 |
| end/cancel/redispatch | 序列快照 -> 目标更新 -> 分发/绘制/上报 -> 清理 | 上下文保留到所有消费者完成。 |

## 高频路径

指针移动、光标绘制、重分发和生成 end 事件属于高频路径。不要在循环中增加整表扫描、字符串格式化、INFO 日志或重复上下文创建。需要额外状态时，优先解析一次并沿链路传递。

## 测试指引

- 归一化变更：就近使用 `service/*_event_normalize/test/`。
- 分发变更：使用 `EventDispatchTest`、`EventHandlerTest` 或对应 subscriber/interceptor/monitor 测试。
- 窗口、焦点、坐标、捕获、重分发或绘制变更：使用 `InputWindowsManager*`、`PointerDrawingManager*`、`CursorDrawingComponent*` 或 `PointerDispatchEventCacheStandaloneTest`。
- 依赖真实显示、窗口、图形或设备状态时，补充 `board-verification.md` 中的板侧证据。
