# OpenHarmony Multimodal Input — 开发约束

## 跨层特性实现约束

当实现涉及事件流的特性（如设备绑定、事件路由、状态隔离）时，**必须在写代码前完成以下分析**：

### 1. 事件流追踪（必做）

追踪受影响事件类型（鼠标/键盘/触控板等）的完整代码路径，从 libinput 事件源到最终消费点。记录每个函数签名和文件路径。

关键链路：
```
鼠标: libinput → EventNormalizeHandler → MouseEventInterface → MouseEventNormalize
      → MouseTransformProcessor → InputWindowsManager → PointerDrawingManager
      → CursorDrawingComponent → RenderService

键盘: libinput → EventNormalizeHandler → KeyEventNormalize
      → InputWindowsManager → EventDispatch → UDS → 客户端
```

在链路上标记所有使用 `MAIN_GROUPID`、`DEFAULT_GROUP_ID`、无参 group helper 的位置。

### 2. 文件级影响清单（必做）

基于事件流追踪，列出所有需要修改的文件，按代码层次组织（不是按功能域）：

| 层次 | 文件 | 改动类型 |
|------|------|---------|
| 事件归一化 | event_normalize_handler.cpp | 传递 groupId |
| 鼠标归一化 | mouse_transform_processor.cpp | per-group 坐标/按钮 |
| ... | ... | ... |

### 3. 参照 PR 对标（有参照时必做）

如果有参照实现或已有 PR，在编码前获取其完整 diff，确认：
- 它改了哪些层，我们的清单是否覆盖
- 它新增了哪些结构体/类，我们的设计是否对应
- 它修改了哪些接口签名，我们的策略是否对齐

### 4. TASK 拆分原则

按**代码层次 + 依赖关系**拆分 TASK，而非按功能域：
- 底层先做（归一化层的状态隔离）
- 中间层次之（窗口管理路由）
- 上层最后（光标绘制、诊断输出）

每个 TASK 的 subagent prompt 必须包含完整事件链路上下文，说明上游已传递什么、本层需要做什么、下游期望什么。

## 接口变更策略

- **内部实现接口**（如 `IMouseEventNormalize`）：可以重写签名，增加 per-group 方法
- **跨模块接口**（如 `IInputWindowsManager`）：用默认参数保持兼容
- **对外 API**（如 `InputManager`）：只增不改

## 状态隔离检查清单

涉及 per-group 状态隔离时，逐层确认：

- [ ] 鼠标坐标状态（`MouseDeviceState`）是否按 group 隔离
- [ ] 鼠标按钮状态是否按 group 隔离
- [ ] 键盘按键/修饰键状态（`KeyEvent` 实例）是否按 group 隔离
- [ ] 光标位置（`cursorPosMap_`）是否按 group 隔离
- [ ] 鼠标位置（`mouseLocationMap_`）是否按 group 隔离
- [ ] 捕获模式（`captureModeInfoMap_`）是否按 group 隔离
- [ ] 光标绘制上下文（`PointerDrawingContext`）是否按 group 隔离
- [ ] 焦点窗口（`focusWindowIdMap_`）是否按 group 隔离
- [ ] 事件序列快照是否记录原始 group/window
