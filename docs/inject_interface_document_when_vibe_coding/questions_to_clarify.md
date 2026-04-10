# MouseController 设计待明确问题清单

## 文档信息
- 创建日期：2026-04-02
- 关联设计：mouse_injection_design_v2.md
- 状态：待确认

---

## 问题分类

### 🔴 高优先级（必须明确）

#### Q1: Button 枚举定义

**问题描述**：
接口中使用了 `Button` 类型，但没有给出具体定义。需要明确按键枚举值及其与 PointerEvent 常量的映射关系。

**需要明确**：
```typescript
enum Button {
  LEFT = ?      // 对应 PointerEvent 的哪个常量？
  RIGHT = ?     // PointerEvent::MOUSE_BUTTON_RIGHT?
  MIDDLE = ?    // PointerEvent::MOUSE_BUTTON_MIDDLE?
  SIDE = ?      // 侧键
  EXTRA = ?     // 额外按键
  FORWARD = ?   // 前进键
  BACK = ?      // 后退键
  // 还有其他按键吗？
}
```

**参考代码**：
- `interfaces/native/innerkits/event/include/pointer_event.h` 中的按键常量定义

**影响范围**：
- NAPI 层的枚举定义
- PointerEvent 构造时的 `SetButtonId()` 参数
- TypeScript 类型定义文件

**建议**：
查看 PointerEvent.h 中的按键常量定义，提供完整的映射表。

---

#### Q2: Axis 枚举定义

**问题描述**：
接口中使用了 `Axis` 类型，需要明确轴类型枚举值，特别是触控板双指手势的支持。

**需要明确**：
```typescript
enum Axis {
  SCROLL_VERTICAL = ?      // 垂直滚轮，对应 PointerEvent 的哪个轴？
  SCROLL_HORIZONTAL = ?    // 水平滚轮

  // 触控板双指手势（需求中提到）
  PINCH = ?               // 双指捏合，是否支持？对应哪个轴？
  SWIPE_HORIZONTAL = ?    // 双指水平滑动
  SWIPE_VERTICAL = ?      // 双指垂直滑动

  // 还有其他轴类型吗？
}
```

**相关需求**：
> "通过接口注入双指捏合/滑动事件，与用户操作物理触控板效果相同（不包含旋转）"

**需要确认**：
1. 双指捏合/滑动是通过 `beginAxis/updateAxis/endAxis` 实现吗？
2. 还是需要单独的接口？
3. PointerEvent 中对应的 action 是什么？
   - `POINTER_ACTION_SWIPE_BEGIN/UPDATE/END`？
   - 还是通过 `POINTER_ACTION_AXIS_*` + 特定轴类型？

**参考代码**：
- `interfaces/native/innerkits/event/include/pointer_event.h` 中的轴类型定义
- `POINTER_ACTION_SWIPE_*` 相关常量

**影响范围**：
- 轴事件的实现逻辑
- PointerEvent 的 action 选择
- 可能需要额外的手势支持

---

#### Q3: PointerEvent 必须设置的字段

**问题描述**：
构造 PointerEvent 时，需要明确哪些字段是必须设置的，哪些是可选的。

**已知必须设置**：
```cpp
pointerEvent->SetPointerAction(action);           // ✅ 必须
pointerEvent->SetSourceType(SOURCE_TYPE_MOUSE);   // ✅ 必须
pointerEvent->SetPointerId(0);                    // ✅ 必须
pointerEvent->AddPointerItem(item);               // ✅ 必须
```

**需要明确是否必须设置**：
```cpp
pointerEvent->SetDeviceId(?);           // ❓ 需要吗？设置什么值？
pointerEvent->SetActionTime(?);         // ❓ 需要吗？使用当前时间？
pointerEvent->SetActionStartTime(?);    // ❓ 需要吗？
pointerEvent->SetTargetDisplayId(?);    // ❓ 与 displayId 的关系？
pointerEvent->SetTargetWindowId(?);     // ❓ 需要吗？-1 表示不指定？
pointerEvent->SetAgentWindowId(?);      // ❓ 需要吗？
```

**影响范围**：
- PointerEvent 构造的完整性
- 事件能否被服务端正确处理
- 事件分发的准确性

**建议**：
参考现有的 `SimulateInputEvent` 实现，查看它是如何构造 PointerEvent 的。

---

### 🟡 中优先级（建议明确）

#### Q4: 对象销毁时的清理策略

**问题描述**：
当 MouseController 对象被 GC 回收时，如果还有按键处于按下状态，应该如何处理？

**场景示例**：
```typescript
async function test() {
  const controller = await createMouseController();
  await controller.pressButton(Button.LEFT);
  // controller 离开作用域，被 GC 回收
  // 但 LEFT 按键在客户端状态中是 pressed
  // 实际系统中也可能是 pressed（如果事件已注入）
}
```

**可选方案**：

**方案 A：自动清理（推荐）**
```cpp
JsMouseController::~JsMouseController() {
  // 释放所有按下的按键
  for (auto& [button, pressed] : buttonStates_) {
    if (pressed) {
      ReleaseButton(button);  // 自动注入 BUTTON_UP 事件
    }
  }

  // 结束进行中的轴事件
  if (axisState_.inProgress) {
    EndAxis(axisState_.axisType);
  }
}
```

**方案 B：不清理**
- 由应用层保证正确的清理
- 文档中明确说明必须手动释放所有按键

**方案 C：警告但不清理**
```cpp
JsMouseController::~JsMouseController() {
  if (!buttonStates_.empty() || axisState_.inProgress) {
    MMI_HILOGW("MouseController destroyed with active state");
  }
}
```

**需要决策**：选择哪个方案？

---

#### Q5: displayId 的验证策略

**问题描述**：
`moveTo(displayId, x, y)` 中的 displayId 应该在哪里验证？

**可选方案**：

**方案 A：客户端不验证，服务端验证（当前设计）**
```cpp
int32_t JsMouseController::MoveTo(int32_t displayId, int32_t x, int32_t y) {
  // 不验证 displayId，直接构造 PointerEvent
  auto event = CreatePointerEvent(...);
  return InputManager::GetInstance()->SimulateInputEvent(event);
  // 如果 displayId 无效，服务端返回 4300002
}
```

**方案 B：客户端预验证**
```cpp
int32_t JsMouseController::MoveTo(int32_t displayId, int32_t x, int32_t y) {
  // 先验证 displayId 是否有效
  if (!IsDisplayValid(displayId)) {
    return ERROR_CODE_DISPLAY_NOT_EXIST;  // 4300002
  }
  // 再构造 PointerEvent
  auto event = CreatePointerEvent(...);
  return InputManager::GetInstance()->SimulateInputEvent(event);
}
```

**方案 B 的问题**：
- 需要客户端查询显示器列表（额外的 IPC 调用）
- 显示器可能在验证后、注入前发生变化（热插拔）

**建议**：方案 A（服务端验证），除非有特殊需求。

---

#### Q6: 坐标范围验证

**问题描述**：
`moveTo(displayId, x, y)` 中的坐标是否需要验证？

**需要明确**：
1. **负数坐标**：是否允许？
   - 某些系统支持负数坐标（多显示器场景）
   - 建议：允许负数，由服务端处理

2. **超出屏幕范围**：如何处理？
   - 选项 A：客户端不验证，服务端裁剪到屏幕边界
   - 选项 B：客户端验证，返回错误
   - 建议：选项 A

3. **坐标类型**：接口定义为 `int`，是否足够？
   - 是否需要支持小数坐标（高 DPI 场景）？
   - 当前定义：`int`，应该足够

**建议**：不在客户端验证坐标范围，由服务端处理。

---

#### Q7: 权限检查的时机

**问题描述**：
权限应该在什么时候检查？

**当前设计**：
```typescript
// 仅在获取 controller 时检查一次
const controller = await createMouseController();  // ✅ 检查权限

// 后续操作不再检查
await controller.moveTo(0, 100, 100);          // ❌ 不检查
await controller.pressButton(Button.LEFT);     // ❌ 不检查
```

**可选方案**：

**方案 A：仅在 createMouseController 时检查（当前设计）**
- 优点：性能好，减少权限检查开销
- 缺点：如果权限在运行时被撤销，无法及时发现

**方案 B：每次操作都检查**
- 优点：安全性高
- 缺点：性能开销大

**方案 C：混合方案**
- `createMouseController` 时检查
- 操作失败时，如果是权限错误，提示用户

**建议**：方案 A，假设权限在 controller 生命周期内不会改变。

---

### 🟢 低优先级（可选明确）

#### Q8: 错误码 4300001 的细分

**问题描述**：
当前 4300001 用于多种状态错误，是否需要细分？

**当前使用场景**：
- 按键已被按下
- 按键未被按下
- 轴事件正在进行中
- 轴事件未开始
- 轴事件类型不匹配

**可选方案**：

**方案 A：统一使用 4300001（当前设计）**
```typescript
// 通过错误消息区分
throw new BusinessError(4300001, "Button already pressed");
throw new BusinessError(4300001, "Button not pressed");
throw new BusinessError(4300001, "Axis event in progress");
```

**方案 B：细分错误码**
```typescript
4300001 - Button already pressed
4300002 - Button not pressed
4300003 - Axis event in progress
4300004 - Axis event not started
4300005 - Axis type mismatch
```

**建议**：方案 A，保持简单。如果需要细分，可以在后续版本中扩展。

---

#### Q9: 模块导出位置

**问题描述**：
`createMouseController()` 应该导出到哪个模块？

**接口注释中**：
```typescript
@syscap SystemCapability.MultimodalInput.Input.InputSimulator
```

**可选方案**：

**方案 A：导出到 @ohos.multimodalInput.inputMonitor**
```typescript
import inputMonitor from '@ohos.multimodalInput.inputMonitor';
const controller = await inputMonitor.createMouseController();
```

**方案 B：新建 @ohos.multimodalInput.inputSimulator 模块**
```typescript
import inputSimulator from '@ohos.multimodalInput.inputSimulator';
const controller = await inputSimulator.createMouseController();
```

**建议**：根据现有模块结构决定。如果 inputMonitor 已经有类似功能，使用方案 A。

---

#### Q10: 事件来源标记

**问题描述**：
通过 MouseController 注入的事件，是否需要标记来源？

**场景**：
- 某些应用可能需要区分"真实鼠标事件"和"注入事件"
- 某些安全策略可能需要限制注入事件

**可选方案**：

**方案 A：完全透明（当前设计）**
- 服务端无法区分事件来源
- 注入事件与真实事件完全相同

**方案 B：标记事件来源**
```cpp
pointerEvent->SetEventSource(EVENT_SOURCE_SIMULATED);
```

**建议**：方案 A，保持透明。如果需要区分，可以使用现有的 `isNativeInject` 参数。

---

## 📋 问题汇总表

| 编号 | 问题 | 优先级 | 影响范围 | 建议方案 |
|------|------|--------|---------|---------|
| Q1 | Button 枚举定义 | 🔴 高 | 接口定义、实现 | 查看 PointerEvent.h |
| Q2 | Axis 枚举定义 | 🔴 高 | 接口定义、实现 | 查看 PointerEvent.h |
| Q3 | PointerEvent 必须字段 | 🔴 高 | 事件构造 | 参考现有实现 |
| Q4 | 对象销毁清理策略 | 🟡 中 | 资源管理 | 方案 A（自动清理） |
| Q5 | displayId 验证策略 | 🟡 中 | 错误处理 | 方案 A（服务端验证） |
| Q6 | 坐标范围验证 | 🟡 中 | 参数验证 | 不验证，由服务端处理 |
| Q7 | 权限检查时机 | 🟡 中 | 安全性 | 方案 A（仅初始检查） |
| Q8 | 错误码细分 | 🟢 低 | 错误处理 | 方案 A（统一 4300001） |
| Q9 | 模块导出位置 | 🟢 低 | API 组织 | 根据现有结构决定 |
| Q10 | 事件来源标记 | 🟢 低 | 事件处理 | 方案 A（完全透明） |

---

## 🎯 下一步行动

### 立即需要做的：
1. ✅ 查看 `pointer_event.h`，确认 Button 和 Axis 的枚举定义
2. ✅ 查看现有 `SimulateInputEvent` 实现，确认 PointerEvent 必须字段
3. ✅ 确认触控板双指手势的实现方式

### 可以稍后决定的：
4. 对象销毁清理策略（建议自动清理）
5. displayId 和坐标验证策略（建议服务端验证）
6. 权限检查时机（建议仅初始检查）

### 可选的：
7. 错误码是否细分（建议不细分）
8. 模块导出位置（根据现有结构）
9. 事件来源标记（建议透明）

---

## 📝 备注

- 本文档会随着问题的明确而更新
- 每个问题明确后，会更新到 `mouse_injection_design_v2.md`
- 建议优先解决高优先级问题，再考虑中低优先级问题

