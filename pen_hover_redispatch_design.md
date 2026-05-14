# 手写笔悬停态事件 Redispatch 支持实现方案.

## 1. 需求背景

### 1.1 当前问题
- **手写笔事件模型**：使用 `SOURCE_TYPE_TOUCHSCREEN` + `TOOL_TYPE_PEN`，与触摸屏事件共享 sourceType
- **激活机制**：当前 TouchRedispatchStore 的激活机制不区分手指和手写笔
- **支持的悬停事件**：
  - `POINTER_ACTION_PROXIMITY_IN` (35)：手写笔接近屏幕
  - `POINTER_ACTION_PROXIMITY_OUT` (36)：手写笔离开屏幕
  - `POINTER_ACTION_LEVITATE_MOVE` (51)：悬停移动
  - `POINTER_ACTION_LEVITATE_IN_WINDOW` (52)：悬停进入窗口
  - `POINTER_ACTION_LEVITATE_OUT_WINDOW` (53)：悬停离开窗口

### 1.2 核心需求
1. **激活时机**：`PROXIMITY_IN` 时激活该 pointerId（整机级别，不绑定窗口）
2. **停用时机**：`PROXIMITY_OUT` 时停用该 pointerId
3. **UP 后行为**：`UP` 事件后仍允许重分发 `LEVITATE_MOVE`（手写笔专用）
4. **跨窗口支持**：手写笔在不同窗口间移动时，动态计算目标窗口（已有机制支持）

### 1.3 架构确认
- ✅ **激活机制是整机级别的**：`{deviceId, pointerId}` 不包含 windowId
- ✅ **目标窗口动态计算**：每次重分发时通过 `UpdateTargetPointer` 重新计算
- ✅ **天然支持跨窗口场景**：PROXIMITY_IN 在窗口 A，LEVITATE_MOVE 在窗口 B，PROXIMITY_OUT 在窗口 C

---

## 2. 技术方案

### 2.1 设计原则
- ✅ **最小改动**：只修改 `TouchRedispatchStore::Abandon` 一个方法
- ✅ **状态一致**：RedispatchStore 和 WindowManager 使用相同的 `{deviceId, pointerId}` 键
- ✅ **向后兼容**：不影响现有手指触摸事件的处理逻辑
- ✅ **跨窗口支持**：利用现有整机级别激活机制

### 2.2 事件处理逻辑

#### 手写笔完整事件序列（支持跨窗口）
```
T1: 窗口 A 上方 - PROXIMITY_IN
    → 自动激活 {deviceId, pointerId} ✅
    → UpdateTargetPointer 计算目标窗口 = A ✅
    → 分发到窗口 A ✅

T2: 移动到窗口 B 上方 - LEVITATE_MOVE
    → {deviceId, pointerId} 仍激活 ✅
    → UpdateTargetPointer 重新计算目标窗口 = B ✅
    → 分发到窗口 B ✅

T3: 在窗口 B - DOWN → MOVE → UP
    → {deviceId, pointerId} 仍激活 ✅
    → 所有事件分发到窗口 B ✅

T4: 抬起后继续悬停 - LEVITATE_MOVE
    → {deviceId, pointerId} 仍激活 ✅
    → 继续分发到窗口 B ✅

T5: 移动到窗口 C 上方 - LEVITATE_OUT
    → {deviceId, pointerId} 仍激活 ✅
    → 分发到窗口 C ✅

T6: 远离屏幕 - PROXIMITY_OUT
    → 停用 {deviceId, pointerId} ✅
    → 允许重分发最后一次，之后停用 ✅
```

#### 核心判断逻辑
1. **PROXIMITY_IN**：自动激活，允许重分发
2. **PROXIMITY_OUT**：停用，但允许重分发这一次
3. **LEVITATE_***：允许重分发，不停用
4. **UP**：
   - 手写笔（TOOL_TYPE_PEN）：允许重分发，**不停用**
   - 手指（TOOL_TYPE_FINGER）：允许重分发，**停用**

---

## 3. 实现细节

### 3.1 文件修改清单

| 文件路径 | 修改内容 | 优先级 |
|---------|---------|--------|
| `service/window_manager/src/touch_redispatch_store.cpp` | 修改 `Abandon` 方法（唯一改动） | 🔴 高 |
| `service/window_manager/test/input_windows_manager_test.cpp` | 添加单元测试 | 🟡 中 |

**不需要修改的文件**：
- ❌ `service/module_loader/src/mmi_service.cpp` - 不需要修改，`UpdateTargetPointer` 已支持动态计算目标窗口
- ❌ `service/window_manager/include/touch_redispatch_store.h` - 接口签名不变

### 3.2 核心代码修改

#### 3.2.1 修改 `TouchRedispatchStore::Abandon`

**文件**：`service/window_manager/src/touch_redispatch_store.cpp`

**位置**：第 161-180 行

**修改前**：
```cpp
bool TouchRedispatchStore::Abandon(const std::shared_ptr<PointerEvent>& pointerEvent)
{
    CHKPF(pointerEvent);
    int32_t deviceId = pointerEvent->GetDeviceId();
    int32_t pointerId = pointerEvent->GetPointerId();
    float zOrder = pointerEvent->GetZOrder();

    if (!IsFingerActive(zOrder, deviceId, pointerId)) {
        MMI_HILOGD("Abandon touch redispatch, z:%{public}f d:%{public}d p:%{public}d not active",
            zOrder, deviceId, pointerId);
        return true;
    }

    int32_t action = pointerEvent->GetPointerAction();
    if (action == PointerEvent::POINTER_ACTION_UP ||
        action == PointerEvent::POINTER_ACTION_CANCEL ||
        action == PointerEvent::POINTER_ACTION_HOVER_CANCEL ||
        action == PointerEvent::POINTER_ACTION_HOVER_EXIT) {
        DeactivateFinger(zOrder, deviceId, pointerId);
    }

    return false;
}
```

**修改后**：
```cpp
bool TouchRedispatchStore::Abandon(const std::shared_ptr<PointerEvent>& pointerEvent)
{
    CHKPF(pointerEvent);
    int32_t deviceId = pointerEvent->GetDeviceId();
    int32_t pointerId = pointerEvent->GetPointerId();
    float zOrder = pointerEvent->GetZOrder();

    // 获取 toolType 以区分手指和手写笔
    PointerEvent::PointerItem pointerItem;
    int32_t toolType = PointerEvent::TOOL_TYPE_FINGER;
    if (pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        toolType = pointerItem.GetToolType();
    }

    int32_t action = pointerEvent->GetPointerAction();

    // ✅ 核心改动 1：手写笔 PROXIMITY_IN 自动激活
    if (toolType == PointerEvent::TOOL_TYPE_PEN &&
        action == PointerEvent::POINTER_ACTION_PROXIMITY_IN) {
        SetFingerActive(zOrder, deviceId, pointerId, pointerEvent);
        MMI_HILOGD("Auto-activate pen on PROXIMITY_IN, z:%{public}f d:%{public}d p:%{public}d",
            zOrder, deviceId, pointerId);
        return false;  // 允许重分发
    }

    // 检查是否激活
    if (!IsFingerActive(zOrder, deviceId, pointerId)) {
        MMI_HILOGD("Abandon touch redispatch, not active, z:%{public}f d:%{public}d p:%{public}d",
            zOrder, deviceId, pointerId);
        return true;  // 未激活，放弃重分发
    }

    // ✅ 核心改动 2：根据 toolType 应用不同的停用逻辑
    if (toolType == PointerEvent::TOOL_TYPE_PEN) {
        // 手写笔：只在 PROXIMITY_OUT 时停用
        if (action == PointerEvent::POINTER_ACTION_PROXIMITY_OUT) {
            DeactivateFinger(zOrder, deviceId, pointerId);
            MMI_HILOGD("Deactivate pen on PROXIMITY_OUT, d:%{public}d p:%{public}d",
                deviceId, pointerId);
        }
        // UP 时不影响激活状态，允许继续 LEVITATE_MOVE
        // LEVITATE_MOVE/IN/OUT_WINDOW 也不影响激活状态
    } else {
        // 手指：保持原有逻辑
        if (action == PointerEvent::POINTER_ACTION_UP ||
            action == PointerEvent::POINTER_ACTION_CANCEL ||
            action == PointerEvent::POINTER_ACTION_HOVER_CANCEL ||
            action == PointerEvent::POINTER_ACTION_HOVER_EXIT) {
            DeactivateFinger(zOrder, deviceId, pointerId);
            MMI_HILOGD("Deactivate finger on action:%{public}d, d:%{public}d p:%{public}d",
                action, deviceId, pointerId);
        }
    }

    return false;  // 允许重分发
}
```

**改动要点**：
1. 在方法开始处获取 `toolType`
2. **核心改动 1**：检测 `PROXIMITY_IN` 并自动激活
3. **核心改动 2**：手写笔只在 `PROXIMITY_OUT` 时停用，手指保持原有逻辑

---

## 4. 测试方案

### 4.1 单元测试

**测试文件**：`service/window_manager/test/input_windows_manager_test.cpp`

**测试用例**：

#### 测试用例 1：手写笔 PROXIMITY_IN 激活
```cpp
TEST_F(InputWindowsManagerTest, PenProximityIn_ActivatePointerId)
{
    // Given: 创建手写笔 PROXIMITY_IN 事件
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PROXIMITY_IN);
    pointerEvent->SetDeviceId(1);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetZOrder(1.0f);

    PointerEvent::PointerItem pointerItem;
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_PEN);
    pointerEvent->UpdatePointerItem(0, pointerItem);

    auto& touchRedispatchStore = WIN_MGR->GetTouchRedispatchStore();

    // When: 调用 Abandon
    bool shouldAbandon = touchRedispatchStore.Abandon(pointerEvent);

    // Then: 不应该放弃，且应该被激活
    ASSERT_FALSE(shouldAbandon);
    ASSERT_TRUE(touchRedispatchStore.IsFingerActive(1.0f, 1, 0));
}
```

#### 测试用例 2：手写笔 UP 事件不停用
```cpp
TEST_F(InputWindowsManagerTest, PenUp_DoNotDeactivate)
{
    // Given: 激活的手写笔 pointerId
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetDeviceId(1);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetZOrder(1.0f);

    PointerEvent::PointerItem pointerItem;
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_PEN);
    pointerEvent->UpdatePointerItem(0, pointerItem);

    auto& touchRedispatchStore = WIN_MGR->GetTouchRedispatchStore();
    touchRedispatchStore.SetFingerActive(1.0f, 1, 0, pointerEvent);

    // When: 调用 Abandon
    bool shouldAbandon = touchRedispatchStore.Abandon(pointerEvent);

    // Then: 不应该放弃，且仍然激活
    ASSERT_FALSE(shouldAbandon);
    ASSERT_TRUE(touchRedispatchStore.IsFingerActive(1.0f, 1, 0));
}
```

#### 测试用例 3：手写笔 PROXIMITY_OUT 停用
```cpp
TEST_F(InputWindowsManagerTest, PenProximityOut_Deactivate)
{
    // Given: 激活的手写笔 pointerId
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PROXIMITY_OUT);
    pointerEvent->SetDeviceId(1);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetZOrder(1.0f);

    PointerEvent::PointerItem pointerItem;
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_PEN);
    pointerEvent->UpdatePointerItem(0, pointerItem);

    auto& touchRedispatchStore = WIN_MGR->GetTouchRedispatchStore();
    touchRedispatchStore.SetFingerActive(1.0f, 1, 0, pointerEvent);

    // When: 调用 Abandon
    bool shouldAbandon = touchRedispatchStore.Abandon(pointerEvent);

    // Then: 不应该放弃重分发，但应该被停用
    ASSERT_FALSE(shouldAbandon);  // 允许重分发这一次
    ASSERT_FALSE(touchRedispatchStore.IsFingerActive(1.0f, 1, 0));  // 之后被停用
}
```

#### 测试用例 4：手指 UP 事件停用（验证不影响手指逻辑）
```cpp
TEST_F(InputWindowsManagerTest, FingerUp_Deactivate)
{
    // Given: 激活的手指 pointerId
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetDeviceId(1);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetZOrder(1.0f);

    PointerEvent::PointerItem pointerItem;
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    pointerEvent->UpdatePointerItem(0, pointerItem);

    auto& touchRedispatchStore = WIN_MGR->GetTouchRedispatchStore();
    touchRedispatchStore.SetFingerActive(1.0f, 1, 0, pointerEvent);

    // When: 调用 Abandon
    bool shouldAbandon = touchRedispatchStore.Abandon(pointerEvent);

    // Then: 应该停用
    ASSERT_FALSE(shouldAbandon);  // 允许重分发这一次
    ASSERT_FALSE(touchRedispatchStore.IsFingerActive(1.0f, 1, 0));  // 被停用
}
```

### 4.2 集成测试

**测试场景**：

#### 场景 1：手写笔完整事件序列
```
1. 调用 RedispatchInputEvent(PROXIMITY_IN)
   → 验证：pointerId 被激活

2. 调用 RedispatchInputEvent(LEVITATE_MOVE)
   → 验证：事件成功重分发到应用

3. 调用 RedispatchInputEvent(DOWN)
   → 验证：事件成功重分发

4. 调用 RedispatchInputEvent(UP)
   → 验证：事件成功重分发

5. 调用 RedispatchInputEvent(LEVITATE_MOVE)
   → 验证：事件成功重分发（UP 后仍允许）

6. 调用 RedispatchInputEvent(PROXIMITY_OUT)
   → 验证：事件成功重分发，之后 pointerId 被停用
```

#### 场景 2：跨窗口场景
```
1. 窗口 A：PROXIMITY_IN
   → 验证：激活，分发到窗口 A

2. 移动到窗口 B：LEVITATE_MOVE
   → 验证：仍激活，分发到窗口 B

3. 窗口 B：DOWN → MOVE → UP
   → 验证：仍激活，分发到窗口 B

4. 抬起后继续悬停：LEVITATE_MOVE
   → 验证：仍激活，分发到窗口 B

5. 移动到窗口 C：LEVITATE_OUT
   → 验证：仍激活，分发到窗口 C

6. 远离屏幕：PROXIMITY_OUT
   → 验证：停用
```

---

## 5. 验证步骤

### 5.1 编译验证
```bash
# 编译服务
ninja -C out/rk3568 multimodalinput_mmi_service

# 编译测试
ninja -C out/rk3568 InputWindowsManagerTest
```

### 5.2 单元测试执行
```bash
# 运行测试
./out/rk3568/InputWindowsManagerTest
```

### 5.3 手动测试步骤

#### 测试环境准备
1. 准备支持手写笔的设备
2. 确认手写笔可以正常识别（toolType = TOOL_TYPE_PEN）
3. 打开测试应用（如笔记应用）

#### 测试步骤
1. **悬停接近测试**
   - 手写笔靠近屏幕但不接触
   - 验证：应用收到 `PROXIMITY_IN` 事件

2. **悬停移动测试**
   - 手写笔在屏幕上方移动
   - 验证：应用收到 `LEVITATE_MOVE` 事件，光标跟随移动

3. **触摸测试**
   - 手写笔接触屏幕（DOWN）
   - 移动手写笔（MOVE）
   - 抬起手写笔（UP）
   - 验证：应用正常收到所有事件

4. **抬起后继续悬停测试**
   - 手写笔抬起后，再次悬停移动
   - 验证：应用继续收到 `LEVITATE_MOVE` 事件

5. **离开屏幕测试**
   - 手写笔远离屏幕
   - 验证：应用收到 `PROXIMITY_OUT` 事件

6. **重分发测试**
   - 使用 RedispatchInputEvent 接口重新分发上述事件
   - 验证：所有事件都能正确重分发到应用

---

## 6. 风险评估

### 6.1 技术风险

| 风险项 | 影响 | 概率 | 缓解措施 |
|--------|------|------|---------|
| toolType 获取失败 | 🟡 中 | 🟢 低 | 增加空指针检查，默认 FINGER |
| 状态机逻辑错误 | 🔴 高 | 🟡 中 | 完善单元测试覆盖 |
| 性能影响 | 🟢 低 | 🟢 低 | Abandon 中增加的 toolType 检查开销极小 |
| 兼容性问题 | 🟡 中 | 🟡 中 | 保持手指原有逻辑不变 |

### 6.2 业务风险

| 风险项 | 影响 | 缓解措施 |
|--------|------|---------|
| 手写笔和手指同时存在冲突 | 🟡 中 | 共享 pointerId，实际场景中较少 |
| 应用层不识别悬停事件 | 🟢 低 | 这是应用层的实现问题，不影响接口 |

---

## 7. 实施计划

### 7.1 开发任务

| 任务 | 预计工时 | 状态 |
|------|---------|------|
| 修改 TouchRedispatchStore::Abandon | 2小时 | ⏳ 待开始 |
| 编写单元测试 | 3小时 | ⏳ 待开始 |
| 代码 Review | 1小时 | ⏳ 待开始 |
| 集成测试 | 2小时 | ⏳ 待开始 |
| 文档更新 | 1小时 | ⏳ 待开始 |

### 7.2 里程碑

- **M1**: 代码修改完成（Day 1）
- **M2**: 单元测试通过（Day 2）
- **M3**: 集成测试通过（Day 3）
- **M4**: 代码合并到主分支（Day 4）

---

## 8. 附录

### 8.1 相关文件路径

```
service/window_manager/src/touch_redispatch_store.cpp
service/window_manager/include/touch_redispatch_store.h
service/module_loader/src/mmi_service.cpp
service/window_manager/test/input_windows_manager_test.cpp
```

### 8.2 相关常量定义

```cpp
// input_event.h
SOURCE_TYPE_TOUCHSCREEN = 2

// pointer_event.h
TOOL_TYPE_FINGER = 0
TOOL_TYPE_PEN = 1

POINTER_ACTION_PROXIMITY_IN = 35
POINTER_ACTION_PROXIMITY_OUT = 36
POINTER_ACTION_LEVITATE_MOVE = 51
POINTER_ACTION_LEVITATE_IN_WINDOW = 52
POINTER_ACTION_LEVITATE_OUT_WINDOW = 53
```

### 8.3 参考资料

- `multimodalinput_input/README.md` - 模块概述
- `CLAUDE.md` - 项目架构说明
- Android Touch 事件处理机制（对比参考）

