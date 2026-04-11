# MouseController 实现差距分析

## 文档说明
本文档对比当前实现与需求描述、验收条件之间的差距，标识已完成和待完成的工作项。

## 日期
2025年

---

## 一、核心功能实现状态

### ✅ 已完成

1. **核心 C++ 类实现**
   - ✅ `JsMouseController` 类（js_mouse_controller.h/cpp）
   - ✅ 客户端状态管理（buttonStates_, axisState_, cursorPos_）
   - ✅ 6个核心方法实现（MoveTo, PressButton, ReleaseButton, BeginAxis, UpdateAxis, EndAxis）
   - ✅ 自动清理机制（析构函数）

2. **NAPI 绑定实现**
   - ✅ `js_mouse_controller_napi.h/cpp` 文件
   - ✅ CreateMouseController 函数
   - ✅ 6个方法的 NAPI 包装
   - ✅ 同步执行模式（不使用 std::thread）
   - ✅ Promise 返回机制

3. **IPC 权限校验链**
   - ✅ MMIService::CreateMouseController() - 服务端权限检查
   - ✅ InputManager::CreateMouseController()
   - ✅ InputManagerImpl::CreateMouseController()
   - ✅ MultimodalInputConnectManager::CreateMouseController()
   - ✅ IMultimodalInputConnect.idl 接口声明

4. **模块注册**
   - ✅ js_register_module.cpp 中添加导出
   - ✅ BUILD.gn 配置更新

5. **事件映射**
   - ✅ Button 枚举映射（JS → Native）
   - ✅ Axis 枚举映射（JS → Native）
   - ✅ PointerEvent 动作映射

---

## 二、待完成项（按优先级排序）

### 🔴 高优先级（必须完成）

#### 1. TypeScript 类型定义文件
**状态**：❌ 未创建

**需要创建**：`interfaces/kits/napi/@ohos.multimodalInput.inputEventClient.d.ts`

**内容要求**：
```typescript
// MouseController 接口定义
interface MouseController {
  moveTo(displayId: number, displayX: number, displayY: number): Promise<void>;
  pressButton(button: Button): Promise<void>;
  releaseButton(button: Button): Promise<void>;
  beginAxis(axis: Axis, value: number): Promise<void>;
  updateAxis(axis: Axis, value: number): Promise<void>;
  endAxis(axis: Axis): Promise<void>;
}

// createMouseController 函数
function createMouseController(): Promise<MouseController>;

// Button 枚举
enum Button {
  LEFT = 0, MIDDLE = 1, RIGHT = 2, SIDE = 3,
  EXTRA = 4, FORWARD = 5, BACK = 6, TASK = 7
}

// Axis 枚举
enum Axis {
  SCROLL_VERTICAL = 0,
  SCROLL_HORIZONTAL = 1,
  PINCH = 2
}
```

**JSDoc 注释要求**：
- @syscap SystemCapability.MultimodalInput.Input.InputSimulator
- @stagemodelonly
- @systemapi
- @since 26.0.0
- @permission ohos.permission.INJECT_INPUT_EVENT
- @throws 错误码说明

#### 2. 坐标范围验证
**状态**：❌ 未实现

**需求**：
- ❌ 不允许负数坐标 → 需要裁剪为 0
- ❌ 超出屏幕范围 → 需要裁剪到屏幕边缘

**当前实现**：直接传递坐标，无验证

**需要修改**：`js_mouse_controller.cpp` 中的 `MoveTo()` 方法

**实现建议**：
```cpp
int32_t JsMouseController::MoveTo(int32_t displayId, int32_t x, int32_t y)
{
    // 负数裁剪
    if (x < 0) x = 0;
    if (y < 0) y = 0;

    // TODO: 获取屏幕尺寸并裁剪到边缘
    // 需要调用 DisplayManager API
    // int32_t screenWidth = GetScreenWidth(displayId);
    // int32_t screenHeight = GetScreenHeight(displayId);
    // if (x > screenWidth) x = screenWidth;
    // if (y > screenHeight) y = screenHeight;

    // ... 后续逻辑
}
```

#### 3. 事件来源标记
**状态**：❌ 未实现

**需求**：设置 `pointerEvent->SetEventSource(EVENT_SOURCE_SIMULATED)`

**当前实现**：未设置事件来源

**需要修改**：`js_mouse_controller.cpp` 中的 `CreatePointerEvent()` 方法

**风险**：需要确认 `EVENT_SOURCE_SIMULATED` 常量是否存在

#### 4. 权限检查（每次调用）
**状态**：⚠️ 部分实现

**需求**：每个方法（moveTo/pressButton等）都要检查权限

**当前实现**：
- ✅ CreateMouseController 时检查权限（服务端）
- ❌ 每次方法调用时未检查权限

**问题**：根据约束条件 7，需要"每次调用接口操作时都需要检查"

**实现方式**：
- 方案 A：每次 NAPI 方法调用时都调用服务端权限检查（性能开销大）
- 方案 B：在客户端缓存权限检查结果（需要考虑权限变化）
- 方案 C：仅在 CreateMouseController 时检查（当前实现，可能不符合需求）

**需要明确**：是否真的需要每次调用都检查权限？

---

### 🟡 中优先级（建议完成）

#### 5. 单元测试
**状态**：❌ 未创建

**需要创建**：`frameworks/napi/input_event_client/test/mouse_controller_test.cpp`

**测试用例**：
```cpp
TEST_F(MouseControllerTest, CreateController_Success)
TEST_F(MouseControllerTest, MoveTo_Success)
TEST_F(MouseControllerTest, MoveTo_NegativeCoordinates_Clamped)
TEST_F(MouseControllerTest, PressButton_Success)
TEST_F(MouseControllerTest, PressButton_AlreadyPressed)
TEST_F(MouseControllerTest, ReleaseButton_Success)
TEST_F(MouseControllerTest, ReleaseButton_NotPressed)
TEST_F(MouseControllerTest, BeginAxis_Success)
TEST_F(MouseControllerTest, BeginAxis_AlreadyInProgress)
TEST_F(MouseControllerTest, UpdateAxis_Success)
TEST_F(MouseControllerTest, UpdateAxis_NotStarted)
TEST_F(MouseControllerTest, EndAxis_Success)
TEST_F(MouseControllerTest, Destructor_AutoCleanup)
TEST_F(MouseControllerTest, MultipleInstances_IndependentState)
```

#### 6. 集成测试
**状态**：❌ 未创建

**需要创建**：`frameworks/napi/input_event_client/test/mouse_controller_integration_test.ets`

**测试场景**：
- 完整鼠标操作流程
- 滚轮操作
- 权限检查
- 错误处理
- 多实例并发

#### 7. 能力检查（PC 设备限制）
**状态**：❌ 未实现

**需求**：非 PC 设备返回 801 错误

**当前实现**：未检查设备类型

**需要添加**：在 `CreateMouseController` 中检查设备能力

---

### 🟢 低优先级（可选）

#### 8. 错误码统一管理
**状态**：⚠️ 临时定义

**当前实现**：在 `js_mouse_controller_napi.cpp` 中临时定义
```cpp
constexpr int32_t INPUT_SERVICE_EXCEPTION = 3800001;
```

**建议**：移到 `util_napi_error.h` 统一管理

#### 9. 性能优化
**状态**：❌ 未测试

**需要验证**：
- 连续注入 1000 个事件的性能
- 多实例并发性能
- 权限检查性能开销

#### 10. 文档完善
**状态**：⚠️ 部分完成

**已有**：
- MouseController_Implementation_Constraints.md（约束条件）
- 代码注释

**缺少**：
- API 使用示例文档
- 错误处理指南
- 性能优化建议

---

## 三、设计约束遵循情况

| 约束条件 | 状态 | 说明 |
|---------|------|------|
| 1. 实现位置 | ✅ | frameworks/napi/input_event_client/ |
| 2. 枚举定义 | ✅ | 使用 mouse_event 中的定义 |
| 3. PointerEvent 字段 | ✅ | 使用 SetTargetDisplayId() |
| 4. 自动清理 | ✅ | 析构函数实现 |
| 5. displayId 验证 | ✅ | 服务端验证 |
| 6. 坐标范围验证 | ❌ | **未实现** |
| 7. 权限检查时机 | ⚠️ | 仅在创建时检查，**需明确** |
| 8. 错误码 | ✅ | 统一使用 4300001 |
| 9. 模块导出 | ⚠️ | 代码已导出，**缺 .d.ts** |
| 10. 事件来源标记 | ❌ | **未实现** |

---

## 四、验收条件对照

### 功能验收

| 验收项 | 状态 | 说明 |
|--------|------|------|
| 基本操作（moveTo/press/release） | ✅ | 核心功能已实现 |
| 坐标验证（负数裁剪） | ❌ | **未实现** |
| 状态验证（重复按键检测） | ✅ | 已实现 |
| 自动清理 | ✅ | 析构函数实现 |
| 权限检查 | ⚠️ | 仅创建时检查 |

### 测试验收

| 验收项 | 状态 | 说明 |
|--------|------|------|
| 单元测试通过 | ❌ | **未创建测试** |
| 集成测试通过 | ❌ | **未创建测试** |
| 代码审查通过 | ⏳ | 待审查 |
| 功能验收通过 | ⏳ | 待验收 |
| 性能测试通过 | ❌ | **未测试** |

### 文档验收

| 验收项 | 状态 | 说明 |
|--------|------|------|
| TypeScript 类型定义 | ❌ | **未创建** |
| API 文档 | ⚠️ | 仅有代码注释 |
| 使用示例 | ❌ | **未提供** |

---

## 五、关键差距总结

### 🔴 阻塞性问题（必须解决）

1. **TypeScript 类型定义文件缺失**
   - 影响：无法在 TypeScript/ArkTS 中使用
   - 优先级：最高

2. **坐标范围验证未实现**
   - 影响：不符合需求约束 6
   - 优先级：高

3. **事件来源标记未实现**
   - 影响：不符合需求约束 10
   - 优先级：高

### ⚠️ 需要明确的问题

1. **权限检查时机**
   - 约束条件 7 要求"每次调用都检查"
   - 当前实现仅在创建时检查
   - 需要明确：是否真的需要每次调用都检查？性能影响如何？

2. **能力检查（PC 设备限制）**
   - TypeScript 定义中要求非 PC 设备返回 801
   - 当前未实现设备类型检查
   - 需要明确：如何判断是否为 PC 设备？

### 📋 建议完成的工作

1. **测试用例**
   - 单元测试（13+ 用例）
   - 集成测试（5+ 场景）

2. **文档完善**
   - API 使用示例
   - 错误处理指南

3. **性能验证**
   - 连续注入性能测试
   - 多实例并发测试

---

## 六、下一步行动计划

### 第一阶段：核心功能补全（1-2天）

1. ✅ 创建 TypeScript 类型定义文件
2. ✅ 实现坐标范围验证
3. ✅ 实现事件来源标记
4. ⚠️ 明确权限检查策略并实现

### 第二阶段：测试完善（1-2天）

1. ✅ 编写单元测试
2. ✅ 编写集成测试
3. ✅ 执行性能测试

### 第三阶段：文档和审查（0.5-1天）

1. ✅ 完善 API 文档
2. ✅ 提交代码审查
3. ✅ 功能验收

---

## 七、风险提示

1. **坐标裁剪实现**：需要调用 DisplayManager API 获取屏幕尺寸，可能存在依赖问题
2. **事件来源标记**：需要确认 `EVENT_SOURCE_SIMULATED` 常量是否存在
3. **权限检查性能**：如果每次调用都检查权限，可能有性能开销
4. **设备能力检查**：需要明确如何判断设备类型（PC vs 非PC）

---

## 附录：完成度统计

- **核心功能**：70% （7/10 项完成）
- **测试覆盖**：0% （0/2 项完成）
- **文档完善**：30% （1/3 项完成）
- **整体完成度**：约 50%

**预计剩余工作量**：3-5 天
