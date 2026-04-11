# KeyboardController 设计实施文档

## 1. 需求概述

### 1.1 应用场景
- **应用名称**：LiveRPA Studio - 桌面自动化工具
- **核心功能**：录制键鼠操作 → 回放
- **使用场景**：录制用户的真实按键序列，然后通过 TS 接口回放这些操作

### 1.2 接口定义
```typescript
interface KeyboardController {
  pressKey(keyCode: KeyCode): Promise<void>;
  releaseKey(keyCode: KeyCode): Promise<void>;
}

function createKeyboardController(): Promise<KeyboardController>;
```

### 1.3 核心约束

#### 1.3.1 按键序列有效性
1. **只能先按下再抬起**
   - 不能在未按下的情况下抬起按键

2. **只有最后一个按下且未抬起的按键可以重复按下**
   - 目的：支持录制回放场景
   - 当用户按住某个键不放时，系统会产生重复事件
   - 录制时会记录多次 pressKey 调用
   - 回放时需要能够重复调用 pressKey 来模拟这种行为
   - 但只能重复"最后按下"的键，防止不合理的序列

3. **最多允许 5 个按键同时处于按下状态**
   - 限制同时按下的按键数量

#### 1.3.2 权限要求
- **权限**：`ohos.permission.CONTROL_DEVICE`
- **注意**：MouseController 也已改为使用 `CONTROL_DEVICE` 权限（不再使用 `INJECT_INPUT_EVENT`）
- **权限检查**：只校验 CONTROL_DEVICE 权限，不需要判断是否是系统应用

#### 1.3.3 错误码
- `201`: 权限验证失败
- `801`: 能力不支持（仅 PC 支持）
- `3800001`: 输入服务异常
- `4300001`: 按键状态错误
  - 按键已按下但不是最后按下的键
  - 按键未按下
  - 超过最大按键数量

### 1.4 服务端自动重复机制

**重要发现**：服务端已有按键自动重复机制（`KeyAutoRepeat`）

- 当注入带 `EVENT_FLAG_SIMULATE` 标志的 KEY_DOWN 事件后：
  - 服务端会自动启动定时器
  - 默认延迟 500ms 后开始重复
  - 之后每 50ms 重复一次（可配置）
  - 直到收到 KEY_UP 事件才停止

- **对设计的影响**：
  - 客户端可以选择依赖服务端自动重复（只调用一次 pressKey）
  - 也可以主动控制重复时机（多次调用 pressKey）
  - 每次调用 pressKey 都会重置服务端的自动重复定时器

## 2. 架构设计

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────┐
│                  JavaScript/ArkTS 层                     │
│  createKeyboardController() → KeyboardController 对象    │
│  - pressKey(keyCode)                                    │
│  - releaseKey(keyCode)                                  │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│                    NAPI 绑定层                           │
│  js_keyboard_controller_napi.cpp                        │
│  - CreateKeyboardController()                           │
│  - KeyboardControllerPressKey()                         │
│  - KeyboardControllerReleaseKey()                       │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│                   C++ 核心实现层                         │
│  JsKeyboardController (js_keyboard_controller.cpp)      │
│  - 状态管理：pressedKeys_ (最多5个)                     │
│  - 序列验证：lastPressedKey_                            │
│  - 事件构造：CreateKeyEvent()                           │
│  - 事件注入：InjectKeyEvent()                           │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│                  InputManager 注入                       │
│  InputManager::SimulateInputEvent(keyEvent)             │
│                          ↓                              │
│              服务端自动重复机制 (KeyAutoRepeat)          │
└─────────────────────────────────────────────────────────┘
```

### 2.2 与 MouseController 的对比

| 特性 | MouseController | KeyboardController |
|------|----------------|-------------------|
| 权限 | CONTROL_DEVICE | CONTROL_DEVICE |
| 状态管理 | 按钮状态 map | 按键集合 (最多5个) |
| 序列约束 | 简单（按下/抬起） | 复杂（最后按下、最多5个、重复） |
| 事件类型 | PointerEvent | KeyEvent |
| 坐标信息 | 需要 | 不需要 |
| 轴事件 | 有 (BeginAxis/UpdateAxis/EndAxis) | 无 |
| 服务端自动重复 | 无 | 有 |

## 3. 核心实现

### 3.1 状态管理

```cpp
class JsKeyboardController {
private:
    // 当前按下的按键集合（最多5个）
    std::set<int32_t> pressedKeys_;

    // 最后一个按下的按键（用于重复按下验证）
    int32_t lastPressedKey_ = -1;

    // 最大同时按下的按键数量
    static constexpr size_t MAX_PRESSED_KEYS = 5;
};
```

### 3.2 按键序列验证逻辑

#### PressKey 验证：
```cpp
int32_t JsKeyboardController::PressKey(int32_t keyCode)
{
    MMI_HILOGD("PressKey: keyCode=%{public}d", keyCode);

    // 1. 检查按键是否已按下
    if (pressedKeys_.count(keyCode) > 0) {
        // 按键已按下，检查是否是最后按下的键
        if (keyCode != lastPressedKey_) {
            MMI_HILOGE("Key %{public}d already pressed but not last pressed key", keyCode);
            return ERROR_CODE_KEY_STATE_ERROR; // 4300001
        }
        // 允许重复最后按下的键（支持录制回放场景）
        MMI_HILOGD("Repeat press last key: %{public}d", keyCode);
    } else {
        // 2. 新按键，检查是否超过最大数量
        if (pressedKeys_.size() >= MAX_PRESSED_KEYS) {
            MMI_HILOGE("Maximum %{public}zu keys already pressed", MAX_PRESSED_KEYS);
            return ERROR_CODE_KEY_STATE_ERROR; // 4300001
        }

        // 3. 添加到按下集合
        pressedKeys_.insert(keyCode);
    }

    // 4. 更新最后按下的按键
    lastPressedKey_ = keyCode;

    // 5. 创建并注入 KEY_DOWN 事件
    auto keyEvent = CreateKeyEvent(KeyEvent::KEY_ACTION_DOWN, keyCode);
    if (keyEvent == nullptr) {
        MMI_HILOGE("Failed to create key event");
        // 回滚状态
        if (pressedKeys_.count(keyCode) == 1) {
            pressedKeys_.erase(keyCode);
        }
        return RET_ERR;
    }

    int32_t ret = InjectKeyEvent(keyEvent);
    if (ret != RET_OK) {
        // 回滚状态
        if (pressedKeys_.count(keyCode) == 1) {
            pressedKeys_.erase(keyCode);
        }
    }

    return ret;
}
```

#### ReleaseKey 验证：
```cpp
int32_t JsKeyboardController::ReleaseKey(int32_t keyCode)
{
    MMI_HILOGD("ReleaseKey: keyCode=%{public}d", keyCode);

    // 1. 检查按键是否已按下
    if (pressedKeys_.count(keyCode) == 0) {
        MMI_HILOGE("Key %{public}d not pressed", keyCode);
        return ERROR_CODE_KEY_STATE_ERROR; // 4300001
    }

    // 2. 创建并注入 KEY_UP 事件
    auto keyEvent = CreateKeyEvent(KeyEvent::KEY_ACTION_UP, keyCode);
    if (keyEvent == nullptr) {
        MMI_HILOGE("Failed to create key event");
        return RET_ERR;
    }

    int32_t ret = InjectKeyEvent(keyEvent);
    if (ret == RET_OK) {
        // 3. 从按下集合中移除
        pressedKeys_.erase(keyCode);

        // 4. 如果是最后按下的按键，更新标记
        if (lastPressedKey_ == keyCode) {
            // 更新为集合中最后一个按键（如果有）
            if (!pressedKeys_.empty()) {
                lastPressedKey_ = *pressedKeys_.rbegin();
            } else {
                lastPressedKey_ = -1;
            }
        }
    }

    return ret;
}
```

### 3.3 KeyEvent 构造

```cpp
std::shared_ptr<KeyEvent> JsKeyboardController::CreateKeyEvent(int32_t action, int32_t keyCode)
{
    auto keyEvent = KeyEvent::Create();
    if (keyEvent == nullptr) {
        MMI_HILOGE("Failed to create KeyEvent");
        return nullptr;
    }

    // 设置基本属性
    keyEvent->SetKeyCode(keyCode);
    keyEvent->SetKeyAction(action); // KEY_ACTION_DOWN / KEY_ACTION_UP

    // 设置时间戳
    int64_t time = GetSysClockTime();
    keyEvent->SetActionTime(time);

    // 设置 DeviceId（虚拟设备）
    keyEvent->SetDeviceId(-1);

    // 标记为模拟事件（触发服务端自动重复）
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_SIMULATE);

    // 添加 KeyItem
    KeyEvent::KeyItem item;
    item.SetKeyCode(keyCode);
    item.SetPressed(action == KeyEvent::KEY_ACTION_DOWN);
    item.SetDownTime(time);
    item.SetDeviceId(-1);
    keyEvent->AddKeyItem(item);

    return keyEvent;
}
```

### 3.4 事件注入

```cpp
int32_t JsKeyboardController::InjectKeyEvent(std::shared_ptr<KeyEvent> event)
{
    if (event == nullptr) {
        MMI_HILOGE("KeyEvent is nullptr");
        return RET_ERR;
    }

    // 注入事件使用 InputManager
    // 注意：SimulateInputEvent 返回 void，假设成功
    InputManager::GetInstance()->SimulateInputEvent(event);

    return RET_OK;
}
```

### 3.5 析构函数自动清理

```cpp
JsKeyboardController::~JsKeyboardController()
{
    MMI_HILOGD("JsKeyboardController destroying, cleaning up state");

    // 自动释放所有按下的按键
    // 注意：需要复制集合，因为 ReleaseKey 会修改 pressedKeys_
    std::set<int32_t> keysToRelease = pressedKeys_;
    for (int32_t keyCode : keysToRelease) {
        MMI_HILOGW("Auto-releasing key %{public}d in destructor", keyCode);
        ReleaseKey(keyCode);
    }
}
```

## 4. 权限检查

### 4.1 权限统一

**重要变更**：MouseController 和 KeyboardController 都使用 `CONTROL_DEVICE` 权限

### 4.2 服务端实现

```cpp
// service/module_loader/src/mmi_service.cpp
ErrCode MMIService::CreateKeyboardController()
{
    CALL_DEBUG_ENTER;
    if (!IsRunning()) {
        MMI_HILOGE("Service is not running");
        return MMISERVICE_NOT_RUNNING;
    }

    // 检查 CONTROL_DEVICE 权限
    if (!PER_HELPER->CheckControlDevicePermission()) {
        MMI_HILOGE("Check CONTROL_DEVICE permission failed");
        return ERROR_NO_PERMISSION;
    }

    MMI_HILOGI("CreateKeyboardController permission check passed");
    return RET_OK;
}
```

**注意**：需要确认 `PermissionHelper` 中是否已有 `CheckControlDevicePermission()` 方法，如果没有需要添加。

## 5. 文件清单

### 5.1 新增文件

1. **C++ 核心实现**
   - `frameworks/napi/input_event_client/include/js_keyboard_controller.h`
   - `frameworks/napi/input_event_client/src/js_keyboard_controller.cpp`

2. **NAPI 绑定**
   - `frameworks/napi/input_event_client/include/js_keyboard_controller_napi.h`
   - `frameworks/napi/input_event_client/src/js_keyboard_controller_napi.cpp`

### 5.2 修改文件

1. **IDL 声明**
   - `service/connect_manager/IMultimodalInputConnect.idl`
   - 添加：`void CreateKeyboardController();`

2. **服务端实现**
   - `service/module_loader/include/mmi_service.h`
   - `service/module_loader/src/mmi_service.cpp`
   - 添加：`ErrCode CreateKeyboardController();`

3. **权限检查**（如需要）
   - `service/permission_helper/include/permission_helper.h`
   - `service/permission_helper/src/permission_helper.cpp`
   - 添加：`bool CheckControlDevicePermission();`（如果不存在）

4. **模块导出**
   - `frameworks/napi/input_event_client/src/js_register_module.cpp`
   - 添加：`DECLARE_NAPI_FUNCTION("createKeyboardController", CreateKeyboardController)`

5. **BUILD.gn**
   - `frameworks/napi/input_event_client/BUILD.gn`
   - 添加新源文件到 sources 列表

6. **TypeScript 定义**（如需要）
   - `interfaces/kits/napi/@ohos.multimodalInput.inputEventClient.d.ts`

## 6. 使用场景示例

### 6.1 基本按键操作
```typescript
const controller = await inputEventClient.createKeyboardController();

// 按下并释放单个按键
await controller.pressKey(KeyCode.KEYCODE_A);
await controller.releaseKey(KeyCode.KEYCODE_A);
```

### 6.2 组合键操作
```typescript
// Ctrl+C 组合键
await controller.pressKey(KeyCode.KEYCODE_CTRL_LEFT);
await controller.pressKey(KeyCode.KEYCODE_C);
await controller.releaseKey(KeyCode.KEYCODE_C);
await controller.releaseKey(KeyCode.KEYCODE_CTRL_LEFT);
```

### 6.3 重复按键（录制回放场景）
```typescript
// 模拟用户按住 A 键不放（产生重复）
await controller.pressKey(KeyCode.KEYCODE_A);     // 第1次
await controller.pressKey(KeyCode.KEYCODE_A);     // 重复第2次（允许）
await controller.pressKey(KeyCode.KEYCODE_A);     // 重复第3次（允许）
await controller.releaseKey(KeyCode.KEYCODE_A);
```

### 6.4 依赖服务端自动重复
```typescript
// 只按下一次，服务端会自动重复
await controller.pressKey(KeyCode.KEYCODE_A);
// 服务端自动每 50ms 重复 KEY_DOWN 事件
await sleep(1000); // 等待 1 秒
await controller.releaseKey(KeyCode.KEYCODE_A); // 停止重复
```

### 6.5 错误场景

#### 场景1：重复非最后按下的键
```typescript
await controller.pressKey(KeyCode.KEYCODE_A);
await controller.pressKey(KeyCode.KEYCODE_B);     // B 变成最后按下的键
await controller.pressKey(KeyCode.KEYCODE_A);     // ❌ 错误 4300001：A 不是最后按下的键
```

#### 场景2：释放未按下的键
```typescript
await controller.releaseKey(KeyCode.KEYCODE_Z);   // ❌ 错误 4300001：键未按下
```

#### 场景3：超过最大按键数量
```typescript
await controller.pressKey(KeyCode.KEYCODE_A);
await controller.pressKey(KeyCode.KEYCODE_B);
await controller.pressKey(KeyCode.KEYCODE_C);
await controller.pressKey(KeyCode.KEYCODE_D);
await controller.pressKey(KeyCode.KEYCODE_E);
await controller.pressKey(KeyCode.KEYCODE_F);     // ❌ 错误 4300001：超过5个
```

## 7. 错误码定义

```cpp
// frameworks/napi/input_event_client/src/js_keyboard_controller.cpp
namespace {
constexpr int32_t ERROR_CODE_KEY_STATE_ERROR = 4300001;  // 按键状态错误
}
```

**错误码 4300001 涵盖的场景**：
- 按键已按下但不是最后按下的键
- 按键未按下
- 超过最大按键数量（5个）

## 8. 实现步骤

### 阶段 1：核心 C++ 实现（1.5 天）
1. 创建 `JsKeyboardController` 类
2. 实现状态管理逻辑（pressedKeys_, lastPressedKey_）
3. 实现按键序列验证（重复按下、最大数量）
4. 实现 KeyEvent 构造和注入
5. 实现析构函数自动清理

### 阶段 2：NAPI 绑定（1 天）
1. 实现 `CreateKeyboardController()`
2. 实现 `KeyboardControllerPressKey()`
3. 实现 `KeyboardControllerReleaseKey()`
4. 权限检查集成
5. 错误处理和 Promise 返回

### 阶段 3：服务端集成（0.5 天）
1. IDL 声明添加
2. 服务端权限检查实现（确认 CheckControlDevicePermission 方法）
3. IPC 消息处理

### 阶段 4：模块导出和配置（0.5 天）
1. 模块导出注册
2. BUILD.gn 配置更新
3. TypeScript 类型定义（如需要）

### 阶段 5：测试（1 天）
1. 单元测试（状态管理、序列验证）
2. 集成测试（录制回放场景）
3. 边界条件测试（错误场景）

**总计**：4.5 天

## 9. 测试用例设计

### 9.1 基本功能测试
```typescript
TEST_F(KeyboardControllerTest, PressAndRelease_Success)
TEST_F(KeyboardControllerTest, MultipleKeys_Success)
```

### 9.2 重复按下测试
```typescript
TEST_F(KeyboardControllerTest, RepeatLastKey_Success)
TEST_F(KeyboardControllerTest, RepeatNonLastKey_Fail)
```

### 9.3 序列验证测试
```typescript
TEST_F(KeyboardControllerTest, ReleaseNotPressed_Fail)
TEST_F(KeyboardControllerTest, MaxKeysLimit_Fail)
```

### 9.4 自动清理测试
```typescript
TEST_F(KeyboardControllerTest, Destructor_AutoCleanup)
```

### 9.5 服务端自动重复测试
```typescript
TEST_F(KeyboardControllerTest, ServerAutoRepeat_Works)
```

## 10. 关键设计决策总结

### 10.1 "重复按下"的理解
- **场景**：录制回放工具（LiveRPA Studio）
- **原因**：用户按住键不放时，系统产生重复事件，录制时会记录多次 pressKey
- **实现**：允许重复调用 pressKey(lastKey)，但只能重复最后按下的键

### 10.2 服务端自动重复
- **发现**：服务端已有 KeyAutoRepeat 机制
- **行为**：注入 KEY_DOWN 后，服务端会自动重复（500ms 延迟，50ms 间隔）
- **影响**：客户端可以选择主动重复或依赖服务端自动重复

### 10.3 权限统一
- **变更**：MouseController 和 KeyboardController 都使用 `CONTROL_DEVICE`
- **原因**：统一权限管理，简化实现

### 10.4 状态管理
- **数据结构**：`std::set<int32_t>` + `lastPressedKey_`
- **原因**：需要跟踪"最后按下的键"，支持重复按下验证

## 11. 风险和注意事项

### 11.1 服务端自动重复冲突
- **风险**：客户端主动重复会重置服务端的自动重复定时器
- **影响**：如果客户端频繁调用 pressKey，服务端的自动重复可能无法正常工作
- **建议**：在文档中说明两种使用方式的区别

### 11.2 权限检查方法
- **风险**：`CheckControlDevicePermission()` 方法可能不存在
- **解决**：实现前需要确认，如不存在需要添加

### 11.3 错误码粒度
- **当前**：所有状态错误都使用 4300001
- **建议**：如果需要更细粒度的错误信息，可以考虑细分错误码

### 11.4 析构函数清理
- **注意**：析构时需要复制 pressedKeys_ 集合，因为 ReleaseKey 会修改它
- **实现**：`std::set<int32_t> keysToRelease = pressedKeys_;`

## 12. 后续优化方向

1. **错误码细分**：区分不同的状态错误
2. **性能优化**：减少不必要的事件注入
3. **日志完善**：添加更详细的调试日志
4. **文档完善**：添加使用指南和最佳实践

## 13. 确认事项

以下事项已确认：

✅ 1. "重复按下"的理解：支持录制回放场景，允许重复最后按下的键
✅ 2. 权限使用 `CONTROL_DEVICE`（MouseController 也已改为此权限）
✅ 3. 错误码使用 4300001（统一状态错误）
✅ 4. 重复按下时每次都注入 KEY_DOWN 事件
✅ 5. 不需要设备类型检查（PC only 通过权限控制）
✅ 6. 服务端已有自动重复机制，客户端可选择使用

## 14. 实施准备

**前置条件**：
1. 确认 `PermissionHelper::CheckControlDevicePermission()` 方法是否存在
2. 确认 MouseController 已改为使用 `CONTROL_DEVICE` 权限

**可以开始实现**：设计方案已确认，可以开始编码实现。
