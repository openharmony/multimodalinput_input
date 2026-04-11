# KeyboardController 改进建议

## 当前发现的问题

### 1. 未使用的变量（低优先级）
**位置**：`js_keyboard_controller.cpp:56`
```cpp
size_t oldSize = pressedKeys_.size();  // 定义了但没有使用
```
**建议**：删除此行

---

### 2. 按键按下时间记录缺失（中优先级）
**问题**：所有 KeyItem 使用相同的当前时间，但已按下的键应该使用它们各自的按下时间。

**当前代码**：
```cpp
int64_t time = GetSysClockTime();
// 所有 KeyItem 都使用相同的 time
item.SetDownTime(time);
```

**建议改进**：
```cpp
// 在头文件中添加
class JsKeyboardController {
private:
    std::vector<int32_t> pressedKeys_;
    std::map<int32_t, int64_t> keyDownTimes_;  // 记录每个键的按下时间
};

// 在 PressKey 中记录
if (isNewKey) {
    pressedKeys_.push_back(keyCode);
    keyDownTimes_[keyCode] = GetSysClockTime();
}

// 在 CreateKeyEvent 中使用
for (int32_t pressedKey : pressedKeys_) {
    KeyEvent::KeyItem pressedItem;
    pressedItem.SetKeyCode(pressedKey);
    pressedItem.SetPressed(true);
    pressedItem.SetDownTime(keyDownTimes_[pressedKey]);  // 使用实际按下时间
    pressedItem.SetDeviceId(-1);
    keyEvent->AddPressedKeyItems(pressedItem);
}

// 在 ReleaseKey 中清理
if (ret == RET_OK) {
    pressedKeys_.erase(it);
    keyDownTimes_.erase(keyCode);
}
```

---

### 3. 析构函数错误处理（中优先级）
**问题**：析构函数中调用 `ReleaseKey()` 可能失败，但没有处理。

**当前代码**：
```cpp
for (int32_t keyCode : keysToRelease) {
    MMI_HILOGW("Auto-releasing key %{public}d in destructor", keyCode);
    ReleaseKey(keyCode);  // 可能失败
}
```

**建议改进**：
```cpp
for (int32_t keyCode : keysToRelease) {
    MMI_HILOGW("Auto-releasing key %{public}d in destructor", keyCode);
    int32_t ret = ReleaseKey(keyCode);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to auto-release key %{public}d, ret=%{public}d", keyCode, ret);
        // Continue trying to release other keys
    }
}
```

或者直接注入事件，不依赖 ReleaseKey 的状态检查：
```cpp
for (int32_t keyCode : keysToRelease) {
    MMI_HILOGW("Auto-releasing key %{public}d in destructor", keyCode);
    auto keyEvent = CreateKeyEvent(KeyEvent::KEY_ACTION_UP, keyCode);
    if (keyEvent != nullptr) {
        InjectKeyEvent(keyEvent);
    }
}
pressedKeys_.clear();
keyDownTimes_.clear();
```

---

### 4. 参数验证缺失（低优先级）
**问题**：`keyCode` 没有进行有效性验证。

**建议**：
```cpp
int32_t JsKeyboardController::PressKey(int32_t keyCode)
{
    // Validate keyCode range
    if (keyCode < 0 || keyCode > MAX_KEYCODE) {
        MMI_HILOGE("Invalid keyCode: %{public}d", keyCode);
        return COMMON_PARAMETER_ERROR;
    }
    // ... rest of the code
}
```

**注意**：需要确认 `MAX_KEYCODE` 的定义，或者依赖服务端验证。

---

### 5. 线程安全问题（高优先级 - 如果支持多线程）
**问题**：`pressedKeys_` 和 `keyDownTimes_` 没有加锁保护。

**建议**：
```cpp
// 在头文件中添加
#include <mutex>

class JsKeyboardController {
private:
    std::vector<int32_t> pressedKeys_;
    std::map<int32_t, int64_t> keyDownTimes_;
    mutable std::mutex mutex_;  // 保护状态
};

// 在方法中使用
int32_t JsKeyboardController::PressKey(int32_t keyCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    // ... rest of the code
}
```

**注意**：需要确认是否支持多线程调用。如果设计上是单线程使用，可以不加锁。

---

### 6. 错误码命名不一致（低优先级）
**问题**：
- MouseController: `ERROR_CODE_STATE_ERROR`
- KeyboardController: `ERROR_CODE_KEY_STATE_ERROR`

**建议**：统一命名，或者使用更具体的名称：
```cpp
// 选项1：统一为 STATE_ERROR
constexpr int32_t ERROR_CODE_STATE_ERROR = 4300001;

// 选项2：使用更具体的名称
constexpr int32_t ERROR_CODE_KEY_STATE_ERROR = 4300001;
constexpr int32_t ERROR_CODE_BUTTON_STATE_ERROR = 4300001;
```

---

### 7. CreateKeyEvent 逻辑优化（低优先级）
**当前代码**：
```cpp
for (int32_t pressedKey : pressedKeys_) {
    if (pressedKey != keyCode) {
        // Add other pressed keys
        KeyEvent::KeyItem pressedItem;
        pressedItem.SetKeyCode(pressedKey);
        pressedItem.SetPressed(true);
        pressedItem.SetDownTime(time);
        pressedItem.SetDeviceId(-1);
        keyEvent->AddPressedKeyItems(pressedItem);
    } else if (action == KeyEvent::KEY_ACTION_DOWN) {
        // For KEY_DOWN, the current key is also pressed
        keyEvent->AddPressedKeyItems(item);
    }
    // For KEY_UP, don't add the current key to pressed keys
}
```

**建议优化**（更清晰）：
```cpp
// Add all pressed keys to the event
// For KEY_UP, exclude the key being released
for (int32_t pressedKey : pressedKeys_) {
    // Skip the key being released in KEY_UP event
    if (action == KeyEvent::KEY_ACTION_UP && pressedKey == keyCode) {
        continue;
    }

    KeyEvent::KeyItem pressedItem;
    pressedItem.SetKeyCode(pressedKey);
    pressedItem.SetPressed(true);
    pressedItem.SetDownTime(keyDownTimes_[pressedKey]);  // Use actual down time
    pressedItem.SetDeviceId(-1);
    keyEvent->AddPressedKeyItems(pressedItem);
}
```

---

### 8. MouseController 也需要记录按钮按下时间（中优先级）
**问题**：MouseController 的 PointerItem 也应该使用实际的按下时间。

**建议**：
```cpp
// 在 js_mouse_controller.h 中添加
std::map<int32_t, int64_t> buttonDownTimes_;

// 在 PressButton 中记录
buttonStates_[button] = true;
buttonDownTimes_[button] = GetSysClockTime();

// 在 MoveTo 中使用
for (const auto& [button, pressed] : buttonStates_) {
    if (pressed) {
        // 设置 item.SetDownTime(buttonDownTimes_[button]);
    }
}
```

---

## 优先级总结

### 高优先级
1. **线程安全问题**（如果支持多线程）
2. **按键按下时间记录**（影响事件正确性）

### 中优先级
3. **析构函数错误处理**（提高健壮性）
4. **MouseController 按钮按下时间**（保持一致性）

### 低优先级
5. **未使用的变量**（代码清理）
6. **参数验证**（可选，服务端可能已验证）
7. **错误码命名统一**（代码规范）
8. **CreateKeyEvent 逻辑优化**（可读性）

---

## 建议实施顺序

1. **立即修复**：
   - 删除未使用的变量
   - 添加按键/按钮按下时间记录

2. **短期改进**：
   - 改进析构函数错误处理
   - 优化 CreateKeyEvent 逻辑

3. **长期考虑**：
   - 评估是否需要线程安全
   - 统一错误码命名
   - 添加参数验证

---

## 测试建议

修改后需要测试的场景：
1. 快速连续按键（测试时间戳正确性）
2. 组合键（Ctrl+Shift+A）
3. 析构时有按键未释放
4. 多线程并发调用（如果支持）
5. 边界条件（最大按键数、无效 keyCode）
