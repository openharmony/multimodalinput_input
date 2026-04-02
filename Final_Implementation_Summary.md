# KeyboardController 和 MouseController 最终实施总结

## 完成的所有改进

### 1. ✅ KeyboardController 按键按下时间记录

#### 添加的成员变量
```cpp
std::map<int32_t, int64_t> keyDownTimes_;  // 记录每个键的按下时间
```

#### 修改的方法

**PressKey()**:
```cpp
// 记录按下时间
if (isNewKey) {
    pressedKeys_.push_back(keyCode);
    keyDownTimes_[keyCode] = GetSysClockTime();
}

// 回滚时清理
if (isNewKey) {
    pressedKeys_.pop_back();
    keyDownTimes_.erase(keyCode);
}
```

**ReleaseKey()**:
```cpp
// 清理按下时间
if (ret == RET_OK) {
    pressedKeys_.erase(it);
    keyDownTimes_.erase(keyCode);
}
```

**CreateKeyEvent()**:
```cpp
// 使用实际按下时间
item.SetDownTime(action == KeyEvent::KEY_ACTION_DOWN ? time : keyDownTimes_[keyCode]);

// 其他按下的键也使用实际时间
pressedItem.SetDownTime(keyDownTimes_[pressedKey]);
```

**析构函数**:
```cpp
// 直接注入事件，绕过状态检查
auto keyEvent = CreateKeyEvent(KeyEvent::KEY_ACTION_UP, keyCode);
if (keyEvent != nullptr) {
    int32_t ret = InjectKeyEvent(keyEvent);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to auto-release key %{public}d, ret=%{public}d", keyCode, ret);
    }
}

// 强制清理状态
auto it = std::find(pressedKeys_.begin(), pressedKeys_.end(), keyCode);
if (it != pressedKeys_.end()) {
    pressedKeys_.erase(it);
}
keyDownTimes_.erase(keyCode);

// 确保清理
pressedKeys_.clear();
keyDownTimes_.clear();
```

---

### 2. ✅ MouseController 按钮按下时间记录

#### 添加的成员变量
```cpp
std::map<int32_t, int64_t> buttonDownTimes_;  // 记录每个按钮的按下时间
```

#### 修改的方法

**PressButton()**:
```cpp
// 记录按下时间
buttonStates_[button] = true;
buttonDownTimes_[button] = GetSysClockTime();

// 使用实际按下时间
item.SetDownTime(buttonDownTimes_[button]);

// 回滚时清理
if (ret != RET_OK) {
    buttonStates_[button] = false;
    buttonDownTimes_.erase(button);
}
```

**ReleaseButton()**:
```cpp
// 使用实际按下时间
item.SetDownTime(buttonDownTimes_[button]);

// 清理按下时间
if (ret == RET_OK) {
    buttonStates_[button] = false;
    buttonDownTimes_.erase(button);
}
```

**MoveTo()**:
```cpp
// 如果有按钮按下，使用最早按下按钮的时间
if (!buttonDownTimes_.empty()) {
    item.SetDownTime(buttonDownTimes_.begin()->second);
} else {
    // 没有按钮按下，使用当前时间
    item.SetDownTime(time);
}
```

**析构函数**:
```cpp
// 直接注入事件，绕过状态检查
auto pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_BUTTON_UP);
if (pointerEvent != nullptr) {
    pointerEvent->SetTargetDisplayId(cursorPos_.displayId);
    int32_t nativeButton = ConvertJsButtonToNative(button);
    pointerEvent->SetButtonId(nativeButton);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(cursorPos_.x);
    item.SetDisplayY(cursorPos_.y);
    item.SetDisplayXPos(cursorPos_.x);
    item.SetDisplayYPos(cursorPos_.y);
    item.SetToolType(PointerEvent::TOOL_TYPE_MOUSE);
    item.SetDownTime(buttonDownTimes_[button]);
    item.SetDeviceId(-1);
    pointerEvent->AddPointerItem(item);

    int32_t ret = InjectPointerEvent(pointerEvent);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to auto-release button %{public}d, ret=%{public}d", button, ret);
    }
}

// 类似处理 axis 事件
// 确保清理
buttonStates_.clear();
buttonDownTimes_.clear();
```

---

### 3. ✅ 修复 KeyboardController 重复键问题

#### 问题描述
`AddKeyItem()` 添加当前键后，循环中又通过 `AddPressedKeyItems()` 添加同一个键，导致重复。

#### 修复方案
```cpp
for (int32_t pressedKey : pressedKeys_) {
    // Skip the current key (already added via AddKeyItem)
    if (pressedKey == keyCode) {
        if (action == KeyEvent::KEY_ACTION_DOWN) {
            MMI_HILOGD("Skip adding key %{public}d to pressedKeys (already in KeyItem for KEY_DOWN)", keyCode);
            continue;  // Already added via AddKeyItem
        } else {
            MMI_HILOGD("Skip adding key %{public}d to pressedKeys (being released in KEY_UP)", keyCode);
            continue;  // Don't add the key being released to pressed keys
        }
    }

    // Add other pressed keys
    KeyEvent::KeyItem pressedItem;
    pressedItem.SetKeyCode(pressedKey);
    pressedItem.SetPressed(true);
    pressedItem.SetDownTime(keyDownTimes_[pressedKey]);
    pressedItem.SetDeviceId(-1);
    keyEvent->AddPressedKeyItems(pressedItem);
    addedCount++;
}

MMI_HILOGD("CreateKeyEvent: action=%{public}d, keyCode=%{public}d, added %{public}d other pressed keys",
    action, keyCode, addedCount);
```

---

### 4. ✅ 线程安全保护

#### 添加的成员变量
```cpp
mutable std::mutex mutex_;  // 保护状态的互斥锁
```

#### KeyboardController 修改的方法

**PressKey()**:
```cpp
int32_t JsKeyboardController::PressKey(int32_t keyCode)
{
    bool isNewKey = false;
    std::shared_ptr<KeyEvent> keyEvent;

    // 锁范围：仅保护状态检查、修改和事件创建
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // 状态检查和修改
        // 创建事件（需要读取状态）
        keyEvent = CreateKeyEvent(KeyEvent::KEY_ACTION_DOWN, keyCode);
    }
    // 锁释放

    // InjectKeyEvent 在锁外执行（可能涉及 IPC）
    int32_t ret = InjectKeyEvent(keyEvent);
    if (ret != RET_OK) {
        // 失败时重新获取锁进行回滚
        std::lock_guard<std::mutex> lock(mutex_);
        if (isNewKey) {
            pressedKeys_.pop_back();
            keyDownTimes_.erase(keyCode);
        }
    }
    return ret;
}
```

**ReleaseKey()**:
```cpp
int32_t JsKeyboardController::ReleaseKey(int32_t keyCode)
{
    std::shared_ptr<KeyEvent> keyEvent;

    // 锁范围：仅保护状态检查和事件创建
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // 状态检查
        // 创建事件（需要读取状态）
        keyEvent = CreateKeyEvent(KeyEvent::KEY_ACTION_UP, keyCode);
    }
    // 锁释放

    // InjectKeyEvent 在锁外执行（可能涉及 IPC）
    int32_t ret = InjectKeyEvent(keyEvent);
    if (ret == RET_OK) {
        // 成功时重新获取锁进行状态清理
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = std::find(pressedKeys_.begin(), pressedKeys_.end(), keyCode);
        if (it != pressedKeys_.end()) {
            pressedKeys_.erase(it);
        }
        keyDownTimes_.erase(keyCode);
    }
    return ret;
}
```

#### MouseController 修改的方法

**MoveTo()**:
```cpp
int32_t JsMouseController::MoveTo(int32_t displayId, int32_t x, int32_t y)
{
    std::shared_ptr<PointerEvent> pointerEvent;

    // 锁范围：更新位置和创建事件
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cursorPos_.displayId = displayId;
        cursorPos_.x = x;
        cursorPos_.y = y;
        pointerEvent = CreatePointerEvent(...);
        // 设置所有属性
    }
    // 锁释放

    // InjectPointerEvent 在锁外执行
    return InjectPointerEvent(pointerEvent);
}
```

**PressButton()**:
```cpp
int32_t JsMouseController::PressButton(int32_t button)
{
    std::shared_ptr<PointerEvent> pointerEvent;

    // 锁范围：状态检查、修改和事件创建
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // 状态检查和修改
        pointerEvent = CreatePointerEvent(...);
    }
    // 锁释放

    // InjectPointerEvent 在锁外执行
    int32_t ret = InjectPointerEvent(pointerEvent);
    if (ret != RET_OK) {
        std::lock_guard<std::mutex> lock(mutex_);
        buttonStates_[button] = false;
        buttonDownTimes_.erase(button);
    }
    return ret;
}
```

**ReleaseButton()**:
```cpp
int32_t JsMouseController::ReleaseButton(int32_t button)
{
    std::shared_ptr<PointerEvent> pointerEvent;
    int64_t downTime;

    // 锁范围：状态检查和事件创建
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // 状态检查
        downTime = buttonDownTimes_[button];
        pointerEvent = CreatePointerEvent(...);
    }
    // 锁释放

    // InjectPointerEvent 在锁外执行
    int32_t ret = InjectPointerEvent(pointerEvent);
    if (ret == RET_OK) {
        std::lock_guard<std::mutex> lock(mutex_);
        buttonStates_[button] = false;
        buttonDownTimes_.erase(button);
    }
    return ret;
}
```

**BeginAxis() / UpdateAxis() / EndAxis()**:
```cpp
// 同样的模式：锁内检查状态和创建事件，锁外注入事件
```

**关键优化点**：
- ✅ 锁只保护状态的读写和事件创建
- ✅ InjectKeyEvent/InjectPointerEvent（同步 IPC 调用）在锁外执行
- ✅ 避免长时间持有锁，提高并发性能
- ✅ 失败回滚时重新获取锁
- ✅ KeyboardController 和 MouseController 都已优化

---

## 日志输出示例

### KeyboardController 日志

#### 单个按键
```
PressKey: keyCode=65 (A)
CreateKeyEvent: action=2 (KEY_DOWN), keyCode=65, added 0 other pressed keys

ReleaseKey: keyCode=65
CreateKeyEvent: action=3 (KEY_UP), keyCode=65, added 0 other pressed keys
```

#### 组合键 (Ctrl+C)
```
PressKey: keyCode=17 (Ctrl)
CreateKeyEvent: action=2 (KEY_DOWN), keyCode=17, added 0 other pressed keys

PressKey: keyCode=67 (C)
Skip adding key 67 to pressedKeys (already in KeyItem for KEY_DOWN)
CreateKeyEvent: action=2 (KEY_DOWN), keyCode=67, added 1 other pressed keys

ReleaseKey: keyCode=67
Skip adding key 67 to pressedKeys (being released in KEY_UP)
CreateKeyEvent: action=3 (KEY_UP), keyCode=67, added 1 other pressed keys

ReleaseKey: keyCode=17
Skip adding key 17 to pressedKeys (being released in KEY_UP)
CreateKeyEvent: action=3 (KEY_UP), keyCode=17, added 0 other pressed keys
```

#### 重复按键
```
PressKey: keyCode=65 (A)
CreateKeyEvent: action=2 (KEY_DOWN), keyCode=65, added 0 other pressed keys

PressKey: keyCode=65 (A)
Repeat press last key: 65
Skip adding key 65 to pressedKeys (already in KeyItem for KEY_DOWN)
CreateKeyEvent: action=2 (KEY_DOWN), keyCode=65, added 0 other pressed keys
```

### MouseController 日志

#### 拖拽操作
```
PressButton: button=0 (LEFT)
MoveTo: displayId=0, x=100, y=100
MoveTo: displayId=0, x=200, y=200
ReleaseButton: button=0
```

#### 析构清理
```
JsKeyboardController destroying, cleaning up state
Auto-releasing key 65 in destructor
CreateKeyEvent: action=3 (KEY_UP), keyCode=65, added 0 other pressed keys

JsMouseController destroying, cleaning up state
Auto-releasing button 0 in destructor
Auto-ending axis 0 in destructor
```

---

## 场景验证

### 场景1: KeyboardController 组合键时间
```cpp
PressKey(Ctrl)  // T1=1000, keyDownTimes_[Ctrl]=1000
PressKey(C)     // T2=1050, keyDownTimes_[C]=1050

CreateKeyEvent(KEY_DOWN, C):
- KeyItem: keyCode=C, downTime=1050 ✅
- PressedKeyItems: keyCode=Ctrl, downTime=1000 ✅

ReleaseKey(C)   // T3=1100
CreateKeyEvent(KEY_UP, C):
- KeyItem: keyCode=C, downTime=1050 ✅
- PressedKeyItems: keyCode=Ctrl, downTime=1000 ✅
```

### 场景2: MouseController 拖拽时间
```cpp
PressButton(LEFT)  // T1=2000, buttonDownTimes_[LEFT]=2000
// PointerItem: downTime=2000 ✅

MoveTo(100, 100)   // T2=2050
// PointerItem: downTime=2000 ✅ (使用按下时的时间)

MoveTo(200, 200)   // T3=2100
// PointerItem: downTime=2000 ✅ (保持一致)

ReleaseButton(LEFT) // T4=2150
// PointerItem: downTime=2000 ✅
```

### 场景3: MouseController 无按钮按下
```cpp
MoveTo(100, 100)   // T1=3000, 无按钮按下
// PointerItem: downTime=3000 ✅ (使用当前时间)

PressButton(LEFT)  // T2=3050, buttonDownTimes_[LEFT]=3050
// PointerItem: downTime=3050 ✅

MoveTo(200, 200)   // T3=3100
// PointerItem: downTime=3050 ✅ (使用按钮按下时间)
```

### 场景4: KeyboardController 无重复
```cpp
PressKey(Ctrl)  // pressedKeys_=[Ctrl]
PressKey(C)     // pressedKeys_=[Ctrl, C]

CreateKeyEvent(KEY_DOWN, C):
- AddKeyItem(C)           // keys_ 添加 C
- Loop: pressedKey=Ctrl   // AddPressedKeyItems(Ctrl)
- Loop: pressedKey=C      // Skip (continue) ✅ 无重复
- Result: keys_=[C], pressedKeys_=[Ctrl]
```

### 场景5: 析构函数健壮性
```cpp
{
    JsKeyboardController controller;
    controller.PressKey(Ctrl);
    controller.PressKey(C);
    // controller 离开作用域
}
// 析构函数:
// 1. 直接注入 KEY_UP(C) 事件 ✅
// 2. 直接注入 KEY_UP(Ctrl) 事件 ✅
// 3. 强制清理所有状态 ✅
// 4. 不依赖 ReleaseKey() 的状态检查 ✅
```

---

## 代码质量改进

### 1. 删除未使用的变量
```cpp
// 删除了
size_t oldSize = pressedKeys_.size();
```

### 2. 改进析构函数
- 直接注入事件，绕过状态检查
- 强制清理状态，确保完全释放
- 添加详细错误日志
- 继续尝试释放其他键/按钮

### 3. 完整的回滚逻辑
- 同时回滚 `pressedKeys_/buttonStates_` 和 `keyDownTimes_/buttonDownTimes_`
- 确保状态一致性

### 4. 详细的调试日志
- 记录跳过重复键的原因
- 记录添加的其他按键数量
- 便于调试和问题排查

### 5. 线程安全
- 添加 mutex 保护共享状态
- PressKey 和 ReleaseKey 都使用 lock_guard
- 防止多线程并发访问导致的状态不一致

---

## 对比总结

| 特性 | 修改前 | 修改后 |
|------|--------|--------|
| **KeyItem 时间** | 所有使用当前时间 | 使用实际按下时间 ✅ |
| **组合键时间** | 所有键时间相同 | 每个键独立时间 ✅ |
| **MoveTo 时间** | 未设置 downTime | 正确设置 downTime ✅ |
| **重复键问题** | 存在重复 | 已修复 ✅ |
| **状态管理** | 单一状态 | 双状态（pressed + downTime）✅ |
| **回滚逻辑** | 不完整 | 完整清理 ✅ |
| **析构函数** | 调用 ReleaseKey | 直接注入事件 ✅ |
| **线程安全** | 无保护 | mutex 保护 ✅ |
| **调试日志** | 基本日志 | 详细日志 ✅ |
| **代码质量** | 有未使用变量 | 已清理 ✅ |

---

## 测试建议

### 单元测试
1. ✅ 测试单个按键/按钮的时间记录
2. ✅ 测试组合键的独立时间
3. ✅ 测试重复按键不更新时间
4. ✅ 测试无重复键问题
5. ✅ 测试回滚逻辑清理时间
6. ✅ 测试析构函数直接注入事件
7. ✅ 测试 MoveTo 无按钮按下时的时间
8. ✅ 测试多线程并发访问

### 集成测试
1. ✅ 快速连续按键（验证时间差异）
2. ✅ 长按场景（验证时间保持）
3. ✅ 组合键场景（Ctrl+Shift+A）
4. ✅ 拖拽场景（按住按钮移动）
5. ✅ 异常场景（创建事件失败）
6. ✅ 析构清理场景（对象销毁时自动释放）

### 日志验证
1. ✅ 检查跳过重复键的日志
2. ✅ 检查添加其他按键的数量
3. ✅ 检查析构函数的清理日志
4. ✅ 检查事件注入失败的错误日志

---

## 编译和测试

### 编译
```bash
ninja -C out/rk3568 inputeventclient
```

### 运行测试
```bash
ninja -C out/rk3568 KeyboardControllerTest
ninja -C out/rk3568 MouseControllerTest
```

---

## 总结

✅ **KeyboardController 完成**：
- 按键按下时间记录
- 修复重复键问题
- 改进析构函数（直接注入事件）
- 添加线程安全保护
- 添加详细日志

✅ **MouseController 完成**：
- 按钮按下时间记录
- 改进析构函数（直接注入事件）
- MoveTo 使用正确时间
- 添加详细日志

✅ **代码质量**：
- 删除未使用变量
- 完整的回滚逻辑
- 详细的调试日志
- 两个 Controller 保持一致性
- 线程安全保护

✅ **准备就绪**：
- 可以编译测试
- 可以集成验证
- 日志完善便于调试
- 析构函数更健壮
