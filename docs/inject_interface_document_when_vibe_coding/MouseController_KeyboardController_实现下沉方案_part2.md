# MouseController/KeyboardController 实现下沉方案（第2部分）

## 四、详细实施步骤

### 阶段 1：创建 Impl 层实现（2天）

#### 1.1 创建 MouseControllerImpl

**文件：** `frameworks/proxy/event_handler/include/mouse_controller_impl.h`

```cpp
#ifndef MOUSE_CONTROLLER_IMPL_H
#define MOUSE_CONTROLLER_IMPL_H

#include <map>
#include <memory>
#include <mutex>
#include "pointer_event.h"

namespace OHOS {
namespace MMI {

/**
 * @brief Mouse controller implementation (core logic)
 * @note Thread-safe, can be used by multiple API layers
 */
class MouseControllerImpl {
public:
    MouseControllerImpl();
    ~MouseControllerImpl();

    // 操作方法（返回错误码）
    int32_t MoveTo(int32_t displayId, int32_t x, int32_t y);
    int32_t PressButton(int32_t button);
    int32_t ReleaseButton(int32_t button);
    int32_t BeginAxis(int32_t axis, int32_t value);
    int32_t UpdateAxis(int32_t axis, int32_t value);
    int32_t EndAxis(int32_t axis);

private:
    // 辅助方法
    PointerEvent::PointerItem CreatePointerItem();
    std::shared_ptr<PointerEvent> CreatePointerEvent(int32_t action);
    int32_t InjectPointerEvent(std::shared_ptr<PointerEvent> event);
    bool ValidateCoordinates(int32_t& x, int32_t& y, int32_t displayId);

    // 状态管理
    std::map<int32_t, bool> buttonStates_;
    std::map<int32_t, int64_t> buttonDownTimes_;
    struct {
        bool inProgress = false;
        int32_t axisType = -1;
        int32_t lastValue = 0;
    } axisState_;
    struct {
        int32_t displayId = 0;
        int32_t x = 0;
        int32_t y = 0;
    } cursorPos_;

    mutable std::mutex mutex_;
};

} // namespace MMI
} // namespace OHOS

#endif // MOUSE_CONTROLLER_IMPL_H
```

**实现文件：** `frameworks/proxy/event_handler/src/mouse_controller_impl.cpp`

**实现说明：**
- 将 `js_mouse_controller.cpp` 中的核心逻辑完整复制过来
- 去掉所有 NAPI 相关代码（napi_env, napi_value, Promise 等）
- 保持线程安全（已有 mutex）
- 保持状态管理逻辑不变
- 保持事件构造和注入逻辑不变

#### 1.2 创建 KeyboardControllerImpl

**文件：** `frameworks/proxy/event_handler/include/keyboard_controller_impl.h`

```cpp
#ifndef KEYBOARD_CONTROLLER_IMPL_H
#define KEYBOARD_CONTROLLER_IMPL_H

#include <map>
#include <memory>
#include <mutex>
#include <vector>
#include "key_event.h"

namespace OHOS {
namespace MMI {

/**
 * @brief Keyboard controller implementation (core logic)
 * @note Thread-safe, can be used by multiple API layers
 */
class KeyboardControllerImpl {
public:
    KeyboardControllerImpl();
    ~KeyboardControllerImpl();

    // 操作方法（返回错误码）
    int32_t PressKey(int32_t keyCode);
    int32_t ReleaseKey(int32_t keyCode);

private:
    // 辅助方法
    std::shared_ptr<KeyEvent> CreateKeyEvent(int32_t action, int32_t keyCode);
    int32_t InjectKeyEvent(std::shared_ptr<KeyEvent> event);

    // 状态管理
    std::vector<int32_t> pressedKeys_;
    std::map<int32_t, int64_t> keyDownTimes_;

    mutable std::mutex mutex_;

    static constexpr size_t MAX_PRESSED_KEYS = 10;
};

} // namespace MMI
} // namespace OHOS

#endif // KEYBOARD_CONTROLLER_IMPL_H
```

**实现文件：** `frameworks/proxy/event_handler/src/keyboard_controller_impl.cpp`

**实现说明：**
- 将 `js_keyboard_controller.cpp` 中的核心逻辑完整复制过来
- 去掉所有 NAPI 相关代码

#### 1.3 在 InputManager 中添加创建接口

**修改文件 1：** `frameworks/proxy/event_handler/include/input_manager_impl.h`

```cpp
class InputManagerImpl {
public:
    // ... 现有方法 ...

    /**
     * @brief Create mouse controller
     * @return Shared pointer to MouseControllerImpl, nullptr on failure
     */
    std::shared_ptr<MouseControllerImpl> CreateMouseController();

    /**
     * @brief Create keyboard controller
     * @return Shared pointer to KeyboardControllerImpl, nullptr on failure
     */
    std::shared_ptr<KeyboardControllerImpl> CreateKeyboardController();
};
```

**修改文件 2：** `frameworks/proxy/event_handler/src/input_manager_impl.cpp`

```cpp
#include "mouse_controller_impl.h"
#include "keyboard_controller_impl.h"

std::shared_ptr<MouseControllerImpl> InputManagerImpl::CreateMouseController()
{
    CALL_DEBUG_ENTER;

    // 1. 权限检查
    if (!CheckInputEventClentPermission()) {
        MMI_HILOGE("Permission check failed");
        return nullptr;
    }

    // 2. 能力检查（仅 PC 支持）
    if (!IsPC()) {
        MMI_HILOGE("Capability not supported");
        return nullptr;
    }

    // 3. 调用服务端创建接口（用于权限验证）
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->CreateMouseController();
    if (ret != RET_OK) {
        MMI_HILOGE("Server-side CreateMouseController failed, ret=%{public}d", ret);
        return nullptr;
    }

    // 4. 创建客户端实例
    return std::make_shared<MouseControllerImpl>();
}

std::shared_ptr<KeyboardControllerImpl> InputManagerImpl::CreateKeyboardController()
{
    CALL_DEBUG_ENTER;

    // 1. 权限检查
    if (!CheckInputEventClentPermission()) {
        MMI_HILOGE("Permission check failed");
        return nullptr;
    }

    // 2. 能力检查（仅 PC 支持）
    if (!IsPC()) {
        MMI_HILOGE("Capability not supported");
        return nullptr;
    }

    // 3. 调用服务端创建接口（用于权限验证）
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->CreateKeyboardController();
    if (ret != RET_OK) {
        MMI_HILOGE("Server-side CreateKeyboardController failed, ret=%{public}d", ret);
        return nullptr;
    }

    // 4. 创建客户端实例
    return std::make_shared<KeyboardControllerImpl>();
}
```

**修改文件 3：** `interfaces/native/innerkits/proxy/include/input_manager.h`

```cpp
// 前置声明
class MouseControllerImpl;
class KeyboardControllerImpl;

class InputManager {
public:
    // ... 现有方法 ...

    /**
     * @brief Create mouse controller
     * @return Shared pointer to MouseControllerImpl, nullptr on failure
     */
    std::shared_ptr<MouseControllerImpl> CreateMouseController();

    /**
     * @brief Create keyboard controller
     * @return Shared pointer to KeyboardControllerImpl, nullptr on failure
     */
    std::shared_ptr<KeyboardControllerImpl> CreateKeyboardController();
};
```

**修改文件 4：** `frameworks/proxy/events/src/input_manager.cpp`

```cpp
std::shared_ptr<MouseControllerImpl> InputManager::CreateMouseController()
{
    CALL_DEBUG_ENTER;
    CHKPP(impl_);
    return impl_->CreateMouseController();
}

std::shared_ptr<KeyboardControllerImpl> InputManager::CreateKeyboardController()
{
    CALL_DEBUG_ENTER;
    CHKPP(impl_);
    return impl_->CreateKeyboardController();
}
```
