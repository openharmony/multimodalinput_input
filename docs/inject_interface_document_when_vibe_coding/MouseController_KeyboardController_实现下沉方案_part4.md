# MouseController/KeyboardController 实现下沉方案（第4部分）

## 阶段 3：ANI 层实现（2天）

### 3.1 ANI 层架构说明

ANI (Application Native Interface) 层是 OpenHarmony 的 C++ 原生接口层，位于 `frameworks/ets/` 目录。

**设计原则**：
- 直接调用 Impl 层，无需异步处理（ANI 是同步接口）
- 错误码映射到 ANI 标准错误码
- 参数验证和权限检查
- 线程安全（Impl 层已保证）

### 3.2 MouseController ANI 实现

**文件：** `frameworks/ets/mouse_controller/include/ani_mouse_controller.h`

```cpp
#ifndef ANI_MOUSE_CONTROLLER_H
#define ANI_MOUSE_CONTROLLER_H

#include <memory>
#include "mouse_controller_impl.h"
#include "ani_common.h"

namespace OHOS {
namespace MMI {

/**
 * @brief ANI wrapper for MouseController
 * @note Synchronous interface, directly calls Impl layer
 */
class AniMouseController {
public:
    /**
     * @brief Create mouse controller
     * @return Shared pointer to AniMouseController, nullptr on failure
     */
    static std::shared_ptr<AniMouseController> Create();

    ~AniMouseController() = default;

    /**
     * @brief Move mouse cursor to specified position
     * @param displayId Display ID
     * @param x X coordinate
     * @param y Y coordinate
     * @return ANI_OK on success, error code otherwise
     */
    int32_t MoveTo(int32_t displayId, int32_t x, int32_t y);

    /**
     * @brief Press mouse button
     * @param button Button ID
     * @return ANI_OK on success, error code otherwise
     */
    int32_t PressButton(int32_t button);

    /**
     * @brief Release mouse button
     * @param button Button ID
     * @return ANI_OK on success, error code otherwise
     */
    int32_t ReleaseButton(int32_t button);

    /**
     * @brief Begin axis event
     * @param axis Axis type
     * @param value Axis value
     * @return ANI_OK on success, error code otherwise
     */
    int32_t BeginAxis(int32_t axis, int32_t value);

    /**
     * @brief Update axis event
     * @param axis Axis type
     * @param value Axis value
     * @return ANI_OK on success, error code otherwise
     */
    int32_t UpdateAxis(int32_t axis, int32_t value);

    /**
     * @brief End axis event
     * @param axis Axis type
     * @return ANI_OK on success, error code otherwise
     */
    int32_t EndAxis(int32_t axis);

private:
    AniMouseController() = default;

    /**
     * @brief Map MMI error code to ANI error code
     * @param mmiErrCode MMI error code
     * @return ANI error code
     */
    static int32_t MapErrorCode(int32_t mmiErrCode);

    std::shared_ptr<MouseControllerImpl> impl_;
};

} // namespace MMI
} // namespace OHOS

#endif // ANI_MOUSE_CONTROLLER_H
```

**实现文件：** `frameworks/ets/mouse_controller/src/ani_mouse_controller.cpp`

```cpp
#include "ani_mouse_controller.h"
#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AniMouseController"

namespace OHOS {
namespace MMI {

std::shared_ptr<AniMouseController> AniMouseController::Create()
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

    // 3. 创建 Impl 实例
    auto impl = InputManager::GetInstance()->CreateMouseController();
    if (impl == nullptr) {
        MMI_HILOGE("Failed to create MouseControllerImpl");
        return nullptr;
    }

    // 4. 创建 ANI 包装对象
    auto controller = std::shared_ptr<AniMouseController>(new AniMouseController());
    controller->impl_ = impl;

    return controller;
}

int32_t AniMouseController::MoveTo(int32_t displayId, int32_t x, int32_t y)
{
    CALL_DEBUG_ENTER;

    if (impl_ == nullptr) {
        MMI_HILOGE("Impl is nullptr");
        return ANI_SERVICE_EXCEPTION;
    }

    int32_t ret = impl_->MoveTo(displayId, x, y);
    return MapErrorCode(ret);
}

int32_t AniMouseController::PressButton(int32_t button)
{
    CALL_DEBUG_ENTER;

    if (impl_ == nullptr) {
        MMI_HILOGE("Impl is nullptr");
        return ANI_SERVICE_EXCEPTION;
    }

    int32_t ret = impl_->PressButton(button);
    return MapErrorCode(ret);
}

int32_t AniMouseController::ReleaseButton(int32_t button)
{
    CALL_DEBUG_ENTER;

    if (impl_ == nullptr) {
        MMI_HILOGE("Impl is nullptr");
        return ANI_SERVICE_EXCEPTION;
    }

    int32_t ret = impl_->ReleaseButton(button);
    return MapErrorCode(ret);
}

int32_t AniMouseController::BeginAxis(int32_t axis, int32_t value)
{
    CALL_DEBUG_ENTER;

    if (impl_ == nullptr) {
        MMI_HILOGE("Impl is nullptr");
        return ANI_SERVICE_EXCEPTION;
    }

    int32_t ret = impl_->BeginAxis(axis, value);
    return MapErrorCode(ret);
}

int32_t AniMouseController::UpdateAxis(int32_t axis, int32_t value)
{
    CALL_DEBUG_ENTER;

    if (impl_ == nullptr) {
        MMI_HILOGE("Impl is nullptr");
        return ANI_SERVICE_EXCEPTION;
    }

    int32_t ret = impl_->UpdateAxis(axis, value);
    return MapErrorCode(ret);
}

int32_t AniMouseController::EndAxis(int32_t axis)
{
    CALL_DEBUG_ENTER;

    if (impl_ == nullptr) {
        MMI_HILOGE("Impl is nullptr");
        return ANI_SERVICE_EXCEPTION;
    }

    int32_t ret = impl_->EndAxis(axis);
    return MapErrorCode(ret);
}

int32_t AniMouseController::MapErrorCode(int32_t mmiErrCode)
{
    switch (mmiErrCode) {
        case RET_OK:
            return ANI_OK;
        case ERROR_INVALID_PARAMETER:
            return ANI_PARAMETER_ERROR;
        case ERROR_DISPLAY_NOT_EXIST:
            return ANI_DISPLAY_NOT_EXIST;
        case ERROR_PERMISSION_DENIED:
            return ANI_PERMISSION_DENIED;
        default:
            return ANI_SERVICE_EXCEPTION;
    }
}

} // namespace MMI
} // namespace OHOS
```

### 3.3 KeyboardController ANI 实现

**文件：** `frameworks/ets/keyboard_controller/include/ani_keyboard_controller.h`

```cpp
#ifndef ANI_KEYBOARD_CONTROLLER_H
#define ANI_KEYBOARD_CONTROLLER_H

#include <memory>
#include "keyboard_controller_impl.h"
#include "ani_common.h"

namespace OHOS {
namespace MMI {

class AniKeyboardController {
public:
    static std::shared_ptr<AniKeyboardController> Create();
    ~AniKeyboardController() = default;

    int32_t PressKey(int32_t keyCode);
    int32_t ReleaseKey(int32_t keyCode);

private:
    AniKeyboardController() = default;
    static int32_t MapErrorCode(int32_t mmiErrCode);

    std::shared_ptr<KeyboardControllerImpl> impl_;
};

} // namespace MMI
} // namespace OHOS

#endif // ANI_KEYBOARD_CONTROLLER_H
```

**实现文件：** `frameworks/ets/keyboard_controller/src/ani_keyboard_controller.cpp`

```cpp
#include "ani_keyboard_controller.h"
#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AniKeyboardController"

namespace OHOS {
namespace MMI {

std::shared_ptr<AniKeyboardController> AniKeyboardController::Create()
{
    CALL_DEBUG_ENTER;

    // 权限和能力检查
    if (!CheckInputEventClentPermission()) {
        MMI_HILOGE("Permission check failed");
        return nullptr;
    }

    if (!IsPC()) {
        MMI_HILOGE("Capability not supported");
        return nullptr;
    }

    // 创建 Impl 实例
    auto impl = InputManager::GetInstance()->CreateKeyboardController();
    if (impl == nullptr) {
        MMI_HILOGE("Failed to create KeyboardControllerImpl");
        return nullptr;
    }

    auto controller = std::shared_ptr<AniKeyboardController>(new AniKeyboardController());
    controller->impl_ = impl;

    return controller;
}

int32_t AniKeyboardController::PressKey(int32_t keyCode)
{
    CALL_DEBUG_ENTER;

    if (impl_ == nullptr) {
        MMI_HILOGE("Impl is nullptr");
        return ANI_SERVICE_EXCEPTION;
    }

    int32_t ret = impl_->PressKey(keyCode);
    return MapErrorCode(ret);
}

int32_t AniKeyboardController::ReleaseKey(int32_t keyCode)
{
    CALL_DEBUG_ENTER;

    if (impl_ == nullptr) {
        MMI_HILOGE("Impl is nullptr");
        return ANI_SERVICE_EXCEPTION;
    }

    int32_t ret = impl_->ReleaseKey(keyCode);
    return MapErrorCode(ret);
}

int32_t AniKeyboardController::MapErrorCode(int32_t mmiErrCode)
{
    switch (mmiErrCode) {
        case RET_OK:
            return ANI_OK;
        case ERROR_INVALID_PARAMETER:
            return ANI_PARAMETER_ERROR;
        case ERROR_PERMISSION_DENIED:
            return ANI_PERMISSION_DENIED;
        default:
            return ANI_SERVICE_EXCEPTION;
    }
}

} // namespace MMI
} // namespace OHOS
```

---

## 阶段 4：编译配置更新（0.5天）

### 4.1 Impl 层 BUILD.gn

**文件：** `frameworks/proxy/event_handler/BUILD.gn`

```gn
import("//build/ohos.gni")
import("//foundation/multimodalinput/input/multimodalinput_mini.gni")

config("event_handler_public_config") {
  include_dirs = [
    "include",
    "//foundation/multimodalinput/input/interfaces/native/innerkits/common/include",
    "//foundation/multimodalinput/input/interfaces/native/innerkits/event/include",
    "//foundation/multimodalinput/input/interfaces/native/innerkits/proxy/include",
  ]
}

ohos_shared_library("libmmi-event-handler") {
  sources = [
    "src/input_manager_impl.cpp",
    "src/mouse_controller_impl.cpp",
    "src/keyboard_controller_impl.cpp",
  ]

  public_configs = [ ":event_handler_public_config" ]

  deps = [
    "//foundation/multimodalinput/input/frameworks/proxy/events:libmmi-common",
    "//foundation/multimodalinput/input/service/connect_manager:mmi_connect_manager_proxy",
  ]

  external_deps = [
    "c_utils:utils",
    "hilog:libhilog",
  ]

  part_name = "input"
  subsystem_name = "multimodalinput"
}
```

### 4.2 NAPI 层 BUILD.gn

**文件：** `frameworks/napi/input_event_client/BUILD.gn`

```gn
import("//build/ohos.gni")
import("//foundation/arkui/napi/napi.gni")

ohos_shared_library("inputeventclient") {
  sources = [
    "src/js_input_event_client.cpp",
    "src/js_mouse_controller.cpp",
    "src/js_keyboard_controller.cpp",
    "src/js_register_module.cpp",
  ]

  include_dirs = [
    "include",
    "//foundation/multimodalinput/input/frameworks/proxy/event_handler/include",
    "//foundation/multimodalinput/input/interfaces/native/innerkits/proxy/include",
    "//foundation/multimodalinput/input/interfaces/native/innerkits/event/include",
    "//foundation/multimodalinput/input/util/common/include",
    "//third_party/node/src",
  ]

  deps = [
    "//foundation/arkui/napi:ace_napi",
    "//foundation/multimodalinput/input/frameworks/proxy/event_handler:libmmi-event-handler",
    "//foundation/multimodalinput/input/frameworks/proxy/events:libmmi-common",
  ]

  external_deps = [
    "c_utils:utils",
    "hilog:libhilog",
    "ipc:ipc_single",
  ]

  relative_install_dir = "module/multimodalinput"
  part_name = "input"
  subsystem_name = "multimodalinput"
}
```

### 4.3 ANI 层 BUILD.gn

**文件：** `frameworks/ets/BUILD.gn`

```gn
import("//build/ohos.gni")

ohos_shared_library("libani_input") {
  sources = [
    "mouse_controller/src/ani_mouse_controller.cpp",
    "keyboard_controller/src/ani_keyboard_controller.cpp",
  ]

  include_dirs = [
    "mouse_controller/include",
    "keyboard_controller/include",
    "common/include",
    "//foundation/multimodalinput/input/frameworks/proxy/event_handler/include",
    "//foundation/multimodalinput/input/interfaces/native/innerkits/proxy/include",
  ]

  deps = [
    "//foundation/multimodalinput/input/frameworks/proxy/event_handler:libmmi-event-handler",
  ]

  external_deps = [
    "c_utils:utils",
    "hilog:libhilog",
  ]

  part_name = "input"
  subsystem_name = "multimodalinput"
}
```

---

## 阶段 5：测试策略（2天）

### 5.1 单元测试

#### Impl 层测试

**文件：** `frameworks/proxy/event_handler/test/mouse_controller_impl_test.cpp`

```cpp
#include <gtest/gtest.h>
#include "mouse_controller_impl.h"

namespace OHOS {
namespace MMI {
namespace {

class MouseControllerImplTest : public testing::Test {
protected:
    void SetUp() override
    {
        controller_ = std::make_shared<MouseControllerImpl>();
    }

    void TearDown() override
    {
        controller_ = nullptr;
    }

    std::shared_ptr<MouseControllerImpl> controller_;
};

/**
 * @tc.name: MoveTo_Success
 * @tc.desc: Test MoveTo with valid parameters
 * @tc.type: FUNC
 */
HWTEST_F(MouseControllerImplTest, MoveTo_Success, TestSize.Level1)
{
    int32_t ret = controller_->MoveTo(0, 100, 100);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: PressButton_Success
 * @tc.desc: Test PressButton with valid button
 * @tc.type: FUNC
 */
HWTEST_F(MouseControllerImplTest, PressButton_Success, TestSize.Level1)
{
    int32_t ret = controller_->PressButton(MOUSE_BUTTON_LEFT);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: PressButton_AlreadyPressed
 * @tc.desc: Test PressButton when button already pressed
 * @tc.type: FUNC
 */
HWTEST_F(MouseControllerImplTest, PressButton_AlreadyPressed, TestSize.Level1)
{
    controller_->PressButton(MOUSE_BUTTON_LEFT);
    int32_t ret = controller_->PressButton(MOUSE_BUTTON_LEFT);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: ReleaseButton_Success
 * @tc.desc: Test ReleaseButton after press
 * @tc.type: FUNC
 */
HWTEST_F(MouseControllerImplTest, ReleaseButton_Success, TestSize.Level1)
{
    controller_->PressButton(MOUSE_BUTTON_LEFT);
    int32_t ret = controller_->ReleaseButton(MOUSE_BUTTON_LEFT);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ReleaseButton_NotPressed
 * @tc.desc: Test ReleaseButton when button not pressed
 * @tc.type: FUNC
 */
HWTEST_F(MouseControllerImplTest, ReleaseButton_NotPressed, TestSize.Level1)
{
    int32_t ret = controller_->ReleaseButton(MOUSE_BUTTON_LEFT);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: BeginAxis_Success
 * @tc.desc: Test BeginAxis with valid parameters
 * @tc.type: FUNC
 */
HWTEST_F(MouseControllerImplTest, BeginAxis_Success, TestSize.Level1)
{
    int32_t ret = controller_->BeginAxis(AXIS_TYPE_SCROLL_VERTICAL, 10);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: BeginAxis_AlreadyInProgress
 * @tc.desc: Test BeginAxis when axis already in progress
 * @tc.type: FUNC
 */
HWTEST_F(MouseControllerImplTest, BeginAxis_AlreadyInProgress, TestSize.Level1)
{
    controller_->BeginAxis(AXIS_TYPE_SCROLL_VERTICAL, 10);
    int32_t ret = controller_->BeginAxis(AXIS_TYPE_SCROLL_VERTICAL, 20);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: UpdateAxis_Success
 * @tc.desc: Test UpdateAxis after begin
 * @tc.type: FUNC
 */
HWTEST_F(MouseControllerImplTest, UpdateAxis_Success, TestSize.Level1)
{
    controller_->BeginAxis(AXIS_TYPE_SCROLL_VERTICAL, 10);
    int32_t ret = controller_->UpdateAxis(AXIS_TYPE_SCROLL_VERTICAL, 20);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: EndAxis_Success
 * @tc.desc: Test EndAxis after begin
 * @tc.type: FUNC
 */
HWTEST_F(MouseControllerImplTest, EndAxis_Success, TestSize.Level1)
{
    controller_->BeginAxis(AXIS_TYPE_SCROLL_VERTICAL, 10);
    int32_t ret = controller_->EndAxis(AXIS_TYPE_SCROLL_VERTICAL);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MultipleInstances_IndependentState
 * @tc.desc: Test multiple instances have independent state
 * @tc.type: FUNC
 */
HWTEST_F(MouseControllerImplTest, MultipleInstances_IndependentState, TestSize.Level1)
{
    auto controller1 = std::make_shared<MouseControllerImpl>();
    auto controller2 = std::make_shared<MouseControllerImpl>();

    controller1->PressButton(MOUSE_BUTTON_LEFT);

    // controller2 should not be affected
    int32_t ret = controller2->ReleaseButton(MOUSE_BUTTON_LEFT);
    EXPECT_NE(ret, RET_OK);
}

} // namespace
} // namespace MMI
} // namespace OHOS
```

#### KeyboardController 测试（类似）

**文件：** `frameworks/proxy/event_handler/test/keyboard_controller_impl_test.cpp`

### 5.2 集成测试

#### NAPI 层集成测试

**文件：** `frameworks/napi/input_event_client/test/mouse_controller_integration_test.ets`

```typescript
import { describe, it, expect } from '@ohos/hypium';
import inputEventClient from '@ohos.multimodalInput.inputEventClient';

export default function mouseControllerIntegrationTest() {
  describe('MouseController Integration', () => {
    it('should complete full mouse operation', async () => {
      const controller = await inputEventClient.createMouseController();

      await controller.moveTo(0, 100, 100);
      await controller.pressButton(inputEventClient.Button.LEFT);
      await controller.moveTo(0, 200, 200);
      await controller.releaseButton(inputEventClient.Button.LEFT);
    });

    it('should handle scroll wheel', async () => {
      const controller = await inputEventClient.createMouseController();

      await controller.beginAxis(inputEventClient.Axis.SCROLL_VERTICAL, 10);
      await controller.updateAxis(inputEventClient.Axis.SCROLL_VERTICAL, 20);
      await controller.endAxis(inputEventClient.Axis.SCROLL_VERTICAL);
    });

    it('should reject when button already pressed', async () => {
      const controller = await inputEventClient.createMouseController();

      await controller.pressButton(inputEventClient.Button.LEFT);

      try {
        await controller.pressButton(inputEventClient.Button.LEFT);
        expect(false).assertTrue(); // Should not reach here
      } catch (error) {
        expect(error.code).assertEqual('4300001');
      }
    });

    it('should check permission on every call', async () => {
      // 需要在无权限环境下测试
      // 模拟场景：移除权限后调用接口
    });
  });
}
```

### 5.3 性能测试

**文件：** `test/performance/mouse_controller_perf_test.cpp`

```cpp
#include <gtest/gtest.h>
#include <chrono>
#include "mouse_controller_impl.h"

namespace OHOS {
namespace MMI {
namespace {

class MouseControllerPerfTest : public testing::Test {
protected:
    void SetUp() override
    {
        controller_ = std::make_shared<MouseControllerImpl>();
    }

    std::shared_ptr<MouseControllerImpl> controller_;
};

/**
 * @tc.name: MoveTo_Performance
 * @tc.desc: Test MoveTo performance with 1000 operations
 * @tc.type: PERF
 */
HWTEST_F(MouseControllerPerfTest, MoveTo_Performance, TestSize.Level1)
{
    constexpr int32_t ITERATIONS = 1000;

    auto start = std::chrono::high_resolution_clock::now();

    for (int32_t i = 0; i < ITERATIONS; ++i) {
        controller_->MoveTo(0, i % 1920, i % 1080);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    MMI_HILOGI("MoveTo %{public}d times took %{public}lld ms",
               ITERATIONS, duration.count());

    // 平均每次操作应该小于 10ms
    EXPECT_LT(duration.count(), ITERATIONS * 10);
}

} // namespace
} // namespace MMI
} // namespace OHOS
```

---

## 总结

### 关键文件清单

#### 新增文件

**Impl 层**：
1. `frameworks/proxy/event_handler/include/mouse_controller_impl.h`
2. `frameworks/proxy/event_handler/src/mouse_controller_impl.cpp`
3. `frameworks/proxy/event_handler/include/keyboard_controller_impl.h`
4. `frameworks/proxy/event_handler/src/keyboard_controller_impl.cpp`

**NAPI 层**：
5. `frameworks/napi/input_event_client/include/js_mouse_controller.h`
6. `frameworks/napi/input_event_client/src/js_mouse_controller.cpp`
7. `frameworks/napi/input_event_client/include/js_keyboard_controller.h`
8. `frameworks/napi/input_event_client/src/js_keyboard_controller.cpp`

**ANI 层**：
9. `frameworks/ets/mouse_controller/include/ani_mouse_controller.h`
10. `frameworks/ets/mouse_controller/src/ani_mouse_controller.cpp`
11. `frameworks/ets/keyboard_controller/include/ani_keyboard_controller.h`
12. `frameworks/ets/keyboard_controller/src/ani_keyboard_controller.cpp`

**测试文件**：
13. `frameworks/proxy/event_handler/test/mouse_controller_impl_test.cpp`
14. `frameworks/proxy/event_handler/test/keyboard_controller_impl_test.cpp`
15. `frameworks/napi/input_event_client/test/mouse_controller_integration_test.ets`
16. `test/performance/mouse_controller_perf_test.cpp`

#### 修改文件

1. `frameworks/proxy/event_handler/include/input_manager_impl.h` - 添加 Create 方法
2. `frameworks/proxy/event_handler/src/input_manager_impl.cpp` - 实现 Create 方法
3. `interfaces/native/innerkits/proxy/include/input_manager.h` - 添加公开接口
4. `frameworks/proxy/events/src/input_manager.cpp` - 转发到 Impl
5. `frameworks/napi/input_event_client/src/js_register_module.cpp` - 注册 NAPI 模块
6. `frameworks/proxy/event_handler/BUILD.gn` - 添加 Impl 层编译
7. `frameworks/napi/input_event_client/BUILD.gn` - 添加 NAPI 层编译
8. `frameworks/ets/BUILD.gn` - 添加 ANI 层编译

### 实施时间估算

- **阶段 1**：Impl 层实现 - 2 天
- **阶段 2**：NAPI 层重构 - 3 天
- **阶段 3**：ANI 层实现 - 2 天
- **阶段 4**：编译配置 - 0.5 天
- **阶段 5**：测试实现 - 2 天
- **总计**：9.5 天

### 验收标准

1. ✅ 所有单元测试通过（覆盖率 > 80%）
2. ✅ 所有集成测试通过
3. ✅ 性能测试达标（1000 次操作 < 10 秒）
4. ✅ 代码审查通过
5. ✅ NAPI、ANI 层功能一致
6. ✅ 多实例状态隔离正确
7. ✅ 权限检查正确
8. ✅ 错误码映射正确
9. ✅ 内存无泄漏
10. ✅ 线程安全

### 风险和注意事项

1. **libuv 事件循环**：
   - 必须使用 `uv_queue_work_with_qos_internal`
   - 不能使用 `std::thread`
   - 注意 RefBase 生命周期管理

2. **状态管理**：
   - 每个实例独立状态
   - 线程安全（Impl 层使用 mutex）
   - 析构时自动清理

3. **错误码映射**：
   - MMI 错误码 → ANI 错误码
   - 保持一致性

4. **权限检查**：
   - 每次调用都检查
   - 不仅在创建时检查

5. **编译依赖**：
   - Impl 层依赖 InputManager
   - NAPI 层依赖 Impl 层
   - ANI 层依赖 Impl 层
