# MouseController/KeyboardController 实现下沉方案（第3部分）

## 阶段 2：NAPI 层重构（3天）

### 2.1 MouseController NAPI 层重构

#### 回调信息结构体

**文件：** `frameworks/napi/input_event_client/include/js_mouse_controller.h`

```cpp
#ifndef JS_MOUSE_CONTROLLER_H
#define JS_MOUSE_CONTROLLER_H

#include <memory>
#include <uv.h>
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "refbase.h"
#include "mouse_controller_impl.h"

namespace OHOS {
namespace MMI {

/**
 * @brief Callback info for mouse controller operations
 * @note Uses RefBase for lifecycle management
 */
class MouseControllerCallbackInfo : public RefBase {
public:
    MouseControllerCallbackInfo() = default;
    ~MouseControllerCallbackInfo() override = default;

    napi_env env = nullptr;
    napi_ref ref = nullptr;
    napi_deferred deferred = nullptr;
    std::shared_ptr<MouseControllerImpl> impl = nullptr;

    // 操作参数
    struct {
        int32_t displayId = 0;
        int32_t x = 0;
        int32_t y = 0;
    } moveToParams;

    struct {
        int32_t button = 0;
    } buttonParams;

    struct {
        int32_t axis = 0;
        int32_t value = 0;
    } axisParams;

    // 操作结果
    int32_t errCode = RET_OK;
};

/**
 * @brief NAPI wrapper for MouseController
 * @note Thin wrapper that delegates to MouseControllerImpl
 */
class JsMouseController {
public:
    JsMouseController() = default;
    ~JsMouseController() = default;

    // NAPI 方法（异步）
    static napi_value MoveTo(napi_env env, napi_callback_info info);
    static napi_value PressButton(napi_env env, napi_callback_info info);
    static napi_value ReleaseButton(napi_env env, napi_callback_info info);
    static napi_value BeginAxis(napi_env env, napi_callback_info info);
    static napi_value UpdateAxis(napi_env env, napi_callback_info info);
    static napi_value EndAxis(napi_env env, napi_callback_info info);

private:
    // libuv 工作线程回调
    static void CallMoveToTask(uv_work_t *work);
    static void CallPressButtonTask(uv_work_t *work);
    static void CallReleaseButtonTask(uv_work_t *work);
    static void CallBeginAxisTask(uv_work_t *work);
    static void CallUpdateAxisTask(uv_work_t *work);
    static void CallEndAxisTask(uv_work_t *work);

    // libuv 主线程回调（处理 Promise）
    static void CallMoveToPromise(uv_work_t *work, int32_t status);
    static void CallButtonPromise(uv_work_t *work, int32_t status);
    static void CallAxisPromise(uv_work_t *work, int32_t status);

    // 辅助方法
    static bool CheckPermission(napi_env env);
    static napi_value CreateBusinessError(napi_env env, int32_t errCode);
};

} // namespace MMI
} // namespace OHOS

#endif // JS_MOUSE_CONTROLLER_H
```

#### NAPI 实现文件

**文件：** `frameworks/napi/input_event_client/src/js_mouse_controller.cpp`

```cpp
#include "js_mouse_controller.h"
#include "mmi_log.h"
#include "error_multimodal.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsMouseController"

namespace OHOS {
namespace MMI {

// ==================== 权限检查 ====================

bool JsMouseController::CheckPermission(napi_env env)
{
    CALL_DEBUG_ENTER;
    if (!CheckInputEventClentPermission()) {
        MMI_HILOGE("Permission check failed");
        napi_throw_error(env, "201", "Permission verification failed");
        return false;
    }
    return true;
}

// ==================== 错误对象创建 ====================

napi_value JsMouseController::CreateBusinessError(napi_env env, int32_t errCode)
{
    napi_value error;
    napi_value code;
    napi_value message;

    std::string errMsg;
    switch (errCode) {
        case RET_ERR:
            errMsg = "Input service exception";
            break;
        case ERROR_INVALID_PARAMETER:
            errMsg = "Invalid parameter";
            break;
        case ERROR_DISPLAY_NOT_EXIST:
            errMsg = "The display does not exist";
            break;
        default:
            errMsg = "Unknown error";
            break;
    }

    napi_create_string_utf8(env, std::to_string(errCode).c_str(), NAPI_AUTO_LENGTH, &code);
    napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &message);

    napi_create_error(env, code, message, &error);
    return error;
}

// ==================== MoveTo 实现 ====================

napi_value JsMouseController::MoveTo(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;

    // 1. 权限检查
    if (!CheckPermission(env)) {
        return nullptr;
    }

    // 2. 获取参数
    size_t argc = 3;
    napi_value argv[3];
    napi_value thisVar;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    // 3. 参数验证
    if (argc != 3) {
        MMI_HILOGE("Invalid parameter count: %{public}zu", argc);
        napi_throw_error(env, "401", "Invalid parameter count");
        return nullptr;
    }

    // 4. 提取参数
    int32_t displayId, x, y;
    napi_get_value_int32(env, argv[0], &displayId);
    napi_get_value_int32(env, argv[1], &x);
    napi_get_value_int32(env, argv[2], &y);

    // 5. 获取 MouseControllerImpl 实例
    std::shared_ptr<MouseControllerImpl>* implPtr = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void**>(&implPtr));
    if (implPtr == nullptr || *implPtr == nullptr) {
        MMI_HILOGE("Failed to get MouseControllerImpl instance");
        napi_throw_error(env, "3800001", "Input service exception");
        return nullptr;
    }

    // 6. 创建 Promise
    napi_deferred deferred;
    napi_value promise;
    napi_create_promise(env, &deferred, &promise);

    // 7. 创建回调信息（使用 RefBase）
    sptr<MouseControllerCallbackInfo> cb = new (std::nothrow) MouseControllerCallbackInfo();
    if (cb == nullptr) {
        MMI_HILOGE("Failed to create callback info");
        napi_reject_deferred(env, deferred, CreateBusinessError(env, RET_ERR));
        return promise;
    }

    cb->env = env;
    cb->deferred = deferred;
    cb->impl = *implPtr;
    cb->moveToParams.displayId = displayId;
    cb->moveToParams.x = x;
    cb->moveToParams.y = y;
    cb->IncStrongRef(nullptr);  // 增加引用计数

    // 8. 获取 libuv 事件循环
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env, &loop);
    if (loop == nullptr) {
        MMI_HILOGE("Failed to get uv event loop");
        cb->DecStrongRef(nullptr);
        napi_reject_deferred(env, deferred, CreateBusinessError(env, RET_ERR));
        return promise;
    }

    // 9. 创建 uv_work_t
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        MMI_HILOGE("Failed to create uv_work_t");
        cb->DecStrongRef(nullptr);
        napi_reject_deferred(env, deferred, CreateBusinessError(env, RET_ERR));
        return promise;
    }
    work->data = cb.GetRefPtr();

    // 10. 提交到 libuv 工作队列
    int32_t ret = uv_queue_work_with_qos_internal(
        loop,
        work,
        [](uv_work_t *work) {
            // 工作线程：执行 MoveTo 操作
            CallMoveToTask(work);
        },
        [](uv_work_t *work, int32_t status) {
            // 主线程回调：处理 Promise
            CallMoveToPromise(work, status);
        },
        uv_qos_user_initiated,
        "moveTo"
    );

    if (ret != 0) {
        MMI_HILOGE("Failed to queue work: %{public}d", ret);
        cb->DecStrongRef(nullptr);
        delete work;
        napi_reject_deferred(env, deferred, CreateBusinessError(env, RET_ERR));
    }

    return promise;
}

// 工作线程回调：执行 MoveTo
void JsMouseController::CallMoveToTask(uv_work_t *work)
{
    CALL_DEBUG_ENTER;

    auto* cb = static_cast<MouseControllerCallbackInfo*>(work->data);
    if (cb == nullptr || cb->impl == nullptr) {
        MMI_HILOGE("Invalid callback info");
        return;
    }

    // 执行 Impl 层的 MoveTo 操作
    cb->errCode = cb->impl->MoveTo(
        cb->moveToParams.displayId,
        cb->moveToParams.x,
        cb->moveToParams.y
    );

    MMI_HILOGD("MoveTo result: %{public}d", cb->errCode);
}

// 主线程回调：处理 Promise
void JsMouseController::CallMoveToPromise(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;

    auto* cb = static_cast<MouseControllerCallbackInfo*>(work->data);
    if (cb == nullptr) {
        MMI_HILOGE("Invalid callback info");
        delete work;
        return;
    }

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);

    if (cb->errCode == RET_OK) {
        // 成功：resolve Promise
        napi_value result;
        napi_get_undefined(cb->env, &result);
        napi_resolve_deferred(cb->env, cb->deferred, result);
    } else {
        // 失败：reject Promise
        napi_value error = CreateBusinessError(cb->env, cb->errCode);
        napi_reject_deferred(cb->env, cb->deferred, error);
    }

    napi_close_handle_scope(cb->env, scope);

    // 清理资源
    cb->DecStrongRef(nullptr);
    delete work;
}

// ==================== PressButton 实现 ====================

napi_value JsMouseController::PressButton(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;

    // 1. 权限检查
    if (!CheckPermission(env)) {
        return nullptr;
    }

    // 2. 获取参数
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    // 3. 参数验证
    if (argc != 1) {
        MMI_HILOGE("Invalid parameter count: %{public}zu", argc);
        napi_throw_error(env, "401", "Invalid parameter count");
        return nullptr;
    }

    // 4. 提取参数
    int32_t button;
    napi_get_value_int32(env, argv[0], &button);

    // 5. 获取 MouseControllerImpl 实例
    std::shared_ptr<MouseControllerImpl>* implPtr = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void**>(&implPtr));
    if (implPtr == nullptr || *implPtr == nullptr) {
        MMI_HILOGE("Failed to get MouseControllerImpl instance");
        napi_throw_error(env, "3800001", "Input service exception");
        return nullptr;
    }

    // 6. 创建 Promise
    napi_deferred deferred;
    napi_value promise;
    napi_create_promise(env, &deferred, &promise);

    // 7. 创建回调信息
    sptr<MouseControllerCallbackInfo> cb = new (std::nothrow) MouseControllerCallbackInfo();
    if (cb == nullptr) {
        MMI_HILOGE("Failed to create callback info");
        napi_reject_deferred(env, deferred, CreateBusinessError(env, RET_ERR));
        return promise;
    }

    cb->env = env;
    cb->deferred = deferred;
    cb->impl = *implPtr;
    cb->buttonParams.button = button;
    cb->IncStrongRef(nullptr);

    // 8. 获取 libuv 事件循环
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env, &loop);
    if (loop == nullptr) {
        MMI_HILOGE("Failed to get uv event loop");
        cb->DecStrongRef(nullptr);
        napi_reject_deferred(env, deferred, CreateBusinessError(env, RET_ERR));
        return promise;
    }

    // 9. 创建 uv_work_t
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        MMI_HILOGE("Failed to create uv_work_t");
        cb->DecStrongRef(nullptr);
        napi_reject_deferred(env, deferred, CreateBusinessError(env, RET_ERR));
        return promise;
    }
    work->data = cb.GetRefPtr();

    // 10. 提交到 libuv 工作队列
    int32_t ret = uv_queue_work_with_qos_internal(
        loop,
        work,
        CallPressButtonTask,
        CallButtonPromise,
        uv_qos_user_initiated,
        "pressButton"
    );

    if (ret != 0) {
        MMI_HILOGE("Failed to queue work: %{public}d", ret);
        cb->DecStrongRef(nullptr);
        delete work;
        napi_reject_deferred(env, deferred, CreateBusinessError(env, RET_ERR));
    }

    return promise;
}

void JsMouseController::CallPressButtonTask(uv_work_t *work)
{
    CALL_DEBUG_ENTER;

    auto* cb = static_cast<MouseControllerCallbackInfo*>(work->data);
    if (cb == nullptr || cb->impl == nullptr) {
        MMI_HILOGE("Invalid callback info");
        return;
    }

    cb->errCode = cb->impl->PressButton(cb->buttonParams.button);
    MMI_HILOGD("PressButton result: %{public}d", cb->errCode);
}

void JsMouseController::CallButtonPromise(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;

    auto* cb = static_cast<MouseControllerCallbackInfo*>(work->data);
    if (cb == nullptr) {
        MMI_HILOGE("Invalid callback info");
        delete work;
        return;
    }

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);

    if (cb->errCode == RET_OK) {
        napi_value result;
        napi_get_undefined(cb->env, &result);
        napi_resolve_deferred(cb->env, cb->deferred, result);
    } else {
        napi_value error = CreateBusinessError(cb->env, cb->errCode);
        napi_reject_deferred(cb->env, cb->deferred, error);
    }

    napi_close_handle_scope(cb->env, scope);

    cb->DecStrongRef(nullptr);
    delete work;
}

// ==================== ReleaseButton 实现（类似 PressButton）====================

napi_value JsMouseController::ReleaseButton(napi_env env, napi_callback_info info)
{
    // 实现与 PressButton 类似，只是调用 impl->ReleaseButton()
    // 为简洁起见，此处省略详细代码
    // ...
}

void JsMouseController::CallReleaseButtonTask(uv_work_t *work)
{
    auto* cb = static_cast<MouseControllerCallbackInfo*>(work->data);
    if (cb == nullptr || cb->impl == nullptr) {
        return;
    }
    cb->errCode = cb->impl->ReleaseButton(cb->buttonParams.button);
}

// ==================== BeginAxis 实现 ====================

napi_value JsMouseController::BeginAxis(napi_env env, napi_callback_info info)
{
    // 实现与 PressButton 类似，提取 axis 和 value 参数
    // 调用 impl->BeginAxis(axis, value)
    // ...
}

void JsMouseController::CallBeginAxisTask(uv_work_t *work)
{
    auto* cb = static_cast<MouseControllerCallbackInfo*>(work->data);
    if (cb == nullptr || cb->impl == nullptr) {
        return;
    }
    cb->errCode = cb->impl->BeginAxis(
        cb->axisParams.axis,
        cb->axisParams.value
    );
}

void JsMouseController::CallAxisPromise(uv_work_t *work, int32_t status)
{
    // 与 CallButtonPromise 相同
    // ...
}

// ==================== UpdateAxis 和 EndAxis 实现（类似）====================

// UpdateAxis 和 EndAxis 的实现模式与 BeginAxis 相同
// ...

} // namespace MMI
} // namespace OHOS
```

### 2.2 创建 MouseController 工厂函数

**文件：** `frameworks/napi/input_event_client/src/js_input_event_client.cpp`

```cpp
#include "js_mouse_controller.h"
#include "input_manager.h"

namespace OHOS {
namespace MMI {

napi_value CreateMouseController(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;

    // 1. 权限检查
    if (!CheckInputEventClentPermission()) {
        MMI_HILOGE("Permission check failed");
        napi_throw_error(env, "201", "Permission verification failed");
        return nullptr;
    }

    // 2. 能力检查（仅 PC 支持）
    if (!IsPC()) {
        MMI_HILOGE("Capability not supported");
        napi_throw_error(env, "801", "Capability not supported");
        return nullptr;
    }

    // 3. 调用 InputManager 创建 Impl 实例
    auto impl = InputManager::GetInstance()->CreateMouseController();
    if (impl == nullptr) {
        MMI_HILOGE("Failed to create MouseControllerImpl");
        napi_throw_error(env, "3800001", "Input service exception");
        return nullptr;
    }

    // 4. 创建 NAPI 对象
    napi_value mouseController;
    napi_create_object(env, &mouseController);

    // 5. 包装 Impl 实例到 NAPI 对象
    auto* implPtr = new std::shared_ptr<MouseControllerImpl>(impl);
    napi_wrap(env, mouseController, implPtr,
        [](napi_env env, void* data, void* hint) {
            auto* ptr = static_cast<std::shared_ptr<MouseControllerImpl>*>(data);
            delete ptr;
        }, nullptr, nullptr);

    // 6. 绑定方法
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("moveTo", JsMouseController::MoveTo),
        DECLARE_NAPI_FUNCTION("pressButton", JsMouseController::PressButton),
        DECLARE_NAPI_FUNCTION("releaseButton", JsMouseController::ReleaseButton),
        DECLARE_NAPI_FUNCTION("beginAxis", JsMouseController::BeginAxis),
        DECLARE_NAPI_FUNCTION("updateAxis", JsMouseController::UpdateAxis),
        DECLARE_NAPI_FUNCTION("endAxis", JsMouseController::EndAxis),
    };
    napi_define_properties(env, mouseController,
        sizeof(descriptors) / sizeof(descriptors[0]), descriptors);

    // 7. 返回 Promise
    napi_deferred deferred;
    napi_value promise;
    napi_create_promise(env, &deferred, &promise);
    napi_resolve_deferred(env, deferred, mouseController);

    return promise;
}

} // namespace MMI
} // namespace OHOS
```

### 2.3 KeyboardController NAPI 层重构

**说明**：KeyboardController 的实现模式与 MouseController 完全相同，只是：

1. **回调信息结构体**：`KeyboardControllerCallbackInfo`
2. **NAPI 包装类**：`JsKeyboardController`
3. **方法**：`PressKey`, `ReleaseKey`
4. **工厂函数**：`CreateKeyboardController`

**关键差异**：
- 参数更简单（只有 keyCode）
- 状态管理更简单（只有按键列表）
- 没有轴事件相关方法

**实现文件**：
- `frameworks/napi/input_event_client/include/js_keyboard_controller.h`
- `frameworks/napi/input_event_client/src/js_keyboard_controller.cpp`

### 2.4 模块注册

**修改文件：** `frameworks/napi/input_event_client/src/js_register_module.cpp`

```cpp
#include "js_mouse_controller.h"
#include "js_keyboard_controller.h"

static napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        // ... 现有导出 ...
        DECLARE_NAPI_FUNCTION("createMouseController", CreateMouseController),
        DECLARE_NAPI_FUNCTION("createKeyboardController", CreateKeyboardController),
    };

    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}

static napi_module inputEventClientModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "multimodalInput.inputEventClient",
    .nm_priv = nullptr,
    .reserved = { nullptr },
};

extern "C" __attribute__((constructor)) void RegisterModule()
{
    napi_module_register(&inputEventClientModule);
}
```
