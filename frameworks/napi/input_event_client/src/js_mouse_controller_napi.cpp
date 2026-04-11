/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "js_mouse_controller_napi.h"

#include <string>

#include "input_manager.h"
#include "ipc_skeleton.h"
#include "js_mouse_controller.h"
#include "mmi_log.h"
#include "napi_constants.h"
#include "util_napi.h"
#include "util_napi_error.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsMouseControllerNapi"

namespace OHOS {
namespace MMI {

namespace {
// TODO: Add these error codes to util_napi_error.h
// Error codes for MouseController
constexpr int32_t INPUT_SERVICE_EXCEPTION = 3800001;      // Input service exception

/**
 * @brief Create business error
 */
napi_value CreateBusinessError(napi_env env, int32_t code, const std::string& msg)
{
    napi_value businessError = nullptr;
    napi_value errorCode = nullptr;
    napi_value errorMsg = nullptr;

    napi_create_int32(env, code, &errorCode);
    napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH, &errorMsg);
    napi_create_error(env, nullptr, errorMsg, &businessError);
    napi_set_named_property(env, businessError, "code", errorCode);

    return businessError;
}

} // namespace

napi_value CreateMouseController(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("CreateMouseController called");

    // Call service to check permission
    int32_t ret = InputManager::GetInstance()->CheckMouseControllerPermission();
    if (ret != RET_OK) {
        MMI_HILOGE("CheckMouseControllerPermission failed, ret=%{public}d", ret);
        THROWERR_CUSTOM(env, ret, "Permission check failed");
        return nullptr;
    }

    // Create MouseController object
    napi_value mouseController;
    napi_status status = napi_create_object(env, &mouseController);
    if (status != napi_ok) {
        MMI_HILOGE("CREATE_OBJECT failed");
        return nullptr;
    }

    // Create C++ instance
    auto* controller = new (std::nothrow) JsMouseController();
    if (controller == nullptr) {
        MMI_HILOGE("Failed to create JsMouseController");
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Wrap C++ instance with JS object
    status = napi_wrap(
        env,
        mouseController,
        controller,
        [](napi_env env, void* data, void* hint) {
            MMI_HILOGD("JsMouseController finalizer called");
            delete static_cast<JsMouseController*>(data);
        },
        nullptr,
        nullptr);

    if (status != napi_ok) {
        MMI_HILOGE("Failed to wrap JsMouseController");
        delete controller;
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Bind methods
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("moveTo", MouseControllerMoveTo),
        DECLARE_NAPI_FUNCTION("pressButton", MouseControllerPressButton),
        DECLARE_NAPI_FUNCTION("releaseButton", MouseControllerReleaseButton),
        DECLARE_NAPI_FUNCTION("beginAxis", MouseControllerBeginAxis),
        DECLARE_NAPI_FUNCTION("updateAxis", MouseControllerUpdateAxis),
        DECLARE_NAPI_FUNCTION("endAxis", MouseControllerEndAxis),
    };

    status = napi_define_properties(env, mouseController,
        sizeof(descriptors) / sizeof(descriptors[0]), descriptors);
    if (status != napi_ok) {
        MMI_HILOGE("DEFINE_PROPERTIES failed");
        return nullptr;
    }

    // Create and return Promise
    napi_deferred deferred;
    napi_value promise;
    status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        MMI_HILOGE("CREATE_PROMISE failed");
        return nullptr;
    }

    status = napi_resolve_deferred(env, deferred, mouseController);
    if (status != napi_ok) {
        MMI_HILOGE("RESOLVE_DEFERRED failed");
        return nullptr;
    }

    MMI_HILOGD("CreateMouseController success");
    return promise;
}

napi_value MouseControllerMoveTo(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("MouseControllerMoveTo called");

    // Get parameters
    size_t argc = 3;
    napi_value argv[3];
    napi_value thisVar;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (status != napi_ok) {
        MMI_HILOGE("GET_CB_INFO failed");
        return nullptr;
    }

    // Validate parameter count
    if (argc != 3) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    // Extract parameters
    int32_t displayId = 0;
    int32_t x = 0;
    int32_t y = 0;
    status = napi_get_value_int32(env, argv[0], &displayId);
    if (status != napi_ok) {
        MMI_HILOGE("GET_VALUE_INT32 failed");
        return nullptr;
    }
    status = napi_get_value_int32(env, argv[1], &x);
    if (status != napi_ok) {
        MMI_HILOGE("GET_VALUE_INT32 failed");
        return nullptr;
    }
    status = napi_get_value_int32(env, argv[2], &y);
    if (status != napi_ok) {
        MMI_HILOGE("GET_VALUE_INT32 failed");
        return nullptr;
    }

    // Get C++ instance
    JsMouseController* controller = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller));
    if (status != napi_ok) {
        MMI_HILOGE("UNWRAP failed");
        return nullptr;
    }
    if (controller == nullptr) {
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Execute synchronously
    int32_t result = controller->MoveTo(displayId, x, y);

    // Create Promise
    napi_deferred deferred;
    napi_value promise;
    status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        MMI_HILOGE("CREATE_PROMISE failed");
        return nullptr;
    }

    if (result == RET_OK) {
        status = napi_resolve_deferred(env, deferred, nullptr);
        if (status != napi_ok) {
            MMI_HILOGE("RESOLVE_DEFERRED failed");
            return nullptr;
        }
    } else {
        napi_value error = CreateBusinessError(env, result, "MoveTo failed");
        status = napi_reject_deferred(env, deferred, error);
        if (status != napi_ok) {
            MMI_HILOGE("REJECT_DEFERRED failed");
            return nullptr;
        }
    }

    return promise;
}

napi_value MouseControllerPressButton(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("MouseControllerPressButton called");

    // Get parameters
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (status != napi_ok) {
        MMI_HILOGE("GET_CB_INFO failed");
        return nullptr;
    }

    if (argc != 1) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    int32_t button;
    status = napi_get_value_int32(env, argv[0], &button);
    if (status != napi_ok) {
        MMI_HILOGE("GET_VALUE_INT32 failed");
        return nullptr;
    }

    JsMouseController* controller = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller));
    if (status != napi_ok) {
        MMI_HILOGE("UNWRAP failed");
        return nullptr;
    }
    if (controller == nullptr) {
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Execute synchronously
    int32_t result = controller->PressButton(button);

    // Create Promise
    napi_deferred deferred;
    napi_value promise;
    status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        MMI_HILOGE("CREATE_PROMISE failed");
        return nullptr;
    }

    if (result == RET_OK) {
        status = napi_resolve_deferred(env, deferred, nullptr);
        if (status != napi_ok) {
            MMI_HILOGE("RESOLVE_DEFERRED failed");
            return nullptr;
        }
    } else {
        napi_value error = CreateBusinessError(env, result, "PressButton failed");
        status = napi_reject_deferred(env, deferred, error);
        if (status != napi_ok) {
            MMI_HILOGE("REJECT_DEFERRED failed");
            return nullptr;
        }
    }

    return promise;
}

napi_value MouseControllerReleaseButton(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("MouseControllerReleaseButton called");

    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (status != napi_ok) {
        MMI_HILOGE("GET_CB_INFO failed");
        return nullptr;
    }

    if (argc != 1) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    int32_t button;
    status = napi_get_value_int32(env, argv[0], &button);
    if (status != napi_ok) {
        MMI_HILOGE("GET_VALUE_INT32 failed");
        return nullptr;
    }

    JsMouseController* controller = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller));
    if (status != napi_ok) {
        MMI_HILOGE("UNWRAP failed");
        return nullptr;
    }
    if (controller == nullptr) {
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Execute synchronously
    int32_t result = controller->ReleaseButton(button);

    // Create Promise
    napi_deferred deferred;
    napi_value promise;
    status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        MMI_HILOGE("CREATE_PROMISE failed");
        return nullptr;
    }

    if (result == RET_OK) {
        status = napi_resolve_deferred(env, deferred, nullptr);
        if (status != napi_ok) {
            MMI_HILOGE("RESOLVE_DEFERRED failed");
            return nullptr;
        }
    } else {
        napi_value error = CreateBusinessError(env, result, "ReleaseButton failed");
        status = napi_reject_deferred(env, deferred, error);
        if (status != napi_ok) {
            MMI_HILOGE("REJECT_DEFERRED failed");
            return nullptr;
        }
    }

    return promise;
}

napi_value MouseControllerBeginAxis(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("MouseControllerBeginAxis called");

    size_t argc = 2;
    napi_value argv[2];
    napi_value thisVar;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (status != napi_ok) {
        MMI_HILOGE("GET_CB_INFO failed");
        return nullptr;
    }

    if (argc != 2) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    int32_t axis = 0;
    int32_t value = 0;
    status = napi_get_value_int32(env, argv[0], &axis);
    if (status != napi_ok) {
        MMI_HILOGE("GET_VALUE_INT32 failed");
        return nullptr;
    }
    status = napi_get_value_int32(env, argv[1], &value);
    if (status != napi_ok) {
        MMI_HILOGE("GET_VALUE_INT32 failed");
        return nullptr;
    }

    JsMouseController* controller = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller));
    if (status != napi_ok) {
        MMI_HILOGE("UNWRAP failed");
        return nullptr;
    }
    if (controller == nullptr) {
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Execute synchronously
    int32_t result = controller->BeginAxis(axis, value);

    // Create Promise
    napi_deferred deferred;
    napi_value promise;
    status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        MMI_HILOGE("CREATE_PROMISE failed");
        return nullptr;
    }

    if (result == RET_OK) {
        status = napi_resolve_deferred(env, deferred, nullptr);
        if (status != napi_ok) {
            MMI_HILOGE("RESOLVE_DEFERRED failed");
            return nullptr;
        }
    } else {
        napi_value error = CreateBusinessError(env, result, "BeginAxis failed");
        status = napi_reject_deferred(env, deferred, error);
        if (status != napi_ok) {
            MMI_HILOGE("REJECT_DEFERRED failed");
            return nullptr;
        }
    }

    return promise;
}

napi_value MouseControllerUpdateAxis(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("MouseControllerUpdateAxis called");

    size_t argc = 2;
    napi_value argv[2];
    napi_value thisVar;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (status != napi_ok) {
        MMI_HILOGE("GET_CB_INFO failed");
        return nullptr;
    }

    if (argc != 2) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    int32_t axis = 0;
    int32_t value = 0;
    status = napi_get_value_int32(env, argv[0], &axis);
    if (status != napi_ok) {
        MMI_HILOGE("GET_VALUE_INT32 failed");
        return nullptr;
    }
    status = napi_get_value_int32(env, argv[1], &value);
    if (status != napi_ok) {
        MMI_HILOGE("GET_VALUE_INT32 failed");
        return nullptr;
    }

    JsMouseController* controller = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller));
    if (status != napi_ok) {
        MMI_HILOGE("UNWRAP failed");
        return nullptr;
    }
    if (controller == nullptr) {
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Execute synchronously
    int32_t result = controller->UpdateAxis(axis, value);

    // Create Promise
    napi_deferred deferred;
    napi_value promise;
    status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        MMI_HILOGE("CREATE_PROMISE failed");
        return nullptr;
    }

    if (result == RET_OK) {
        status = napi_resolve_deferred(env, deferred, nullptr);
        if (status != napi_ok) {
            MMI_HILOGE("RESOLVE_DEFERRED failed");
            return nullptr;
        }
    } else {
        napi_value error = CreateBusinessError(env, result, "UpdateAxis failed");
        status = napi_reject_deferred(env, deferred, error);
        if (status != napi_ok) {
            MMI_HILOGE("REJECT_DEFERRED failed");
            return nullptr;
        }
    }

    return promise;
}

napi_value MouseControllerEndAxis(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("MouseControllerEndAxis called");

    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (status != napi_ok) {
        MMI_HILOGE("GET_CB_INFO failed");
        return nullptr;
    }

    if (argc != 1) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    int32_t axis;
    status = napi_get_value_int32(env, argv[0], &axis);
    if (status != napi_ok) {
        MMI_HILOGE("GET_VALUE_INT32 failed");
        return nullptr;
    }

    JsMouseController* controller = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller));
    if (status != napi_ok) {
        MMI_HILOGE("UNWRAP failed");
        return nullptr;
    }
    if (controller == nullptr) {
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Execute synchronously
    int32_t result = controller->EndAxis(axis);

    // Create Promise
    napi_deferred deferred;
    napi_value promise;
    status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        MMI_HILOGE("CREATE_PROMISE failed");
        return nullptr;
    }

    if (result == RET_OK) {
        status = napi_resolve_deferred(env, deferred, nullptr);
        if (status != napi_ok) {
            MMI_HILOGE("RESOLVE_DEFERRED failed");
            return nullptr;
        }
    } else {
        napi_value error = CreateBusinessError(env, result, "EndAxis failed");
        status = napi_reject_deferred(env, deferred, error);
        if (status != napi_ok) {
            MMI_HILOGE("REJECT_DEFERRED failed");
            return nullptr;
        }
    }

    return promise;
}

} // namespace MMI
} // namespace OHOS
