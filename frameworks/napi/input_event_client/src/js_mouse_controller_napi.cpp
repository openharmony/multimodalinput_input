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

#include "error_multimodal.h"
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

constexpr const char* CONTROL_DEVICE_PERMISSION = "ohos.permission.CONTROL_DEVICE";

enum class MouseControllerOperation {
    CREATE,
    MOVE_TO,
    PRESS_BUTTON,
    RELEASE_BUTTON,
    BEGIN_AXIS,
    UPDATE_AXIS,
    END_AXIS,
};

const char* GetMouseControllerActionName(MouseControllerOperation operation)
{
    switch (operation) {
        case MouseControllerOperation::CREATE:
            return "create MouseController";
        case MouseControllerOperation::MOVE_TO:
            return "move mouse cursor";
        case MouseControllerOperation::PRESS_BUTTON:
            return "press mouse button";
        case MouseControllerOperation::RELEASE_BUTTON:
            return "release mouse button";
        case MouseControllerOperation::BEGIN_AXIS:
            return "begin axis event";
        case MouseControllerOperation::UPDATE_AXIS:
            return "update axis event";
        case MouseControllerOperation::END_AXIS:
            return "end axis event";
        default:
            return "unknown operation";
    }
}

int32_t NormalizeControllerErrorCode(int32_t code)
{
    if (code == ERROR_NO_PERMISSION) {
        return COMMON_PERMISSION_CHECK_ERROR;
    }
    if (code == CAPABILITY_NOT_SUPPORTED) {
        return INPUT_DEVICE_NOT_SUPPORTED;
    }
    if (code == ERROR_NOT_SYSAPI) {
        return COMMON_USE_SYSAPI_ERROR;
    }
    return code;
}

std::string MakePermissionErrorMsg(int32_t code, MouseControllerOperation operation)
{
    NapiError codeMsg;
    if (!UtilNapiError::GetApiError(code, codeMsg)) {
        return "Permission denied.";
    }
    char msg[300] = {};
    int32_t ret = sprintf_s(msg, sizeof(msg), codeMsg.msg.c_str(),
        GetMouseControllerActionName(operation), CONTROL_DEVICE_PERMISSION);
    if (ret <= 0) {
        return codeMsg.msg;
    }
    return msg;
}

std::string GetControllerErrorMsg(int32_t code, MouseControllerOperation operation)
{
    if (code == COMMON_PERMISSION_CHECK_ERROR) {
        return MakePermissionErrorMsg(code, operation);
    }
    NapiError codeMsg;
    if (UtilNapiError::GetApiError(code, codeMsg)) {
        return codeMsg.msg;
    }
    if (UtilNapiError::GetApiError(INPUT_SERVICE_EXCEPTION, codeMsg)) {
        return codeMsg.msg;
    }
    return "Input service exception.";
}

napi_value CreateBusinessError(napi_env env, int32_t code, MouseControllerOperation operation)
{
    napi_value businessError = nullptr;
    napi_value errorCode = nullptr;
    napi_value errorMsg = nullptr;

    int32_t normalizedCode = NormalizeControllerErrorCode(code);
    std::string msg = GetControllerErrorMsg(normalizedCode, operation);

    napi_create_int32(env, normalizedCode, &errorCode);
    napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH, &errorMsg);
    napi_create_error(env, nullptr, errorMsg, &businessError);
    napi_set_named_property(env, businessError, "code", errorCode);

    return businessError;
}

void ThrowControllerError(napi_env env, int32_t code, MouseControllerOperation operation)
{
    napi_value businessError = CreateBusinessError(env, code, operation);
    napi_throw(env, businessError);
}

} // namespace

napi_value CreateMouseController(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("CreateMouseController called");

    // Call service to check permission
    int32_t ret = InputManager::GetInstance()->CheckMouseControllerPermission();
    if (ret != RET_OK) {
        MMI_HILOGE("CheckMouseControllerPermission failed, ret=%{public}d", ret);
        ThrowControllerError(env, ret, MouseControllerOperation::CREATE);
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
        nullptr, nullptr);

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
        napi_value error = CreateBusinessError(env, result, MouseControllerOperation::MOVE_TO);
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
        napi_value error = CreateBusinessError(env, result, MouseControllerOperation::PRESS_BUTTON);
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
        napi_value error = CreateBusinessError(env, result, MouseControllerOperation::RELEASE_BUTTON);
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
        napi_value error = CreateBusinessError(env, result, MouseControllerOperation::BEGIN_AXIS);
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
        napi_value error = CreateBusinessError(env, result, MouseControllerOperation::UPDATE_AXIS);
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
        napi_value error = CreateBusinessError(env, result, MouseControllerOperation::END_AXIS);
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
