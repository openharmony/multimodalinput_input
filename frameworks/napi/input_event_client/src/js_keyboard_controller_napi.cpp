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

#include "js_keyboard_controller_napi.h"

#include <string>

#include "error_multimodal.h"
#include "input_manager.h"
#include "ipc_skeleton.h"
#include "js_keyboard_controller.h"
#include "mmi_log.h"
#include "napi_constants.h"
#include "util_napi.h"
#include "util_napi_error.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsKeyboardControllerNapi"

namespace OHOS {
namespace MMI {

namespace {

constexpr const char* CONTROL_DEVICE_PERMISSION = "ohos.permission.CONTROL_DEVICE";

enum class KeyboardControllerOperation {
    CREATE,
    PRESS_KEY,
    RELEASE_KEY,
};

const char* GetKeyboardControllerActionName(KeyboardControllerOperation operation)
{
    switch (operation) {
        case KeyboardControllerOperation::CREATE:
            return "create KeyboardController";
        case KeyboardControllerOperation::PRESS_KEY:
            return "press key";
        case KeyboardControllerOperation::RELEASE_KEY:
            return "release key";
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

std::string MakePermissionErrorMsg(int32_t code, KeyboardControllerOperation operation)
{
    NapiError codeMsg;
    if (!UtilNapiError::GetApiError(code, codeMsg)) {
        return "Permission denied.";
    }
    char msg[300] = {};
    int32_t ret = sprintf_s(msg, sizeof(msg), codeMsg.msg.c_str(),
        GetKeyboardControllerActionName(operation), CONTROL_DEVICE_PERMISSION);
    if (ret <= 0) {
        return codeMsg.msg;
    }
    return msg;
}

std::string GetControllerErrorMsg(int32_t code, KeyboardControllerOperation operation)
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

napi_value CreateBusinessError(napi_env env, int32_t code, KeyboardControllerOperation operation)
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

void ThrowControllerError(napi_env env, int32_t code, KeyboardControllerOperation operation)
{
    napi_value businessError = CreateBusinessError(env, code, operation);
    napi_throw(env, businessError);
}

} // namespace

napi_value CreateKeyboardController(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("CreateKeyboardController called");

    // Call service to check permission
    int32_t ret = InputManager::GetInstance()->CheckKeyboardControllerPermission();
    if (ret != RET_OK) {
        MMI_HILOGE("CheckKeyboardControllerPermission failed, ret=%{public}d", ret);
        ThrowControllerError(env, ret, KeyboardControllerOperation::CREATE);
        return nullptr;
    }

    // Create KeyboardController object
    napi_value keyboardController;
    napi_status status = napi_create_object(env, &keyboardController);
    if (status != napi_ok) {
        MMI_HILOGE("CREATE_OBJECT failed");
        return nullptr;
    }

    // Create C++ instance
    auto* controller = new (std::nothrow) JsKeyboardController();
    if (controller == nullptr) {
        MMI_HILOGE("Failed to create JsKeyboardController");
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Wrap C++ instance with JS object
    status = napi_wrap(
        env,
        keyboardController,
        controller,
        [](napi_env env, void* data, void* hint) {
            MMI_HILOGD("JsKeyboardController finalizer called");
            delete static_cast<JsKeyboardController*>(data);
        },
        nullptr,
        nullptr);

    if (status != napi_ok) {
        MMI_HILOGE("Failed to wrap JsKeyboardController");
        delete controller;
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Bind methods
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("pressKey", KeyboardControllerPressKey),
        DECLARE_NAPI_FUNCTION("releaseKey", KeyboardControllerReleaseKey),
    };

    status = napi_define_properties(env, keyboardController,
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

    status = napi_resolve_deferred(env, deferred, keyboardController);
    if (status != napi_ok) {
        MMI_HILOGE("RESOLVE_DEFERRED failed");
        return nullptr;
    }

    MMI_HILOGD("CreateKeyboardController success");
    return promise;
}

napi_value KeyboardControllerPressKey(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("KeyboardControllerPressKey called");

    // Get parameters
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (status != napi_ok) {
        MMI_HILOGE("GET_CB_INFO failed");
        return nullptr;
    }

    // Validate parameter count
    if (argc != 1) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    // Extract keyCode parameter
    int32_t keyCode;
    status = napi_get_value_int32(env, argv[0], &keyCode);
    if (status != napi_ok) {
        MMI_HILOGE("GET_VALUE_INT32 failed");
        return nullptr;
    }

    // Get C++ instance
    JsKeyboardController* controller = nullptr;
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
    int32_t result = controller->PressKey(keyCode);

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
        napi_value error = CreateBusinessError(env, result, KeyboardControllerOperation::PRESS_KEY);
        status = napi_reject_deferred(env, deferred, error);
        if (status != napi_ok) {
            MMI_HILOGE("REJECT_DEFERRED failed");
            return nullptr;
        }
    }

    return promise;
}

napi_value KeyboardControllerReleaseKey(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("KeyboardControllerReleaseKey called");

    // Get parameters
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (status != napi_ok) {
        MMI_HILOGE("GET_CB_INFO failed");
        return nullptr;
    }

    // Validate parameter count
    if (argc != 1) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    // Extract keyCode parameter
    int32_t keyCode;
    status = napi_get_value_int32(env, argv[0], &keyCode);
    if (status != napi_ok) {
        MMI_HILOGE("GET_VALUE_INT32 failed");
        return nullptr;
    }

    // Get C++ instance
    JsKeyboardController* controller = nullptr;
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
    int32_t result = controller->ReleaseKey(keyCode);

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
        napi_value error = CreateBusinessError(env, result, KeyboardControllerOperation::RELEASE_KEY);
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
