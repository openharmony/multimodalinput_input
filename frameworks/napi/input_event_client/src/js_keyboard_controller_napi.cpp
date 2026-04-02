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
// Error codes for KeyboardController
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

napi_value CreateKeyboardController(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("CreateKeyboardController called");

    // Call service to check permission
    int32_t ret = InputManager::GetInstance()->CreateKeyboardController();
    if (ret != RET_OK) {
        MMI_HILOGE("CreateKeyboardController permission check failed, ret=%{public}d", ret);
        THROWERR_CUSTOM(env, ret, "Permission check failed");
        return nullptr;
    }

    // Create KeyboardController object
    napi_value keyboardController;
    CHKRP(napi_create_object(env, &keyboardController), CREATE_OBJECT);

    // Create C++ instance
    auto* controller = new (std::nothrow) JsKeyboardController();
    if (controller == nullptr) {
        MMI_HILOGE("Failed to create JsKeyboardController");
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Wrap C++ instance with JS object
    napi_status status = napi_wrap(
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

    CHKRP(napi_define_properties(env, keyboardController,
        sizeof(descriptors) / sizeof(descriptors[0]), descriptors), DEFINE_PROPERTIES);

    // Create and return Promise
    napi_deferred deferred;
    napi_value promise;
    CHKRP(napi_create_promise(env, &deferred, &promise), CREATE_PROMISE);
    CHKRP(napi_resolve_deferred(env, deferred, keyboardController), RESOLVE_DEFERRED);

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
    CHKRP(napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), GET_CB_INFO);

    // Validate parameter count
    if (argc != 1) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    // Extract keyCode parameter
    int32_t keyCode;
    CHKRP(napi_get_value_int32(env, argv[0], &keyCode), GET_VALUE_INT32);

    // Get C++ instance
    JsKeyboardController* controller = nullptr;
    CHKRP(napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller)), UNWRAP);
    if (controller == nullptr) {
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Execute synchronously
    int32_t result = controller->PressKey(keyCode);

    // Create Promise
    napi_deferred deferred;
    napi_value promise;
    CHKRP(napi_create_promise(env, &deferred, &promise), CREATE_PROMISE);

    if (result == RET_OK) {
        CHKRP(napi_resolve_deferred(env, deferred, nullptr), RESOLVE_DEFERRED);
    } else {
        napi_value error = CreateBusinessError(env, result, "PressKey failed");
        CHKRP(napi_reject_deferred(env, deferred, error), REJECT_DEFERRED);
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
    CHKRP(napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), GET_CB_INFO);

    // Validate parameter count
    if (argc != 1) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    // Extract keyCode parameter
    int32_t keyCode;
    CHKRP(napi_get_value_int32(env, argv[0], &keyCode), GET_VALUE_INT32);

    // Get C++ instance
    JsKeyboardController* controller = nullptr;
    CHKRP(napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller)), UNWRAP);
    if (controller == nullptr) {
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Execute synchronously
    int32_t result = controller->ReleaseKey(keyCode);

    // Create Promise
    napi_deferred deferred;
    napi_value promise;
    CHKRP(napi_create_promise(env, &deferred, &promise), CREATE_PROMISE);

    if (result == RET_OK) {
        CHKRP(napi_resolve_deferred(env, deferred, nullptr), RESOLVE_DEFERRED);
    } else {
        napi_value error = CreateBusinessError(env, result, "ReleaseKey failed");
        CHKRP(napi_reject_deferred(env, deferred, error), REJECT_DEFERRED);
    }

    return promise;
}

} // namespace MMI
} // namespace OHOS
