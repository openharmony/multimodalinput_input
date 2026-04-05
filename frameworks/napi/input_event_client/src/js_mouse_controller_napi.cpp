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
    CHKRP(napi_create_object(env, &mouseController), CREATE_OBJECT);

    // Create C++ instance
    auto* controller = new (std::nothrow) JsMouseController();
    if (controller == nullptr) {
        MMI_HILOGE("Failed to create JsMouseController");
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Wrap C++ instance with JS object
    napi_status status = napi_wrap(
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

    CHKRP(napi_define_properties(env, mouseController,
        sizeof(descriptors) / sizeof(descriptors[0]), descriptors), DEFINE_PROPERTIES);

    // Create and return Promise
    napi_deferred deferred;
    napi_value promise;
    CHKRP(napi_create_promise(env, &deferred, &promise), CREATE_PROMISE);
    CHKRP(napi_resolve_deferred(env, deferred, mouseController), RESOLVE_DEFERRED);

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
    CHKRP(napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), GET_CB_INFO);

    // Validate parameter count
    if (argc != 3) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    // Extract parameters
    int32_t displayId, x, y;
    CHKRP(napi_get_value_int32(env, argv[0], &displayId), GET_VALUE_INT32);
    CHKRP(napi_get_value_int32(env, argv[1], &x), GET_VALUE_INT32);
    CHKRP(napi_get_value_int32(env, argv[2], &y), GET_VALUE_INT32);

    // Get C++ instance
    JsMouseController* controller = nullptr;
    CHKRP(napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller)), UNWRAP);
    if (controller == nullptr) {
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Execute synchronously
    int32_t result = controller->MoveTo(displayId, x, y);

    // Create Promise
    napi_deferred deferred;
    napi_value promise;
    CHKRP(napi_create_promise(env, &deferred, &promise), CREATE_PROMISE);

    if (result == RET_OK) {
        CHKRP(napi_resolve_deferred(env, deferred, nullptr), RESOLVE_DEFERRED);
    } else {
        napi_value error = CreateBusinessError(env, result, "MoveTo failed");
        CHKRP(napi_reject_deferred(env, deferred, error), REJECT_DEFERRED);
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
    CHKRP(napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), GET_CB_INFO);

    if (argc != 1) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    int32_t button;
    CHKRP(napi_get_value_int32(env, argv[0], &button), GET_VALUE_INT32);

    JsMouseController* controller = nullptr;
    CHKRP(napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller)), UNWRAP);
    if (controller == nullptr) {
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Execute synchronously
    int32_t result = controller->PressButton(button);

    // Create Promise
    napi_deferred deferred;
    napi_value promise;
    CHKRP(napi_create_promise(env, &deferred, &promise), CREATE_PROMISE);

    if (result == RET_OK) {
        CHKRP(napi_resolve_deferred(env, deferred, nullptr), RESOLVE_DEFERRED);
    } else {
        napi_value error = CreateBusinessError(env, result, "PressButton failed");
        CHKRP(napi_reject_deferred(env, deferred, error), REJECT_DEFERRED);
    }

    return promise;
}

napi_value MouseControllerReleaseButton(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("MouseControllerReleaseButton called");

    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    CHKRP(napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), GET_CB_INFO);

    if (argc != 1) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    int32_t button;
    CHKRP(napi_get_value_int32(env, argv[0], &button), GET_VALUE_INT32);

    JsMouseController* controller = nullptr;
    CHKRP(napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller)), UNWRAP);
    if (controller == nullptr) {
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Execute synchronously
    int32_t result = controller->ReleaseButton(button);

    // Create Promise
    napi_deferred deferred;
    napi_value promise;
    CHKRP(napi_create_promise(env, &deferred, &promise), CREATE_PROMISE);

    if (result == RET_OK) {
        CHKRP(napi_resolve_deferred(env, deferred, nullptr), RESOLVE_DEFERRED);
    } else {
        napi_value error = CreateBusinessError(env, result, "ReleaseButton failed");
        CHKRP(napi_reject_deferred(env, deferred, error), REJECT_DEFERRED);
    }

    return promise;
}

napi_value MouseControllerBeginAxis(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("MouseControllerBeginAxis called");

    size_t argc = 2;
    napi_value argv[2];
    napi_value thisVar;
    CHKRP(napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), GET_CB_INFO);

    if (argc != 2) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    int32_t axis, value;
    CHKRP(napi_get_value_int32(env, argv[0], &axis), GET_VALUE_INT32);
    CHKRP(napi_get_value_int32(env, argv[1], &value), GET_VALUE_INT32);

    JsMouseController* controller = nullptr;
    CHKRP(napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller)), UNWRAP);
    if (controller == nullptr) {
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Execute synchronously
    int32_t result = controller->BeginAxis(axis, value);

    // Create Promise
    napi_deferred deferred;
    napi_value promise;
    CHKRP(napi_create_promise(env, &deferred, &promise), CREATE_PROMISE);

    if (result == RET_OK) {
        CHKRP(napi_resolve_deferred(env, deferred, nullptr), RESOLVE_DEFERRED);
    } else {
        napi_value error = CreateBusinessError(env, result, "BeginAxis failed");
        CHKRP(napi_reject_deferred(env, deferred, error), REJECT_DEFERRED);
    }

    return promise;
}

napi_value MouseControllerUpdateAxis(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("MouseControllerUpdateAxis called");

    size_t argc = 2;
    napi_value argv[2];
    napi_value thisVar;
    CHKRP(napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), GET_CB_INFO);

    if (argc != 2) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    int32_t axis, value;
    CHKRP(napi_get_value_int32(env, argv[0], &axis), GET_VALUE_INT32);
    CHKRP(napi_get_value_int32(env, argv[1], &value), GET_VALUE_INT32);

    JsMouseController* controller = nullptr;
    CHKRP(napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller)), UNWRAP);
    if (controller == nullptr) {
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Execute synchronously
    int32_t result = controller->UpdateAxis(axis, value);

    // Create Promise
    napi_deferred deferred;
    napi_value promise;
    CHKRP(napi_create_promise(env, &deferred, &promise), CREATE_PROMISE);

    if (result == RET_OK) {
        CHKRP(napi_resolve_deferred(env, deferred, nullptr), RESOLVE_DEFERRED);
    } else {
        napi_value error = CreateBusinessError(env, result, "UpdateAxis failed");
        CHKRP(napi_reject_deferred(env, deferred, error), REJECT_DEFERRED);
    }

    return promise;
}

napi_value MouseControllerEndAxis(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("MouseControllerEndAxis called");

    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    CHKRP(napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr), GET_CB_INFO);

    if (argc != 1) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    int32_t axis;
    CHKRP(napi_get_value_int32(env, argv[0], &axis), GET_VALUE_INT32);

    JsMouseController* controller = nullptr;
    CHKRP(napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller)), UNWRAP);
    if (controller == nullptr) {
        THROWERR_CUSTOM(env, INPUT_SERVICE_EXCEPTION, "Input service exception");
        return nullptr;
    }

    // Execute synchronously
    int32_t result = controller->EndAxis(axis);

    // Create Promise
    napi_deferred deferred;
    napi_value promise;
    CHKRP(napi_create_promise(env, &deferred, &promise), CREATE_PROMISE);

    if (result == RET_OK) {
        CHKRP(napi_resolve_deferred(env, deferred, nullptr), RESOLVE_DEFERRED);
    } else {
        napi_value error = CreateBusinessError(env, result, "EndAxis failed");
        CHKRP(napi_reject_deferred(env, deferred, error), REJECT_DEFERRED);
    }

    return promise;
}

} // namespace MMI
} // namespace OHOS
