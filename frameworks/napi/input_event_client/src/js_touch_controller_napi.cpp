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

#include "js_touch_controller_napi.h"

#include <climits>
#include <memory>
#include <string>

#include "input_manager.h"
#include "js_register_util.h"
#include "js_touch_controller.h"
#include "mmi_log.h"
#include "napi_constants.h"
#include "util_napi.h"
#include "util_napi_error.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsTouchControllerNapi"

namespace OHOS {
namespace MMI {

namespace {

// Internal code used only to select the public 4300001 error message.
constexpr int32_t TOUCH_ID_INVALID_ERROR = 4300003;
constexpr size_t TOUCH_CONTROLLER_ARG_COUNT = 1;
constexpr size_t CREATE_CONTROLLER_ARG_COUNT = 0;
constexpr const char* CONTROL_DEVICE_PERMISSION = "ohos.permission.CONTROL_DEVICE";

enum class TouchControllerOperation {
    CREATE,
    DOWN,
    MOVE,
    UP,
};

const char* GetTouchControllerActionName(TouchControllerOperation operation)
{
    switch (operation) {
        case TouchControllerOperation::DOWN:
            return "touch down";
        case TouchControllerOperation::MOVE:
            return "touch move";
        case TouchControllerOperation::UP:
            return "touch up";
        case TouchControllerOperation::CREATE:
        default:
            return "create TouchController";
    }
}

const char* GetTouchControllerStateErrorMsg(TouchControllerOperation operation)
{
    switch (operation) {
        case TouchControllerOperation::DOWN:
            return TOUCH_DOWN_STATE_ERROR_MSG;
        case TouchControllerOperation::MOVE:
        case TouchControllerOperation::UP:
            return TOUCH_NOT_DOWN_STATE_ERROR_MSG;
        case TouchControllerOperation::CREATE:
        default:
            return "Input service exception.";
    }
}

int32_t NormalizeTouchControllerErrorCode(int32_t code)
{
    if (code == ERROR_NO_PERMISSION) {
        return COMMON_PERMISSION_CHECK_ERROR;
    }
    if (code == CAPABILITY_NOT_SUPPORTED) {
        return INPUT_DEVICE_NOT_SUPPORTED;
    }
    return code;
}

int32_t GetExposedTouchControllerErrorCode(int32_t code)
{
    return code == TOUCH_ID_INVALID_ERROR ? ERROR_CODE_STATE_ERROR : code;
}

std::string MakePermissionErrorMsg(int32_t code, TouchControllerOperation operation)
{
    NapiError codeMsg;
    if (!UtilNapiError::GetApiError(code, codeMsg)) {
        return "Permission denied.";
    }
    char msg[300] = {};
    int32_t ret = sprintf_s(msg, sizeof(msg), codeMsg.msg.c_str(),
        GetTouchControllerActionName(operation), CONTROL_DEVICE_PERMISSION);
    if (ret <= 0) {
        return codeMsg.msg;
    }
    return msg;
}

std::string GetTouchControllerErrorMsg(int32_t code, TouchControllerOperation operation)
{
    if (code == COMMON_PERMISSION_CHECK_ERROR) {
        return MakePermissionErrorMsg(code, operation);
    }
    if (code == TOUCH_ID_INVALID_ERROR) {
        return TOUCH_ID_INVALID_ERROR_MSG;
    }
    if (code == ERROR_CODE_STATE_ERROR) {
        return GetTouchControllerStateErrorMsg(operation);
    }
    NapiError codeMsg;
    if (UtilNapiError::GetApiError(code, codeMsg)) {
        return codeMsg.msg;
    }
    if (UtilNapiError::GetApiError(CONTROLLER_INPUT_SERVICE_EXCEPTION, codeMsg)) {
        return codeMsg.msg;
    }
    return "Input service exception.";
}

napi_value CreateBusinessError(napi_env env, int32_t code, TouchControllerOperation operation)
{
    napi_value businessError = nullptr;
    napi_value errorCode = nullptr;
    napi_value errorMsg = nullptr;

    int32_t normalizedCode = NormalizeTouchControllerErrorCode(code);
    std::string msg = GetTouchControllerErrorMsg(normalizedCode, operation);
    int32_t exposedCode = GetExposedTouchControllerErrorCode(normalizedCode);
    napi_create_int32(env, exposedCode, &errorCode);
    napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH, &errorMsg);
    napi_create_error(env, nullptr, errorMsg, &businessError);
    napi_set_named_property(env, businessError, "code", errorCode);

    return businessError;
}

void ThrowTouchControllerError(napi_env env, int32_t code,
    TouchControllerOperation operation = TouchControllerOperation::CREATE)
{
    napi_value businessError = CreateBusinessError(env, code, operation);
    napi_throw(env, businessError);
}

bool ParseTouchPoint(napi_env env, napi_value value, TouchPointParams &touchPoint)
{
    if (GetNamedPropertyInt32(env, value, "id", touchPoint.id) != RET_OK) {
        return false;
    }
    if (GetNamedPropertyInt32(env, value, "displayId", touchPoint.displayId) != RET_OK) {
        return false;
    }
    if (GetNamedPropertyInt32(env, value, "displayX", touchPoint.displayX) != RET_OK) {
        return false;
    }
    if (GetNamedPropertyInt32(env, value, "displayY", touchPoint.displayY) != RET_OK) {
        return false;
    }
    return true;
}

napi_value GetTouchControllerCallbackInfo(napi_env env, napi_callback_info info, size_t argcExpected,
    napi_value &argv, JsTouchController **controller)
{
    size_t argc = argcExpected;
    napi_value thisVar = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, &argv, &thisVar, nullptr);
    if (status != napi_ok) {
        MMI_HILOGE("GET_CB_INFO failed");
        return nullptr;
    }
    if (argc != argcExpected) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(controller));
    if (status != napi_ok || controller == nullptr) {
        MMI_HILOGE("UNWRAP failed");
        return nullptr;
    }
    if (*controller == nullptr) {
        ThrowTouchControllerError(env, CONTROLLER_INPUT_SERVICE_EXCEPTION);
        return nullptr;
    }
    return thisVar;
}

bool CheckCreateTouchControllerArgs(napi_env env, napi_callback_info info)
{
    size_t argc = TOUCH_CONTROLLER_ARG_COUNT;
    napi_value argv[TOUCH_CONTROLLER_ARG_COUNT] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok) {
        MMI_HILOGE("GET_CB_INFO failed");
        return false;
    }
    if (argc != CREATE_CONTROLLER_ARG_COUNT) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return false;
    }
    return true;
}

int32_t HandleTouchControllerOperation(JsTouchController* controller, napi_env env, napi_value argv,
    TouchControllerOperation operation)
{
    napi_valuetype type = napi_undefined;
    if (napi_typeof(env, argv, &type) != napi_ok || type != napi_object) {
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "touch", "object");
        return INT32_MIN;
    }
    TouchPointParams touchPoint;
    if (!ParseTouchPoint(env, argv, touchPoint)) {
        return INT32_MIN;
    }
    switch (operation) {
        case TouchControllerOperation::DOWN:
            return controller->TouchDown(touchPoint.id, touchPoint.displayId, touchPoint.displayX, touchPoint.displayY);
        case TouchControllerOperation::MOVE:
            return controller->TouchMove(touchPoint.id, touchPoint.displayId, touchPoint.displayX, touchPoint.displayY);
        case TouchControllerOperation::UP:
            return controller->TouchUp(touchPoint.id, touchPoint.displayId, touchPoint.displayX, touchPoint.displayY);
        case TouchControllerOperation::CREATE:
        default:
            MMI_HILOGE("Invalid touch controller operation");
            return CONTROLLER_INPUT_SERVICE_EXCEPTION;
    }
}

napi_value ResolveTouchControllerPromise(napi_env env, napi_deferred deferred, napi_value promise)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    napi_status status = napi_resolve_deferred(env, deferred, result);
    if (status != napi_ok) {
        MMI_HILOGE("RESOLVE_DEFERRED failed");
        return nullptr;
    }
    return promise;
}

napi_value RejectTouchControllerPromise(napi_env env, napi_deferred deferred, napi_value promise,
    int32_t result, TouchControllerOperation operation)
{
    napi_value error = CreateBusinessError(env, result, operation);
    napi_status status = napi_reject_deferred(env, deferred, error);
    if (status != napi_ok) {
        MMI_HILOGE("REJECT_DEFERRED failed");
        return nullptr;
    }
    return promise;
}

napi_value HandleTouchControllerPromise(napi_env env, napi_callback_info info, TouchControllerOperation operation)
{
    napi_value argv = nullptr;
    JsTouchController* controller = nullptr;
    if (GetTouchControllerCallbackInfo(env, info, TOUCH_CONTROLLER_ARG_COUNT, argv, &controller) == nullptr) {
        return nullptr;
    }

    int32_t result = HandleTouchControllerOperation(controller, env, argv, operation);
    if (result == INT32_MIN) {
        MMI_HILOGE("TouchController handler failed");
        return nullptr;
    }

    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_status status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        MMI_HILOGE("CREATE_PROMISE failed");
        return nullptr;
    }
    if (result == RET_OK) {
        return ResolveTouchControllerPromise(env, deferred, promise);
    }
    return RejectTouchControllerPromise(env, deferred, promise, result, operation);
}

} // namespace

void FinalizeTouchController(napi_env env, void* data, void* hint)
{
    (void)env;
    (void)hint;
    MMI_HILOGD("JsTouchController finalizer called");
    delete static_cast<JsTouchController*>(data);
}

napi_status WrapTouchController(napi_env env, napi_value touchController, JsTouchController* controller)
{
    return napi_wrap(env, touchController, controller, FinalizeTouchController, nullptr, nullptr);
}

bool DefineTouchControllerProperties(napi_env env, napi_value touchController)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("touchDown", TouchControllerTouchDown),
        DECLARE_NAPI_FUNCTION("touchMove", TouchControllerTouchMove),
        DECLARE_NAPI_FUNCTION("touchUp", TouchControllerTouchUp),
    };
    napi_status status = napi_define_properties(env, touchController,
        sizeof(descriptors) / sizeof(descriptors[0]), descriptors);
    if (status != napi_ok) {
        MMI_HILOGE("DEFINE_PROPERTIES failed");
        return false;
    }
    return true;
}

napi_value ResolveCreateTouchControllerPromise(napi_env env, napi_value touchController)
{
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_status status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        MMI_HILOGE("CREATE_PROMISE failed");
        return nullptr;
    }
    status = napi_resolve_deferred(env, deferred, touchController);
    if (status != napi_ok) {
        MMI_HILOGE("RESOLVE_DEFERRED failed");
        return nullptr;
    }
    return promise;
}

napi_value CreateTouchController(napi_env env, napi_callback_info info)
{
    MMI_HILOGD("CreateTouchController called");
    if (!CheckCreateTouchControllerArgs(env, info)) {
        return nullptr;
    }
    std::shared_ptr<TouchControllerImpl> nativeImpl = nullptr;
    int32_t ret = InputManager::GetInstance()->CreateTouchController(nativeImpl);
    if (ret != RET_OK || nativeImpl == nullptr) {
        MMI_HILOGE("CreateTouchController failed, ret=%{public}d", ret);
        ThrowTouchControllerError(env, ret);
        return nullptr;
    }

    napi_value touchController = nullptr;
    if (napi_create_object(env, &touchController) != napi_ok) {
        MMI_HILOGE("CREATE_OBJECT failed");
        return nullptr;
    }
    auto* controller = new (std::nothrow) JsTouchController(nativeImpl);
    if (controller == nullptr) {
        MMI_HILOGE("Failed to create JsTouchController");
        ThrowTouchControllerError(env, CONTROLLER_INPUT_SERVICE_EXCEPTION);
        return nullptr;
    }
    if (WrapTouchController(env, touchController, controller) != napi_ok) {
        MMI_HILOGE("Failed to wrap JsTouchController");
        delete controller;
        ThrowTouchControllerError(env, CONTROLLER_INPUT_SERVICE_EXCEPTION);
        return nullptr;
    }
    if (!DefineTouchControllerProperties(env, touchController)) {
        return nullptr;
    }
    MMI_HILOGD("CreateTouchController success");
    return ResolveCreateTouchControllerPromise(env, touchController);
}

napi_value TouchControllerTouchDown(napi_env env, napi_callback_info info)
{
    return HandleTouchControllerPromise(env, info, TouchControllerOperation::DOWN);
}

napi_value TouchControllerTouchMove(napi_env env, napi_callback_info info)
{
    return HandleTouchControllerPromise(env, info, TouchControllerOperation::MOVE);
}

napi_value TouchControllerTouchUp(napi_env env, napi_callback_info info)
{
    return HandleTouchControllerPromise(env, info, TouchControllerOperation::UP);
}

} // namespace MMI
} // namespace OHOS
