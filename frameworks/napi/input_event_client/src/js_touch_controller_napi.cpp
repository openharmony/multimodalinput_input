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

std::string GetTouchControllerErrorMsg(int32_t code, const char* stateErrorMsg = nullptr)
{
    code = NormalizeTouchControllerErrorCode(code);
    if (code == ERROR_CODE_STATE_ERROR && stateErrorMsg != nullptr) {
        return stateErrorMsg;
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

napi_value CreateBusinessError(napi_env env, int32_t code, const char* stateErrorMsg = nullptr)
{
    napi_value businessError = nullptr;
    napi_value errorCode = nullptr;
    napi_value errorMsg = nullptr;

    code = NormalizeTouchControllerErrorCode(code);
    std::string msg = GetTouchControllerErrorMsg(code, stateErrorMsg);
    napi_create_int32(env, code, &errorCode);
    napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH, &errorMsg);
    napi_create_error(env, nullptr, errorMsg, &businessError);
    napi_set_named_property(env, businessError, "code", errorCode);

    return businessError;
}

void ThrowTouchControllerError(napi_env env, int32_t code)
{
    napi_value businessError = CreateBusinessError(env, code);
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

napi_value ResolveTouchControllerPromise(napi_env env, napi_deferred deferred, napi_value promise)
{
    napi_status status = napi_resolve_deferred(env, deferred, nullptr);
    if (status != napi_ok) {
        MMI_HILOGE("RESOLVE_DEFERRED failed");
        return nullptr;
    }
    return promise;
}

napi_value RejectTouchControllerPromise(napi_env env, napi_deferred deferred, napi_value promise,
    int32_t result, const char* stateErrorMsg)
{
    napi_value error = CreateBusinessError(env, result, stateErrorMsg);
    napi_status status = napi_reject_deferred(env, deferred, error);
    if (status != napi_ok) {
        MMI_HILOGE("REJECT_DEFERRED failed");
        return nullptr;
    }
    return promise;
}

template<typename Handler>
napi_value HandleTouchControllerPromise(napi_env env, napi_callback_info info, size_t argcExpected,
    const char* stateErrorMsg, Handler handler)
{
    napi_value argv = nullptr;
    JsTouchController* controller = nullptr;
    if (GetTouchControllerCallbackInfo(env, info, argcExpected, argv, &controller) == nullptr) {
        return nullptr;
    }

    int32_t result = handler(controller, env, argv);
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
    return RejectTouchControllerPromise(env, deferred, promise, result, stateErrorMsg);
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
    (void)info;
    MMI_HILOGD("CreateTouchController called");
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
    return HandleTouchControllerPromise(env, info, 1, TOUCH_DOWN_STATE_ERROR_MSG,
        [](JsTouchController* controller, napi_env env, napi_value argv0) -> int32_t {
            napi_valuetype type = napi_undefined;
            if (napi_typeof(env, argv0, &type) != napi_ok || type != napi_object) {
                THROWERR_API9(env, COMMON_PARAMETER_ERROR, "touch", "object");
                return INT32_MIN;
            }
            TouchPointParams touchPoint;
            if (!ParseTouchPoint(env, argv0, touchPoint)) {
                return INT32_MIN;
            }
            return controller->TouchDown(touchPoint.id, touchPoint.displayId, touchPoint.displayX,
                touchPoint.displayY);
        });
}

napi_value TouchControllerTouchMove(napi_env env, napi_callback_info info)
{
    return HandleTouchControllerPromise(env, info, 1, TOUCH_NOT_DOWN_STATE_ERROR_MSG,
        [](JsTouchController* controller, napi_env env, napi_value argv0) -> int32_t {
            napi_valuetype type = napi_undefined;
            if (napi_typeof(env, argv0, &type) != napi_ok || type != napi_object) {
                THROWERR_API9(env, COMMON_PARAMETER_ERROR, "touch", "object");
                return INT32_MIN;
            }
            TouchPointParams touchPoint;
            if (!ParseTouchPoint(env, argv0, touchPoint)) {
                return INT32_MIN;
            }
            return controller->TouchMove(touchPoint.id, touchPoint.displayId, touchPoint.displayX,
                touchPoint.displayY);
        });
}

napi_value TouchControllerTouchUp(napi_env env, napi_callback_info info)
{
    return HandleTouchControllerPromise(env, info, 1, TOUCH_NOT_DOWN_STATE_ERROR_MSG,
        [](JsTouchController* controller, napi_env env, napi_value argv0) -> int32_t {
            napi_valuetype type = napi_undefined;
            if (napi_typeof(env, argv0, &type) != napi_ok || type != napi_object) {
                THROWERR_API9(env, COMMON_PARAMETER_ERROR, "touch", "object");
                return INT32_MIN;
            }
            TouchPointParams touchPoint;
            if (!ParseTouchPoint(env, argv0, touchPoint)) {
                return INT32_MIN;
            }
            return controller->TouchUp(touchPoint.id, touchPoint.displayId, touchPoint.displayX,
                touchPoint.displayY);
        });
}

} // namespace MMI
} // namespace OHOS
