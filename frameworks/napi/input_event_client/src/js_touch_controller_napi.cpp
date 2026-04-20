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

constexpr int32_t TOUCH_INPUT_SERVICE_EXCEPTION = 3800001;
constexpr int32_t TOUCH_STATE_ERROR = 4300001;
constexpr const char* TOUCH_DOWN_STATE_ERROR_MSG = "The touch point is touching the display.";
constexpr const char* TOUCH_NOT_DOWN_STATE_ERROR_MSG = "The touch point is not touching the display.";

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
    if (code == TOUCH_STATE_ERROR && stateErrorMsg != nullptr) {
        return stateErrorMsg;
    }
    NapiError codeMsg;
    if (UtilNapiError::GetApiError(code, codeMsg)) {
        return codeMsg.msg;
    }
    if (UtilNapiError::GetApiError(TOUCH_INPUT_SERVICE_EXCEPTION, codeMsg)) {
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

bool ParseTouchPoint(napi_env env, napi_value value, int32_t& id, int32_t& displayId,
    int32_t& displayX, int32_t& displayY)
{
    if (GetNamedPropertyInt32(env, value, "id", id) != RET_OK) {
        return false;
    }
    if (GetNamedPropertyInt32(env, value, "displayId", displayId) != RET_OK) {
        return false;
    }
    if (GetNamedPropertyInt32(env, value, "displayX", displayX) != RET_OK) {
        return false;
    }
    if (GetNamedPropertyInt32(env, value, "displayY", displayY) != RET_OK) {
        return false;
    }
    return true;
}

template<typename Handler>
napi_value HandleTouchControllerPromise(napi_env env, napi_callback_info info, size_t argcExpected,
    const char* stateErrorMsg, Handler handler)
{
    size_t argc = argcExpected;
    napi_value argv[1] = { nullptr };
    napi_value thisVar = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (status != napi_ok) {
        MMI_HILOGE("GET_CB_INFO failed");
        return nullptr;
    }
    if (argc != argcExpected) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid parameter count");
        return nullptr;
    }

    JsTouchController* controller = nullptr;
    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&controller));
    if (status != napi_ok) {
        MMI_HILOGE("UNWRAP failed");
        return nullptr;
    }
    if (controller == nullptr) {
        ThrowTouchControllerError(env, TOUCH_INPUT_SERVICE_EXCEPTION);
        return nullptr;
    }

    constexpr int32_t HANDLER_THROWN_ERROR = INT32_MIN;
    int32_t result = handler(controller, env, argv[0]);
    if (result == HANDLER_THROWN_ERROR) {
        return nullptr;
    }

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
        return promise;
    }

    napi_value error = CreateBusinessError(env, result, stateErrorMsg);
    status = napi_reject_deferred(env, deferred, error);
    if (status != napi_ok) {
        MMI_HILOGE("REJECT_DEFERRED failed");
        return nullptr;
    }
    return promise;
}

} // namespace

napi_value CreateTouchController(napi_env env, napi_callback_info info)
{
    (void)info;
    MMI_HILOGD("CreateTouchController called");

    int32_t ret = InputManager::GetInstance()->CheckTouchControllerPermission();
    if (ret != RET_OK) {
        MMI_HILOGE("CheckTouchControllerPermission failed, ret=%{public}d", ret);
        if (ret == CAPABILITY_NOT_SUPPORTED || ret == ERROR_NO_PERMISSION) {
            ThrowTouchControllerError(env, ret);
        } else {
            ThrowTouchControllerError(env, TOUCH_INPUT_SERVICE_EXCEPTION);
        }
        return nullptr;
    }

    napi_value touchController;
    napi_status status = napi_create_object(env, &touchController);
    if (status != napi_ok) {
        MMI_HILOGE("CREATE_OBJECT failed");
        return nullptr;
    }

    auto* controller = new (std::nothrow) JsTouchController();
    if (controller == nullptr) {
        MMI_HILOGE("Failed to create JsTouchController");
        ThrowTouchControllerError(env, TOUCH_INPUT_SERVICE_EXCEPTION);
        return nullptr;
    }

    status = napi_wrap(
        env,
        touchController,
        controller,
        [](napi_env env, void* data, void* hint) {
            (void)env;
            (void)hint;
            MMI_HILOGD("JsTouchController finalizer called");
            delete static_cast<JsTouchController*>(data);
        },
        nullptr,
        nullptr);
    if (status != napi_ok) {
        MMI_HILOGE("Failed to wrap JsTouchController");
        delete controller;
        ThrowTouchControllerError(env, TOUCH_INPUT_SERVICE_EXCEPTION);
        return nullptr;
    }

    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("touchDown", TouchControllerTouchDown),
        DECLARE_NAPI_FUNCTION("touchMove", TouchControllerTouchMove),
        DECLARE_NAPI_FUNCTION("touchUp", TouchControllerTouchUp),
    };
    status = napi_define_properties(env, touchController, sizeof(descriptors) / sizeof(descriptors[0]), descriptors);
    if (status != napi_ok) {
        MMI_HILOGE("DEFINE_PROPERTIES failed");
        return nullptr;
    }

    napi_deferred deferred;
    napi_value promise;
    status = napi_create_promise(env, &deferred, &promise);
    if (status != napi_ok) {
        MMI_HILOGE("CREATE_PROMISE failed");
        return nullptr;
    }
    status = napi_resolve_deferred(env, deferred, touchController);
    if (status != napi_ok) {
        MMI_HILOGE("RESOLVE_DEFERRED failed");
        return nullptr;
    }
    MMI_HILOGD("CreateTouchController success");
    return promise;
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
            int32_t id = 0;
            int32_t displayId = 0;
            int32_t displayX = 0;
            int32_t displayY = 0;
            if (!ParseTouchPoint(env, argv0, id, displayId, displayX, displayY)) {
                return INT32_MIN;
            }
            return controller->TouchDown(id, displayId, displayX, displayY);
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
            int32_t id = 0;
            int32_t displayId = 0;
            int32_t displayX = 0;
            int32_t displayY = 0;
            if (!ParseTouchPoint(env, argv0, id, displayId, displayX, displayY)) {
                return INT32_MIN;
            }
            return controller->TouchMove(id, displayId, displayX, displayY);
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
            int32_t id = 0;
            int32_t displayId = 0;
            int32_t displayX = 0;
            int32_t displayY = 0;
            if (!ParseTouchPoint(env, argv0, id, displayId, displayX, displayY)) {
                return INT32_MIN;
            }
            return controller->TouchUp(id, displayId, displayX, displayY);
        });
}

} // namespace MMI
} // namespace OHOS
