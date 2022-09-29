/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "js_register_module.h"

#include <cinttypes>

#include "input_manager.h"
#include "js_register_util.h"
#include "napi_constants.h"
#include "util_napi.h"
#include "util_napi_error.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JSRegisterModule" };
} // namespace

static napi_value InjectEvent(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    napi_value result = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok) {
        MMI_HILOGE("Call napi_get_cb_info failed");
        napi_create_int32(env, MMI_STANDARD_EVENT_INVALID_PARAM, &result);
        return result;
    }
    NAPI_ASSERT(env, argc == 1, "paramater num error");

    napi_value keyHandle = nullptr;
    napi_get_named_property(env, argv[0], "KeyEvent", &keyHandle);
    napi_valuetype tmpType = napi_undefined;
    napi_typeof(env, keyHandle, &tmpType);
    NAPI_ASSERT(env, tmpType == napi_object, "parameter1 is not napi_object");

    auto keyEvent = KeyEvent::Create();
    if (keyEvent == nullptr) {
        MMI_HILOGE("The keyEvent is null");
        napi_create_int32(env, MMI_STANDARD_EVENT_INVALID_PARAM, &result);
        return result;
    }
    bool isPressed = false;
    int32_t ret = GetNamedPropertyBool(env, keyHandle, "isPressed", isPressed);
    if (ret != RET_OK) {
        MMI_HILOGE("Get isPressed failed");
        return result;
    }
    if (isPressed) {
        keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    } else {
        keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    }
    int32_t keyCode;
    ret = GetNamedPropertyInt32(env, keyHandle, "keyCode", keyCode);
    if (ret != RET_OK) {
        MMI_HILOGE("Get keyCode failed");
        return result;
    }
    keyEvent->SetKeyCode(keyCode);
    bool isIntercepted = false;
    if (!isIntercepted) {
        keyEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
    }
    int32_t keyDownDuration;
    ret = GetNamedPropertyInt32(env, keyHandle, "keyDownDuration", keyDownDuration);
    if (ret != RET_OK) {
        MMI_HILOGE("Get keyDownDuration failed");
        return result;
    }
    KeyEvent::KeyItem item;
    item.SetKeyCode(keyCode);
    item.SetPressed(isPressed);
    item.SetDownTime(static_cast<int64_t>(keyDownDuration));
    keyEvent->AddKeyItem(item);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    napi_create_int32(env, 0, &result);
    return result;
}

static napi_value InjectKeyEvent(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    napi_value result = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc == 0) {
        MMI_HILOGE("Paramater num error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "KeyEvent", "string");
        return nullptr;
    }
    napi_value keyHandle = nullptr;
    CHKRP(env, napi_get_named_property(env, argv[0], "KeyEvent", &keyHandle), GET_NAMED_PROPERTY);
    if (keyHandle == nullptr) {
        MMI_HILOGE("KeyEvent is nullptr");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "KeyEvent not exist");
        return nullptr;
    }
    napi_valuetype tmpType = napi_undefined;
    CHKRP(env, napi_typeof(env, keyHandle, &tmpType), TYPEOF);
    if (tmpType != napi_object) {
        MMI_HILOGE("KeyEvent is not napi_object");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "KeyEvent", "object");
        return nullptr;
    }
    auto keyEvent = KeyEvent::Create();
    if (keyEvent == nullptr) {
        MMI_HILOGE("The keyEvent is null");
        CHKRP(env, napi_create_int32(env, MMI_STANDARD_EVENT_INVALID_PARAM, &result), CREATE_INT32);
        return result;
    }
    bool isPressed = false;
    int32_t ret = GetNamedPropertyBool(env, keyHandle, "isPressed", isPressed);
    if (ret != RET_OK) {
        MMI_HILOGE("Get isPressed failed");
        return result;
    }
    if (isPressed) {
        keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    } else {
        keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    }
    int32_t keyCode;
    ret = GetNamedPropertyInt32(env, keyHandle, "keyCode", keyCode);
    if (ret != RET_OK) {
        MMI_HILOGE("Get keyCode failed");
        return result;
    }
    keyEvent->SetKeyCode(keyCode);
    bool isIntercepted = false;
    if (!isIntercepted) {
        keyEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
    }
    int32_t keyDownDuration;
    ret = GetNamedPropertyInt32(env, keyHandle, "keyDownDuration", keyDownDuration);
    if (ret != RET_OK) {
        MMI_HILOGE("Get keyDownDuration failed");
        return result;
    }
    KeyEvent::KeyItem item;
    item.SetKeyCode(keyCode);
    item.SetPressed(isPressed);
    item.SetDownTime(static_cast<int64_t>(keyDownDuration));
    keyEvent->AddKeyItem(item);
    InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    CHKRP(env, napi_create_int32(env, 0, &result), CREATE_INT32);
    return result;
}

EXTERN_C_START
static napi_value MmiInit(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("injectEvent", InjectEvent),
        DECLARE_NAPI_FUNCTION("injectKeyEvent", InjectKeyEvent),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}
EXTERN_C_END

static napi_module mmiModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = MmiInit,
    .nm_modname = "multimodalInput.inputEventClient",
    .nm_priv = ((void*)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&mmiModule);
}
} // namespace MMI
} // namespace OHOS
