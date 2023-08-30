/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("Parameter number error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "parameter number error");
        return nullptr;
    }
    napi_valuetype tmpType = napi_undefined;
    CHKRP(napi_typeof(env, argv[0], &tmpType), TYPEOF);
    if (tmpType != napi_object) {
        MMI_HILOGE("KeyEvent is not napi_object");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "KeyEvent", "object");
        return nullptr;
    }
    napi_value keyHandle = nullptr;
    CHKRP(napi_get_named_property(env, argv[0], "KeyEvent", &keyHandle), GET_NAMED_PROPERTY);
    if (keyHandle == nullptr) {
        MMI_HILOGE("KeyEvent is nullptr");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "KeyEvent not found");
        return nullptr;
    }
    CHKRP(napi_typeof(env, keyHandle, &tmpType), TYPEOF);
    if (tmpType != napi_object) {
        MMI_HILOGE("KeyEvent is not napi_object");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "KeyEvent", "object");
        return nullptr;
    }
    auto keyEvent = KeyEvent::Create();
    CHKPP(keyEvent);

    bool isPressed = false;
    int32_t ret = GetNamedPropertyBool(env, keyHandle, "isPressed", isPressed);
    if (ret != RET_OK) {
        MMI_HILOGE("Get isPressed failed");
        return nullptr;
    }

    napi_value keyCodes;
    CHKRP(napi_get_named_property(env, keyHandle, "keyCodes", &keyCodes), GET_NAMED_PROPERTY);
    if (keyCodes == nullptr) {
        MMI_HILOGE("The keyCodes is null");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "keyCodes not found");
        return nullptr;
    }
    napi_valuetype Type = napi_undefined;
    CHKRP(napi_typeof(env, keyCodes, &Type), TYPEOF);
    if (Type != napi_object) {
        MMI_HILOGE("The value is not object");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "keyCodes", "object");
        return nullptr;
    }

    uint32_t size = 0;
    CHKRP(napi_get_array_length(env, keyCodes, &size), GET_ARRAY_LENGTH);
    int32_t data = 0;
    std::vector<int32_t> downKey;
    for (uint32_t i = 0; i < size; ++i) {
        napi_value keyValue = nullptr;
        CHKRP(napi_get_element(env, keyCodes, i, &keyValue), GET_ELEMENT);
        napi_valuetype valuetype;
        CHKRP(napi_typeof(env, keyValue, &valuetype), TYPEOF);
        if (valuetype != napi_number) {
            MMI_HILOGE("keyCodes parameter type error");
            return nullptr;
        }
        CHKRP(napi_get_value_int32(env, keyValue, &data), GET_VALUE_INT32);
        downKey.push_back(data);
    }

    bool isIntercepted = false;
    ret = GetNamedPropertyBool(env, keyHandle, "isIntercepted", isIntercepted);
    if (ret != RET_OK) {
        MMI_HILOGE("Get isIntercepted failed");
        return nullptr;
    }
    MMI_HILOGD("isIntercepted:%{public}d", isIntercepted);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);

    int32_t keyDownDuration;
    ret = GetNamedPropertyInt32(env, keyHandle, "keyDownDuration", keyDownDuration);
    if (ret != RET_OK) {
        MMI_HILOGE("Get keyDownDuration failed");
        return nullptr;
    }
    if (keyDownDuration < 0) {
        MMI_HILOGE("keyDownDuration:%{public}d is less 0, can not process", keyDownDuration);
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "keyDownDuration must be greater than or equal to 0");
        return nullptr;
    }

    KeyEvent::KeyItem item[downKey.size()];
    for (size_t i = 0; i < downKey.size(); i++) {
        keyEvent->SetKeyCode(data);
        if (isPressed) {
            keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
        } else {
            keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
        }
        item[i].SetKeyCode(downKey[i]);
        item[i].SetPressed(isPressed);
        item[i].SetDownTime(static_cast<int64_t>(keyDownDuration));
        keyEvent->AddKeyItem(item[i]);
    }
    InputManager::GetInstance()->SimulateInputEvent(keyEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(keyDownDuration));
    CHKRP(napi_create_int32(env, 0, &result), CREATE_INT32);
    return result;
}

static napi_value InjectMouseEvent(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    napi_value result = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("Parameter number error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "parameter number error");
        return nullptr;
    }
    napi_valuetype tmpType = napi_undefined;
    CHKRP(napi_typeof(env, argv[0], &tmpType), TYPEOF);
    if (tmpType != napi_object) {
        MMI_HILOGE("MouseEvent is not napi_object");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "MouseEvent", "object");
        return nullptr;
    }
    napi_value mouseHandle = nullptr;
    CHKRP(napi_get_named_property(env, argv[0], "MouseEvent", &mouseHandle), GET_NAMED_PROPERTY);
    if (mouseHandle == nullptr) {
        MMI_HILOGE("MouseEvent is nullptr");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "MouseEvent not found");
        return nullptr;
    }
    CHKRP(napi_typeof(env, mouseHandle, &tmpType), TYPEOF);
    if (tmpType != napi_object) {
        MMI_HILOGE("MouseEvent is not napi_object");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "MouseEvent", "object");
        return nullptr;
    }
    auto pointerEvent = PointerEvent::Create();
    PointerEvent::PointerItem item;
    CHKPP(pointerEvent);

    int32_t action;
    int32_t ret = GetNamedPropertyInt32(env, mouseHandle, "action", action);
    if (ret != RET_OK) {
        MMI_HILOGE("Get action failed");
        return nullptr;
    }
    switch (action) {
        case JS_CALLBACK_MOUSE_ACTION_MOVE : {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
            break;
        }
        case JS_CALLBACK_MOUSE_ACTION_BUTTON_DOWN: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
            item.SetPressed(true);
            break;
        }
        case JS_CALLBACK_MOUSE_ACTION_BUTTON_UP: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
            item.SetPressed(false);
            break;
        }
        case JS_CALLBACK_POINTER_ACTION_DOWN : {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
            item.SetPressed(true);
            break;
        }
        case JS_CALLBACK_POINTER_ACTION_UP: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
            item.SetPressed(false);
            break;
        }
        default: {
            MMI_HILOGE("action is unknown");
            break;
        }
    }

    if(action == JS_CALLBACK_MOUSE_ACTION_BUTTON_DOWN || action == JS_CALLBACK_MOUSE_ACTION_BUTTON_UP) {
        int32_t button;
        ret = GetNamedPropertyInt32(env, mouseHandle, "button", button);
        if (ret != RET_OK) {
            MMI_HILOGE("Get button failed");
            return nullptr;
        }
        if (button < 0) {
            MMI_HILOGE("button:%{public}d is less 0, can not process", button);
            THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "button must be greater than or equal to 0");
            return nullptr;
        }
        pointerEvent->SetButtonId(button);
        pointerEvent->SetButtonPressed(button);
    }

    int32_t screenX;
    ret = GetNamedPropertyInt32(env, mouseHandle, "screenX", screenX);
    if (ret != RET_OK) {
        MMI_HILOGE("Get screenX failed");
        return nullptr;
    }

    int32_t screenY;
    ret = GetNamedPropertyInt32(env, mouseHandle, "screenY", screenY);
    if (ret != RET_OK) {
        MMI_HILOGE("Get screenY failed");
        return nullptr;
    }

    int32_t toolType;
    ret = GetNamedPropertyInt32(env, mouseHandle, "toolType", toolType);
    if (ret != RET_OK) {
        MMI_HILOGE("Get toolType failed");
        return nullptr;
    }
    if (toolType < 0) {
        MMI_HILOGE("toolType:%{public}d is less 0, can not process", toolType);
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "toolType must be greater than or equal to 0");
        return nullptr;
    }
    pointerEvent->SetSourceType(toolType);
    item.SetPointerId(0);
    item.SetDisplayX(screenX);
    item.SetDisplayY(screenY);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    CHKRP(napi_create_int32(env, 0, &result), CREATE_INT32);
    return result;
}

static napi_value InjectTouchEvent(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    napi_value result = nullptr;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("Parameter number error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "parameter number error");
        return nullptr;
    }
    napi_valuetype tmpType = napi_undefined;
    CHKRP(napi_typeof(env, argv[0], &tmpType), TYPEOF);
    if (tmpType != napi_object) {
        MMI_HILOGE("TouchEvent is not napi_object");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "TouchEvent", "object");
        return nullptr;
    }
    napi_value touchHandle = nullptr;
    CHKRP(napi_get_named_property(env, argv[0], "TouchEvent", &touchHandle), GET_NAMED_PROPERTY);
    if (touchHandle == nullptr) {
        MMI_HILOGE("TouchEvent is nullptr");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "TouchEvent not found");
        return nullptr;
    }
    CHKRP(napi_typeof(env, touchHandle, &tmpType), TYPEOF);
    if (tmpType != napi_object) {
        MMI_HILOGE("TouchEvent is not napi_object");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "TouchEvent", "object");
        return nullptr;
    }
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);

    int32_t action;
    PointerEvent::PointerItem item;
    int32_t ret = GetNamedPropertyInt32(env, touchHandle, "action", action);
    if (ret != RET_OK) {
        MMI_HILOGE("Get action failed");
        return nullptr;
    }
    switch (action) {
        case JS_CALLBACK_TOUCH_ACTION_DOWN: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
            item.SetPressed(true);
            break;
        }
        case JS_CALLBACK_TOUCH_ACTION_MOVE: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
            break;
        }
        case JS_CALLBACK_TOUCH_ACTION_UP: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
            item.SetPressed(false);
            break;
        }
        default: {
            MMI_HILOGE("action is unknown");
            break;
        }
    }

    int32_t sourceType;
    ret = GetNamedPropertyInt32(env, touchHandle, "sourceType", sourceType);
    if (ret != RET_OK) {
        MMI_HILOGE("Get sourceType failed");
        return nullptr;
    }
    if (sourceType < 0) {
        MMI_HILOGE("sourceType:%{public}d is less 0, can not process", sourceType);
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "sourceType must be greater than or equal to 0");
        return nullptr;
    }
    if (sourceType == TOUCH_SCREEN) {
        sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    }

    int32_t screenX;
    ret = GetNamedPropertyInt32(env, touchHandle, "screenX", screenX);
    if (ret != RET_OK) {
        MMI_HILOGE("Get screenX failed");
        return nullptr;
    }

    int32_t screenY;
    ret = GetNamedPropertyInt32(env, touchHandle, "screenY", screenY);
    if (ret != RET_OK) {
        MMI_HILOGE("Get screenY failed");
        return nullptr;
    }

    int64_t pressedTime;
    ret = GetNamedPropertyInt64(env, touchHandle, "pressedTime", pressedTime);
    if (ret != RET_OK) {
        MMI_HILOGE("Get pressed time failed");
        return nullptr;
    }
    item.SetDisplayX(screenX);
    item.SetDisplayY(screenY);
    item.SetPointerId(0);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetSourceType(sourceType);
    pointerEvent->SetActionTime(pressedTime);
    if ((action == JS_CALLBACK_TOUCH_ACTION_MOVE) || (action == JS_CALLBACK_TOUCH_ACTION_UP)) {
        pointerEvent->UpdatePointerItem(0, item);
    }
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    CHKRP(napi_create_int32(env, 0, &result), CREATE_INT32);
    return result;
}

EXTERN_C_START
static napi_value MmiInit(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("injectEvent", InjectEvent),
        DECLARE_NAPI_FUNCTION("injectMouseEvent", InjectMouseEvent),
        DECLARE_NAPI_FUNCTION("injectTouchEvent", InjectTouchEvent),
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
