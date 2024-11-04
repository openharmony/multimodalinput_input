/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "js_joystick_event.h"

#include "mmi_log.h"
#include "napi_constants.h"
#include "util_napi.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsJoystickEvent"

namespace OHOS {
namespace MMI {
napi_value JsJoystickEvent::GetNapiInt32(napi_env env, int32_t code)
{
    CALL_DEBUG_ENTER;
    napi_value ret = nullptr;
    CHKRP(napi_create_int32(env, code, &ret), CREATE_INT32);
    return ret;
}

napi_value JsJoystickEvent::EnumClassConstructor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 0;
    napi_value args[1] = { 0 };
    napi_value ret = nullptr;
    void *data = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &ret, &data), GET_CB_INFO);
    return ret;
}

napi_value JsJoystickEvent::HandleButtonPropertyArr(napi_env env, napi_value exports)
{
    napi_property_descriptor buttonArr[] = {
        DECLARE_NAPI_STATIC_PROPERTY("TL2", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_TL2))),
        DECLARE_NAPI_STATIC_PROPERTY("TR2", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_TR2))),
        DECLARE_NAPI_STATIC_PROPERTY("TL", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_TL))),
        DECLARE_NAPI_STATIC_PROPERTY("TR", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_TR))),
        DECLARE_NAPI_STATIC_PROPERTY("WEST", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_WEST))),
        DECLARE_NAPI_STATIC_PROPERTY("SOUTH", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_SOUTH))),
        DECLARE_NAPI_STATIC_PROPERTY("NORTH", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_NORTH))),
        DECLARE_NAPI_STATIC_PROPERTY("EAST", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_EAST))),
        DECLARE_NAPI_STATIC_PROPERTY("START", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_START))),
        DECLARE_NAPI_STATIC_PROPERTY("SELECT", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_SELECT))),
        DECLARE_NAPI_STATIC_PROPERTY("HOMEPAGE", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_HOMEPAGE))),
        DECLARE_NAPI_STATIC_PROPERTY("THUMB_L", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_THUMBL))),
        DECLARE_NAPI_STATIC_PROPERTY("THUMB_R", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_THUMBR))),
        DECLARE_NAPI_STATIC_PROPERTY("TRIGGER", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_TRIGGER))),
        DECLARE_NAPI_STATIC_PROPERTY("THUMB", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_THUMB))),
        DECLARE_NAPI_STATIC_PROPERTY("THUMB2", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_THUMB2))),
        DECLARE_NAPI_STATIC_PROPERTY("TOP", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_TOP))),
        DECLARE_NAPI_STATIC_PROPERTY("TOP2", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_TOP2))),
        DECLARE_NAPI_STATIC_PROPERTY("PINKIE", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_PINKIE))),
        DECLARE_NAPI_STATIC_PROPERTY("BASE", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_BASE))),
        DECLARE_NAPI_STATIC_PROPERTY("BASE2", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_BASE2))),
        DECLARE_NAPI_STATIC_PROPERTY("BASE3", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_BASE3))),
        DECLARE_NAPI_STATIC_PROPERTY("BASE4", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_BASE4))),
        DECLARE_NAPI_STATIC_PROPERTY("BASE5", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_BASE5))),
        DECLARE_NAPI_STATIC_PROPERTY("BASE6", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_BASE6))),
        DECLARE_NAPI_STATIC_PROPERTY("DEAD", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_DEAD))),
        DECLARE_NAPI_STATIC_PROPERTY("C", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_C))),
        DECLARE_NAPI_STATIC_PROPERTY("Z", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_Z))),
        DECLARE_NAPI_STATIC_PROPERTY("MODE", GetNapiInt32(env, static_cast<int32_t>(Button::BUTTON_MODE))),
    };
    napi_value button = nullptr;
    CHKRP(napi_define_class(env, "Button", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(buttonArr) / sizeof(*buttonArr), buttonArr, &button), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "Button", button), SET_NAMED_PROPERTY);
    return button;
}

napi_value JsJoystickEvent::Export(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;

    napi_property_descriptor actionArr[] = {
        DECLARE_NAPI_STATIC_PROPERTY("CANCEL", GetNapiInt32(env, static_cast<int32_t>(Action::CANCEL))),
        DECLARE_NAPI_STATIC_PROPERTY("BUTTON_DOWN", GetNapiInt32(env, static_cast<int32_t>(Action::BUTTON_DOWN))),
        DECLARE_NAPI_STATIC_PROPERTY("BUTTON_UP", GetNapiInt32(env, static_cast<int32_t>(Action::BUTTON_UP))),
        DECLARE_NAPI_STATIC_PROPERTY("AXIS_BEGIN", GetNapiInt32(env, static_cast<int32_t>(Action::ABS_BEGIN))),
        DECLARE_NAPI_STATIC_PROPERTY("AXIS_UPDATE", GetNapiInt32(env, static_cast<int32_t>(Action::ABS_UPDATE))),
        DECLARE_NAPI_STATIC_PROPERTY("AXIS_END", GetNapiInt32(env, static_cast<int32_t>(Action::ABS_END))),
    };
    napi_value action = nullptr;
    CHKRP(napi_define_class(env, "Action", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(actionArr) / sizeof(*actionArr), actionArr, &action), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "Action", action), SET_NAMED_PROPERTY);

    HandleButtonPropertyArr(env, exports);
    
    napi_property_descriptor axisArr[] = {
        DECLARE_NAPI_STATIC_PROPERTY("ABS_X", GetNapiInt32(env, static_cast<int32_t>(Axis::ABS_X))),
        DECLARE_NAPI_STATIC_PROPERTY("ABS_Y", GetNapiInt32(env, static_cast<int32_t>(Axis::ABS_Y))),
        DECLARE_NAPI_STATIC_PROPERTY("ABS_Z", GetNapiInt32(env, static_cast<int32_t>(Axis::ABS_Z))),
        DECLARE_NAPI_STATIC_PROPERTY("ABS_RZ", GetNapiInt32(env, static_cast<int32_t>(Axis::ABS_RZ))),
        DECLARE_NAPI_STATIC_PROPERTY("ABS_GAS", GetNapiInt32(env, static_cast<int32_t>(Axis::ABS_GAS))),
        DECLARE_NAPI_STATIC_PROPERTY("ABS_BRAKE", GetNapiInt32(env, static_cast<int32_t>(Axis::ABS_BRAKE))),
        DECLARE_NAPI_STATIC_PROPERTY("ABS_HAT0X", GetNapiInt32(env, static_cast<int32_t>(Axis::ABS_HAT0X))),
        DECLARE_NAPI_STATIC_PROPERTY("ABS_HAT0Y", GetNapiInt32(env, static_cast<int32_t>(Axis::ABS_HAT0Y))),
        DECLARE_NAPI_STATIC_PROPERTY("ABS_THROTTLE", GetNapiInt32(env, static_cast<int32_t>(Axis::ABS_THROTTLE))),
    };
    napi_value axis = nullptr;
    CHKRP(napi_define_class(env, "Axis", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(axisArr) / sizeof(*axisArr), axisArr, &axis), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "Axis", axis), SET_NAMED_PROPERTY);

    return exports;
}
} // namespace MMI
} // namespace OHOS