/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "js_mouse_event.h"

#include "mmi_log.h"
#include "napi_constants.h"
#include "util_napi.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsMouseEvent"

namespace OHOS {
namespace MMI {
namespace {
enum class Action : int32_t {
    CANCEL = 0,
    MOVE = 1,
    BUTTON_DOWN = 2,
    BUTTON_UP = 3,
    AXIS_BEGIN = 4,
    AXIS_UPDATE = 5,
    AXIS_END = 6,
    ACTION_DOWN = 7,
    ACTION_UP = 8,
};

enum class Button : int32_t {
    LEFT = 0,
    MIDDLE = 1,
    RIGHT = 2,
    SIDE = 3,
    EXTRA = 4,
    FORWARD = 5,
    BACK = 6,
    TASK = 7
};

enum class Axis : int32_t {
    SCROLL_VERTICAL = 0,
    SCROLL_HORIZONTAL = 1,
    PINCH = 2,
};

enum class ToolType : int32_t {
    UNKNOWN = 0,
    MOUSE = 1,
    JOYSTICK = 2,
    TOUCHPAD = 3
};
} // namespace

napi_value JsMouseEvent::GetNapiInt32(napi_env env, int32_t code)
{
    CALL_DEBUG_ENTER;
    napi_value ret = nullptr;
    CHKRP(napi_create_int32(env, code, &ret), CREATE_INT32);
    return ret;
}

napi_value JsMouseEvent::EnumClassConstructor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 0;
    napi_value args[1] = { 0 };
    napi_value ret = nullptr;
    void *data = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &ret, &data), GET_CB_INFO);
    return ret;
}

napi_value JsMouseEvent::HandleActionPropertyArr(napi_env env, napi_value exports)
{
    napi_property_descriptor actionArr[] = {
        DECLARE_NAPI_STATIC_PROPERTY("CANCEL", GetNapiInt32(env, static_cast<int32_t>(Action::CANCEL))),
        DECLARE_NAPI_STATIC_PROPERTY("MOVE", GetNapiInt32(env, static_cast<int32_t>(Action::MOVE))),
        DECLARE_NAPI_STATIC_PROPERTY("BUTTON_DOWN", GetNapiInt32(env, static_cast<int32_t>(Action::BUTTON_DOWN))),
        DECLARE_NAPI_STATIC_PROPERTY("BUTTON_UP", GetNapiInt32(env, static_cast<int32_t>(Action::BUTTON_UP))),
        DECLARE_NAPI_STATIC_PROPERTY("AXIS_BEGIN", GetNapiInt32(env, static_cast<int32_t>(Action::AXIS_BEGIN))),
        DECLARE_NAPI_STATIC_PROPERTY("AXIS_UPDATE", GetNapiInt32(env, static_cast<int32_t>(Action::AXIS_UPDATE))),
        DECLARE_NAPI_STATIC_PROPERTY("AXIS_END", GetNapiInt32(env, static_cast<int32_t>(Action::AXIS_END))),
        DECLARE_NAPI_STATIC_PROPERTY("ACTION_DOWN", GetNapiInt32(env, static_cast<int32_t>(Action::ACTION_DOWN))),
        DECLARE_NAPI_STATIC_PROPERTY("ACTION_UP", GetNapiInt32(env, static_cast<int32_t>(Action::ACTION_UP))),
    };
    napi_value action = nullptr;
    CHKRP(napi_define_class(env, "Action", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(actionArr) / sizeof(*actionArr), actionArr, &action), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "Action", action), SET_NAMED_PROPERTY);
    return action;
}

napi_value JsMouseEvent::Export(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_property_descriptor toolTypeArr[] = {
        DECLARE_NAPI_STATIC_PROPERTY("UNKNOWN", GetNapiInt32(env, static_cast<int32_t>(ToolType::UNKNOWN))),
        DECLARE_NAPI_STATIC_PROPERTY("MOUSE", GetNapiInt32(env, static_cast<int32_t>(ToolType::MOUSE))),
        DECLARE_NAPI_STATIC_PROPERTY("JOYSTICK", GetNapiInt32(env, static_cast<int32_t>(ToolType::JOYSTICK))),
        DECLARE_NAPI_STATIC_PROPERTY("TOUCHPAD", GetNapiInt32(env, static_cast<int32_t>(ToolType::TOUCHPAD))),
    };
    napi_value toolType = nullptr;
    CHKRP(napi_define_class(env, "ToolType", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(toolTypeArr) / sizeof(*toolTypeArr), toolTypeArr, &toolType), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "ToolType", toolType), SET_NAMED_PROPERTY);

    HandleActionPropertyArr(env, exports);

    napi_property_descriptor buttonArr[] = {
        DECLARE_NAPI_STATIC_PROPERTY("LEFT", GetNapiInt32(env, static_cast<int32_t>(Button::LEFT))),
        DECLARE_NAPI_STATIC_PROPERTY("MIDDLE", GetNapiInt32(env, static_cast<int32_t>(Button::MIDDLE))),
        DECLARE_NAPI_STATIC_PROPERTY("RIGHT", GetNapiInt32(env, static_cast<int32_t>(Button::RIGHT))),
        DECLARE_NAPI_STATIC_PROPERTY("SIDE", GetNapiInt32(env, static_cast<int32_t>(Button::SIDE))),
        DECLARE_NAPI_STATIC_PROPERTY("EXTRA", GetNapiInt32(env, static_cast<int32_t>(Button::EXTRA))),
        DECLARE_NAPI_STATIC_PROPERTY("FORWARD", GetNapiInt32(env, static_cast<int32_t>(Button::FORWARD))),
        DECLARE_NAPI_STATIC_PROPERTY("BACK", GetNapiInt32(env, static_cast<int32_t>(Button::BACK))),
        DECLARE_NAPI_STATIC_PROPERTY("TASK", GetNapiInt32(env, static_cast<int32_t>(Button::TASK))),
    };
    napi_value button = nullptr;
    CHKRP(napi_define_class(env, "Button", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(buttonArr) / sizeof(*buttonArr), buttonArr, &button), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "Button", button), SET_NAMED_PROPERTY);

    napi_property_descriptor axisArr[] = {
        DECLARE_NAPI_STATIC_PROPERTY("SCROLL_VERTICAL", GetNapiInt32(env, static_cast<int32_t>(Axis::SCROLL_VERTICAL))),
        DECLARE_NAPI_STATIC_PROPERTY("SCROLL_HORIZONTAL",
            GetNapiInt32(env, static_cast<int32_t>(Axis::SCROLL_HORIZONTAL))),
        DECLARE_NAPI_STATIC_PROPERTY("PINCH", GetNapiInt32(env, static_cast<int32_t>(Axis::PINCH))),
    };
    napi_value axis = nullptr;
    CHKRP(napi_define_class(env, "Axis", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(axisArr) / sizeof(*axisArr), axisArr, &axis), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "Axis", axis), SET_NAMED_PROPERTY);
    return exports;
}
} // namespace MMI
} // namespace OHOS