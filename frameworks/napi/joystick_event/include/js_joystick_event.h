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

#ifndef JS_JOYSTICK_EVENT
#define JS_JOYSTICK_EVENT

#include "napi/native_node_api.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class JsJoystickEvent final {
public:
    enum class Action : int32_t {
        CANCEL = 0,
        BUTTON_DOWN = 1,
        BUTTON_UP = 2,
        ABS_BEGIN = 3,
        ABS_UPDATE = 4,
        ABS_END = 5,
    };

    enum class Button : int32_t {
        BUTTON_TL2 = 0,
        BUTTON_TR2 = 1,
        BUTTON_TL = 2,
        BUTTON_TR = 3,
        BUTTON_WEST = 4,
        BUTTON_SOUTH = 5,
        BUTTON_NORTH = 6,
        BUTTON_EAST = 7,
        BUTTON_START = 8,
        BUTTON_SELECT = 9,
        BUTTON_HOMEPAGE = 10,
        BUTTON_THUMBL = 11,
        BUTTON_THUMBR = 12,
        BUTTON_TRIGGER = 13,
        BUTTON_THUMB = 14,
        BUTTON_THUMB2 = 15,
        BUTTON_TOP = 16,
        BUTTON_TOP2 = 17,
        BUTTON_PINKIE = 18,
        BUTTON_BASE = 19,
        BUTTON_BASE2 = 20,
        BUTTON_BASE3 = 21,
        BUTTON_BASE4 = 22,
        BUTTON_BASE5 = 23,
        BUTTON_BASE6 = 24,
        BUTTON_DEAD = 25,
        BUTTON_C = 26,
        BUTTON_Z = 27,
        BUTTON_MODE = 28
    };

    enum class Axis : int32_t {
        ABS_X = 0,
        ABS_Y = 1,
        ABS_Z = 2,
        ABS_RZ = 3,
        ABS_GAS = 4,
        ABS_BRAKE = 5,
        ABS_HAT0X = 6,
        ABS_HAT0Y = 7,
        ABS_THROTTLE = 8,
    };

public:
    JsJoystickEvent() = default;
    ~JsJoystickEvent() = default;
    DISALLOW_COPY_AND_MOVE(JsJoystickEvent);
    static napi_value Export(napi_env env, napi_value exports);
private:
    static napi_value GetNapiInt32(napi_env env, int32_t code);
    static napi_value EnumClassConstructor(napi_env env, napi_callback_info info);
    static napi_value HandleButtonPropertyArr(napi_env env, napi_value exports);
};
} // namespace MMI
} // namespace OHOS

#endif // JS_JOYSTICK_EVENT