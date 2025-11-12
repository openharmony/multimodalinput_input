/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef INPUT_EVENT_CLIENT_H
#define INPUT_EVENT_CLIENT_H
#include <map>
#include "pointer_event.h"

using PointerEvent = OHOS::MMI::PointerEvent;

enum TAHE_ACTION {
    TAHE_CANCEL = 0,
    TAHE_MOVE = 1,
    TAHE_BUTTON_DOWN = 2,
    TAHE_BUTTON_UP = 3,
    TAHE_AXIS_BEGIN = 4,
    TAHE_AXIS_UPDATE = 5,
    TAHE_AXIS_END = 6,
    TAHE_ACTION_DOWN = 7,
    TAHE_ACTION_UP = 8,
};

enum TH_MOUSE_CALLBACK_EVENT {
    JS_CALLBACK_MOUSE_ACTION_MOVE = 1,
    JS_CALLBACK_MOUSE_ACTION_BUTTON_DOWN = 2,
    JS_CALLBACK_MOUSE_ACTION_BUTTON_UP = 3,
    JS_CALLBACK_POINTER_ACTION_DOWN = 7,
    JS_CALLBACK_POINTER_ACTION_UP = 8,
};

enum TH_TOUCH_CALLBACK_EVENT {
    JS_CALLBACK_TOUCH_ACTION_DOWN = 1,
    JS_CALLBACK_TOUCH_ACTION_MOVE = 2,
    JS_CALLBACK_TOUCH_ACTION_UP = 3,
};

enum TH_TOUCH_CALLBACK_SOURCETYPE {
    TOUCH_SCREEN = 0,
    PEN = 1,
    TOUCH_PAD = 2
};

enum TH_MOUSE_BUTTON {
    JS_MOUSE_BUTTON_LEFT = 0,
    JS_MOUSE_BUTTON_MIDDLE = 1,
    JS_MOUSE_BUTTON_RIGHT = 2,
    JS_MOUSE_BUTTON_SIDE = 3,
    JS_MOUSE_BUTTON_EXTRA = 4,
    JS_MOUSE_BUTTON_FORWARD = 5,
    JS_MOUSE_BUTTON_BACK = 6,
    JS_MOUSE_BUTTON_TASK = 7
};

static std::unordered_map<int32_t, int32_t> THMouseButton2Native = {
    { JS_MOUSE_BUTTON_LEFT, PointerEvent::MOUSE_BUTTON_LEFT },
    { JS_MOUSE_BUTTON_RIGHT, PointerEvent::MOUSE_BUTTON_RIGHT },
    { JS_MOUSE_BUTTON_MIDDLE, PointerEvent::MOUSE_BUTTON_MIDDLE },
    { JS_MOUSE_BUTTON_SIDE, PointerEvent::MOUSE_BUTTON_SIDE },
    { JS_MOUSE_BUTTON_EXTRA, PointerEvent::MOUSE_BUTTON_EXTRA },
    { JS_MOUSE_BUTTON_FORWARD, PointerEvent::MOUSE_BUTTON_FORWARD },
    { JS_MOUSE_BUTTON_BACK, PointerEvent::MOUSE_BUTTON_BACK },
    { JS_MOUSE_BUTTON_TASK, PointerEvent::MOUSE_BUTTON_TASK }
};

#endif