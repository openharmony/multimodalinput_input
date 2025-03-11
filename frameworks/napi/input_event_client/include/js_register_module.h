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

#ifndef JS_REGISTER_MODULE_H
#define JS_REGISTER_MODULE_H

#include "define_multimodal.h"
#include "js_joystick_event.h"

enum MOUSE_CALLBACK_EVENT {
    JS_CALLBACK_MOUSE_ACTION_MOVE = 1,
    JS_CALLBACK_MOUSE_ACTION_BUTTON_DOWN = 2,
    JS_CALLBACK_MOUSE_ACTION_BUTTON_UP = 3,
    JS_CALLBACK_POINTER_ACTION_DOWN = 7,
    JS_CALLBACK_POINTER_ACTION_UP = 8,
};

enum TOUCH_CALLBACK_EVENT {
    JS_CALLBACK_TOUCH_ACTION_DOWN = 1,
    JS_CALLBACK_TOUCH_ACTION_MOVE = 2,
    JS_CALLBACK_TOUCH_ACTION_UP = 3,
};

enum TOUCH_CALLBACK_SOURCETYPE {
    TOUCH_SCREEN = 0,
    PEN = 1,
    TOUCH_PAD = 2
};
#endif // JS_REGISTER_MODULE_H