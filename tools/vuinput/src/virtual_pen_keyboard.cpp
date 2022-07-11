/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "virtual_pen_keyboard.h"

namespace OHOS {
namespace MMI {
VirtualPenKeyboard::VirtualPenKeyboard() : VirtualDevice("V-Pencil-keyboard", BUS_BLUETOOTH, 0x12d1, 0x10a5)
{
    eventTypes_ = { EV_KEY, EV_MSC };
    miscellaneous_ = { MSC_SCAN };
    keys_ = {
        KEY_LEFTCTRL, KEY_LEFTSHIFT, KEY_RIGHTSHIFT, KEY_KPASTERISK, KEY_LEFTALT, KEY_NUMLOCK, KEY_KP7, KEY_KP8,
        KEY_KP9, KEY_KPMINUS, KEY_KP4, KEY_KP5, KEY_KP6, KEY_KPPLUS, KEY_KP1, KEY_KP2, KEY_KP3, KEY_KP0, KEY_KPDOT,
        KEY_102ND, KEY_KPENTER, KEY_RIGHTCTRL, KEY_KPSLASH, KEY_RIGHTALT, KEY_UP, KEY_PAGEUP, KEY_LEFT, KEY_RIGHT,
        KEY_END, KEY_DOWN, KEY_PAGEDOWN, KEY_DELETE, KEY_POWER, KEY_KPEQUAL, KEY_LEFTMETA, KEY_RIGHTMETA, KEY_COMPOSE,
        KEY_F13, KEY_F14, KEY_F15, KEY_F16, KEY_F17, KEY_F18, KEY_F19, KEY_F20, KEY_F21
    };
}
} // namespace MMI
} // namespace OHOS