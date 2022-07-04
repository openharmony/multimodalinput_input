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

#include "virtual_joystick.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ABS_MAX_XY = 16383;
constexpr int32_t ABS_FUZZ = 63;
constexpr int32_t ABS_FLAT = 1023;
constexpr int32_t ABS_MAX_RZ = 255;
constexpr int32_t ABS_FLAT_RZ = 15;
constexpr int32_t ABS_MIN_HAT = -1;

AbsInfo absInfos[] = {
    {ABS_X, 0, ABS_MAX_XY, ABS_FUZZ, ABS_FLAT},
    {ABS_Y, 0, ABS_MAX_XY, ABS_FUZZ, ABS_FLAT},
    {ABS_RZ, 0, ABS_MAX_RZ, 0, ABS_FLAT_RZ},
    {ABS_THROTTLE, 0, ABS_MAX_RZ, 0, ABS_FLAT_RZ},
    {ABS_HAT0X, ABS_MIN_HAT, 1, 0, 0},
    {ABS_HAT0Y, ABS_MIN_HAT, 1, 0, 0}
};
} // namespace

VirtualJoystick::VirtualJoystick() : VirtualDevice("Virtual Joystick", BUS_USB, 0x44f, 0xb10a)
{
    eventTypes_ = { EV_KEY, EV_ABS };
    abs_ = { ABS_X, ABS_Y, ABS_RZ, ABS_THROTTLE, ABS_HAT0X, ABS_HAT0Y };
    keys_ = {
        BTN_TRIGGER, BTN_THUMB, BTN_THUMB2, BTN_TOP, BTN_TOP2,
        BTN_PINKIE, BTN_BASE, BTN_BASE2, BTN_BASE3, BTN_BASE4,
        BTN_BASE5, BTN_BASE6, BTN_DEAD
    };

    for (const auto &item : absInfos) {
        SetAbsValue(item);
    }
}
} // namespace MMI
} // namespace OHOS