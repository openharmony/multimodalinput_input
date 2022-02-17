/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

OHOS::MMI::VirtualJoystick::VirtualJoystick() : VirtualDevice("Virtual Joystick",
    BUS_USB, 0x44f, 0xb10a)
{
    const int32_t ABS_MAX_XY = 16383;
    const int32_t ABS_FUZZ = 63;
    const int32_t ABS_FLAT = 1023;
    const int32_t ABS_MAX_RZ = 255;
    const int32_t ABS_FLAT_RZ = 15;
    const int32_t ABS_MIN_HAT = -1;

    dev_.absmin[ABS_X] = 0;
    dev_.absmax[ABS_X] = ABS_MAX_XY;
    dev_.absfuzz[ABS_X] = ABS_FUZZ;
    dev_.absflat[ABS_X] = ABS_FLAT;

    dev_.absmin[ABS_Y] = 0;
    dev_.absmax[ABS_Y] = ABS_MAX_XY;
    dev_.absfuzz[ABS_Y] = ABS_FUZZ;
    dev_.absflat[ABS_Y] = ABS_FLAT;

    dev_.absmin[ABS_RZ] = 0;
    dev_.absmax[ABS_RZ] = ABS_MAX_RZ;
    dev_.absfuzz[ABS_RZ] = 0;
    dev_.absflat[ABS_RZ] = ABS_FLAT_RZ;

    dev_.absmin[ABS_THROTTLE] = 0;
    dev_.absmax[ABS_THROTTLE] = ABS_MAX_RZ;
    dev_.absfuzz[ABS_THROTTLE] = 0;
    dev_.absflat[ABS_THROTTLE] = ABS_FLAT_RZ;

    dev_.absmin[ABS_HAT0X] = ABS_MIN_HAT;
    dev_.absmax[ABS_HAT0X] = 1;
    dev_.absfuzz[ABS_HAT0X] = 0;
    dev_.absflat[ABS_HAT0X] = 0;

    dev_.absmin[ABS_HAT0Y] = ABS_MIN_HAT;
    dev_.absmax[ABS_HAT0Y] = 1;
    dev_.absfuzz[ABS_HAT0Y] = 0;
    dev_.absflat[ABS_HAT0Y] = 0;
}

OHOS::MMI::VirtualJoystick::~VirtualJoystick() {}

const std::vector<uint32_t>& OHOS::MMI::VirtualJoystick::GetEventTypes() const
{
    static const std::vector<uint32_t> evt_types {
        EV_KEY, EV_ABS
    };
    return evt_types;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualJoystick::GetKeys() const
{
    static const std::vector<uint32_t> keys {
        BTN_TRIGGER, BTN_THUMB, BTN_THUMB2, BTN_TOP, BTN_TOP2, BTN_PINKIE, BTN_BASE,
        BTN_BASE2, BTN_BASE3, BTN_BASE4, BTN_BASE5, BTN_BASE6, BTN_DEAD
    };
    return keys;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualJoystick::GetAbs() const
{
    static const std::vector<uint32_t> abs {
        ABS_X, ABS_Y, ABS_RZ, ABS_THROTTLE, ABS_HAT0X, ABS_HAT0Y
    };
    return abs;
}