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

#include "virtual_gamepad.h"

OHOS::MMI::VirtualGamePad::VirtualGamePad() : VirtualDevice("Virtual GamePad",
    BUS_USB, 0x79, 0x181c)
{
    const int32_t ABS_MAX_RXYZ = 255;
    const int32_t ABS_FLAT = 15;
    const int32_t ABS_MIN_HAT = -1;
    const int32_t ABS_min_VALUE = -32768;
    const int32_t ABS_MAX_VALUE = 32767;
    const int32_t ABS_FUZZ_VALUE = 16;
    const int32_t ABS_FLAT_VALUE = 128;

    dev_.absmin[ABS_X] = 0;
    dev_.absmax[ABS_X] = ABS_MAX_RXYZ;
    dev_.absfuzz[ABS_X] = 0;
    dev_.absflat[ABS_X] = ABS_FLAT;

    dev_.absmin[ABS_Y] = 0;
    dev_.absmax[ABS_Y] = ABS_MAX_RXYZ;
    dev_.absfuzz[ABS_Y] = 0;
    dev_.absflat[ABS_Y] = ABS_FLAT;

    dev_.absmin[ABS_Z] = 0;
    dev_.absmax[ABS_Z] = ABS_MAX_RXYZ;
    dev_.absfuzz[ABS_Z] = 0;
    dev_.absflat[ABS_Z] = ABS_FLAT;

    dev_.absmin[ABS_RX] = ABS_min_VALUE;
    dev_.absmax[ABS_RX] = ABS_MAX_VALUE;
    dev_.absfuzz[ABS_RX] = ABS_FUZZ_VALUE;
    dev_.absflat[ABS_RX] = ABS_FLAT_VALUE;

    dev_.absmin[ABS_RY] = ABS_min_VALUE;
    dev_.absmax[ABS_RY] = ABS_MAX_VALUE;
    dev_.absfuzz[ABS_RY] = ABS_FUZZ_VALUE;
    dev_.absflat[ABS_RY] = ABS_FLAT_VALUE;

    dev_.absmin[ABS_RZ] = 0;
    dev_.absmax[ABS_RZ] = ABS_MAX_RXYZ;
    dev_.absfuzz[ABS_RZ] = 0;
    dev_.absflat[ABS_RZ] = ABS_FLAT;

    dev_.absmin[ABS_GAS] = 0;
    dev_.absmax[ABS_GAS] = ABS_MAX_RXYZ;
    dev_.absfuzz[ABS_GAS] = 0;
    dev_.absflat[ABS_GAS] = ABS_FLAT;

    dev_.absmin[ABS_BRAKE] = 0;
    dev_.absmax[ABS_BRAKE] = ABS_MAX_RXYZ;
    dev_.absfuzz[ABS_BRAKE] = 0;
    dev_.absflat[ABS_BRAKE] = ABS_FLAT;

    dev_.absmin[ABS_HAT0X] = ABS_MIN_HAT;
    dev_.absmax[ABS_HAT0X] = 1;
    dev_.absfuzz[ABS_HAT0X] = 0;
    dev_.absflat[ABS_HAT0X] = 0;

    dev_.absmin[ABS_HAT0Y] = ABS_MIN_HAT;
    dev_.absmax[ABS_HAT0Y] = 1;
    dev_.absfuzz[ABS_HAT0Y] = 0;
    dev_.absflat[ABS_HAT0Y] = 0;
}

OHOS::MMI::VirtualGamePad::~VirtualGamePad() {}

const std::vector<uint32_t>& OHOS::MMI::VirtualGamePad::GetEventTypes() const
{
    static const std::vector<uint32_t> evt_types {
        EV_KEY, EV_ABS, EV_MSC
    };
    return evt_types;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualGamePad::GetKeys() const
{
    static const std::vector<uint32_t> keys {
        KEY_HOMEPAGE, BTN_SOUTH, BTN_EAST, BTN_C, BTN_NORTH, BTN_WEST, BTN_Z,
        BTN_TL, BTN_TR, BTN_TL2, BTN_TR2, BTN_SELECT, BTN_START, BTN_MODE, BTN_THUMBL, BTN_THUMBR
    };

    return keys;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualGamePad::GetAbs() const
{
    static const std::vector<uint32_t> abs {
        ABS_X, ABS_Y, ABS_Z, ABS_RX, ABS_RY, ABS_RZ, ABS_GAS, ABS_BRAKE, ABS_HAT0X, ABS_HAT0Y
    };

    return abs;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualGamePad::GetMscs() const
{
    static const std::vector<uint32_t> mscs {
        MSC_SCAN
    };
    return mscs;
}
