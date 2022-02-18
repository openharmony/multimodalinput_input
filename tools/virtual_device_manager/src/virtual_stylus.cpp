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

#include "virtual_stylus.h"

OHOS::MMI::VirtualStylus::VirtualStylus() : VirtualDevice("Virtual Stylus",
    BUS_USB, 0x56a, 0x392)
{
    const int32_t ABS_MAX_X = 31920;
    const int32_t ABS_MAX_Y = 19950;
    const int32_t ABS_MIN_Z = -900;
    const int32_t ABS_MAX_Z = 899;
    const int32_t ABS_MAX_WHEEL = 2047;
    const int32_t ABS_MAX_PRESSURE = 8191;
    const int32_t ABS_MIN_TILT_XY = -64;
    const int32_t ABS_MAX_TILT_XY_DISTANCE = 63;
    const int32_t ABS_MIN_MISC = -2147483648;
    const int32_t ABS_MAX_MISC = 2147483647;
    const int32_t ABS_FUZZ_XY = 4;

    dev_.absmin[ABS_X] = 0;
    dev_.absmax[ABS_X] = ABS_MAX_X;
    dev_.absfuzz[ABS_X] = ABS_FUZZ_XY;
    dev_.absflat[ABS_X] = 0;

    dev_.absmin[ABS_Y] = 0;
    dev_.absmax[ABS_Y] = ABS_MAX_Y;
    dev_.absfuzz[ABS_Y] = ABS_FUZZ_XY;
    dev_.absflat[ABS_Y] = 0;

    dev_.absmin[ABS_Z] = ABS_MIN_Z;
    dev_.absmax[ABS_Z] = ABS_MAX_Z;
    dev_.absfuzz[ABS_Z] = 0;
    dev_.absflat[ABS_Z] = 0;

    dev_.absmin[ABS_WHEEL] = 0;
    dev_.absmax[ABS_WHEEL] = ABS_MAX_WHEEL;
    dev_.absfuzz[ABS_WHEEL] = 0;
    dev_.absflat[ABS_WHEEL] = 0;

    dev_.absmin[ABS_PRESSURE] = 0;
    dev_.absmax[ABS_PRESSURE] = ABS_MAX_PRESSURE;
    dev_.absfuzz[ABS_PRESSURE] = 0;
    dev_.absflat[ABS_PRESSURE] = 0;

    dev_.absmin[ABS_DISTANCE] = 0;
    dev_.absmax[ABS_DISTANCE] = ABS_MAX_TILT_XY_DISTANCE;
    dev_.absfuzz[ABS_DISTANCE] = 0;
    dev_.absflat[ABS_DISTANCE] = 0;

    dev_.absmin[ABS_TILT_X] = ABS_MIN_TILT_XY;
    dev_.absmax[ABS_TILT_X] = ABS_MAX_TILT_XY_DISTANCE;
    dev_.absfuzz[ABS_TILT_X] = 0;
    dev_.absflat[ABS_TILT_X] = 0;

    dev_.absmin[ABS_TILT_Y] = ABS_MIN_TILT_XY;
    dev_.absmax[ABS_TILT_Y] = ABS_MAX_TILT_XY_DISTANCE;
    dev_.absfuzz[ABS_TILT_Y] = 0;
    dev_.absflat[ABS_TILT_Y] = 0;

    dev_.absmin[ABS_MISC] = ABS_MIN_MISC;
    dev_.absmax[ABS_MISC] = ABS_MAX_MISC;
    dev_.absfuzz[ABS_MISC] = 0;
    dev_.absflat[ABS_MISC] = 0;
}

OHOS::MMI::VirtualStylus::~VirtualStylus() {}

const std::vector<uint32_t>& OHOS::MMI::VirtualStylus::GetEventTypes() const
{
    static const std::vector<uint32_t> evt_types {
        EV_KEY, EV_ABS, EV_MSC
    };
    return evt_types;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualStylus::GetKeys() const
{
    static const std::vector<uint32_t> keys {
        BTN_TOOL_PEN, BTN_TOOL_RUBBER, BTN_TOOL_BRUSH, BTN_TOOL_PENCIL, BTN_TOOL_AIRBRUSH, BTN_TOOL_MOUSE,
        BTN_TOOL_LENS, BTN_STYLUS3, BTN_TOUCH, BTN_STYLUS, BTN_STYLUS2
    };
    return keys;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualStylus::GetAbs() const
{
    static const std::vector<uint32_t> abs {
        ABS_X, ABS_Y, ABS_Z, ABS_WHEEL, ABS_PRESSURE, ABS_DISTANCE, ABS_TILT_X, ABS_TILT_Y, ABS_MISC
    };
    return abs;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualStylus::GetMscs() const
{
    static const std::vector<uint32_t> mscs {
        MSC_SERIAL
    };

    return mscs;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualStylus::GetProperties() const
{
    static const std::vector<uint32_t> pros {
        INPUT_PROP_POINTER
    };
    return pros;
}