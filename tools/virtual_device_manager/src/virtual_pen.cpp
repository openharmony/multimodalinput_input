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

#include "virtual_pen.h"
namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ABS_MAX_X = 20479;
constexpr int32_t ABS_MAX_Y = 12799;
constexpr int32_t ABS_MAX_PRESSURE = 4096;
constexpr int32_t ABS_MIN_TILT_X = -90;
constexpr int32_t ABS_MAX_TILT_X = 90;
constexpr int32_t ABS_MIN_TILT_Y = -90;
constexpr int32_t ABS_MAX_TILT_Y = 90;
constexpr int32_t ABS_MAX_TYPE = 15;
} // namespace

VirtualPen::VirtualPen() : VirtualDevice("V-Pencil", BUS_USB, 0, 0)
{
    dev_.absmin[ABS_X] = 0;
    dev_.absmax[ABS_X] = ABS_MAX_X;
    dev_.absfuzz[ABS_X] = 0;
    dev_.absflat[ABS_X] = 0;

    dev_.absmin[ABS_Y] = 0;
    dev_.absmax[ABS_Y] = ABS_MAX_Y;
    dev_.absfuzz[ABS_Y] = 0;
    dev_.absflat[ABS_Y] = 0;

    dev_.absmin[ABS_PRESSURE] = 0;
    dev_.absmax[ABS_PRESSURE] = ABS_MAX_PRESSURE;
    dev_.absfuzz[ABS_PRESSURE] = 0;
    dev_.absflat[ABS_PRESSURE] = 0;

    dev_.absmin[ABS_TILT_X] = ABS_MIN_TILT_X;
    dev_.absmax[ABS_TILT_X] = ABS_MAX_TILT_X;
    dev_.absfuzz[ABS_TILT_X] = 0;
    dev_.absflat[ABS_TILT_X] = 0;

    dev_.absmin[ABS_TILT_Y] = ABS_MIN_TILT_Y;
    dev_.absmax[ABS_TILT_Y] = ABS_MAX_TILT_Y;
    dev_.absfuzz[ABS_TILT_Y] = 0;
    dev_.absflat[ABS_TILT_Y] = 0;

    dev_.absmin[ABS_MT_TOOL_TYPE] = 0;
    dev_.absmax[ABS_MT_TOOL_TYPE] = ABS_MAX_TYPE;
    dev_.absfuzz[ABS_MT_TOOL_TYPE] = 0;
    dev_.absflat[ABS_MT_TOOL_TYPE] = 0;
}

const std::vector<uint32_t>& VirtualPen::GetEventTypes() const
{
    static const std::vector<uint32_t> eventTypes { EV_KEY, EV_ABS };
    return eventTypes;
}

const std::vector<uint32_t>& VirtualPen::GetKeys() const
{
    static const std::vector<uint32_t> keys { 0xc5, 0xc6, BTN_TOOL_PEN, BTN_TOUCH, BTN_STYLUS };
    return keys;
}

const std::vector<uint32_t>& VirtualPen::GetAbs() const
{
    static const std::vector<uint32_t> abs { ABS_X, ABS_Y, ABS_PRESSURE, ABS_TILT_X, ABS_TILT_Y, ABS_MT_TOOL_TYPE };
    return abs;
}

const std::vector<uint32_t>& VirtualPen::GetProperties() const
{
    static const std::vector<uint32_t> properties { INPUT_PROP_DIRECT };
    return properties;
}
} // namespace MMI
} // namespace OHOS