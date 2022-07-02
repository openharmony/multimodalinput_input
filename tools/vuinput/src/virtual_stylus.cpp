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

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ABS_MAX_X = 31920;
constexpr int32_t ABS_MAX_Y = 19950;
constexpr int32_t ABS_MIN_Z = -900;
constexpr int32_t ABS_MAX_Z = 899;
constexpr int32_t ABS_MAX_WHEEL = 2047;
constexpr int32_t ABS_MAX_PRESSURE = 8191;
constexpr int32_t ABS_MIN_TILT_XY = -64;
constexpr int32_t ABS_MAX_TILT_XY_DISTANCE = 63;
constexpr int32_t ABS_MIN_MISC = -2147483648;
constexpr int32_t ABS_MAX_MISC = 2147483647;
constexpr int32_t ABS_FUZZ_XY = 4;
constexpr int32_t STYLUS_ABS_RANGE = 200;

AbsInfo absInfos[] = {
    {ABS_X, 0, ABS_MAX_X, ABS_FUZZ_XY, 0},
    {ABS_Y, 0, ABS_MAX_Y, ABS_FUZZ_XY, 0},
    {ABS_Z, ABS_MIN_Z, ABS_MAX_Z, 0, 0},
    {ABS_WHEEL, 0, ABS_MAX_WHEEL, 0, 0},
    {ABS_PRESSURE, 0, ABS_MAX_PRESSURE, 0, 0},
    {ABS_DISTANCE, 0, ABS_MAX_TILT_XY_DISTANCE, 0, 0},
    {ABS_TILT_X, ABS_MIN_TILT_XY, ABS_MAX_TILT_XY_DISTANCE, 0, 0},
    {ABS_TILT_Y, ABS_MIN_TILT_XY, ABS_MAX_TILT_XY_DISTANCE, 0, 0},
    {ABS_MISC, ABS_MIN_MISC, ABS_MAX_MISC, 0, 0}
};

ResolutionInfo resolutionInfos[] = {
    {ABS_X, STYLUS_ABS_RANGE},
    {ABS_Y, STYLUS_ABS_RANGE}
};
} // namespace

VirtualStylus::VirtualStylus() : VirtualDevice("Virtual Stylus", BUS_USB, 0x56a, 0x392)
{
    eventTypes_ = { EV_KEY, EV_ABS, EV_MSC };
    miscellaneous_ = { MSC_SERIAL };
    properties_ = { INPUT_PROP_POINTER };
    abs_ = { ABS_X, ABS_Y, ABS_Z, ABS_WHEEL, ABS_PRESSURE, ABS_DISTANCE, ABS_TILT_X, ABS_TILT_Y, ABS_MISC };
    keys_ = {
        BTN_TOOL_PEN, BTN_TOOL_RUBBER, BTN_TOOL_BRUSH, BTN_TOOL_PENCIL, BTN_TOOL_AIRBRUSH, BTN_TOOL_MOUSE,
        BTN_TOOL_LENS, BTN_STYLUS3, BTN_TOUCH, BTN_STYLUS, BTN_STYLUS2
    };

    for (const auto &item : absInfos) {
        SetAbsValue(item);
    }

    for (const auto &item : resolutionInfos) {
        SetResolution(item);
    }
}
} // namespace MMI
} // namespace OHOS