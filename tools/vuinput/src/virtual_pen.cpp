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
constexpr int32_t PEN_ABS_RANGE = 200;

ResolutionInfo resolutionInfos[] = {
    {ABS_X, PEN_ABS_RANGE},
    {ABS_Y, PEN_ABS_RANGE}
};

AbsInfo absInfos[] = {
    {ABS_X, 0, ABS_MAX_X, 0, 0},
    {ABS_Y, 0, ABS_MAX_Y, 0, 0},
    {ABS_PRESSURE, 0, ABS_MAX_PRESSURE, 0, 0},
    {ABS_TILT_X, ABS_MIN_TILT_X, ABS_MAX_TILT_X, 0, 0},
    {ABS_TILT_Y, ABS_MIN_TILT_Y, ABS_MAX_TILT_Y, 0, 0},
    {ABS_MT_TOOL_TYPE, 0, ABS_MAX_TYPE, 0, 0}
};
} // namespace

VirtualPen::VirtualPen() : VirtualDevice("V-Pencil", BUS_USB, 0, 0)
{
    eventTypes_ = { EV_KEY, EV_ABS };
    keys_ = { 0xc5, 0xc6, BTN_TOOL_PEN, BTN_TOUCH, BTN_STYLUS };
    properties_ = { INPUT_PROP_DIRECT };
    abs_ = { ABS_X, ABS_Y, ABS_PRESSURE, ABS_TILT_X, ABS_TILT_Y, ABS_MT_TOOL_TYPE };

    for (const auto &item : absInfos) {
        SetAbsValue(item);
    }

    for (const auto &item : resolutionInfos) {
        SetResolution(item);
    }
}
} // namespace MMI
} // namespace OHOS