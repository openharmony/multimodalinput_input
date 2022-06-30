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

#include "virtual_touchpad.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ABS_MAX_WHEEL = 71;
constexpr int32_t ABS_RANGE = 200;

AbsInfo absInfos[] = {
    {ABS_X, 0, 1, 0, 0},
    {ABS_Y, 0, 1, 0, 0},
    {ABS_WHEEL, 0, ABS_MAX_WHEEL, 0, 0},
    {ABS_MISC, 0, 0, 0, 0},
};

ResolutionInfo resolutionInfos[] = {
    {ABS_X, ABS_RANGE},
    {ABS_Y, ABS_RANGE}
};
} // namespace

VirtualTouchpad::VirtualTouchpad() : VirtualDevice("Virtual Touchpad", BUS_USB, 0x56a, 0x392)
{
    eventTypes_ = { EV_KEY, EV_ABS };
    abs_ = { ABS_X, ABS_Y, ABS_WHEEL, ABS_MISC };
    keys_ = { BTN_0, BTN_1, BTN_2, BTN_3, BTN_4, BTN_5, BTN_6, BTN_STYLUS, BTN_TOOL_PEN };

    for (const auto &item : absInfos) {
        SetAbsValue(item);
    }

    for (const auto &item : resolutionInfos) {
        SetResolution(item);
    }
}
} // namespace MMI
} // namespace OHOS