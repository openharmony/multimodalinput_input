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

#include "virtual_single_touchscreen.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ABS_MAX_X = 720;
constexpr int32_t ABS_MAX_Y = 1280;
constexpr int32_t ABS_PRESSURE_MAX = 100;

AbsInfo absInfos[] = {
    {ABS_X, 0, ABS_MAX_X, 0, 0},
    {ABS_Y, 0, ABS_MAX_Y, 0, 0},
    {ABS_PRESSURE, 0, ABS_PRESSURE_MAX, 0, 0}
};
} // namespace

VirtualSingleTouchScreen::VirtualSingleTouchScreen()
    : VirtualDevice("Virtual SingleTouchScreen", BUS_USB, 0x6006, 0x6006)
{
    eventTypes_ = { EV_ABS, EV_KEY };
    keys_ = { BTN_TOUCH };
    abs_ = { ABS_X, ABS_Y, ABS_PRESSURE };
    properties_ = { INPUT_PROP_DIRECT };

    for (const auto &item : absInfos) {
        SetAbsValue(item);
    }
}
} // namespace MMI
} // namespace OHOS