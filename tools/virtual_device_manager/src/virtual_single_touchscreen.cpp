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
} // namespace

VirtualSingleTouchScreen::VirtualSingleTouchScreen()
    : VirtualDevice("Virtual SingleTouchScreen", BUS_USB, 0x6006, 0x6006)
{
    dev_.absmin[ABS_X] = 0;
    dev_.absmax[ABS_X] = ABS_MAX_X;
    dev_.absmin[ABS_Y] = 0;
    dev_.absmax[ABS_Y] = ABS_MAX_Y;

    dev_.absmin[ABS_PRESSURE] = 0;
    dev_.absmax[ABS_PRESSURE] = ABS_PRESSURE_MAX;
}

const std::vector<uint32_t>& VirtualSingleTouchScreen::GetEventTypes() const
{
    static const std::vector<uint32_t> eventTypes { EV_ABS, EV_KEY };
    return eventTypes;
}

const std::vector<uint32_t>& VirtualSingleTouchScreen::GetKeys() const
{
    static const std::vector<uint32_t> keys { BTN_TOUCH };
    return keys;
}

const std::vector<uint32_t>& VirtualSingleTouchScreen::GetProperties() const
{
    static const std::vector<uint32_t> properties { INPUT_PROP_DIRECT };
    return properties;
}

const std::vector<uint32_t>& VirtualSingleTouchScreen::GetAbs() const
{
    static const std::vector<uint32_t> abs { ABS_X, ABS_Y, ABS_PRESSURE };
    return abs;
}
} // namespace MMI
} // namespace OHOS