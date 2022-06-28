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

#include "virtual_single_finger.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ABS_MAX_X = 6400;
constexpr int32_t ABS_MAX_Y = 4000;
constexpr int32_t ABS_PRESSURE_MAX = 8191;
} // namespace

VirtualSingleFinger::VirtualSingleFinger()
    : VirtualDevice("Virtual SingleFinger", BUS_USB, 0x56a, 0x392)
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
    dev_.absmax[ABS_PRESSURE] = ABS_PRESSURE_MAX;
}

const std::vector<uint32_t>& VirtualSingleFinger::GetEventTypes() const
{
    static const std::vector<uint32_t> eventTypes { EV_KEY, EV_ABS, EV_SW };
    return eventTypes;
}

const std::vector<uint32_t>& VirtualSingleFinger::GetKeys() const
{
    static const std::vector<uint32_t> keys { BTN_TOUCH };
    return keys;
}

const std::vector<uint32_t>& VirtualSingleFinger::GetAbs() const
{
    static const std::vector<uint32_t> abs { ABS_X, ABS_Y,  ABS_PRESSURE };
    return abs;
}

const std::vector<uint32_t>& VirtualSingleFinger::GetSwitches() const
{
    static const std::vector<uint32_t> switches { SW_MUTE_DEVICE };
    return switches;
}

const std::vector<uint32_t>& VirtualSingleFinger::GetProperties() const
{
    static const std::vector<uint32_t> pros { INPUT_PROP_POINTER };
    return pros;
}
} // namespace MMI
} // namespace OHOS