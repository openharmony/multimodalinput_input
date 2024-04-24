/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "virtual_touch_screen.h"

#include "linux/input-event-codes.h"
#include "linux/uinput.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ABS_MAX_PRESSURE = 100;
constexpr int32_t ABS_MT_MIN_ORIENTATION = -90;
constexpr int32_t ABS_MT_MAX_ORIENTATION = 90;
constexpr int32_t ABS_MT_BLOB_MAX_ID = 10;
constexpr int32_t ABS_MT_TRACKING_MAX_ID = 9;
constexpr int32_t ABS_MT_MAX_PRESSURE = 100;
} // namespace

const std::vector<uint32_t> &VirtualTouchScreen::GetEventTypes() const
{
    static const std::vector<uint32_t> evtTypes {EV_ABS, EV_KEY, EV_SYN};
    return evtTypes;
}

const std::vector<uint32_t> &VirtualTouchScreen::GetKeys() const
{
    static const std::vector<uint32_t> keys {BTN_TOUCH};
    return keys;
}

const std::vector<uint32_t> &VirtualTouchScreen::GetProperties() const
{
    static const std::vector<uint32_t> properties {INPUT_PROP_DIRECT};
    return properties;
}

const std::vector<uint32_t> &VirtualTouchScreen::GetAbs() const
{
    static const std::vector<uint32_t> abs {
        ABS_X,
        ABS_Y,
        ABS_PRESSURE,
        ABS_MT_TOUCH_MAJOR,
        ABS_MT_TOUCH_MINOR,
        ABS_MT_ORIENTATION,
        ABS_MT_POSITION_X,
        ABS_MT_POSITION_Y,
        ABS_MT_BLOB_ID,
        ABS_MT_TRACKING_ID,
        ABS_MT_PRESSURE
        };
    return abs;
}

VirtualTouchScreen::VirtualTouchScreen(const uint32_t maxX, const uint32_t maxY)
    : VirtualDevice("VSoC touchscreen", 0x6006)
{
    dev_.absmin[ABS_X] = 0;
    dev_.absmax[ABS_X] = maxX;
    dev_.absmin[ABS_Y] = 0;
    dev_.absmax[ABS_Y] = maxY;

    dev_.absmin[ABS_PRESSURE] = 0;
    dev_.absmax[ABS_PRESSURE] = ABS_MAX_PRESSURE;

    dev_.absmin[ABS_MT_TOUCH_MAJOR] = 0;
    dev_.absmax[ABS_MT_TOUCH_MAJOR] = 1;
    dev_.absmin[ABS_MT_TOUCH_MINOR] = 0;
    dev_.absmax[ABS_MT_TOUCH_MINOR] = 1;

    dev_.absmin[ABS_MT_ORIENTATION] = ABS_MT_MIN_ORIENTATION;
    dev_.absmax[ABS_MT_ORIENTATION] = ABS_MT_MAX_ORIENTATION;

    dev_.absmin[ABS_MT_POSITION_X] = 0;
    dev_.absmax[ABS_MT_POSITION_X] = maxX;
    dev_.absmin[ABS_MT_POSITION_Y] = 0;
    dev_.absmax[ABS_MT_POSITION_Y] = maxY;

    dev_.absmin[ABS_MT_BLOB_ID] = 0;
    dev_.absmax[ABS_MT_BLOB_ID] = ABS_MT_BLOB_MAX_ID;
    dev_.absmin[ABS_MT_TRACKING_ID] = 0;
    dev_.absmax[ABS_MT_TRACKING_ID] = ABS_MT_TRACKING_MAX_ID;
    dev_.absmin[ABS_MT_PRESSURE] = 0;
    dev_.absmax[ABS_MT_PRESSURE] = ABS_MT_MAX_PRESSURE;
}
} // namespace MMI
} // namespace OHOS
