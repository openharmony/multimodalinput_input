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

#include "virtual_touchscreen.h"

OHOS::MMI::VirtualTouchScreen::VirtualTouchScreen()
    : VirtualDevice("Virtual TouchScreen", BUS_USB, 0x6006, 0x6006)
{
    const int32_t ABS_MAX_X = 480;
    const int32_t ABS_MAX_Y = 960;
    const int32_t ABS_PRESSURE_MAX = 100;
    const int32_t ABS_MT_ORIENTATION_MIN = -90;
    const int32_t ABS_MT_ORIENTATION_MAX = 90;
    const int32_t ABS_MT_BLOB_ID_MAX = 10;
    const int32_t ABS_MT_TRACKING_ID_MAX = 9;

    dev_.absmin[ABS_X] = 0;
    dev_.absmax[ABS_X] = ABS_MAX_X;
    dev_.absmin[ABS_Y] = 0;
    dev_.absmax[ABS_Y] = ABS_MAX_Y;

    dev_.absmin[ABS_PRESSURE] = 0;
    dev_.absmax[ABS_PRESSURE] = ABS_PRESSURE_MAX;

    dev_.absmin[ABS_MT_TOUCH_MAJOR] = 0;
    dev_.absmax[ABS_MT_TOUCH_MAJOR] = 1;
    dev_.absmin[ABS_MT_TOUCH_MINOR] = 0;
    dev_.absmax[ABS_MT_TOUCH_MINOR] = 1;

    dev_.absmin[ABS_MT_ORIENTATION] = ABS_MT_ORIENTATION_MIN;
    dev_.absmax[ABS_MT_ORIENTATION] = ABS_MT_ORIENTATION_MAX;

    dev_.absmin[ABS_MT_POSITION_X] = 0;
    dev_.absmax[ABS_MT_POSITION_X] = ABS_MAX_X;
    dev_.absmin[ABS_MT_POSITION_Y] = 0;
    dev_.absmax[ABS_MT_POSITION_Y] = ABS_MAX_Y;

    dev_.absmin[ABS_MT_BLOB_ID] = 0;
    dev_.absmax[ABS_MT_BLOB_ID] = ABS_MT_BLOB_ID_MAX;
    dev_.absmin[ABS_MT_TRACKING_ID] = 0;
    dev_.absmax[ABS_MT_TRACKING_ID] = ABS_MT_TRACKING_ID_MAX;
    dev_.absmin[ABS_MT_PRESSURE] = 0;
    dev_.absmax[ABS_MT_PRESSURE] = ABS_PRESSURE_MAX;
}

OHOS::MMI::VirtualTouchScreen::~VirtualTouchScreen() {}

const std::vector<uint32_t>& OHOS::MMI::VirtualTouchScreen::GetEventTypes() const
{
    static const std::vector<uint32_t> evTypes {
        EV_ABS, EV_KEY
    };
    return evTypes;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualTouchScreen::GetKeys() const
{
    static const std::vector<uint32_t> keys {
        BTN_TOUCH
    };
    return keys;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualTouchScreen::GetProperties() const
{
    static const std::vector<uint32_t> properties {
        INPUT_PROP_DIRECT
    };
    return properties;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualTouchScreen::GetAbs() const
{
    static const std::vector<uint32_t> abs {
        ABS_X, ABS_Y, ABS_PRESSURE, ABS_MT_TOUCH_MAJOR, ABS_MT_TOUCH_MINOR, ABS_MT_ORIENTATION, ABS_MT_POSITION_X,
        ABS_MT_POSITION_Y, ABS_MT_BLOB_ID, ABS_MT_TRACKING_ID, ABS_MT_PRESSURE
    };
    return abs;
}
