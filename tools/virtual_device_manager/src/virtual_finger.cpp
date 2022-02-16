/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "virtual_finger.h"

OHOS::MMI::VirtualFinger::VirtualFinger() : VirtualDevice("Virtual Finger",
    BUS_USB, 0x56a, 0x392)
{
    const int32_t ABS_MAX_X = 6400;
    const int32_t ABS_MAX_Y = 4000;
    const int32_t ABS_MAX_MT_SLOT = 9;
    const int32_t ABS_MAX_MT_TOUCH_MAJOR = 21;
    const int32_t ABS_MAX_MT_TRACKING_ID = 65535;

    dev_.absmin[ABS_X] = 0;
    dev_.absmax[ABS_X] = ABS_MAX_X;
    dev_.absfuzz[ABS_X] = 0;
    dev_.absflat[ABS_X] = 0;

    dev_.absmin[ABS_Y] = 0;
    dev_.absmax[ABS_Y] = ABS_MAX_Y;
    dev_.absfuzz[ABS_Y] = 0;
    dev_.absflat[ABS_Y] = 0;

    dev_.absmin[ABS_MT_SLOT] = 0;
    dev_.absmax[ABS_MT_SLOT] = ABS_MAX_MT_SLOT;
    dev_.absfuzz[ABS_MT_SLOT] = 0;
    dev_.absflat[ABS_MT_SLOT] = 0;

    dev_.absmin[ABS_MT_TOUCH_MAJOR] = 0;
    dev_.absmax[ABS_MT_TOUCH_MAJOR] = ABS_MAX_MT_TOUCH_MAJOR;
    dev_.absfuzz[ABS_MT_TOUCH_MAJOR] = 0;
    dev_.absflat[ABS_MT_TOUCH_MAJOR] = 0;

    dev_.absmin[ABS_MT_TOUCH_MINOR] = 0;
    dev_.absmax[ABS_MT_TOUCH_MINOR] = ABS_MAX_MT_TOUCH_MAJOR;
    dev_.absfuzz[ABS_MT_TOUCH_MINOR] = 0;
    dev_.absflat[ABS_MT_TOUCH_MINOR] = 0;

    dev_.absmin[ABS_MT_ORIENTATION] = 0;
    dev_.absmax[ABS_MT_ORIENTATION] = 1;
    dev_.absfuzz[ABS_MT_ORIENTATION] = 0;
    dev_.absflat[ABS_MT_ORIENTATION] = 0;

    dev_.absmin[ABS_MT_POSITION_X] = 0;
    dev_.absmax[ABS_MT_POSITION_X] = ABS_MAX_X;
    dev_.absfuzz[ABS_MT_POSITION_X] = 0;
    dev_.absflat[ABS_MT_POSITION_X] = 0;

    dev_.absmin[ABS_MT_POSITION_Y] = 0;
    dev_.absmax[ABS_MT_POSITION_Y] = ABS_MAX_Y;
    dev_.absfuzz[ABS_MT_POSITION_Y] = 0;
    dev_.absflat[ABS_MT_POSITION_Y] = 0;

    dev_.absmin[ABS_MT_TRACKING_ID] = 0;
    dev_.absmax[ABS_MT_TRACKING_ID] = ABS_MAX_MT_TRACKING_ID;
    dev_.absfuzz[ABS_MT_TRACKING_ID] = 0;
    dev_.absflat[ABS_MT_TRACKING_ID] = 0;
}

OHOS::MMI::VirtualFinger::~VirtualFinger() {}

const std::vector<uint32_t>& OHOS::MMI::VirtualFinger::GetEventTypes() const
{
    static const std::vector<uint32_t> evt_types {
        EV_KEY, EV_ABS, EV_SW
    };
    return evt_types;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualFinger::GetKeys() const
{
    static const std::vector<uint32_t> keys {
        BTN_TOOL_FINGER, BTN_TOOL_QUINTTAP, BTN_TOUCH, BTN_TOOL_DOUBLETAP, BTN_TOOL_TRIPLETAP, BTN_TOOL_QUADTAP
    };
    return keys;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualFinger::GetAbs() const
{
    static const std::vector<uint32_t> abs {
        ABS_X, ABS_Y, ABS_MT_SLOT, ABS_MT_TOUCH_MAJOR, ABS_MT_TOUCH_MINOR, ABS_MT_ORIENTATION, ABS_MT_POSITION_X,
        ABS_MT_POSITION_Y, ABS_MT_TRACKING_ID
    };

    return abs;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualFinger::GetSws() const
{
    static const std::vector<uint32_t> sws {
        SW_MUTE_DEVICE
    };
    return sws;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualFinger::GetProperties() const
{
    static const std::vector<uint32_t> pros {
        INPUT_PROP_POINTER
    };
    return pros;
}
