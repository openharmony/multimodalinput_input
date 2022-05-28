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

#include "virtual_finger.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ABS_MAX_X = 6400;
constexpr int32_t ABS_MAX_Y = 4000;
constexpr int32_t ABS_MAX_MT_SLOT = 9;
constexpr int32_t ABS_MAX_MT_TOUCH_MAJOR = 21;
constexpr int32_t ABS_MAX_MT_TOUCH_MINOR = 21;
constexpr int32_t ABS_MAX_MT_TRACKING_ID = 65535;
constexpr int32_t ABS_MAX_MT_PRESSURE = 8191;
constexpr int32_t ABS_TOOL_TYPE_MAX = 15;
constexpr int32_t ABS_MAX_MT_ORIENTATION = 1;
#define SETABSMAXVALUE(code, maxValue) do { \
    dev_.absmin[code] = 0; \
    dev_.absmax[code] = maxValue; \
    dev_.absfuzz[code] = 0; \
    dev_.absflat[code] = 0; \
} while (0)
} // namespace

VirtualFinger::VirtualFinger() : VirtualDevice("Virtual Finger",
    BUS_USB, 0x56a, 0x392)
{
    SETABSMAXVALUE(ABS_X, ABS_MAX_X);
    SETABSMAXVALUE(ABS_Y, ABS_MAX_Y);
    SETABSMAXVALUE(ABS_MT_SLOT, ABS_MAX_MT_SLOT);
    SETABSMAXVALUE(ABS_MT_TOUCH_MAJOR, ABS_MAX_MT_TOUCH_MAJOR);
    SETABSMAXVALUE(ABS_MT_TOUCH_MINOR, ABS_MAX_MT_TOUCH_MINOR);
    SETABSMAXVALUE(ABS_MT_ORIENTATION, ABS_MAX_MT_ORIENTATION);
    SETABSMAXVALUE(ABS_MT_POSITION_X, ABS_MAX_X);
    SETABSMAXVALUE(ABS_MT_POSITION_Y, ABS_MAX_Y);
    SETABSMAXVALUE(ABS_MT_TRACKING_ID, ABS_MAX_MT_TRACKING_ID);
    SETABSMAXVALUE(ABS_MT_PRESSURE, ABS_MAX_MT_PRESSURE);
    SETABSMAXVALUE(ABS_MT_TOOL_TYPE, ABS_TOOL_TYPE_MAX);
    SETABSMAXVALUE(ABS_MT_TOOL_X, ABS_MAX_X);
    SETABSMAXVALUE(ABS_MT_TOOL_Y, ABS_MAX_Y);
    SETABSMAXVALUE(ABS_MT_WIDTH_MAJOR, ABS_MAX_X);
    SETABSMAXVALUE(ABS_MT_WIDTH_MINOR, ABS_MAX_Y);
}

VirtualFinger::~VirtualFinger() {}

const std::vector<uint32_t>& VirtualFinger::GetEventTypes() const
{
    static const std::vector<uint32_t> evt_types {
        EV_KEY, EV_ABS, EV_SW
    };
    return evt_types;
}

const std::vector<uint32_t>& VirtualFinger::GetKeys() const
{
    static const std::vector<uint32_t> keys {
        BTN_TOOL_FINGER, BTN_TOOL_QUINTTAP, BTN_TOUCH, BTN_TOOL_DOUBLETAP, BTN_TOOL_TRIPLETAP, BTN_TOOL_QUADTAP,
        BTN_TOOL_RUBBER, BTN_TOOL_BRUSH, BTN_TOOL_PENCIL, BTN_TOOL_AIRBRUSH, BTN_TOOL_FINGER,
        BTN_TOOL_MOUSE, BTN_TOOL_LENS
    };
    return keys;
}

const std::vector<uint32_t>& VirtualFinger::GetAbs() const
{
    static const std::vector<uint32_t> abs {
        ABS_X, ABS_Y, ABS_MT_SLOT, ABS_MT_TOUCH_MAJOR, ABS_MT_TOUCH_MINOR, ABS_MT_ORIENTATION,
        ABS_MT_POSITION_X, ABS_MT_POSITION_Y, ABS_MT_TRACKING_ID, ABS_MT_PRESSURE, ABS_MT_TOOL_TYPE,
        ABS_MT_TOOL_X, ABS_MT_TOOL_Y, ABS_MT_WIDTH_MAJOR, ABS_MT_WIDTH_MINOR
    };

    return abs;
}

const std::vector<uint32_t>& VirtualFinger::GetSwitchs() const
{
    static const std::vector<uint32_t> switchs {
        SW_MUTE_DEVICE
    };
    return switchs;
}

const std::vector<uint32_t>& VirtualFinger::GetProperties() const
{
    static const std::vector<uint32_t> pros {
        INPUT_PROP_POINTER
    };
    return pros;
}
} // namespace MMI
} // namespace OHOS