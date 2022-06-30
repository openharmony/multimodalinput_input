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
constexpr int32_t FINGER_ABS_RANGE = 40;

ResolutionInfo resolutionInfos[] = {
    {ABS_X, FINGER_ABS_RANGE},
    {ABS_Y, FINGER_ABS_RANGE},
    {ABS_MT_POSITION_X, FINGER_ABS_RANGE},
    {ABS_MT_POSITION_Y, FINGER_ABS_RANGE},
    {ABS_MT_TOOL_X, FINGER_ABS_RANGE},
    {ABS_MT_TOOL_Y, FINGER_ABS_RANGE},
};

AbsInfo absInfos[] = {
    {ABS_X, 0, ABS_MAX_X, 0, 0},
    {ABS_Y, 0, ABS_MAX_Y, 0, 0},
    {ABS_MT_SLOT, 0, ABS_MAX_MT_SLOT, 0, 0},
    {ABS_MT_TOUCH_MAJOR, 0, ABS_MAX_MT_TOUCH_MAJOR, 0, 0},
    {ABS_MT_TOUCH_MINOR, 0, ABS_MAX_MT_TOUCH_MINOR, 0, 0},
    {ABS_MT_ORIENTATION, 0, ABS_MAX_MT_ORIENTATION, 0, 0},
    {ABS_MT_POSITION_X, 0, ABS_MAX_X, 0, 0},
    {ABS_MT_POSITION_Y, 0, ABS_MAX_Y, 0, 0},
    {ABS_MT_TRACKING_ID, 0, ABS_MAX_MT_TRACKING_ID, 0, 0},
    {ABS_MT_PRESSURE, 0, ABS_MAX_MT_PRESSURE, 0, 0},
    {ABS_MT_TOOL_TYPE, 0, ABS_TOOL_TYPE_MAX, 0, 0},
    {ABS_MT_TOOL_X, 0, ABS_MAX_X, 0, 0},
    {ABS_MT_TOOL_Y, 0, ABS_MAX_Y, 0, 0},
    {ABS_MT_WIDTH_MAJOR, 0, ABS_MAX_X, 0, 0},
    {ABS_MT_WIDTH_MINOR, 0, ABS_MAX_Y, 0, 0}
};
} // namespace

VirtualFinger::VirtualFinger() : VirtualDevice("Virtual Finger", BUS_USB, 0x56a, 0x392)
{
    eventTypes_ = { EV_KEY, EV_ABS, EV_SW };
    properties_ = { INPUT_PROP_POINTER };
    switches_ = { SW_MUTE_DEVICE };
    keys_ = {
        BTN_TOOL_FINGER, BTN_TOOL_QUINTTAP, BTN_TOUCH, BTN_TOOL_DOUBLETAP, BTN_TOOL_TRIPLETAP,
        BTN_TOOL_QUADTAP, BTN_TOOL_RUBBER, BTN_TOOL_BRUSH, BTN_TOOL_PENCIL, BTN_TOOL_AIRBRUSH,
        BTN_TOOL_FINGER, BTN_TOOL_MOUSE, BTN_TOOL_LENS
    };
    abs_ = {
        ABS_X, ABS_Y, ABS_MT_SLOT, ABS_MT_TOUCH_MAJOR, ABS_MT_TOUCH_MINOR, ABS_MT_ORIENTATION,
        ABS_MT_POSITION_X, ABS_MT_POSITION_Y, ABS_MT_TRACKING_ID, ABS_MT_PRESSURE, ABS_MT_TOOL_TYPE,
        ABS_MT_TOOL_X, ABS_MT_TOOL_Y, ABS_MT_WIDTH_MAJOR, ABS_MT_WIDTH_MINOR
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