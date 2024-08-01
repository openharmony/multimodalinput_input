/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "virtual_uwb_remote_control.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ABS_MAX_X = 719;
constexpr int32_t ABS_MAX_Y = 1279;
constexpr int32_t ABS_PRESSURE_MAX = 3000;
constexpr int32_t ABS_MT_MOVEFLAG_MAX = 10;
constexpr int32_t ABS_MT_SLOT_MAX = 10;
constexpr int32_t ABS_MT_TOUCH_MAJOR_MAX = 1;
constexpr int32_t ABS_MT_TOUCH_MINOR_MAX = 1;
constexpr int32_t ABS_MT_ORIENTATION_MIN = -90;
constexpr int32_t ABS_MT_ORIENTATION_MAX = 90;
constexpr int32_t ABS_MT_BLOB_ID_MAX = 10;
constexpr int32_t ABS_MT_TRACKING_ID_MAX = 9;

AbsInfo absInfos[] = {
    { ABS_X, 0, ABS_MAX_X, 0, 0 },
    { ABS_Y, 0, ABS_MAX_Y, 0, 0 },
    { ABS_PRESSURE, 0, ABS_PRESSURE_MAX, 0, 0 },
    { ABS_MT_PRESSURE, 0, ABS_PRESSURE_MAX, 0, 0 },
    { ABS_MT_MOVEFLAG, 0, ABS_MT_MOVEFLAG_MAX, 0, 0 },
    { ABS_MT_SLOT, 0, ABS_MT_SLOT_MAX, 0, 0 },
    { ABS_MT_TOUCH_MAJOR, 0, ABS_MT_TOUCH_MAJOR_MAX, 0, 0 },
    { ABS_MT_TOUCH_MINOR, 0, ABS_MT_TOUCH_MINOR_MAX, 0, 0 },
    { ABS_MT_ORIENTATION, ABS_MT_ORIENTATION_MIN, ABS_MT_ORIENTATION_MAX, 0, 0 },
    { ABS_MT_POSITION_X, 0, ABS_MAX_X, 0, 0 },
    { ABS_MT_POSITION_Y, 0, ABS_MAX_Y, 0, 0 },
    { ABS_MT_BLOB_ID, 0, ABS_MT_BLOB_ID_MAX, 0, 0 },
    { ABS_MT_TRACKING_ID, 0, ABS_MT_TRACKING_ID_MAX, 0, 0 }
};
} // namespace

VirtualUwbRemoteControl::VirtualUwbRemoteControl() : VirtualDevice("Virtual UWB RemoteControl", BUS_USB, 0x6006, 0x6006)
{
    eventTypes_ = { EV_SYN, EV_KEY, EV_REL, EV_ABS };
    properties_ = { INPUT_PROP_DIRECT };
    keys_ = {
        KEY_HOMEPAGE, KEY_POWER, KEY_BACK, KEY_MENU, KEY_ENTER, KEY_LEFT, KEY_RIGHT, KEY_UP, KEY_DOWN,
        KEY_VOICECOMMAND, KEY_VOLUMEDOWN, KEY_VOLUMEUP, BTN_TOUCH, BTN_LEFT, BTN_RIGHT, BTN_TOOL_FINGER
    };
    abs_ = {
        ABS_X, ABS_Y, ABS_PRESSURE, ABS_MT_SLOT, ABS_MT_TOUCH_MAJOR, ABS_MT_TOUCH_MINOR, ABS_MT_ORIENTATION,
        ABS_MT_POSITION_X, ABS_MT_POSITION_Y, ABS_MT_BLOB_ID, ABS_MT_TRACKING_ID, ABS_MT_PRESSURE, ABS_MT_MOVEFLAG
    };
    relBits_ = { REL_X, REL_Y, REL_WHEEL, REL_WHEEL_HI_RES };
    for (const auto &item : absInfos) {
        SetAbsValue(item);
    }
}
} // namespace MMI
} // namespace OHOS