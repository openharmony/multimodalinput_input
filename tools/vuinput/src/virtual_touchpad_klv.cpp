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

#include "virtual_touchpad_klv.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ABS_MAX_X = 1919;
constexpr int32_t ABS_MAX_Y = 1079;
constexpr int32_t ABS_SLOT_MAX = 4;
constexpr int32_t ABS_POSITION_X_MAX = 1919;
constexpr int32_t ABS_POSITION_Y_MAX = 1079;
constexpr int32_t ABS_MT_TOOL_TYPE_MAX = 2;
constexpr int32_t ABS_MT_TRACKING_ID_MAX = 65535;

AbsInfo absInfos[] = {
    { ABS_X, 0, ABS_MAX_X, 0, 0 },
    { ABS_Y, 0, ABS_MAX_Y, 0, 0 },
    { ABS_MT_SLOT, 0, ABS_SLOT_MAX, 0, 0 },
    { ABS_MT_POSITION_X, 0, ABS_POSITION_X_MAX, 0, 0 },
    { ABS_MT_POSITION_Y, 0, ABS_POSITION_Y_MAX, 0, 0 },
    { ABS_MT_TOOL_TYPE, 0, ABS_MT_TOOL_TYPE_MAX, 0, 0 },
    { ABS_MT_TRACKING_ID, 0, ABS_MT_TRACKING_ID_MAX, 0, 0 }
};
} // namespace

VirtualTouchpadKLV::VirtualTouchpadKLV() : VirtualDevice("Virtual TouchPadKLV", BUS_USB, 0x27c6, 0x100)
{
    eventTypes_ = { EV_KEY, EV_ABS, EV_MSC };
    keys_ = { BTN_LEFT, BTN_TOOL_FINGER, BTN_TOOL_QUINTTAP, BTN_TOUCH, BTN_TOOL_DOUBLETAP, BTN_TOOL_TRIPLETAP, BTN_TOOL_QUADTAP };
    abs_ = { ABS_X, ABS_Y, ABS_MT_SLOT, ABS_MT_POSITION_X, ABS_MT_POSITION_Y, ABS_MT_TOOL_TYPE, ABS_MT_TRACKING_ID, };
    miscellaneous_ = { MSC_SCAN };
    for (const auto &item : absInfos) {
        SetAbsValue(item);
    }
}
} // namespace MMI
} // namespace OHOS