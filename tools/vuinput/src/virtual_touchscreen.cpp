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

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ABS_MAX_X = 480;
constexpr int32_t ABS_MAX_Y = 960;
constexpr int32_t ABS_PRESSURE_MAX = 100;
constexpr int32_t ABS_MT_ORIENTATION_MIN = -90;
constexpr int32_t ABS_MT_ORIENTATION_MAX = 90;
constexpr int32_t ABS_MT_BLOB_ID_MAX = 10;
constexpr int32_t ABS_MT_TRACKING_ID_MAX = 9;
constexpr int32_t ABS_TOOL_TYPE_MAX = 15;

AbsInfo absInfos[] = {
    {ABS_X, 0, ABS_MAX_X, 0, 0},
    {ABS_Y, 0, ABS_MAX_Y, 0, 0},
    {ABS_PRESSURE, 0, ABS_PRESSURE_MAX, 0, 0},
    {ABS_MT_TOUCH_MAJOR, 0, 1, 0, 0},
    {ABS_MT_TOUCH_MINOR, 0, 1, 0, 0},
    {ABS_MT_ORIENTATION, ABS_MT_ORIENTATION_MIN, ABS_MT_ORIENTATION_MAX, 0, 0},
    {ABS_MT_POSITION_X, 0, ABS_MAX_X, 0, 0},
    {ABS_MT_POSITION_Y, 0, ABS_MAX_Y, 0, 0},
    {ABS_MT_BLOB_ID, 0, ABS_MT_BLOB_ID_MAX, 0, 0},
    {ABS_MT_TRACKING_ID, 0, ABS_MT_TRACKING_ID_MAX, 0, 0},
    {ABS_MT_PRESSURE, 0, ABS_PRESSURE_MAX, 0, 0},
    {ABS_MT_TOOL_TYPE, 0, ABS_TOOL_TYPE_MAX, 0, 0},
    {ABS_MT_WIDTH_MAJOR, 0, 1, 0, 0},
    {ABS_MT_WIDTH_MINOR, 0, 1, 0, 0},
    {ABS_MT_TOOL_X, 0, ABS_MAX_X, 0, 0},
    {ABS_MT_TOOL_Y, 0, 1, 0, 0}
};
} // namespace

VirtualTouchScreen::VirtualTouchScreen() : VirtualDevice("Virtual TouchScreen", BUS_USB, 0x6006, 0x6006)
{
    eventTypes_ = { EV_ABS, EV_KEY };
    properties_ = { INPUT_PROP_DIRECT };
    keys_ = {
        BTN_TOUCH, BTN_TOOL_RUBBER, BTN_TOOL_BRUSH, BTN_TOOL_PENCIL, BTN_TOOL_AIRBRUSH, BTN_TOOL_FINGER,
        BTN_TOOL_MOUSE, BTN_TOOL_LENS
    };
    abs_ = {
        ABS_X, ABS_Y, ABS_PRESSURE, ABS_MT_TOUCH_MAJOR, ABS_MT_TOUCH_MINOR, ABS_MT_ORIENTATION, ABS_MT_POSITION_X,
        ABS_MT_POSITION_Y, ABS_MT_BLOB_ID, ABS_MT_TRACKING_ID, ABS_MT_PRESSURE, ABS_MT_WIDTH_MAJOR, ABS_MT_WIDTH_MINOR,
        ABS_MT_TOOL_X, ABS_MT_TOOL_Y, ABS_MT_TOOL_TYPE
    };

    for (const auto &item : absInfos) {
        SetAbsValue(item);
    }
}
} // namespace MMI
} // namespace OHOS