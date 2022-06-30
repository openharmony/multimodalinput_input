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

#include "virtual_gamepad.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ABS_MAX_RXYZ = 255;
constexpr int32_t ABS_FLAT = 15;
constexpr int32_t ABS_MIN_HAT = -1;
constexpr int32_t ABS_MIN_VALUE = -32768;
constexpr int32_t ABS_MAX_VALUE = 32767;
constexpr int32_t ABS_FUZZ_VALUE = 16;
constexpr int32_t ABS_FLAT_VALUE = 128;

AbsInfo absInfos[] = {
    {ABS_X, 0, ABS_MAX_RXYZ, 0, ABS_FLAT},
    {ABS_Y, 0, ABS_MAX_RXYZ, 0, ABS_FLAT},
    {ABS_Z, 0, ABS_MAX_RXYZ, 0, ABS_FLAT},
    {ABS_RX, ABS_MIN_VALUE, ABS_MAX_RXYZ, ABS_FUZZ_VALUE, ABS_FLAT_VALUE},
    {ABS_RY, ABS_MIN_VALUE, ABS_MAX_VALUE, ABS_FUZZ_VALUE, ABS_FLAT_VALUE},
    {ABS_RZ, 0, ABS_MAX_RXYZ, 0, ABS_FLAT},
    {ABS_GAS, 0, ABS_MAX_RXYZ, 0, ABS_FLAT},
    {ABS_BRAKE, 0, ABS_MAX_RXYZ, 0, ABS_FLAT},
    {ABS_HAT0X, ABS_MIN_HAT, 1, 0, 0},
    {ABS_HAT0Y, ABS_MIN_HAT, 1, 0, 0}
};
} // namespace

VirtualGamePad::VirtualGamePad() : VirtualDevice("Virtual GamePad", BUS_USB, 0x79, 0x181c)
{
    eventTypes_ = { EV_KEY, EV_ABS, EV_MSC };
    abs_ = { ABS_X, ABS_Y, ABS_Z, ABS_RX, ABS_RY, ABS_RZ, ABS_GAS, ABS_BRAKE, ABS_HAT0X, ABS_HAT0Y };
    keys_ = {
        KEY_HOMEPAGE, BTN_SOUTH, BTN_EAST, BTN_C, BTN_NORTH, BTN_WEST, BTN_Z, BTN_TL, BTN_TR,
        BTN_TL2, BTN_TR2, BTN_SELECT, BTN_START, BTN_MODE, BTN_THUMBL, BTN_THUMBR
    };
    miscellaneous_ = { MSC_SCAN };

    for (const auto &item : absInfos) {
        SetAbsValue(item);
    }
}
} // namespace MMI
} // namespace OHOS