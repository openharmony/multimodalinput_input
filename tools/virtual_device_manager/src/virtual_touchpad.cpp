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
 
#include "virtual_touchpad.h"

OHOS::MMI::VirtualTouchpad::VirtualTouchpad() : VirtualDevice("Virtual Touchpad",
    BUS_USB, 0x56a, 0x392)
{
    const int ABS_MAX_WHEEL = 71;
    
    dev_.absmin[ABS_X] = 0;
    dev_.absmax[ABS_X] = 1;
    dev_.absfuzz[ABS_X] = 0;
    dev_.absflat[ABS_X] = 0;
    
    dev_.absmin[ABS_Y] = 0;
    dev_.absmax[ABS_Y] = 1;
    dev_.absfuzz[ABS_Y] = 0;
    dev_.absflat[ABS_Y] = 0;
    
    dev_.absmin[ABS_WHEEL] = 0;
    dev_.absmax[ABS_WHEEL] = ABS_MAX_WHEEL;
    dev_.absfuzz[ABS_WHEEL] = 0;
    dev_.absflat[ABS_WHEEL] = 0;
    
    dev_.absmin[ABS_MISC] = 0;
    dev_.absmax[ABS_MISC] = 0;
    dev_.absfuzz[ABS_MISC] = 0;
    dev_.absflat[ABS_MISC] = 0;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualTouchpad::GetEventTypes() const
{
    static const std::vector<uint32_t> evt_types {
        EV_KEY, EV_ABS
    };
    return evt_types;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualTouchpad::GetKeys() const
{
    static const std::vector<uint32_t> keys {
        BTN_0, BTN_1, BTN_2, BTN_3, BTN_4, BTN_5, BTN_6, BTN_STYLUS, BTN_TOOL_PEN
    };
    return keys;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualTouchpad::GetAbs() const
{
    static const std::vector<uint32_t> abs {
        ABS_X, ABS_Y, ABS_WHEEL, ABS_MISC
    };
    return abs;
}