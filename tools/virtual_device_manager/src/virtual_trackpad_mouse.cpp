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

#include "virtual_trackpad_mouse.h"

OHOS::MMI::VirtualTrackpadMouse::VirtualTrackpadMouse() : VirtualDevice("Virtual TrackPadMouse",
    BUS_USB, 0x62a, 0x8255)
{
}

OHOS::MMI::VirtualTrackpadMouse::~VirtualTrackpadMouse() {}

const std::vector<uint32_t>& OHOS::MMI::VirtualTrackpadMouse::GetEventTypes() const
{
    static const std::vector<uint32_t> evt_types {
        EV_KEY, EV_REL, EV_MSC
    };
    return evt_types;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualTrackpadMouse::GetKeys() const
{
    static const std::vector<uint32_t> keys {
        BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA
    };
    return keys;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualTrackpadMouse::GetRelBits() const
{
    static const std::vector<uint32_t> rels {
        REL_X, REL_Y, REL_HWHEEL, REL_WHEEL, REL_WHEEL_HI_RES, REL_HWHEEL_HI_RES
    };
    return rels;
}

const std::vector<uint32_t>& OHOS::MMI::VirtualTrackpadMouse::GetMscs() const
{
    static const std::vector<uint32_t> mscs {
        MSC_SCAN
    };
    return mscs;
}
