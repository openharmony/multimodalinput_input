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

#include "virtual_knob_sys_ctrl.h"

namespace OHOS {
namespace MMI {
VirtualKnobSysCtrl::VirtualKnobSysCtrl() : VirtualDevice("Virtual KnobSysCtrl",
    BUS_USB, 0x5ac, 0x202)
{
}

VirtualKnobSysCtrl::~VirtualKnobSysCtrl() {}

const std::vector<uint32_t>& VirtualKnobSysCtrl::GetEventTypes() const
{
    static const std::vector<uint32_t> evt_types {
        EV_KEY, EV_MSC
    };
    return evt_types;
}

const std::vector<uint32_t>& VirtualKnobSysCtrl::GetKeys() const
{
    static const std::vector<uint32_t> keys {
        KEY_POWER, KEY_SLEEP, KEY_WAKEUP
    };
    return keys;
}

const std::vector<uint32_t>& VirtualKnobSysCtrl::GetMscs() const
{
    static const std::vector<uint32_t> mscs {
        MSC_SCAN
    };
    return mscs;
}
} // namespace MMI
} // namespace OHOS