/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "virtual_mouse.h"

#include <iostream>
#include <thread>
#include <unordered_map>

#include <linux/input.h>

#include "virtual_mouse.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t SLEEP_TIME { 500 };
}

VirtualMouse::VirtualMouse()
    : VirtualDevice(GetDeviceName(), BUS_USB, 0x93a, 0x2510)
{
    eventTypes_ = { EV_KEY, EV_REL, EV_MSC };
    keys_ = { BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA, BTN_FORWARD, BTN_BACK, BTN_TASK };
    relBits_ = { REL_X, REL_Y, REL_WHEEL, REL_WHEEL_HI_RES };
    miscellaneous_ = { MSC_SCAN };
}

bool VirtualMouse::SetUp()
{
    if (!VirtualDevice::SetUp()) {
        return false;
    }
    int32_t nTries = 6;

    while (nTries-- > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
        std::string node;
        if (VirtualDevice::FindDeviceNode(GetDeviceName(), node)) {
            std::cout << "Found node path: " << node << std::endl;
            auto vMouse = std::make_unique<VInputDevice>(node);
            vMouse->Open();
            if (vMouse->IsActive()) {
                vMouse_ = std::move(vMouse);
                return true;
            }
        }
    }
    return false;
}

void VirtualMouse::SendEvent(uint16_t type, uint16_t code, int32_t value)
{
    if (vMouse_ == nullptr) {
        std::cout << "No pointer device" << std::endl;
        return;
    }
    vMouse_->SendEvent(type, code, value);
}

std::string VirtualMouse::GetDevPath() const
{
    return (vMouse_ != nullptr ? vMouse_->GetDevPath() : std::string());
}

std::string VirtualMouse::GetDeviceName()
{
    return std::string("Virtual Mouse");
}
} // namespace MMI
} // namespace OHOS