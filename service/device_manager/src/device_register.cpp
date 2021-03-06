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

#include "device_register.h"

namespace OHOS {
namespace MMI {
    namespace {
        [[maybe_unused]] static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
            LOG_CORE, MMI_LOG_DOMAIN, "DeviceRegister" };
    }
DeviceRegister::DeviceRegister()
{
}

DeviceRegister::~DeviceRegister()
{
}

bool DeviceRegister::Init()
{
    setDeviceId_.clear();
    mapDeviceInfo_.clear();
    if (mu_.try_lock()) {
        mu_.unlock();
    }
    SeniorDeviceInfo sensor = { "hos_input_device_aisensor", INPUT_DEVICE_AISENSOR };
    SeniorDeviceInfo knuckle = { "hos_input_device_knuckle", INPUT_DEVICE_KNUCKLE };
    setDeviceId_.insert(sensor.seniorDeviceType);
    mapDeviceInfo_.insert(std::pair<std::string, uint32_t>(sensor.devicePhys, sensor.seniorDeviceType));
    setDeviceId_.insert(knuckle.seniorDeviceType);
    mapDeviceInfo_.insert(std::pair<std::string, uint32_t>(knuckle.devicePhys, knuckle.seniorDeviceType));
    return true;
}

uint32_t DeviceRegister::FindDeviceIdByDevicePhys(std::string& devicePhys)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = mapDeviceInfo_.find(devicePhys);
    if (it != mapDeviceInfo_.end()) {
        return it->second;
    }
    return 0;
}

uint32_t DeviceRegister::AddDeviceInfo(std::string& devicePhys)
{
    std::lock_guard<std::mutex> lock(mu_);
    const uint32_t BEGIN_NUM = 1;
    if (!setDeviceId_.count(BEGIN_NUM)) {
        setDeviceId_.insert(BEGIN_NUM);
        mapDeviceInfo_.insert(std::pair<std::string, uint32_t>(devicePhys, BEGIN_NUM));
        return BEGIN_NUM;
    } else {
        std::set<uint32_t>::iterator previousPtr = setDeviceId_.begin();
        std::set<uint32_t>::iterator nextPtr = (++setDeviceId_.begin());
        uint32_t addDeviceId = 0;
        for (; previousPtr != setDeviceId_.end() && nextPtr != setDeviceId_.end(); previousPtr++, nextPtr++) {
            if (*previousPtr + 1 != *nextPtr) {
                addDeviceId = *previousPtr + 1;
                break;
            }
        }
        if (!addDeviceId) {
            addDeviceId = *(--setDeviceId_.end()) + 1;
        }
        if (setDeviceId_.count(addDeviceId)) {
            return 0;
        }
        setDeviceId_.insert(addDeviceId);
        mapDeviceInfo_.insert(std::pair<std::string, uint32_t>(devicePhys, addDeviceId));
        return addDeviceId;
    }
}

bool DeviceRegister::DeleteDeviceInfo(std::string& devicePhys)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = mapDeviceInfo_.find(devicePhys);
    if (it != mapDeviceInfo_.end()) {
        uint32_t deviceId = it->second;
        mapDeviceInfo_.erase(it);
        setDeviceId_.erase(deviceId);
        return true;
    } else {
        return false;
    }
}
}
}
