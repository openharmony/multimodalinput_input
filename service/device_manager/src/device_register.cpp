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
        [[maybe_unused]] constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
            LOG_CORE, MMI_LOG_DOMAIN, "DeviceRegister"
        };
    }
DeviceRegister::DeviceRegister()
{
}

DeviceRegister::~DeviceRegister()
{
}

bool DeviceRegister::Init()
{
    MMI_LOGD("enter");
    deviceId_.clear();
    deviceInfo_.clear();
    if (mu_.try_lock()) {
        mu_.unlock();
    }
    SeniorDeviceInfo sensor = { "hos_input_device_aisensor", INPUT_DEVICE_AISENSOR };
    SeniorDeviceInfo knuckle = { "hos_input_device_knuckle", INPUT_DEVICE_KNUCKLE };
    deviceId_.insert(sensor.seniorDeviceType);
    deviceInfo_.insert(std::pair<std::string, uint32_t>(sensor.physical, sensor.seniorDeviceType));
    deviceId_.insert(knuckle.seniorDeviceType);
    deviceInfo_.insert(std::pair<std::string, uint32_t>(knuckle.physical, knuckle.seniorDeviceType));
    MMI_LOGD("leave");
    return true;
}

bool DeviceRegister::FindDeviceId(const std::string& physical, uint32_t& deviceId)
{
    MMI_LOGD("enter");
    std::lock_guard<std::mutex> lock(mu_);
    const uint32_t DEFAULT_DEVICE_ID = 0;
    auto it = deviceInfo_.find(physical);
    if (it == deviceInfo_.end()) {
        deviceId = DEFAULT_DEVICE_ID;
        return false;
    }
    deviceId = it->second;
    MMI_LOGD("leave");
    return true;
}

uint32_t DeviceRegister::AddDeviceInfo(const std::string& physical)
{
    MMI_LOGD("enter");
    std::lock_guard<std::mutex> lock(mu_);
    const uint32_t BEGIN_NUM = 1;
    auto it = deviceId_.find(BEGIN_NUM);
    if (it == deviceId_.end()) {
        deviceId_.insert(BEGIN_NUM);
        deviceInfo_.insert(std::pair<std::string, uint32_t>(physical, BEGIN_NUM));
        return BEGIN_NUM;
    } else {
        auto addDeviceId = *deviceId_.rbegin() + 1;
        if (addDeviceId >= std::numeric_limits<uint32_t>::max()) {
            MMI_LOGE("Device number exceeds bounds of uint32_t");
            return 0;
        }
        deviceId_.insert(addDeviceId);
        deviceInfo_.insert(std::pair<std::string, uint32_t>(physical, addDeviceId));
        MMI_LOGD("Adding Device number succeed");
        MMI_LOGD("leave");
        return addDeviceId;
    }
}

bool DeviceRegister::DeleteDeviceInfo(const std::string& physical)
{
    MMI_LOGD("enter");
    std::lock_guard<std::mutex> lock(mu_);
    auto it = deviceInfo_.find(physical);
    if (it != deviceInfo_.end()) {
        uint32_t deviceId = it->second;
        deviceInfo_.erase(it);
        deviceId_.erase(deviceId);
        return true;
    }
    MMI_LOGE("Failed to delete device info");
    MMI_LOGD("leave");
    return false;
}
} // namespace MMI
} // namespace OHOS
