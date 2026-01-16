/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "input_device_manager.h"
#include "define_multimodal.h"

namespace OHOS {
namespace MMI {
std::shared_ptr<InputDeviceManagerMock> InputDeviceManagerMock::instance_ = nullptr;

std::shared_ptr<InputDeviceManagerMock> InputDeviceManagerMock::GetInstance()
{
    if (instance_ == nullptr) {
        instance_ = std::make_shared<InputDeviceManagerMock>();
    }
    return instance_;
}

void InputDeviceManagerMock::ReleaseInstance()
{
    instance_.reset();
}

void InputDeviceManagerMock::AddInputDevice(int32_t deviceId, std::shared_ptr<IInputDevice> dev)
{
    CHKPV(dev);
    devices_.emplace(deviceId, dev);
}

void InputDeviceManagerMock::RemoveInputDevice(int32_t deviceId)
{
    devices_.erase(deviceId);
}

void InputDeviceManagerMock::ForEachDevice(std::function<void(int32_t, const IInputDevice&)> callback) const
{
    for (const auto &[deviceId, dev] : devices_) {
        if (callback && (dev != nullptr)) {
            callback(deviceId, *dev);
        }
    }
}

void InputDeviceManagerMock::ForDevice(int32_t deviceId, std::function<void(const IInputDevice&)> callback) const
{
    if (auto iter = devices_.find(deviceId); iter != devices_.cend()) {
        if (callback && (iter->second != nullptr)) {
            callback(*iter->second);
        }
    }
}

void InputDeviceManagerMock::ForOneDevice(std::function<bool(int32_t, const IInputDevice&)> pred,
    std::function<void(int32_t, const IInputDevice&)> callback) const
{
    for (const auto &[deviceId, dev] : devices_) {
        CHKPC(dev);
        if (pred && pred(deviceId, *dev)) {
            if (callback) {
                callback(deviceId, *dev);
            }
        }
    }
}
} // namespace MMI
} // namespace OHOS