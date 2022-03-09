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

#include "input_device_manager.h"

namespace OHOS {
namespace MMI {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputDeviceManager"};
    constexpr int32_t INVALID_DEVICE_ID {-1};
}

std::shared_ptr<InputDevice> InputDeviceManager::GetInputDevice(int32_t id) const
{
    MMI_LOGD("begin");
    auto item = inputDevice_.find(id);
    if (item == inputDevice_.end()) {
        MMI_LOGE("failed to search for the device");
        return nullptr;
    }

    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    if (inputDevice == nullptr) {
        MMI_LOGE("create InputDevice ptr failed");
        return nullptr;
    }
    inputDevice->SetId(item->first);
    int32_t deviceType = static_cast<int32_t>(libinput_device_get_tags(item->second));
    inputDevice->SetType(deviceType);
    std::string name = libinput_device_get_name(item->second);
    inputDevice->SetName(name);
    MMI_LOGD("end");
    return inputDevice;
}

std::vector<int32_t> InputDeviceManager::GetInputDeviceIds() const
{
    MMI_LOGD("begin");
    std::vector<int32_t> ids;
    for (const auto &item : inputDevice_) {
        ids.push_back(item.first);
    }
    MMI_LOGD("end");
    return ids;
}

void InputDeviceManager::OnInputDeviceAdded(struct libinput_device* inputDevice)
{
    MMI_LOGD("begin");
    CHKPV(inputDevice);
    for (const auto& item : inputDevice_) {
        if (item.second == inputDevice) {
            MMI_LOGI("the device already exists");
            return;
        }
    }
    if (nextId_ == INT32_MAX) {
        MMI_LOGE("the nextId_ exceeded the upper limit");
        return;
    }
    inputDevice_[nextId_] = inputDevice;
    ++nextId_;

    if (IsPointerDevice(static_cast<struct libinput_device *>(inputDevice))) {
        NotifyPointerDevice(true);
    }
    MMI_LOGD("end");
}

void InputDeviceManager::OnInputDeviceRemoved(struct libinput_device* inputDevice)
{
    MMI_LOGD("begin");
    CHKPV(inputDevice);
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (it->second == inputDevice) {
            inputDevice_.erase(it);
            if (IsPointerDevice(inputDevice)) {
                NotifyPointerDevice(false);
            }
            break;
        }
    }
    MMI_LOGD("end");
}

bool InputDeviceManager::IsPointerDevice(struct libinput_device* device)
{
    CHKPF(device);
    enum evdev_device_udev_tags udevTags = libinput_device_get_tags(device);
    MMI_LOGD("udev tag:%{public}d", static_cast<int32_t>(udevTags));
    return udevTags & (EVDEV_UDEV_TAG_MOUSE | EVDEV_UDEV_TAG_TRACKBALL | EVDEV_UDEV_TAG_POINTINGSTICK | 
    EVDEV_UDEV_TAG_TOUCHPAD | EVDEV_UDEV_TAG_TABLET_PAD);
}

void InputDeviceManager::Attach(std::shared_ptr<DeviceObserver> observer)
{
    MMI_LOGI("begin");
    observers_.push_back(observer);
}

void InputDeviceManager::Detach(std::shared_ptr<DeviceObserver> observer)
{
    MMI_LOGI("begin");
    observers_.remove(observer);
}

void InputDeviceManager::NotifyPointerDevice(bool hasPointerDevice)
{
    MMI_LOGI("observers_ size:%{public}zu", observers_.size());
    for (auto observer = observers_.begin(); observer != observers_.end(); observer++) {
        (*observer)->UpdatePointerDevice(hasPointerDevice);
    }
}

int32_t InputDeviceManager::FindInputDeviceId(struct libinput_device* inputDevice)
{
    MMI_LOGD("begin");
    CHKPR(inputDevice, INVALID_DEVICE_ID);
    for (const auto& item : inputDevice_) {
        if (item.second == inputDevice) {
            MMI_LOGI("find input device id success");
            return item.first;
        }
    }
    MMI_LOGE("find input device id failed");
    return INVALID_DEVICE_ID;
}
} // namespace MMI
} // namespace OHOS
